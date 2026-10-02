// [Core Engine] Orchestrator, fetching, and execution pipeline (Modularized)

use crate::cli::CliConfig;
use crate::input_analyzer::InputSource;
use crate::sanitizer::{ProcessedResult, Rules, get_rules, sanitize_html};
use crate::{CustomError, RemovedElement};
use std::io::Read;
use std::sync::{Arc, Mutex};
use std::thread;

pub fn build_text_report(result: &ProcessedResult, verbosity_level: &str) -> String {
    if verbosity_level == "quiet" {
        return String::new();
    }

    let mut output = String::new();
    let is_verbose = verbosity_level == "verbose";

    output.push_str(&format!("Final result length: {} bytes\n", result.get_final_html().len()));

    if let Some(removed_parts) = result.get_content_status().get_removed_elements() {
        if removed_parts.len() != 0 {
            output.push_str("Elements removed:\n");
        }

        removed_parts.for_each(|item: &RemovedElement| {
            item.get_elements_removed()
                .for_each(|element: &String| output.push_str(&format!("  - {}\n", element)));

            if is_verbose {
                output.push_str(&format!("    Reason: {}\n\n", item.get_reason()));
            }
        });
    }

    output
}

pub fn build_json_report(result: &ProcessedResult) -> String {
    serde_json::to_string_pretty(result).unwrap_or_else(|_| "{}".to_string())
}

pub fn apply_sanitization(
    input: &InputSource,
    rules_arc: Arc<Rules>,
) -> Result<ProcessedResult, CustomError> {
    let timeout_secs = rules_arc.fetch_timeout_secs.unwrap_or(10);
    let max_bytes = rules_arc.max_parser_memory.unwrap_or(10 * 1024 * 1024);

    let html_bytes = match input {
        InputSource::Url(link) => {
            let client = reqwest::blocking::Client::builder()
                .timeout(std::time::Duration::from_secs(timeout_secs))
                .build()?;
            
            let response = client.get(link).send()?;
            let mut reader = response.take(max_bytes as u64); 
            let mut bytes = Vec::new();
            
            reader.read_to_end(&mut bytes).map_err(|e| {
                CustomError::GenericError(format!("Failed to read downloaded content: {}", e))
            })?;
            
            bytes
        }
        InputSource::File(path) => {
            let metadata = std::fs::metadata(path).map_err(|e| {
                CustomError::GenericError(format!("Failed to read file metadata: {}", e))
            })?;
            
            let file_size = metadata.len();
            if file_size > max_bytes as u64 {
                return Err(CustomError::GenericError(format!(
                    "File size ({} bytes) exceeds the maximum allowed budget of {} bytes",
                    file_size, max_bytes
                )));
            }

            std::fs::read(path).map_err(|e| CustomError::GenericError(e.to_string()))?
        }
    };

    sanitize_html(rules_arc, &html_bytes)
}

// Sub-routine per la gestione dei worker threads e della coda condivisa
fn execute_worker_pool(
    all_sources: Vec<InputSource>,
    rules_arc: Arc<Rules>,
) -> Result<Vec<Result<(InputSource, ProcessedResult), (InputSource, CustomError)>>, CustomError> {
    let num_workers = thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);

    let (job_sender, job_receiver) = std::sync::mpsc::channel::<InputSource>();
    let job_receiver = Arc::new(Mutex::new(job_receiver));

    let (result_sender, result_receiver) = std::sync::mpsc::channel::<
        Result<(InputSource, ProcessedResult), (InputSource, CustomError)>,
    >();

    let mut worker_handles = Vec::with_capacity(num_workers);

    for _ in 0..num_workers {
        let job_rx = Arc::clone(&job_receiver);
        let res_tx = result_sender.clone();
        let rules_clone = Arc::clone(&rules_arc);

        let handle = thread::spawn(move || {
            loop {
                let task = {
                    let rx = job_rx.lock().unwrap();
                    rx.recv()
                };

                match task {
                    Ok(source) => {
                        let res = apply_sanitization(&source, Arc::clone(&rules_clone));
                        let processed = match res {
                            Ok(p) => Ok((source, p)),
                            Err(e) => Err((source, e)),
                        };
                        if res_tx.send(processed).is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });

        worker_handles.push(handle);
    }

    drop(result_sender);

    for source in all_sources {
        job_sender.send(source).unwrap();
    }
    drop(job_sender);

    let mut results = Vec::new();
    for res in result_receiver {
        results.push(res);
    }

    for handle in worker_handles {
        handle.join().map_err(|_| {
            CustomError::GenericError(String::from("A worker thread panicked during execution"))
        })?;
    }

    Ok(results)
}

// Sub-routine per la gestione dell'output, dei report e dei codici di uscita
fn process_results_and_output(
    results: Vec<Result<(InputSource, ProcessedResult), (InputSource, CustomError)>>,
    config: &CliConfig,
    verbosity_str: &str,
) -> Result<(), CustomError> {
    if let Some(dir) = &config.out_dir {
        std::fs::create_dir_all(dir).map_err(|e| {
            CustomError::GenericError(format!("Failed to create output directory: {}", e))
        })?;
    }

    let mut has_rejection = false;
    let mut has_error = false;

    for (index, item) in results.into_iter().enumerate() {
        match item {
            Ok((source, result)) => {
                let file_base_name = match &source {
                    InputSource::File(p) => p
                        .file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .into_owned(),
                    InputSource::Url(_) => format!("url_resource_{}", index),
                };

                if let Some(out_dir) = &config.out_dir {
                    let out_html_path = std::path::Path::new(out_dir).join(&file_base_name);
                    if let Err(e) = std::fs::write(&out_html_path, result.get_final_html()) {
                        eprintln!("Failed to write sanitized file {:?}: {}", out_html_path, e);
                    }

                    if config.json_output {
                        let json_report = build_json_report(&result);
                        let out_json_path = std::path::Path::new(out_dir)
                            .join(format!("{}.report.json", file_base_name));
                        if let Err(e) = std::fs::write(&out_json_path, json_report) {
                            eprintln!("Failed to write JSON report {:?}: {}", out_json_path, e);
                        }
                    }
                } else if config.json_output {
                    println!("{}", build_json_report(&result));
                }

                let text_report = build_text_report(&result, verbosity_str);
                if !text_report.is_empty() {
                    print!("{}", text_report);
                }
            }
            Err((_source, e)) => match e {
                CustomError::RejectedContent(tag) => {
                    eprintln!("Content rejected due to policy on tag: {}", tag);
                    has_rejection = true;
                }
                other => {
                    eprintln!("Error during sanitization: {}", other);
                    has_error = true;
                }
            },
        }
    }

    if has_error {
        std::process::exit(2);
    }
    if has_rejection {
        std::process::exit(1);
    }

    Ok(())
}

// Funzione principale che coordina i passaggi
pub fn run_sanitizer(config: &CliConfig) -> Result<(), CustomError> {
    let config_content = std::fs::read_to_string(&config.config_path)
        .map_err(|e| CustomError::GenericError(format!("Error reading config file: {}", e)))?;

    let rules = get_rules(&config_content)?;
    let rules_arc = Arc::new(rules.clone());

    let mut all_sources = Vec::new();
    for src_str in &config.sources {
        let sources = crate::input_analyzer::analyze_input(
            src_str,
            rules.max_files_allowed,
            rules.max_recursion_depth,
        )
        .map_err(CustomError::GenericError)?;

        all_sources.extend(sources);
    }

    let verbosity_str = format!("{:?}", config.verbosity).to_lowercase();

    let results = execute_worker_pool(all_sources, rules_arc)?;
    process_results_and_output(results, config, &verbosity_str)?;

    Ok(())
}