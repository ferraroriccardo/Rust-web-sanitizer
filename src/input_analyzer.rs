// [Input Layer] Gestione file locali, directory e fetch HTTP con controlli di sicurezza anti-traversal

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

const ABSOLUTE_MAX_FILES: usize = 5000;
const ABSOLUTE_MAX_DEPTH: usize = 64;

const DEFAULT_MAX_FILES: usize = 1000;
const DEFAULT_MAX_DEPTH: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InputSource {
    File(PathBuf),
    Url(String),
}

// Funzione ricorsiva di scansione con protezione anti-ciclo, limiti e path traversal jail
fn scan_directory_safely(
    dir_path: &Path,
    root_base_path: &Path,
    sources: &mut Vec<InputSource>,
    visited: &mut HashSet<PathBuf>,
    current_depth: usize,
    max_depth: usize,
    max_files: usize,
) -> Result<(), String> {
    if current_depth > max_depth {
        return Err(format!(
            "Maximum recursion depth ({}) reached at directory: {:?}",
            max_depth, dir_path
        ));
    }

    if sources.len() >= max_files {
        return Err(format!(
            "Maximum allowed file count ({}) exceeded during analysis.",
            max_files
        ));
    }

    let canonical_path = match dir_path.canonicalize() {
        Ok(p) => p,
        Err(e) => {
            return Err(format!("Failed to canonicalize path {:?}: {}", dir_path, e));
        }
    };

    // Prevenzione path traversal: verifica che il percorso canonico rimanga confinato dentro la root base
    if !canonical_path.starts_with(root_base_path) {
        return Err(format!(
            "Security violation: path traversal detected outside root directory: {:?}",
            canonical_path
        ));
    }

    if !visited.insert(canonical_path.clone()) {
        return Ok(());
    }

    let entries = fs::read_dir(dir_path)
        .map_err(|e| format!("Failed to read directory {:?}: {}", dir_path, e))?;

    for entry in entries {
        let entry = entry.map_err(|e| format!("I/O error reading directory entry: {}", e))?;
        let path = entry.path();

        let metadata = match fs::symlink_metadata(&path) {
            Ok(m) => m,
            Err(_) => continue,
        };

        if metadata.is_dir() {
            scan_directory_safely(
                &path,
                root_base_path,
                sources,
                visited,
                current_depth + 1,
                max_depth,
                max_files,
            )?;
        } else if metadata.is_file() || metadata.file_type().is_symlink() {
            // Risolviamo l'eventuale symlink per verificare che il file effettivo sia valido
            if let Ok(target_metadata) = fs::metadata(&path) {
                if target_metadata.is_file() {
                    if let Some(ext) = path.extension() {
                        if ext.eq_ignore_ascii_case("html") || ext.eq_ignore_ascii_case("htm") {
                            sources.push(InputSource::File(path));

                            if sources.len() >= max_files {
                                return Err(format!(
                                    "Maximum allowed file count ({}) exceeded during analysis.",
                                    max_files
                                ));
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

pub fn analyze_input(
    input: &str,
    configured_max_files: Option<usize>,
    configured_max_depth: Option<usize>,
) -> Result<Vec<InputSource>, String> {
    let max_files = configured_max_files
        .unwrap_or(DEFAULT_MAX_FILES)
        .min(ABSOLUTE_MAX_FILES);

    let max_depth = configured_max_depth
        .unwrap_or(DEFAULT_MAX_DEPTH)
        .min(ABSOLUTE_MAX_DEPTH);

    if input.starts_with("http://") || input.starts_with("https://") {
        Ok(vec![InputSource::Url(input.to_string())])
    } else {
        let path = Path::new(input);
        if !path.exists() {
            return Err(format!("Invalid or non-existent input path: {}", input));
        }

        let metadata = fs::metadata(path)
            .map_err(|e| format!("Failed to retrieve metadata for {}: {}", input, e))?;

        if metadata.is_dir() {
            let root_base_path = path
                .canonicalize()
                .map_err(|e| format!("Failed to canonicalize root directory {}: {}", input, e))?;

            let mut sources = Vec::new();
            let mut visited = HashSet::new();
            scan_directory_safely(
                path,
                &root_base_path,
                &mut sources,
                &mut visited,
                0,
                max_depth,
                max_files,
            )?;
            Ok(sources)
        } else if metadata.is_file() {
            Ok(vec![InputSource::File(path.to_path_buf())])
        } else {
            Err(format!("Unsupported input format: {}", input))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;
    use tempfile::tempdir;

    #[test]
    fn test_url_detection() {
        let result = analyze_input("https://example.com/page.html", None, None);
        assert!(result.is_ok());
        let sources = result.unwrap();
        assert_eq!(sources.len(), 1);
        match &sources[0] {
            InputSource::Url(url) => assert_eq!(url, "https://example.com/page.html"),
            _ => panic!("Expected URL source"),
        }
    }

    #[test]
    fn test_invalid_input_path() {
        let result = analyze_input("non_existent_path_12345.html", None, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_single_file_detection() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("test.html");
        let mut tmp_file = File::create(&file_path).unwrap();
        writeln!(tmp_file, "<html></html>").unwrap();

        let result = analyze_input(file_path.to_str().unwrap(), None, None);
        assert!(result.is_ok());
        let sources = result.unwrap();
        assert_eq!(sources.len(), 1);
        match &sources[0] {
            InputSource::File(p) => assert_eq!(p.file_name(), file_path.file_name()),
            _ => panic!("Expected File source"),
        }
    }

    #[test]
    fn test_directory_recursion_and_filtering() {
        let dir = tempdir().unwrap();

        // Crea un file .html valido
        let html_path = dir.path().join("index.html");
        File::create(&html_path).unwrap();

        // Crea un file con altra estensione (dovrebbe essere ignorato)
        let txt_path = dir.path().join("notes.txt");
        File::create(&txt_path).unwrap();

        // Crea una sottodirectory con un altro .html
        let sub_dir = dir.path().join("sub");
        fs::create_dir(&sub_dir).unwrap();
        let sub_html_path = sub_dir.join("page.html");
        File::create(&sub_html_path).unwrap();

        let result = analyze_input(dir.path().to_str().unwrap(), Some(10), Some(5));
        assert!(result.is_ok());
        let sources = result.unwrap();

        // Dovrebbe trovare esattamente 2 file HTML e ignorare il file .txt
        assert_eq!(sources.len(), 2);
    }

    #[test]
    fn test_max_files_limit() {
        let dir = tempdir().unwrap();
        for i in 0..5 {
            let file_path = dir.path().join(format!("test{}.html", i));
            File::create(&file_path).unwrap();
        }

        // Impostiamo il limite massimo a 2 file
        let result = analyze_input(dir.path().to_str().unwrap(), Some(2), Some(5));
        assert!(result.is_err());
    }
}

/*
// Test section
#[cfg(test)]
mod tests {
    use crate::{CustomError, InputSource, create_sanitizer_rules};
    use core::{assert, matches};
    use std::todo;


    // checking if it properly detects urls or paths
    #[test]
    fn check_correct_input_detection() {
        let src_http = detect_src("http://example.com");
        assert!(matches!(src_http, InputSource::Url(_)));

        let src_https = detect_src("https://example.com");
        assert!(matches!(src_https, InputSource::Url(_)));

        let src_file_relative = detect_src("./tests/sample.html");
        assert!(matches!(src_file_relative, InputSource::File(_)));

        let src_file_absolute = detect_src("/var/www/sample.html");
        assert!(matches!(src_file_absolute, InputSource::File(_)));
        todo!("non è più detect_src ma analyze_input");
    }


    // testing CustomError::Http error
    #[test]
    fn test_reqwest_error() {
        let toml = r#""#;

        let (rules, summary) = create_sanitizer_rules(&toml).unwrap();

        let result = apply_sanitization(
            rules,
            InputSource::Url(String::from("this is not a valid url at all")),
            summary,
        );

        assert!(matches!(result, Err(CustomError::Http(_))));
    }
}
    */
