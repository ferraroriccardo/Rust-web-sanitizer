// [Parsing Layer] Regole e logica con lol_html
pub mod handlers;
pub mod rules;
pub mod security;
pub mod status;

pub use rules::Rules;
pub use status::{ContentStatus, ProcessedResult, RemovedElement};

use crate::CustomError;
use handlers::{
    configure_element_rules, configure_meta_rule, configure_script_rule,
    configure_uri_and_event_rules,
};
use lol_html::errors::RewritingError;
use lol_html::{HtmlRewriter, MemorySettings, Settings};
use std::{cell::RefCell, rc::Rc, sync::Arc};

const DEFAULT_MAX_PARSER_MEMORY: usize = 10 * 1024 * 1024;

pub fn get_rules(toml_file: &str) -> Result<Rules, CustomError> {
    let rules: Rules = toml::from_str(toml_file)?;

    return Ok(rules);
}

fn map_rewriting_error(e: RewritingError) -> CustomError {
    match e {
        RewritingError::MemoryLimitExceeded(_) => {
            CustomError::RejectedContent(String::from("memory limit exceeded"))
        }
        other => CustomError::from(other),
    }
}

pub fn create_sanitizer_rules<'a>(
    rules: &'a Rules,
) -> Result<(Settings<'a, 'a>, Rc<RefCell<ContentStatus>>), CustomError> {
    let mut settings =
        Settings::new().with_memory_settings(MemorySettings::new().with_max_allowed_memory_usage(
            rules.max_parser_memory.unwrap_or(DEFAULT_MAX_PARSER_MEMORY),
        ));
    let shared_summary = Rc::new(RefCell::new(ContentStatus::Accepted(Vec::new())));

    // 1. Regole per iframe, link, form, immagini, stili e oggetti
    settings = configure_element_rules(settings, rules, Rc::clone(&shared_summary));

    // 2. Regole per URI pericolosi (javascript:, data:) ed eventi (on*)
    settings = configure_uri_and_event_rules(settings, rules, Rc::clone(&shared_summary));

    // 3. Regole speciali per il tag <meta> (redirect)
    settings = configure_meta_rule(settings, rules.meta.as_ref(), Rc::clone(&shared_summary));

    // 4. Regole speciali per il tag <script> (allow-list e inline)
    settings = configure_script_rule(settings, rules.script.as_ref(), Rc::clone(&shared_summary));

    Ok((settings, shared_summary))
}

pub fn sanitize_html(rules_file: Arc<Rules>, html: &[u8]) -> Result<ProcessedResult, CustomError> {
    let (settings, shared_summary) = create_sanitizer_rules(&rules_file)?;
    let removed_elements = shared_summary;

    let mut output: Vec<u8> = Vec::new();

    let mut rewriter = HtmlRewriter::new(settings, |c: &[u8]| {
        output.extend_from_slice(c);
    });

    rewriter.write(html).map_err(map_rewriting_error)?;
    rewriter.end().map_err(map_rewriting_error)?;

    let elements = removed_elements.replace(ContentStatus::Empty);

    match elements {
        ContentStatus::Accepted(_) => {
            let final_html = String::from_utf8(output)
                .unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned());
            Ok(ProcessedResult::new(final_html, elements))
        }
        ContentStatus::Rejected(ref tag_name) => {
            Err(CustomError::RejectedContent(tag_name.clone()))
        }
        _ => Err(CustomError::GenericError(String::from(
            "It should not return this kind of error here",
        ))),
    }
}

#[cfg(test)]
mod tests {
    use crate::engine::build_text_report;

use super::*;

    #[test]
    fn test_get_rules_variants() {
        // 1. TOML valido
        let valid_toml = r#"
            max_parser_memory = 5000000
            max_files_allowed = 10
        "#;
        let res_valid = get_rules(valid_toml);
        assert!(res_valid.is_ok());
        assert_eq!(res_valid.unwrap().max_parser_memory, Some(5000000));

        // 2. Stringa vuota (deve usare i default)
        let res_empty = get_rules("");
        assert!(res_empty.is_ok());
        assert!(res_empty.unwrap().max_parser_memory.is_none());

        // 3. TOML non valido (sintassi errata)
        let invalid_toml = "chiave_senza_valore = ";
        let res_invalid = get_rules(invalid_toml);
        assert!(res_invalid.is_err());
    }

    #[test]
    fn test_create_sanitizer_rules() {
        // Inizializziamo le rules tramite TOML vuoto sfruttando i default di serde
        let rules: Rules = toml::from_str("").unwrap();
        let result = create_sanitizer_rules(&rules);

        assert!(result.is_ok());
        let (_settings, summary) = result.unwrap();

        // Verifica che lo stato iniziale dello summary sia Accepted con un vettore vuoto
        let borrowed = summary.borrow();
        assert!(matches!(*borrowed, ContentStatus::Accepted(_)));
        if let ContentStatus::Accepted(ref vec) = *borrowed {
            assert!(vec.is_empty());
        }
    }

    // testing each rule, one by one, to make sure that they do their proper work
    // iframe
    // allow-list proper behaviour
    #[test]
    fn test_iframe_proper_behaviour() {
        let toml = r#"
           [iframe]
           need_replace = false # in this case we choose the attribute instead of the complete html removal
           filters = ["https://benevolent_resource.com"]
        "#;

        let bad_input = br#"<iframe src="https://malicious_resource.com/phishing"></iframe>"#;
        let good_input = br#"<iframe src="https://benevolent_resource.com"></iframe>"#;

        let rules: Rules = toml::from_str(toml).unwrap();
        let rules_arc = Arc::new(rules);

        let bad_result = sanitize_html(Arc::clone(&rules_arc), bad_input).unwrap();
        let good_result = sanitize_html(Arc::clone(&rules_arc), good_input).unwrap();

        println!("bad result {:?}", bad_result);
        println!("good result {:?}", good_result);

        assert!(
            !bad_result
                .get_final_html()
                .contains("https://malicious_resource.com")
        );
        assert!(
            good_result
                .get_final_html()
                .contains("https://benevolent_resource.com")
        );
    }
    // object
    // allow-list proper behaviour
    #[test]
    fn test_object_proper_behaviour() {
        let toml = r#"
           [object]
           need_replace = false 
           filters = ["https://benevolent_resource.com"]
        "#;

        let bad_input = br#"<object data="https://malicious_resource.com/phishing"></object>"#;
        let good_input = br#"<object data="https://benevolent_resource.com"></object>"#;

        let rules: Rules = toml::from_str(toml).unwrap();
        let rules_arc = Arc::new(rules);

        let bad_result = sanitize_html(Arc::clone(&rules_arc), bad_input).unwrap();
        let good_result = sanitize_html(Arc::clone(&rules_arc), good_input).unwrap();

        assert!(
            !bad_result
                .get_final_html()
                .contains("https://malicious_resource.com")
        );
        assert!(
            good_result
                .get_final_html()
                .contains("https://benevolent_resource.com")
        );
    }
    // embed
    // allow-list proper behaviour
    #[test]
    fn test_embed_proper_behaviour() {
        let toml = r#"
           [embed]
           need_replace = false 
           filters = ["https://benevolent_resource.com"]
        "#;

        let bad_input = br#"<embed src="https://malicious_resource.com/phishing"></embed>"#;
        let good_input = br#"<embed src="https://benevolent_resource.com"></embed>"#;

        let rules: Rules = toml::from_str(toml).unwrap();
        let rules_arc = Arc::new(rules);

        let bad_result = sanitize_html(Arc::clone(&rules_arc), bad_input).unwrap();
        let good_result = sanitize_html(Arc::clone(&rules_arc), good_input).unwrap();

        assert!(
            !bad_result
                .get_final_html()
                .contains("https://malicious_resource.com")
        );
        assert!(
            good_result
                .get_final_html()
                .contains("https://benevolent_resource.com")
        );
    }
    // javascript:
    // attribute removal proper behaviour
    #[test]
    fn test_javascript_uri_proper_behaviour() {
        let toml = r#"
           [javascript_uri]
           need_replace = false 
        "#;

        let bad_input =
            br#"<embed src=" javasCrIPt  :https://malicious_resource.com/phishing"></embed>"#;
        let good_input = br#"<embed src="   javaSCRIPT :https://benevolent_resource.com"></embed>"#;

        let rules: Rules = toml::from_str(toml).unwrap();
        let rules_arc = Arc::new(rules);

        let bad_result = sanitize_html(Arc::clone(&rules_arc), bad_input).unwrap();
        let good_result = sanitize_html(Arc::clone(&rules_arc), good_input).unwrap();

        assert!(
            !bad_result
                .get_final_html()
                .contains("https://malicious_resource.com")
        );
        assert!(
            !good_result
                .get_final_html()
                .contains("https://benevolent_resource.com")
        );
    }
    // data:
    // allow-list proper behaviour
    #[test]
    fn test_data_uri_proper_behaviour() {
        let toml = r#"
           [data_uri]
           need_replace = false 
           filters = ["image/png, image/jpeg, image/web"]
        "#;

        let bad_input = br#"<embed src=" dAtA:https://malicious_resource.com/phishing"></embed>"#;
        let good_input = br#"<embed src=" DaTa:image/png"></embed>"#;

        let rules: Rules = toml::from_str(toml).unwrap();
        let rules_arc = Arc::new(rules);

        let bad_result = sanitize_html(Arc::clone(&rules_arc), bad_input).unwrap();
        let good_result = sanitize_html(Arc::clone(&rules_arc), good_input).unwrap();

        assert!(
            !bad_result
                .get_final_html()
                .contains("https://malicious_resource.com")
        );
        assert!(!good_result.get_final_html().contains("image/jpeg"));
    }
    // on prefix
    // attribute removal proper behaviour
    #[test]
    fn test_on_prefix_proper_behaviour() {
        let toml = r#"
           [on_prefix]
           need_replace = false 
        "#;

        let bad_input = br#"<embed onError="https://malicious_resource.com/phishing"></embed>"#;
        let good_input = br#"<embed onClick="https://benevolent_resource.com"></embed>"#;

        let rules: Rules = toml::from_str(toml).unwrap();
        let rules_arc = Arc::new(rules);

        let bad_result = sanitize_html(Arc::clone(&rules_arc), bad_input).unwrap();
        let good_result = sanitize_html(Arc::clone(&rules_arc), good_input).unwrap();

        assert!(
            !bad_result
                .get_final_html()
                .contains("https://malicious_resource.com")
        );
        assert!(
            !good_result
                .get_final_html()
                .contains("https://benevolent_resource.com")
        );
    }
    // meta
    // allow-list proper behaviour
    // meta
    #[test]
    fn test_meta_proper_behaviour() {
        let toml = r#"
           [meta]
           need_replace = false
        "#;

        let bad_input = br#"<meta http-equiv="refresh" content="0;url=https://malicious_resource.com/phishing" />"#;
        let good_input = br#"<meta src="https://benevolent_resource.com" />"#;

        let rules: Rules = toml::from_str(toml).unwrap();
        let rules_arc = Arc::new(rules);

        let bad_result = sanitize_html(Arc::clone(&rules_arc), bad_input).unwrap();
        let good_result = sanitize_html(Arc::clone(&rules_arc), good_input).unwrap();

        assert!(!bad_result.get_final_html().contains("meta"));
        assert!(
            !bad_result
                .get_final_html()
                .contains("malicious_resource.com")
        );
        assert!(
            good_result
                .get_final_html()
                .contains("https://benevolent_resource.com")
        );
    }

    // meta safe should not be changed
    #[test]
    fn test_meta_benign_http_equiv_is_unchanged() {
        let toml = "[meta]\nneed_replace = false\n";
        let inputs: [&[u8]; 3] = [
            br#"<meta http-equiv="Content-Type" content="text/html; charset=utf-8">"#,
            br#"<meta http-equiv="X-UA-Compatible" content="IE=edge">"#,
            br#"<meta charset="utf-8">"#,
        ];
        for html in inputs {
            let res = run(toml, html).unwrap();
            assert_eq!(res.get_final_html().as_bytes(), html);
            assert!(all_actions(&res).is_empty());
        }
    }

    // refresh uppercase or with spazi should be removed
    #[test]
    fn test_meta_refresh_case_and_spaces() {
        let toml = "[meta]\nneed_replace = false\n";
        let inputs: [&[u8]; 3] = [
            br#"<meta http-equiv="REFRESH" content="0;url=https://malicious_resource.com">"#,
            br#"<meta http-equiv="Refresh" content="0;url=https://malicious_resource.com">"#,
            br#"<meta http-equiv=" refresh " content="0;url=https://malicious_resource.com">"#,
        ];
        for html in inputs {
            let res = run(toml, html).unwrap();
            assert!(!res.get_final_html().contains("malicious_resource.com"));
            assert_eq!(all_actions(&res).len(), 1);
        }
    }

    // with need_replace = true meta refresh becomes span
    #[test]
    fn test_meta_refresh_replaced_with_span() {
        let toml = "[meta]\nneed_replace = true\n";
        let res = run(
            toml,
            br#"<meta http-equiv="refresh" content="0;url=https://malicious_resource.com">"#,
        )
        .unwrap();
        assert!(!res.get_final_html().contains("<meta"));
        assert!(res.get_final_html().contains("<span"));
    }
    // script
    // allow-list proper behaviour
    #[test]
    fn test_script_proper_behaviour() {
        let toml = r#"
           [script]
           need_replace = false 
           filters = ["https://benevolent_resource.com"]
        "#;

        let bad_input = br#"<script src="https://malicious_resource.com/phishing"></script>"#;
        let good_input = br#"<script src="https://benevolent_resource.com></script>"#;

        let rules: Rules = toml::from_str(toml).unwrap();
        let rules_arc = Arc::new(rules);

        let bad_result = sanitize_html(Arc::clone(&rules_arc), bad_input).unwrap();
        let good_result = sanitize_html(Arc::clone(&rules_arc), good_input).unwrap();

        assert!(
            !bad_result
                .get_final_html()
                .contains("https://malicious_resource.com/phishing")
        );
        assert!(
            good_result
                .get_final_html()
                .contains("https://benevolent_resource.com")
        );
    }

    // links
    // block-list proper behaviour
    #[test]
    fn test_links_proper_behaviour() {
        let toml = r#"
           [links]
           need_replace = true
           filters = ["malicious_resource.com"]
        "#;

        let bad_input = br#"<a href="https://malicious_resource.com/phishing">Click</a>"#;
        let good_input = br#"<a href="https://benevolent_resource.com">Click</a>"#;

        let rules: Rules = toml::from_str(toml).unwrap();
        let rules_arc = Arc::new(rules);

        let bad_result = sanitize_html(Arc::clone(&rules_arc), bad_input).unwrap();
        let good_result = sanitize_html(Arc::clone(&rules_arc), good_input).unwrap();

        // Si aspetta che il link cattivo venga rimpiazzato con "#"
        assert!(bad_result.get_final_html().contains("\"#\""));
        assert!(
            good_result
                .get_final_html()
                .contains("https://benevolent_resource.com")
        );
    }

    // forms
    // block-list proper behaviour
    #[test]
    fn test_forms_proper_behaviour() {
        let toml = r#"
           [forms]
           need_replace = true
           filters = ["malicious_resource.com"]
        "#;

        let bad_input = br#"<form action="https://malicious_resource.com/phishing"></form>"#;
        let good_input = br#"<form action="https://benevolent_resource.com"></form>"#;

        let rules: Rules = toml::from_str(toml).unwrap();
        let rules_arc = Arc::new(rules);

        let bad_result = sanitize_html(Arc::clone(&rules_arc), bad_input).unwrap();
        let good_result = sanitize_html(Arc::clone(&rules_arc), good_input).unwrap();

        assert!(bad_result.get_final_html().contains("\"#\""));
        assert!(
            good_result
                .get_final_html()
                .contains("https://benevolent_resource.com")
        );
    }

    // images
    // block-list proper behaviour
    #[test]
    fn test_images_proper_behaviour() {
        let toml = r#"
           [images]
           need_replace = true
           filters = ["malicious_resource.com"]
        "#;

        let bad_input = br#"<img src="https://malicious_resource.com/tracker.png" />"#;
        let good_input = br#"<img src="https://benevolent_resource.com/logo.png" />"#;

        let rules: Rules = toml::from_str(toml).unwrap();
        let rules_arc = Arc::new(rules);

        let bad_result = sanitize_html(Arc::clone(&rules_arc), bad_input).unwrap();
        let good_result = sanitize_html(Arc::clone(&rules_arc), good_input).unwrap();

        assert!(bad_result.get_final_html().contains("\"#\""));
        assert!(
            good_result
                .get_final_html()
                .contains("https://benevolent_resource.com")
        );
    }

    // styles
    // block-list proper behaviour
    #[test]
    fn test_styles_proper_behaviour() {
        let toml = r#"
           [styles]
           need_replace = true
           filters = ["malicious_resource.com"]
        "#;

        let bad_input = br#"<link href="https://malicious_resource.com/style.css" />"#;
        let good_input = br#"<link href="https://benevolent_resource.com/style.css" />"#;

        let rules: Rules = toml::from_str(toml).unwrap();
        let rules_arc = Arc::new(rules);

        let bad_result = sanitize_html(Arc::clone(&rules_arc), bad_input).unwrap();
        let good_result = sanitize_html(Arc::clone(&rules_arc), good_input).unwrap();

        assert!(bad_result.get_final_html().contains("\"#\""));
        assert!(
            good_result
                .get_final_html()
                .contains("https://benevolent_resource.com")
        );
    }

    // testing proper reject case error
    #[test]
    fn test_rejection() {
        let toml = r#"
           [iframe]
           need_replace = true # to trigger rejection
           filters = ["https://benevolent_resource.com"]
        "#;

        let bad_input = br#"<iframe src="https://malicious_resource.com/phishing"></iframe>"#;
        let good_input = br#"<iframe src="https://benevolent_resource.com"></iframe>"#;

        let rules: Rules = toml::from_str(toml).unwrap();
        let rules_arc = Arc::new(rules);

        let bad_result = sanitize_html(Arc::clone(&rules_arc), bad_input);
        let good_result = sanitize_html(Arc::clone(&rules_arc), good_input);

        assert!(matches!(bad_result, Err(CustomError::RejectedContent(_))));
        assert!(good_result.is_ok());
    }

    // testing CustomError::ConfigParse error
    #[test]
    fn test_config_parse_error() {
        // the config should not have invalid field values
        let toml_invalid_need_replace_value = r#"
            [iframe] # using iframe as example
            need_replace = "not a boolean value"
        "#;

        assert!(matches!(
            toml::from_str::<Rules>(toml_invalid_need_replace_value),
            Err(_)
        ));

        let toml_invalid_filter_value = r#"
            [iframe]
            filters = "not a vector"
        "#;

        assert!(matches!(
            toml::from_str::<Rules>(toml_invalid_filter_value),
            Err(_)
        ));

        // empty fields must be valid
        let valid_toml_empty = r#"
            [iframe]
        "#;

        assert!(matches!(toml::from_str::<Rules>(valid_toml_empty), Ok(_)));

        // base usage of a rules
        let toml_sample = r#"
            [iframe]
            need_replace = false
            filters = ["a", "b", "c"]
        "#;

        assert!(matches!(toml::from_str::<Rules>(toml_sample), Ok(_)));
    }

    fn sample_processed_result() -> ProcessedResult {
        let toml = r#"
            [iframe]
            need_replace = false
            filters = [""]
        "#;

        let input = br#"<!doctype html><html><body><iframe src="http://172.17.0.1:3100/html/script-tag"></iframe></body></html>"#;

        let rules: Rules = toml::from_str(toml).unwrap();
        let rules_arc = Arc::new(rules);
        sanitize_html(rules_arc, input).unwrap()
    }

    #[test]
    fn test_default_output() {
        let result = sample_processed_result();
        let report = build_text_report(&result, "default");

        assert!(report.contains("Elements removed:"));
        assert!(!report.contains("Reason:"));
    }

    #[test]
    fn test_quiet_output() {
        let result = sample_processed_result();
        let report = build_text_report(&result, "quiet");

        assert!(!report.contains("Elements removed:"));
        assert!(!report.contains("Reason:"));
    }

    #[test]
    fn test_verbose_output() {
        let result = sample_processed_result();
        let report = build_text_report(&result, "verbose");

        assert!(report.contains("Elements removed:"));
        assert!(report.contains("Reason:"));
    }

    //helper
    fn run(toml: &str, html: &[u8]) -> Result<ProcessedResult, CustomError> {
        let rules = Arc::new(get_rules(toml).unwrap());
        sanitize_html(rules, html)
    }

    fn all_actions(r: &ProcessedResult) -> Vec<String> {
        r.get_content_status()
            .get_removed_elements()
            .map(|it| {
                it.flat_map(|e| e.get_elements_removed().cloned())
                    .collect::<Vec<String>>()
            })
            .unwrap_or_default()
    }

    //thread safety
    fn assert_send_sync<T: Send + Sync>() {}

    #[test]
    fn test_types_are_send_sync() {
        assert_send_sync::<Rules>();
        assert_send_sync::<ProcessedResult>();
    }

    #[test]
    fn test_multithread_shared_rules() {
        let rules = Arc::new(get_rules("[on_prefix]\nneed_replace = false\n").unwrap());
        let handles: Vec<_> = (0..8)
            .map(|i| {
                let rules = Arc::clone(&rules);
                std::thread::spawn(move || {
                    let html = format!("<div onclick=\"x{}\">hi</div>", i);
                    // il risultato attraversa il thread: prova che e' Send
                    sanitize_html(rules, html.as_bytes()).unwrap()
                })
            })
            .collect();
        for h in handles {
            let res = h.join().unwrap();
            assert!(!res.get_final_html().contains("onclick"));
            assert!(res.get_final_html().contains("hi"));
        }
    }

    #[test]
    fn test_get_rules_errors() {
        assert!(matches!(
            get_rules("[iframe]\nneed_replace = \"x\""),
            Err(CustomError::ConfigParse(_))
        ));
        assert!(get_rules("").is_ok());
        // campo sconosciuto dentro una regola: gia' rifiutato
        assert!(get_rules("[iframe]\nfilterz = []").is_err());
    }

    #[test]
    fn test_unknown_rule_section_is_rejected() {
        assert!(matches!(
            get_rules("[iframes]\nneed_replace = true"),
            Err(CustomError::ConfigParse(_))
        ));
    }

    #[test]
    fn test_benign_page_is_unchanged() {
        let toml = r#"
            [on_prefix]
            need_replace = false
            [javascript_uri]
            need_replace = false
            [links]
            need_replace = true
            filters = ["malicious_resource.com"]
            [images]
            need_replace = true
            filters = ["malicious_resource.com"]
        "#;
        let html = br#"<p class="x">Hello</p><a href="https://example.com/page">link</a><img src="https://example.com/a.png">"#;
        let res = run(toml, html).unwrap();
        assert_eq!(res.get_final_html().as_bytes(), &html[..]);
        assert!(all_actions(&res).is_empty());
    }

    #[test]
    fn test_empty_input() {
        let res = run("[on_prefix]\nneed_replace = false\n", b"").unwrap();
        assert_eq!(res.get_final_html(), "");
    }

    #[test]
    fn test_javascript_uri_with_tab_is_removed() {
        let res = run(
            "[javascript_uri]\nneed_replace = false\n",
            b"<a href=\"jav\tascript:alert(1)\">x</a>",
        )
        .unwrap();
        assert!(!res.get_final_html().contains("alert"));
    }

    #[test]
    fn test_on_prefix_uppercase_removed() {
        let res = run(
            "[on_prefix]\nneed_replace = false\n",
            br#"<img src="a.png" ONERROR="alert(1)">"#,
        )
        .unwrap();
        assert!(!res.get_final_html().to_lowercase().contains("onerror"));
    }

    #[test]
    fn test_no_duplicate_actions() {
        let res = run(
            "[on_prefix]\nneed_replace = false\n",
            br#"<a onclick="x"></a><b onclick="y"></b>"#,
        )
        .unwrap();
        assert_eq!(all_actions(&res).len(), 2);
    }

    #[test]
    fn test_script_in_allowlist_produces_no_empty_action() {
        let toml = r#"
            [script]
            need_replace = false
            filters = ["https://benevolent_resource.com"]
        "#;
        let res = run(
            toml,
            br#"<script src="https://benevolent_resource.com"></script>"#,
        )
        .unwrap();
        assert!(
            res.get_final_html()
                .contains("https://benevolent_resource.com")
        );
        assert!(all_actions(&res).iter().all(|a| !a.is_empty()));
    }

    #[test]
    fn test_object_data_attribute_is_checked() {
        let toml = r#"
            [object]
            need_replace = false
            filters = ["https://benevolent_resource.com"]
        "#;
        let res = run(
            toml,
            br#"<object data="https://malicious_resource.com/x"></object>"#,
        )
        .unwrap();
        assert!(!res.get_final_html().contains("malicious_resource.com"));
    }

    #[test]
    fn test_iframe_srcdoc_is_not_a_bypass() {
        let toml = r#"
            [iframe]
            need_replace = false
            filters = ["https://benevolent_resource.com"]
        "#;
        let res = run(
            toml,
            br#"<iframe srcdoc="<script>alert(1)</script>"></iframe>"#,
        )
        .unwrap();
        assert!(!res.get_final_html().contains("alert(1)"));
    }

    #[test]
    fn test_non_utf8_input_is_not_dropped() {
        // 0xE9 = 'e' accentata in Latin-1, non e' UTF-8 valido
        let res = run("[on_prefix]\nneed_replace = false\n", b"<p>caf\xE9</p>").unwrap();
        assert!(res.get_final_html().contains("caf"));
    }

    //no panic
    #[test]
    fn test_hostile_input_does_not_panic() {
        let rules = "[on_prefix]\nneed_replace = false\n";
        let nested = "<div>".repeat(100_000);
        let _ = run(rules, nested.as_bytes());

        let huge_attr = format!("<a href=\"{}\">x</a>", "A".repeat(2_000_000));
        let _ = run(rules, huge_attr.as_bytes());

        let unclosed = format!("<a href=\"{}", "B".repeat(2_000_000));
        let _ = run(rules, unclosed.as_bytes());
    }

    #[test]
    fn test_memory_limit_from_config() {
        let toml = "max_parser_memory = 65536\n[on_prefix]\nneed_replace = false\n";
        let big = format!("<a href=\"{}\">x</a>", "A".repeat(200_000));
        let res = run(toml, big.as_bytes());
        assert!(matches!(res, Err(CustomError::RejectedContent(_))));
    }

    #[test]
    fn test_memory_limit_default_when_not_configured() {
        let big = format!("<a href=\"{}\">x</a>", "A".repeat(200_000));
        let res = run("[on_prefix]\nneed_replace = false\n", big.as_bytes());
        assert!(res.is_ok());
    }
    #[test]
    fn test_idn_homograph_and_host_split() {
        let toml = "[links]\nneed_replace = true\nfilters = [\"malicious_resource.com\"]\n";
        let bad = [
            "<a href=\"https://\u{430}pple.com/\">x</a>", // 'a' cirillica
            "<a href=\"https://xn--pple-43d.com/\">x</a>", // punycode
            "<a href=\"https://example.com\u{FF0F}evil.com/\">x</a>", // '／' a larghezza piena
        ];
        for html in bad {
            let res = run(toml, html.as_bytes()).unwrap();
            assert!(res.get_final_html().contains("\"#\""));
        }
        let ok = "<a href=\"https://example.com/caf\u{e9}\">x</a>"; // non-ASCII nel path: ammesso
        let res = run(toml, ok.as_bytes()).unwrap();
        assert!(res.get_final_html().contains("example.com"));
    }
}
