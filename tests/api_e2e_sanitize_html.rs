use rust_web_sanitizer::*;

// ==========================================
// Test per sanitize_html
// ==========================================
#[cfg(test)]
mod sanitize_html_tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn test_sanitize_html_happy_path() {
        // Regole di default (nessuna restrizione attiva)
        let rules = Arc::new(toml::from_str("").unwrap());
        let html_input = b"<html><body><h1>Benvenuto</h1><p>Pagina sicura.</p></body></html>";

        let result = sanitize_html(rules, html_input);
        assert!(
            result.is_ok(),
            "Il parsing dell'HTML pulito non deve fallire"
        );

        let processed = result.unwrap();
        assert!(processed.get_final_html().contains("Benvenuto"));

        // Verifica che lo stato sia Accepted e vuoto
        match processed.get_content_status() {
            ContentStatus::Accepted(vec) => assert!(vec.is_empty()),
            _ => panic!("Lo stato del contenuto pulito doveva essere Accepted"),
        }
    }

    #[test]
    fn test_sanitize_html_malicious_injection() {
        // Configurazione per bloccare script e attributi on* (con need_replace = true)
        let toml_config = r#"
                [script]
                active = true
                need_replace = true
                
                [on_prefix]
                active = true
                need_replace = true
            "#;
        let rules = Arc::new(toml::from_str(toml_config).unwrap());
        let html_input = b"<html><body><script>maliciousCode()</script><div onclick=\"stealData()\">Clicca</div></body></html>";

        let result = sanitize_html(rules, html_input);
        assert!(result.is_ok());

        let processed = result.unwrap();
        let final_html = processed.get_final_html();

        // Lo script inline deve essere rimosso/svuotato e l'evento neutralizzato con "#"
        assert!(!final_html.contains("maliciousCode()"));
        assert!(final_html.contains("onclick=\"#\""));
    }

    #[test]
    fn test_sanitize_html_policy_rejection() {
        // Configurazione che attiva il rifiuto totale per gli iframe non in allow-list
        let toml_config = r#"
                [iframe]
                active = true
                need_replace = true # Attiva il comportamento di reject sull'iframe
                filters = ["https://trusted-iframe.com"]
            "#;
        let rules = Arc::new(toml::from_str(toml_config).unwrap());
        let hostile_html =
            b"<html><body><iframe src=\"https://malicious-site.com\"></iframe></body></html>";

        let result = sanitize_html(rules, hostile_html);

        // Deve restituire un errore di tipo RejectedContent
        assert!(result.is_err());
        match result.unwrap_err() {
            CustomError::RejectedContent(tag) => {
                assert_eq!(tag, "iframe");
            }
            other => panic!("Errore inatteso ricevuto: {:?}", other),
        }
    }

    #[test]
    fn test_memory_limit_exceeded() {
        // Impostiamo un budget di memoria restrittivo (es. 20 byte)
        let toml_config = r#"
                max_parser_memory = 20
            "#;
        let rules = Arc::new(toml::from_str(toml_config).unwrap());
        let large_html = b"<html><body>Questo e un blocco HTML decisamente troppo lungo per il budget di memoria impostato.</body></html>";

        let result = sanitize_html(rules, large_html);

        // Il motore di lol_html o il wrapper devono intercettare il limite di memoria
        assert!(result.is_err());
    }
}
