use rust_web_sanitizer::*;

// ==========================================
// Test per create_sanitizer_rules
// ==========================================
#[cfg(test)]
mod create_sanitizer_rules_tests {
    use super::*;

    #[test]
    fn test_create_sanitizer_rules_default() {
        // Utilizziamo le regole di default tramite il parsing di un TOML vuoto
        let rules: Rules = toml::from_str("").unwrap();

        let result = create_sanitizer_rules(&rules);
        assert!(
            result.is_ok(),
            "La creazione delle regole di default non deve fallire"
        );

        let (_settings, summary) = result.unwrap();

        // Verifichiamo che lo stato iniziale dello summary sia Accepted con un vettore vuoto
        let borrowed = summary.borrow();
        match *borrowed {
            ContentStatus::Accepted(ref vec) => {
                assert!(
                    vec.is_empty(),
                    "Il vettore degli elementi rimossi deve essere inizialmente vuoto"
                );
            }
            _ => panic!("Lo stato iniziale delle regole doveva essere ContentStatus::Accepted"),
        }
    }

    #[test]
    fn test_create_sanitizer_rules_custom() {
        // Creiamo una configurazione personalizzata con alcune regole mirate
        let toml_config = r#"
                max_parser_memory = 2097152
                
                [iframe]
                active = true
                need_replace = false
                
                [script]
                active = true
                need_replace = true
            "#;
        let rules: Rules = toml::from_str(toml_config).unwrap();

        let result = create_sanitizer_rules(&rules);
        assert!(
            result.is_ok(),
            "La creazione delle regole personalizzate deve andare a buon fine"
        );

        let (_settings, summary) = result.unwrap();

        // Verifichiamo sempre che lo summary parta correttamente nello stato Accepted
        let borrowed = summary.borrow();
        assert!(matches!(*borrowed, ContentStatus::Accepted(_)));
    }
}
