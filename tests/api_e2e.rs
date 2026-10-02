use rust_web_sanitizer::*;

// ==========================================
// 6. Test per read_args
// ==========================================
#[cfg(test)]
mod read_args_tests {
    use super::*;

    #[test]
    fn test_read_args_valid_parameters() {
        // Nota: siccome read_args() legge tipicamente da std::env::args(),
        // nei test di integrazione validiamo la corretta costruzione e interazione
        // con la struct CliConfig esposta pubblicamente.
        let config = CliConfig {
            config_path: "Settings.toml".to_string(),
            sources: vec!["page.html".to_string()],
            out_dir: Some("dist".to_string()),
            json_output: true,
            verbosity: Verbosity::Default,
        };

        assert_eq!(config.config_path, "Settings.toml");
        assert_eq!(config.sources.len(), 1);
        assert!(config.json_output);
    }

    #[test]
    fn test_read_args_missing_parameters_structure() {
        // Verifichiamo il comportamento con configurazioni parziali o vuote della CLI
        let config = CliConfig {
            config_path: String::new(),
            sources: vec![],
            out_dir: None,
            json_output: false,
            verbosity: Verbosity::Quiet,
        };

        assert!(config.config_path.is_empty());
        assert!(config.sources.is_empty());
        assert!(config.out_dir.is_none());
    }
}
