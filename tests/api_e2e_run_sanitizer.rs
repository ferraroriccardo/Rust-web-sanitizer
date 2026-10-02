use rust_web_sanitizer::*;

// ==========================================
// 4. Test per run_sanitizer
// ==========================================
mod run_sanitizer_tests {
    use super::*;
    use std::env;
    use std::fs::File;
    use std::io::Write;

    #[test]
    fn test_run_sanitizer_workflow_success() {
        let mut temp_dir = env::temp_dir();
        temp_dir.push("test_workflow_success");
        let _ = std::fs::create_dir_all(&temp_dir);

        // 1. Creiamo un file di configurazione TOML temporaneo
        let mut config_path = temp_dir.clone();
        config_path.push("config.toml");
        {
            let mut f = File::create(&config_path).unwrap();
            f.write_all(
                b"max_parser_memory = 1048576\n[script]\nactive = true\nneed_replace = true\n",
            )
            .unwrap();
        }

        // 2. Creiamo un file HTML di input con uno script da rimuovere
        let mut html_path = temp_dir.clone();
        html_path.push("input.html");
        {
            let mut f = File::create(&html_path).unwrap();
            f.write_all(b"<html><body><script>alert(1)</script><p>Safe content</p></body></html>")
                .unwrap();
        }

        // 3. Creiamo una cartella di output temporanea
        let mut out_dir = temp_dir.clone();
        out_dir.push("output");

        // 4. Costruiamo il CliConfig per run_sanitizer
        let cli_config = CliConfig {
            config_path: config_path.to_str().unwrap().to_string(),
            sources: vec![html_path.to_str().unwrap().to_string()],
            out_dir: Some(out_dir.to_str().unwrap().to_string()),
            json_output: true,
            verbosity: Verbosity::Default,
        };

        // 5. Eseguiamo run_sanitizer
        let result = run_sanitizer(&cli_config);
        assert!(
            result.is_ok(),
            "Il workflow completo di run_sanitizer non deve fallire: {:?}",
            result.err()
        );

        // 6. Verifichiamo che i file di output e il report JSON siano stati scritti sul disco
        let mut expected_output_file = out_dir.clone();
        expected_output_file.push("input.html");
        assert!(
            expected_output_file.exists(),
            "Il file HTML sanificato deve esistere nella cartella di output"
        );

        let mut expected_json_report = out_dir.clone();
        expected_json_report.push("input.html.report.json");
        assert!(
            expected_json_report.exists(),
            "Il report JSON associato deve esistere nella cartella di output"
        );

        // Pulizia finale
        let _ = std::fs::remove_dir_all(temp_dir);
    }

    #[test]
    fn test_run_sanitizer_missing_config() {
        let cli_config = CliConfig {
            config_path: "config_inesistente_999.toml".to_string(),
            sources: vec![],
            out_dir: None,
            json_output: false,
            verbosity: Verbosity::Default,
        };

        let result = run_sanitizer(&cli_config);
        assert!(
            result.is_err(),
            "Se il file di configurazione manca, run_sanitizer deve restituire un errore"
        );
    }

    #[test]
    fn test_run_sanitizer_file_size_budget() {
        let mut temp_dir = env::temp_dir();
        temp_dir.push("test_file_size_budget");
        let _ = std::fs::create_dir_all(&temp_dir);

        // 1. Configurazione con memoria massima molto bassa (es. 50 byte)
        let mut config_path = temp_dir.clone();
        config_path.push("config.toml");
        {
            let mut f = File::create(&config_path).unwrap();
            f.write_all(b"max_parser_memory = 50\n").unwrap();
        }

        // 2. Creiamo un file HTML più grande del budget consentito
        let mut html_path = temp_dir.clone();
        html_path.push("large_input.html");
        {
            let mut f = File::create(&html_path).unwrap();
            f.write_all(b"<html><body>Questo e un file HTML decisamente troppo grande per il budget impostato di soli cinquanta byte.</body></html>").unwrap();
        }

        let cli_config = CliConfig {
            config_path: config_path.to_str().unwrap().to_string(),
            sources: vec![html_path.to_str().unwrap().to_string()],
            out_dir: None,
            json_output: false,
            verbosity: Verbosity::Default,
        };

        // 3. Eseguiamo run_sanitizer: deve fallire perché la dimensione supera il budget
        let result = run_sanitizer(&cli_config);
        assert!(
            result.is_err(),
            "Il file di dimensioni superiori al budget di memoria deve essere rifiutato"
        );

        // Pulizia finale
        let _ = std::fs::remove_dir_all(temp_dir);
    }
}
