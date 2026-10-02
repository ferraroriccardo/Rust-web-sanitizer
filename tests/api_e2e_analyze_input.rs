use rust_web_sanitizer::*;

// ==========================================
// Test per analyze_input
// ==========================================
#[cfg(test)]
mod analyze_input_tests {
    use super::*;
    use std::{env, fs::File, io::Write};

    #[test]
    fn test_analyze_input_valid_file() {
        // Creiamo un file temporaneo sicuro per il test
        let mut temp_path = env::temp_dir();
        temp_path.push("test_analyze_input_valid.html");

        {
            let mut file = File::create(&temp_path).unwrap();
            file.write_all(b"<html><body>Contenuto di prova</body></html>")
                .unwrap();
        }

        let path_str = temp_path.to_str().unwrap();
        // Inovochiamo analyze_input con limiti di default (es. max 10 file, profondità 2)
        let result = analyze_input(path_str, Some(10), Some(2));

        assert!(
            result.is_ok(),
            "L'analisi di un file locale valido deve restituire Ok"
        );
        let sources = result.unwrap();
        assert_eq!(
            sources.len(),
            1,
            "Ci aspettiamo esattamente una sorgente risolta"
        );

        // Pulizia del file temporaneo
        let _ = std::fs::remove_file(temp_path);
    }

    #[test]
    fn test_analyze_input_invalid_file() {
        let invalid_path = "percorso/inesistente/file_fantasma_999.html";
        let result = analyze_input(invalid_path, Some(10), Some(2));

        assert!(
            result.is_err(),
            "L'analisi di un percorso inesistente deve restituire un errore"
        );
    }

    #[test]
    fn test_analyze_input_limits_and_recursion() {
        // Creiamo una directory temporanea con qualche file dentro
        let mut temp_dir = env::temp_dir();
        temp_dir.push("test_sanitizer_recursion");
        let _ = std::fs::create_dir_all(&temp_dir);

        for i in 0..3 {
            let mut file_path = temp_dir.clone();
            file_path.push(format!("file_{}.html", i));
            let mut file = File::create(file_path).unwrap();
            file.write_all(b"<html></html>").unwrap();
        }

        let dir_str = temp_dir.to_str().unwrap();

        // Testiamo il limite sul numero massimo di file consentiti (es. massimo 1 file ammesso)
        let result_limited = analyze_input(dir_str, Some(1), Some(1));
        assert!(
            result_limited.is_err(),
            "Se il numero di file supera max_files_allowed deve restituire errore"
        );

        // Pulizia della directory temporanea
        let _ = std::fs::remove_dir_all(temp_dir);
    }
}
