use rust_web_sanitizer::*;

// ==========================================
// 5. Test per build_json_report
// ==========================================
#[cfg(test)]
mod build_json_report_tests {
    use super::*;

    #[test]
    fn test_build_json_report_serialization() {
        // Creiamo un risultato elaborato fittizio
        let status = ContentStatus::Empty;
        let processed = ProcessedResult::new(
            String::from("<html><body>Clean Content</body></html>"),
            status,
        );

        // Generiamo il report JSON tramite l'API pubblica
        let json_output = build_json_report(&processed);

        assert!(
            !json_output.is_empty(),
            "La stringa JSON generata non deve essere vuota"
        );
        assert!(
            json_output.contains("Clean Content"),
            "Il report JSON deve contenere l'HTML finale elaborato"
        );
    }
}
