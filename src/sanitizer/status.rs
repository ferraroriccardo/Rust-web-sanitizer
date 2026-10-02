use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct ProcessedResult {
    final_html: String,
    parts_removed: ContentStatus,
}

impl ProcessedResult {
    pub fn new(final_html: String, parts_removed: ContentStatus) -> Self {
        Self {
            final_html,
            parts_removed,
        }
    }

    pub fn get_final_html(&self) -> &str {
        &self.final_html
    }

    pub fn get_content_status(&self) -> &ContentStatus {
        &self.parts_removed
    }
}

#[derive(Debug, Serialize)]
pub enum ContentStatus {
    Accepted(Vec<RemovedElement>),
    Empty,
    Rejected(String), // to insert the name of the tag
}

impl ContentStatus {
    pub fn get_removed_elements(&self) -> Option<std::slice::Iter<'_, RemovedElement>> {
        if let Self::Accepted(removed_element) = self {
            Some(removed_element.iter())
        } else {
            None
        }
    }
}

#[derive(Debug, Serialize)]
pub struct RemovedElement {
    elements: Vec<String>,
    reason: String,
}

impl RemovedElement {
    pub fn new(elements: Vec<String>, reason: String) -> Self {
        Self { elements, reason }
    }

    pub fn get_elements_removed(&self) -> std::slice::Iter<'_, String> {
        self.elements.iter()
    }

    pub fn get_reason(&self) -> &str {
        &self.reason
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_removed_element_getters() {
        let elements = vec![String::from("script"), String::from("onclick")];
        let reason = String::from("Malicious payload detected");
        let removed = RemovedElement::new(elements.clone(), reason.clone());

        assert_eq!(removed.get_reason(), &reason);
        let collected: Vec<&String> = removed.get_elements_removed().collect();
        assert_eq!(collected.len(), 2);
        assert_eq!(collected[0], &elements[0]);
    }

    #[test]
    fn test_content_status_variants() {
        // Caso 1: Accepted (deve restituire Some)
        let removed =
            RemovedElement::new(vec![String::from("iframe")], String::from("Not allowed"));
        let status_accepted = ContentStatus::Accepted(vec![removed]);

        assert!(status_accepted.get_removed_elements().is_some());
        let count = status_accepted.get_removed_elements().unwrap().count();
        assert_eq!(count, 1);

        // Caso 2: Empty (dovrebbe restituire None)
        let status_empty = ContentStatus::Empty;
        assert!(status_empty.get_removed_elements().is_none());

        // Caso 3: Rejected (dovrebbe restituire None)
        let status_rejected = ContentStatus::Rejected(String::from("script"));
        assert!(status_rejected.get_removed_elements().is_none());
    }

    #[test]
    fn test_processed_result_and_serialization() {
        let status = ContentStatus::Empty;
        let result = ProcessedResult::new(String::from("<html>Clean</html>"), status);

        assert_eq!(result.get_final_html(), "<html>Clean</html>");
        assert!(matches!(result.get_content_status(), ContentStatus::Empty));

        // Test rapido sulla serializzazione JSON (fondamentale per i report)
        let json_output = serde_json::to_string(&result);
        assert!(json_output.is_ok());
        let json_str = json_output.unwrap();
        assert!(json_str.contains("<html>Clean</html>"));
    }
}
