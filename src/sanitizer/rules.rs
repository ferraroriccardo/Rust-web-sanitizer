// defining struct for config rules
use serde::Deserialize;

#[derive(Debug, Deserialize, Default, Clone)]
#[serde(deny_unknown_fields)]
pub struct Fields {
    pub filters: Option<Vec<String>>,
    #[serde(default)] // for automatically setting the rule to false in case it's not used
    pub need_replace: bool, // this is useful in case we want either delete or replace a specific tag/attribute/value
    #[serde(default)]
    pub active: bool,
}
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct Rules {
    #[serde(default)]
    pub max_parser_memory: Option<usize>,
    #[serde(default)]
    pub max_files_allowed: Option<usize>,
    #[serde(default)]
    pub max_recursion_depth: Option<usize>,
    #[serde(default)]
    pub fetch_timeout_secs: Option<u64>,
    #[serde(default)]
    pub script: Option<Fields>,
    #[serde(default)]
    pub on_prefix: Option<Fields>,
    #[serde(default)]
    pub meta: Option<Fields>,
    #[serde(default)]
    pub iframe: Option<Fields>,
    #[serde(default)]
    pub object: Option<Fields>,
    #[serde(default)]
    pub embed: Option<Fields>,
    #[serde(default)]
    pub data_uri: Option<Fields>,
    #[serde(default)]
    pub javascript_uri: Option<Fields>,
    #[serde(default)]
    pub links: Option<Fields>,
    #[serde(default)]
    pub forms: Option<Fields>,
    #[serde(default)]
    pub images: Option<Fields>,
    #[serde(default)]
    pub styles: Option<Fields>,
}

#[derive(Clone, Copy)]
pub enum ActionMode {
    Reject,
    Replace,
    Remove,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_toml_deserialization() {
        let toml_data = r#"
            max_parser_memory = 2097152
            max_files_allowed = 50
            
            [script]
            need_replace = true
            active = true
            filters = ["https://trusted.com/script.js"]
        "#;

        let rules: Result<Rules, toml::de::Error> = toml::from_str(toml_data);
        assert!(rules.is_ok());

        let r = rules.unwrap();
        assert_eq!(r.max_parser_memory, Some(2097152));
        assert_eq!(r.max_files_allowed, Some(50));
        assert!(r.max_recursion_depth.is_none()); // Test del default (None)

        let script_field = r.script.unwrap();
        assert!(script_field.need_replace);
        assert!(script_field.active);
        assert_eq!(script_field.filters.unwrap().len(), 1);
    }

    #[test]
    fn test_deny_unknown_fields_enforcement() {
        // Inseriamo un campo non valido ("invalid_field_typo") per testare deny_unknown_fields
        let invalid_toml = r#"
            invalid_field_typo = 123
        "#;

        let rules: Result<Rules, toml::de::Error> = toml::from_str(invalid_toml);
        assert!(
            rules.is_err(),
            "Dovrebbe fallire a causa di campi sconosciuti non consentiti"
        );
    }

    #[test]
    fn test_default_values_application() {
        // TOML vuoto: deve usare i default senza andare in errore
        let empty_toml = "";
        let rules: Result<Rules, toml::de::Error> = toml::from_str(empty_toml);
        assert!(rules.is_ok());

        let r = rules.unwrap();
        assert!(r.max_parser_memory.is_none());
        assert!(r.script.is_none());
    }
}
