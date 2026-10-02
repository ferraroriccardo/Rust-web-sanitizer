pub fn suspicious_host(link: &String) -> bool {
    let splitting_string: Vec<&str> = link.split_inclusive("//").collect();

    // URL relativo
    if splitting_string.len() < 2 {
        return false;
    }
    let mut string_with_domain = splitting_string[1].to_string();
    let idx_slash = string_with_domain
        .find('/')
        .unwrap_or(string_with_domain.len());
    let idx_question_mark = string_with_domain
        .find('?')
        .unwrap_or(string_with_domain.len());
    let idx_sharp = string_with_domain
        .find('#')
        .unwrap_or(string_with_domain.len());
    let idx_back_slash = string_with_domain
        .find('\\')
        .unwrap_or(string_with_domain.len());
    let idx = idx_slash
        .min(idx_question_mark)
        .min(idx_sharp)
        .min(idx_back_slash);

    let _rest = string_with_domain.split_off(idx);
    let authority = string_with_domain;

    let domain = match authority.rfind('@') {
        Some(at_idx) => &authority[at_idx + 1..],
        None => &authority[..],
    };

    if !domain.is_ascii() || domain.to_ascii_lowercase().contains("xn--") || domain.contains('%') {
        true
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_relative_or_empty_urls() {
        assert!(!suspicious_host(&String::from("")));
        assert!(!suspicious_host(&String::from("index.html")));
        assert!(!suspicious_host(&String::from(
            "/relative/path/to/resource"
        )));
    }

    #[test]
    fn test_benign_hosts() {
        assert!(!suspicious_host(&String::from("https://example.com")));
        assert!(!suspicious_host(&String::from(
            "http://sub.domain.org/path?query=1#hash"
        )));
        // Test con credenziali legittime prima della chiocciola
        assert!(!suspicious_host(&String::from(
            "https://user:pass@example.com/index.html"
        )));
    }

    #[test]
    fn test_suspicious_idn_non_ascii() {
        // Caratteri non ASCII nel dominio (IDN homograph attack)
        assert!(suspicious_host(&String::from("https://exämple.com")));
    }

    #[test]
    fn test_suspicious_punycode_xn() {
        // Presenza di xn-- (Punycode)
        assert!(suspicious_host(&String::from(
            "http://xn--80akhbyknj4f.com"
        )));
    }

    #[test]
    fn test_suspicious_percent_encoding() {
        // Presenza di % nel dominio (normalizzazione confusion / host split)
        assert!(suspicious_host(&String::from("http://example%2ecom/path")));
    }

    #[test]
    fn test_different_delimiters_in_authority() {
        // Verifica che i delimitatori \, ?, # taglino correttamente l'autorità
        assert!(!suspicious_host(&String::from("http://example.com\\path")));
        assert!(!suspicious_host(&String::from("http://example.com?query")));
        assert!(!suspicious_host(&String::from(
            "http://example.com#fragment"
        )));
    }
}
