use std::collections::HashMap;
use std::sync::OnceLock;

static TABLE: OnceLock<HashMap<String, String>> = OnceLock::new();

const BUNDLED: &str = include_str!("../data/oui.txt");

fn table() -> &'static HashMap<String, String> {
    TABLE.get_or_init(|| {
        let mut map = HashMap::new();
        for line in BUNDLED.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut parts = line.splitn(2, char::is_whitespace);
            if let (Some(prefix), Some(vendor)) = (parts.next(), parts.next()) {
                map.insert(prefix.to_ascii_uppercase(), vendor.trim().to_string());
            }
        }
        map
    })
}

pub fn lookup_vendor(mac: &str) -> Option<String> {
    let hex: String = mac
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .take(6)
        .collect::<String>()
        .to_ascii_uppercase();
    if hex.len() < 6 {
        return None;
    }
    table().get(&hex).cloned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_known_prefix() {
        assert_eq!(
            lookup_vendor("00:1A:11:22:33:44").as_deref(),
            Some("Google")
        );
        assert_eq!(lookup_vendor("F0-D4-E2-00-00-01").as_deref(), Some("Tesla"));
        assert_eq!(lookup_vendor("aa:aa:aa:aa:aa:aa"), None);
    }
}
