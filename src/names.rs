//! Domain normalization and pattern matching.
//!
//! Patterns:
//! - `example.com` matches that name and any subdomain
//! - `=example.com` matches only that name
//! - `*.example.com` matches subdomains, not the apex
//! - `*keyword*` is a glob (`*` is any run of characters)
//! - `*` matches every name

use crate::names::Pattern::{Contains, Exact, Glob, Subdomain, Suffix};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pattern {
    Exact(String),
    Suffix(String),
    Subdomain(String),
    /// Empty string matches everything. Used for a rule pattern of `*`.
    Contains(String),
    Glob(String),
}

pub fn normalize_name(raw: &str) -> String {
    let trimmed = raw.trim().trim_end_matches('.').trim();
    if trimmed.is_empty() {
        return String::new();
    }
    let lower = trimmed.to_ascii_lowercase();
    if lower.is_ascii() {
        return lower;
    }
    idna::domain_to_ascii(&lower).unwrap_or(lower)
}

pub fn parse_pattern(raw: &str) -> Result<Pattern, String> {
    let raw = raw.trim().to_ascii_lowercase();
    if raw.is_empty() {
        return Err("pattern is empty".into());
    }
    if raw == "*" {
        return Ok(Contains(String::new()));
    }
    if let Some(rest) = raw.strip_prefix('=') {
        let name = normalize_name(rest);
        if name.is_empty() || name.contains('*') {
            return Err(format!("invalid exact pattern `{raw}`"));
        }
        return Ok(Exact(name));
    }
    if let Some(rest) = raw.strip_prefix("*.") {
        if rest.contains('*') || rest.is_empty() {
            return Err(format!("invalid subdomain pattern `{raw}`"));
        }
        return Ok(Subdomain(normalize_name(rest)));
    }
    if raw.contains('*') {
        return Ok(Glob(raw));
    }
    let name = normalize_name(&raw);
    if name.is_empty() {
        return Err(format!("invalid pattern `{raw}`"));
    }
    Ok(Suffix(name))
}

pub fn matches(pattern: &Pattern, domain: &str) -> bool {
    let domain = normalize_name(domain);
    if domain.is_empty() {
        return false;
    }
    match pattern {
        Exact(p) => domain == *p,
        Suffix(p) => domain == *p || domain.ends_with(&format!(".{p}")),
        Subdomain(p) => domain.ends_with(&format!(".{p}")) && domain != *p,
        Contains(p) if p.is_empty() => true,
        Contains(p) => domain.contains(p),
        Glob(g) => glob_match(g, &domain),
    }
}

fn glob_match(glob: &str, domain: &str) -> bool {
    let parts: Vec<&str> = glob.split('*').collect();
    if parts.len() == 1 {
        return domain == glob;
    }
    let mut rest = domain;
    for (i, part) in parts.iter().enumerate() {
        if part.is_empty() {
            continue;
        }
        let anchored_start = i == 0;
        let anchored_end = i + 1 == parts.len();
        if anchored_start {
            if !rest.starts_with(part) {
                return false;
            }
            rest = &rest[part.len()..];
            continue;
        }
        if anchored_end {
            return rest.ends_with(part);
        }
        match rest.find(part) {
            Some(idx) => rest = &rest[idx + part.len()..],
            None => return false,
        }
    }
    true
}

pub fn is_infrastructure(domain: &str) -> bool {
    let domain = normalize_name(domain);
    if domain.is_empty() || !domain.contains('.') {
        return true;
    }
    const SUFFIXES: &[&str] = &[
        "local",
        "lan",
        "home",
        "internal",
        "arpa",
        "localhost",
        "localdomain",
        "invalid",
    ];
    SUFFIXES
        .iter()
        .any(|s| domain == *s || domain.ends_with(&format!(".{s}")))
}

/// Best-effort registrable domain, used only as context for the decision model.
pub fn registrable(domain: &str) -> String {
    let domain = normalize_name(domain);
    let labels: Vec<&str> = domain.split('.').filter(|s| !s.is_empty()).collect();
    if labels.len() <= 2 {
        return domain;
    }
    let last2 = format!("{}.{}", labels[labels.len() - 2], labels[labels.len() - 1]);
    const MULTI: &[&str] = &[
        "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.nz", "com.br",
        "co.jp", "com.mx", "co.za", "com.tr", "com.sg", "co.in",
    ];
    if MULTI.contains(&last2.as_str()) && labels.len() >= 3 {
        return format!(
            "{}.{}.{}",
            labels[labels.len() - 3],
            labels[labels.len() - 2],
            labels[labels.len() - 1]
        );
    }
    last2
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suffix_matches_apex_and_subdomain_only() {
        let p = parse_pattern("Example.COM").unwrap();
        assert!(matches(&p, "example.com"));
        assert!(matches(&p, "a.example.com."));
        assert!(!matches(&p, "notexample.com"));
        assert!(!matches(&p, "example.com.evil"));
    }

    #[test]
    fn exact_and_subdomain_and_glob() {
        let exact = parse_pattern("=ads.example.com").unwrap();
        assert!(matches(&exact, "ads.example.com"));
        assert!(!matches(&exact, "x.ads.example.com"));

        let sub = parse_pattern("*.example.com").unwrap();
        assert!(matches(&sub, "a.example.com"));
        assert!(!matches(&sub, "example.com"));

        let glob = parse_pattern("*porn*").unwrap();
        assert!(matches(&glob, "www.porn.example"));
        assert!(!matches(&glob, "example.com"));
        assert!(matches(&parse_pattern("*").unwrap(), "anything.example"));
    }

    #[test]
    fn infrastructure_skips_reverse_and_lan() {
        assert!(is_infrastructure("1.2.3.4.in-addr.arpa"));
        assert!(is_infrastructure("printer.local"));
        assert!(is_infrastructure("router"));
        assert!(!is_infrastructure("example.com"));
    }
}
