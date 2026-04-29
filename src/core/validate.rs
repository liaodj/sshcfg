use anyhow::{Result, bail};

use crate::core::model::HostEntry;

pub fn validate_entry(entry: &HostEntry) -> Result<()> {
    let issues = collect_entry_issues(entry);
    if issues.is_empty() {
        return Ok(());
    }

    bail!(issues.join("; "))
}

pub fn collect_entry_issues(entry: &HostEntry) -> Vec<String> {
    let mut issues = Vec::new();

    if entry.host_patterns.is_empty() {
        issues.push("host patterns cannot be empty".to_string());
    }

    if entry
        .host_patterns
        .iter()
        .any(|pattern| pattern.trim().is_empty())
    {
        issues.push("host patterns cannot contain empty items".to_string());
    }

    let is_pattern = entry.kind().label() == "pattern";
    if !is_pattern && entry.hostname.as_deref().is_none_or(str::is_empty) {
        issues.push("HostName is required for non-pattern entries".to_string());
    }

    if let Some(port) = entry.port {
        if port == 0 {
            issues.push("Port must be greater than 0".to_string());
        }
    }

    for value in &entry.identity_files {
        if value.trim().is_empty() {
            issues.push("IdentityFile cannot be empty".to_string());
        }
    }

    for value in &entry.local_forwards {
        if let Some(issue) = validate_local_forward_value(value) {
            issues.push(issue);
        }
    }

    for value in &entry.remote_forwards {
        if let Some(issue) = validate_remote_forward_value(value) {
            issues.push(issue);
        }
    }

    if let Some(value) = &entry.strict_host_key_checking {
        let normalized = value.trim().to_ascii_lowercase();
        let allowed = [
            "yes",
            "no",
            "ask",
            "off",
            "accept-new",
            "true",
            "false",
            "on",
        ];
        if !allowed.contains(&normalized.as_str()) {
            issues.push(format!(
                "StrictHostKeyChecking expects `yes`, `no`, `ask`, `off`, or `accept-new`, got `{value}`"
            ));
        }
    }

    if let Some(value) = &entry.forward_agent {
        if value.trim().is_empty() {
            issues.push("ForwardAgent cannot be empty".to_string());
        }
    }

    if let Some(value) = &entry.tag {
        if value.trim().is_empty() {
            issues.push("Tag cannot be empty".to_string());
        }
    }

    for (key, value) in &entry.extra_options {
        if key.trim().is_empty() || value.trim().is_empty() {
            issues.push("custom directives require non-empty key and value".to_string());
            continue;
        }

        if key.eq_ignore_ascii_case("RemoteForward") {
            if let Some(issue) = validate_remote_forward_value(value) {
                issues.push(issue);
            }
        }
    }

    issues
}

fn validate_local_forward_value(value: &str) -> Option<String> {
    validate_port_forward_value("LocalForward", value)
}

fn validate_remote_forward_value(value: &str) -> Option<String> {
    validate_port_forward_value("RemoteForward", value)
}

fn validate_port_forward_value(field_name: &str, value: &str) -> Option<String> {
    let parts: Vec<&str> = value.split_whitespace().collect();
    if parts.len() != 2 {
        return Some(format!(
            "{field_name} must contain exactly two tokens: `{value}`"
        ));
    }

    let local = parts[0];
    let remote = parts[1];

    if !is_valid_local_forward_endpoint(local) {
        return Some(format!(
            "{field_name} has invalid local endpoint `{local}`: `{value}`"
        ));
    }

    if !is_valid_remote_forward_endpoint(remote) {
        return Some(format!(
            "{field_name} has invalid remote endpoint `{remote}`: `{value}`"
        ));
    }

    None
}

fn is_valid_local_forward_endpoint(token: &str) -> bool {
    is_path_like(token) || is_valid_port(token) || is_valid_host_port(token)
}

fn is_valid_remote_forward_endpoint(token: &str) -> bool {
    is_path_like(token) || is_valid_host_port(token)
}

fn is_path_like(token: &str) -> bool {
    token.contains('/') || token.contains('\\')
}

fn is_valid_host_port(token: &str) -> bool {
    if token.starts_with('[') {
        return is_valid_bracketed_host_port(token);
    }

    let Some((host, port)) = token.rsplit_once(':') else {
        return false;
    };

    !host.is_empty() && !host.contains(':') && is_valid_port(port)
}

fn is_valid_bracketed_host_port(token: &str) -> bool {
    let Some(close_idx) = token.find(']') else {
        return false;
    };

    let host = &token[1..close_idx];
    let Some(port) = token[close_idx + 1..].strip_prefix(':') else {
        return false;
    };

    !host.is_empty() && is_valid_port(port)
}

fn is_valid_port(token: &str) -> bool {
    matches!(token.parse::<u16>(), Ok(port) if port > 0)
}

#[cfg(test)]
mod tests {
    use crate::core::model::HostEntry;

    use super::{
        collect_entry_issues, validate_local_forward_value, validate_remote_forward_value,
    };

    #[test]
    fn accepts_common_local_forward_tcp_forms() {
        for value in [
            "8080 127.0.0.1:80",
            "127.0.0.1:8080 localhost:80",
            "[::1]:8080 [::1]:80",
        ] {
            assert_eq!(validate_local_forward_value(value), None, "{value}");
        }
    }

    #[test]
    fn accepts_local_forward_socket_paths() {
        for value in [
            "/tmp/local.sock 127.0.0.1:80",
            "8080 /tmp/remote.sock",
            "C:\\sshcfg\\local.sock 127.0.0.1:80",
        ] {
            assert_eq!(validate_local_forward_value(value), None, "{value}");
        }
    }

    #[test]
    fn accepts_remote_forward_socket_and_tcp_forms() {
        for value in [
            "8080 127.0.0.1:80",
            "/tmp/remote.sock 127.0.0.1:80",
            "8080 /tmp/remote.sock",
        ] {
            assert_eq!(validate_remote_forward_value(value), None, "{value}");
        }
    }

    #[test]
    fn rejects_local_forward_with_missing_or_extra_tokens() {
        for value in ["8080", "8080 127.0.0.1:80 extra"] {
            let issue = validate_local_forward_value(value).unwrap();
            assert!(issue.contains("exactly two tokens"), "{issue}");
        }
    }

    #[test]
    fn rejects_local_forward_with_invalid_local_endpoint() {
        for value in ["host:abc 127.0.0.1:80", "[::1] [::1]:80", "0 127.0.0.1:80"] {
            let issue = validate_local_forward_value(value).unwrap();
            assert!(issue.contains("invalid local endpoint"), "{issue}");
        }
    }

    #[test]
    fn rejects_local_forward_with_invalid_remote_endpoint() {
        for value in ["8080 host", "8080 127.0.0.1", "8080 [::1]"] {
            let issue = validate_local_forward_value(value).unwrap();
            assert!(issue.contains("invalid remote endpoint"), "{issue}");
        }
    }

    #[test]
    fn accepts_common_strict_host_key_checking_values() {
        for value in [
            "yes",
            "no",
            "ask",
            "off",
            "accept-new",
            "true",
            "false",
            "on",
        ] {
            let entry = HostEntry {
                host_patterns: vec!["demo".to_string()],
                hostname: Some("127.0.0.1".to_string()),
                strict_host_key_checking: Some(value.to_string()),
                ..HostEntry::default()
            };

            let issues = collect_entry_issues(&entry);
            assert!(issues.is_empty(), "{value}: {issues:?}");
        }
    }

    #[test]
    fn rejects_invalid_strict_host_key_checking_value() {
        let entry = HostEntry {
            host_patterns: vec!["demo".to_string()],
            hostname: Some("127.0.0.1".to_string()),
            strict_host_key_checking: Some("maybe".to_string()),
            ..HostEntry::default()
        };

        let issues = collect_entry_issues(&entry);

        assert_eq!(issues.len(), 1);
        assert!(issues[0].contains("StrictHostKeyChecking expects"));
    }

    #[test]
    fn accepts_forward_agent_boolean_env_and_path_forms() {
        for value in [
            "yes",
            "no",
            "true",
            "off",
            "$SSH_AUTH_SOCK",
            "/tmp/agent.sock",
            "agent.sock",
        ] {
            let entry = HostEntry {
                host_patterns: vec!["demo".to_string()],
                hostname: Some("127.0.0.1".to_string()),
                forward_agent: Some(value.to_string()),
                ..HostEntry::default()
            };

            let issues = collect_entry_issues(&entry);
            assert!(issues.is_empty(), "{value}: {issues:?}");
        }
    }

    #[test]
    fn rejects_empty_tag_value() {
        let entry = HostEntry {
            host_patterns: vec!["demo".to_string()],
            hostname: Some("127.0.0.1".to_string()),
            tag: Some("   ".to_string()),
            ..HostEntry::default()
        };

        let issues = collect_entry_issues(&entry);

        assert_eq!(issues.len(), 1);
        assert!(issues[0].contains("Tag cannot be empty"));
    }

    #[test]
    fn collect_entry_issues_reports_local_forward_validation_error() {
        let entry = HostEntry {
            host_patterns: vec!["demo".to_string()],
            hostname: Some("127.0.0.1".to_string()),
            local_forwards: vec!["8080 host".to_string()],
            ..HostEntry::default()
        };

        let issues = collect_entry_issues(&entry);

        assert_eq!(issues.len(), 1);
        assert!(issues[0].contains("invalid remote endpoint"));
    }

    #[test]
    fn collect_entry_issues_reports_remote_forward_validation_error() {
        let entry = HostEntry {
            host_patterns: vec!["demo".to_string()],
            hostname: Some("127.0.0.1".to_string()),
            remote_forwards: vec!["8080 host".to_string()],
            ..HostEntry::default()
        };

        let issues = collect_entry_issues(&entry);

        assert_eq!(issues.len(), 1);
        assert!(issues[0].contains("RemoteForward"));
        assert!(issues[0].contains("invalid remote endpoint"));
    }

    #[test]
    fn collect_entry_issues_still_validates_remote_forward_in_extra_options_for_compatibility() {
        let entry = HostEntry {
            host_patterns: vec!["demo".to_string()],
            hostname: Some("127.0.0.1".to_string()),
            extra_options: vec![("RemoteForward".to_string(), "8080 host".to_string())],
            ..HostEntry::default()
        };

        let issues = collect_entry_issues(&entry);

        assert_eq!(issues.len(), 1);
        assert!(issues[0].contains("RemoteForward"));
    }
}
