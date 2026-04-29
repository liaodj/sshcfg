use crate::core::model::HostEntry;

pub fn directives(entry: &HostEntry) -> Vec<(String, String)> {
    let mut lines = Vec::new();
    lines.push(("Host".to_string(), entry.host_patterns.join(" ")));

    if let Some(value) = &entry.hostname {
        lines.push(("HostName".to_string(), value.clone()));
    }
    if let Some(value) = &entry.user {
        lines.push(("User".to_string(), value.clone()));
    }
    if let Some(value) = entry.port {
        lines.push(("Port".to_string(), value.to_string()));
    }
    if let Some(value) = &entry.proxy_jump {
        lines.push(("ProxyJump".to_string(), value.clone()));
    }
    for value in &entry.identity_files {
        lines.push(("IdentityFile".to_string(), value.clone()));
    }
    for value in &entry.local_forwards {
        lines.push(("LocalForward".to_string(), value.clone()));
    }
    for value in &entry.remote_forwards {
        lines.push(("RemoteForward".to_string(), value.clone()));
    }
    if let Some(value) = &entry.strict_host_key_checking {
        lines.push(("StrictHostKeyChecking".to_string(), value.clone()));
    }
    if let Some(value) = &entry.user_known_hosts_file {
        lines.push(("UserKnownHostsFile".to_string(), value.clone()));
    }
    if let Some(value) = &entry.host_key_algorithms {
        lines.push(("HostKeyAlgorithms".to_string(), value.clone()));
    }
    if let Some(value) = &entry.pubkey_accepted_algorithms {
        lines.push(("PubkeyAcceptedAlgorithms".to_string(), value.clone()));
    }
    if let Some(value) = &entry.forward_agent {
        lines.push(("ForwardAgent".to_string(), value.clone()));
    }
    if let Some(value) = &entry.tag {
        lines.push(("Tag".to_string(), value.clone()));
    }
    for (key, value) in &entry.extra_options {
        lines.push((key.clone(), value.clone()));
    }

    lines
}

pub fn render_host_entry(entry: &HostEntry, newline: &str) -> String {
    let mut rendered = String::new();

    for (index, (key, value)) in directives(entry).into_iter().enumerate() {
        if index == 0 {
            rendered.push_str(&format!("{key} {value}{newline}"));
        } else {
            rendered.push_str(&format!("  {key} {value}{newline}"));
        }
    }

    rendered
}
