use std::path::Path;

use anyhow::{Context, Result, bail};

use crate::core::model::HostEntry;

pub fn parse_host_entry(path: &Path, content: &str) -> Result<HostEntry> {
    parse_directive_block(path, content, true)
}

pub fn parse_match_entry(path: &Path, content: &str) -> Result<HostEntry> {
    parse_directive_block(path, content, false)
}

fn parse_directive_block(
    path: &Path,
    content: &str,
    require_host_header: bool,
) -> Result<HostEntry> {
    let mut entry = HostEntry::default();
    let mut saw_host = false;

    for raw_line in content.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let (key, value) = split_key_value(line)
            .with_context(|| format!("invalid directive in {}", path.display()))?;

        if key.eq_ignore_ascii_case("Host") {
            if !require_host_header {
                bail!(
                    "unexpected `Host` directive in Match block: {}",
                    path.display()
                );
            }
            if saw_host {
                bail!(
                    "multiple `Host` blocks in one managed file are not supported: {}",
                    path.display()
                );
            }
            let patterns: Vec<String> = value.split_whitespace().map(ToString::to_string).collect();
            if patterns.is_empty() {
                bail!("`Host` directive is empty in {}", path.display());
            }
            entry.host_patterns = patterns;
            saw_host = true;
            continue;
        }

        if require_host_header && !saw_host {
            bail!(
                "expected `Host` as the first directive in managed file: {}",
                path.display()
            );
        }

        match key.to_ascii_lowercase().as_str() {
            "hostname" => entry.hostname = Some(value.to_string()),
            "user" => entry.user = Some(value.to_string()),
            "port" => {
                entry.port = Some(value.parse().with_context(|| {
                    format!("invalid `Port` value `{value}` in {}", path.display())
                })?)
            }
            "proxyjump" => entry.proxy_jump = Some(value.to_string()),
            "identityfile" => entry.identity_files.push(value.to_string()),
            "localforward" => entry.local_forwards.push(value.to_string()),
            "remoteforward" => entry.remote_forwards.push(value.to_string()),
            "stricthostkeychecking" => entry.strict_host_key_checking = Some(value.to_string()),
            "userknownhostsfile" => entry.user_known_hosts_file = Some(value.to_string()),
            "hostkeyalgorithms" => entry.host_key_algorithms = Some(value.to_string()),
            "pubkeyacceptedalgorithms" => {
                entry.pubkey_accepted_algorithms = Some(value.to_string())
            }
            "forwardagent" => entry.forward_agent = Some(value.to_string()),
            "tag" => entry.tag = Some(value.to_string()),
            _ => entry
                .extra_options
                .push((key.to_string(), value.to_string())),
        }
    }

    if require_host_header && !saw_host {
        bail!("no `Host` block found in {}", path.display());
    }

    Ok(entry)
}

fn split_key_value(line: &str) -> Option<(&str, &str)> {
    let idx = line.find(char::is_whitespace)?;
    let key = &line[..idx];
    let value = line[idx..].trim();
    if value.is_empty() {
        None
    } else {
        Some((key, value))
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::{parse_host_entry, parse_match_entry};

    #[test]
    fn parses_basic_host_entry() {
        let content = "Host bs-215\n  HostName 172.16.0.215\n  Port 2222\n  LocalForward 8080 127.0.0.1:80\n  RemoteForward 9090 127.0.0.1:90\n";
        let entry = parse_host_entry(Path::new("x.conf"), content).unwrap();

        assert_eq!(entry.host_patterns, vec!["bs-215"]);
        assert_eq!(entry.hostname.as_deref(), Some("172.16.0.215"));
        assert_eq!(entry.port, Some(2222));
        assert_eq!(entry.local_forwards, vec!["8080 127.0.0.1:80"]);
        assert_eq!(entry.remote_forwards, vec!["9090 127.0.0.1:90"]);
    }

    #[test]
    fn parses_match_body_entry() {
        let content = "  HostName alpha.example.com\n  User root\n  ForwardAgent no\n  Tag ops\n";
        let entry = parse_match_entry(Path::new("match.conf"), content).unwrap();

        assert_eq!(entry.hostname.as_deref(), Some("alpha.example.com"));
        assert_eq!(entry.user.as_deref(), Some("root"));
        assert_eq!(entry.forward_agent.as_deref(), Some("no"));
        assert_eq!(entry.tag.as_deref(), Some("ops"));
    }
}
