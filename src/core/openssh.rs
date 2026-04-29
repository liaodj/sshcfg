use std::collections::BTreeMap;
use std::path::Path;
use std::process::Command;
use std::sync::OnceLock;

use anyhow::{Context, Result, bail};

#[derive(Debug, Clone, Default)]
pub struct OpenSshProbe {
    pub version: Option<String>,
    pub error: Option<String>,
}

impl OpenSshProbe {
    pub fn discover() -> Self {
        match probe_version() {
            Ok(version) => Self {
                version: Some(version),
                error: None,
            },
            Err(err) => Self {
                version: None,
                error: Some(err.to_string()),
            },
        }
    }

    pub fn available(&self) -> bool {
        self.error.is_none() && self.version.is_some()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SshResolvedConfig {
    options: BTreeMap<String, Vec<String>>,
}

static MATCH_VERSION_CACHE: OnceLock<Option<String>> = OnceLock::new();

impl SshResolvedConfig {
    pub fn get_first(&self, key: &str) -> Option<&str> {
        self.options
            .get(&key.to_ascii_lowercase())
            .and_then(|values| values.first().map(String::as_str))
    }

    pub fn get_all(&self, key: &str) -> Option<&[String]> {
        self.options
            .get(&key.to_ascii_lowercase())
            .map(Vec::as_slice)
    }
}

pub fn probe_version() -> Result<String> {
    let output = Command::new("ssh")
        .arg("-V")
        .output()
        .context("failed to launch `ssh -V`")?;

    if !output.status.success() {
        bail!(
            "`ssh -V` failed: {}",
            command_message(&output.stdout, &output.stderr, output.status.code())
        );
    }

    parse_version_output(
        &String::from_utf8_lossy(&output.stdout),
        &String::from_utf8_lossy(&output.stderr),
    )
}

pub fn run_ssh_g(config_path: &Path, target: &str) -> Result<SshResolvedConfig> {
    let output = Command::new("ssh")
        .arg("-G")
        .arg(target)
        .arg("-F")
        .arg(config_path)
        .output()
        .with_context(|| format!("failed to launch `ssh -G {target}`"))?;

    if !output.status.success() {
        bail!(
            "{}",
            command_message(&output.stdout, &output.stderr, output.status.code())
        );
    }

    parse_ssh_g_output(&String::from_utf8_lossy(&output.stdout))
}

pub fn detect_match_version_string() -> Option<String> {
    MATCH_VERSION_CACHE
        .get_or_init(|| {
            probe_version()
                .ok()
                .and_then(|raw| normalize_match_version_string(&raw))
        })
        .clone()
}

pub fn normalize_match_version_string(raw: &str) -> Option<String> {
    let token = raw
        .trim()
        .split([' ', '\t', ','])
        .find(|part| !part.trim().is_empty())?
        .trim_end_matches(',');
    (!token.is_empty()).then_some(token.to_string())
}

pub fn parse_ssh_g_output(stdout: &str) -> Result<SshResolvedConfig> {
    let mut options = BTreeMap::<String, Vec<String>>::new();

    for raw_line in stdout.lines() {
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }

        let (key, value) = split_key_value(line)
            .with_context(|| format!("invalid `ssh -G` output line `{line}`"))?;
        options
            .entry(key.to_ascii_lowercase())
            .or_default()
            .push(value.to_string());
    }

    if options.is_empty() {
        bail!("`ssh -G` produced no config output");
    }

    Ok(SshResolvedConfig { options })
}

fn parse_version_output(stdout: &str, stderr: &str) -> Result<String> {
    first_non_empty_line(stderr)
        .or_else(|| first_non_empty_line(stdout))
        .map(ToString::to_string)
        .context("`ssh -V` produced no version text")
}

fn split_key_value(line: &str) -> Option<(&str, &str)> {
    let index = line.find(char::is_whitespace)?;
    let key = &line[..index];
    let value = line[index..].trim();
    (!value.is_empty()).then_some((key, value))
}

fn first_non_empty_line(text: &str) -> Option<&str> {
    text.lines().map(str::trim).find(|line| !line.is_empty())
}

fn command_message(stdout: &[u8], stderr: &[u8], code: Option<i32>) -> String {
    let stderr = String::from_utf8_lossy(stderr);
    let stdout = String::from_utf8_lossy(stdout);

    first_non_empty_line(&stderr)
        .or_else(|| first_non_empty_line(&stdout))
        .map(ToString::to_string)
        .unwrap_or_else(|| match code {
            Some(code) => format!("process exited with status code {code}"),
            None => "process terminated without an exit code".to_string(),
        })
}

#[cfg(test)]
mod tests {
    use super::{normalize_match_version_string, parse_ssh_g_output, parse_version_output};

    #[test]
    fn parses_version_from_stderr() {
        let version = parse_version_output("", "OpenSSH_9.5p1 for Windows").unwrap();
        assert_eq!(version, "OpenSSH_9.5p1 for Windows");
    }

    #[test]
    fn parses_ssh_g_output_and_preserves_repeated_keys() {
        let parsed = parse_ssh_g_output(
            "user demo\nhostname demo.example.com\nidentityfile ~/.ssh/id_a\nidentityfile ~/.ssh/id_b\n",
        )
        .unwrap();

        assert_eq!(parsed.get_first("user"), Some("demo"));
        assert_eq!(parsed.get_first("hostname"), Some("demo.example.com"));
        assert_eq!(parsed.get_first("identityfile"), Some("~/.ssh/id_a"));
    }

    #[test]
    fn rejects_invalid_ssh_g_output_line() {
        let err = parse_ssh_g_output("invalid-line-without-value").unwrap_err();
        assert!(err.to_string().contains("invalid `ssh -G` output line"));
    }

    #[test]
    fn normalizes_version_text_for_match_context() {
        assert_eq!(
            normalize_match_version_string("OpenSSH_for_Windows_9.5p1, LibreSSL 3.8.2"),
            Some("OpenSSH_for_Windows_9.5p1".to_string())
        );
        assert_eq!(
            normalize_match_version_string("OpenSSH_9.5p1 for Windows"),
            Some("OpenSSH_9.5p1".to_string())
        );
    }
}
