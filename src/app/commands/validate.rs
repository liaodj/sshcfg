use std::path::{Path, PathBuf};

use anyhow::{Result, bail};

use crate::app::cli::ValidateArgs;
use crate::core::model::{EntryKind, HostEntry, IgnoredScalarOverride, ManagedEntry};
use crate::core::openssh::{self, OpenSshProbe, SshResolvedConfig};
use crate::core::render;
use crate::core::resolve;
use crate::core::root_config;
use crate::core::store;
use crate::core::validate as core_validate;
use crate::fs::layout::{AppPaths, has_include_line, has_managed_block, platform_newline};
use crate::fs::writer;

#[derive(Debug, Clone, Default)]
pub struct ValidateOptions {
    pub ssh_g: bool,
}

impl From<ValidateArgs> for ValidateOptions {
    fn from(value: ValidateArgs) -> Self {
        Self { ssh_g: value.ssh_g }
    }
}

#[derive(Debug, Clone)]
pub struct ExternalSshReport {
    pub ssh_available: bool,
    pub ssh_version: Option<String>,
    pub ssh_error: Option<String>,
    pub checked_target_count: usize,
    pub skipped_pattern_count: usize,
    pub skipped_invalid_target_count: usize,
    pub compared_fields: Vec<&'static str>,
    pub root_match_influenced_mismatch_count: usize,
    pub root_influenced_mismatch_count: usize,
    pub managed_semantic_mismatch_count: usize,
    pub unclassified_mismatch_count: usize,
}

#[derive(Debug, Clone)]
pub struct ValidationReport {
    pub managed_entry_count: usize,
    pub root_config_exists: bool,
    pub has_managed_block: bool,
    pub has_include_line: bool,
    pub root_match_block_count: usize,
    pub root_match_unsupported_block_count: usize,
    pub root_match_unsupported_conditions: Vec<String>,
    pub issues: Vec<String>,
    pub external_ssh: Option<ExternalSshReport>,
}

impl ValidationReport {
    pub fn is_ok(&self) -> bool {
        self.issues.is_empty()
    }

    pub fn summary(&self) -> String {
        if self.is_ok() {
            let mut summary = format!(
                "Validation passed | {} managed entr{} checked",
                self.managed_entry_count,
                if self.managed_entry_count == 1 {
                    "y"
                } else {
                    "ies"
                }
            );

            if let Some(report) = &self.external_ssh {
                summary.push_str(&format!(
                    " | ssh -G {} target(s)",
                    report.checked_target_count
                ));
            }

            if self.root_match_block_count > 0 {
                summary.push_str(&format!(
                    " | root Match blocks {} detected",
                    self.root_match_block_count
                ));
            }
            if self.root_match_unsupported_block_count > 0 {
                summary.push_str(&format!(
                    " | unsupported root Match {}",
                    self.root_match_unsupported_block_count
                ));
            }

            summary
        } else {
            format!("Validation failed with {} issue(s)", self.issues.len())
        }
    }

    pub fn detail_lines(&self) -> Vec<String> {
        let mut lines = vec![
            format!("managed entries checked: {}", self.managed_entry_count),
            format!("root config exists: {}", self.root_config_exists),
            format!("has managed block: {}", self.has_managed_block),
            format!("has include line: {}", self.has_include_line),
            format!("root Match block count: {}", self.root_match_block_count),
            format!(
                "unsupported root Match block count: {}",
                self.root_match_unsupported_block_count
            ),
            format!(
                "unsupported root Match conditions: {}",
                if self.root_match_unsupported_conditions.is_empty() {
                    "-".to_string()
                } else {
                    self.root_match_unsupported_conditions.join(" | ")
                }
            ),
        ];

        if let Some(report) = &self.external_ssh {
            lines.push(String::new());
            lines.push("External ssh -G check:".to_string());
            lines.push(format!("ssh available: {}", report.ssh_available));
            lines.push(format!(
                "ssh version: {}",
                report.ssh_version.as_deref().unwrap_or("-")
            ));
            if let Some(error) = &report.ssh_error {
                lines.push(format!("ssh error: {error}"));
            }
            lines.push(format!(
                "checked exact targets: {}",
                report.checked_target_count
            ));
            lines.push(format!(
                "skipped pattern-only entries: {}",
                report.skipped_pattern_count
            ));
            lines.push(format!(
                "skipped invalid exact targets: {}",
                report.skipped_invalid_target_count
            ));
            lines.push(format!(
                "compared fields: {}",
                report.compared_fields.join(", ")
            ));
            lines.push(format!(
                "root Match influenced mismatches: {}",
                report.root_match_influenced_mismatch_count
            ));
            lines.push(format!(
                "root/global influenced mismatches: {}",
                report.root_influenced_mismatch_count
            ));
            lines.push(format!(
                "managed semantic mismatches: {}",
                report.managed_semantic_mismatch_count
            ));
            lines.push(format!(
                "unclassified mismatches: {}",
                report.unclassified_mismatch_count
            ));
        }

        lines.push(String::new());

        if self.issues.is_empty() {
            lines.push("No validation issues found.".to_string());
        } else {
            lines.push("Issues:".to_string());
            lines.extend(self.issues.iter().map(|issue| format!("- {issue}")));
        }

        lines
    }
}

pub fn collect_report(paths: &AppPaths, options: &ValidateOptions) -> Result<ValidationReport> {
    let mut issues = Vec::new();
    let mut root_config_exists = false;
    let mut has_managed_block_flag = false;
    let mut has_include_line_flag = false;
    let mut root_match_block_count = 0;
    let mut root_match_unsupported_block_count = 0;
    let mut root_match_unsupported_conditions = Vec::new();

    if paths.root_config.exists() {
        root_config_exists = true;
        let content = std::fs::read_to_string(&paths.root_config)?;
        has_managed_block_flag = has_managed_block(&content);
        has_include_line_flag = has_include_line(&content);
        let root_match_blocks = root_config::extract_match_blocks(&content);
        root_match_block_count = root_match_blocks.len();
        root_match_unsupported_block_count =
            root_config::unsupported_match_block_count(&root_match_blocks);
        root_match_unsupported_conditions =
            root_config::unsupported_match_conditions(&root_match_blocks);

        if !(has_managed_block_flag || has_include_line_flag) {
            issues.push(format!(
                "root config is missing `Include ~/.ssh/config.d/*`: {}",
                paths.root_config.display()
            ));
        }
    } else {
        issues.push(format!(
            "root config does not exist: {}",
            paths.root_config.display()
        ));
    }

    let entries = store::load_managed_entries(paths)?;
    for entry in &entries {
        let entry_issues = core_validate::collect_entry_issues(&entry.entry);
        for issue in entry_issues {
            issues.push(format!("{}: {}", entry.path.display(), issue));
        }
    }

    let external_ssh = options
        .ssh_g
        .then(|| collect_external_ssh_report(paths, &entries, &mut issues));

    Ok(ValidationReport {
        managed_entry_count: entries.len(),
        root_config_exists,
        has_managed_block: has_managed_block_flag,
        has_include_line: has_include_line_flag,
        root_match_block_count,
        root_match_unsupported_block_count,
        root_match_unsupported_conditions,
        issues,
        external_ssh,
    })
}

pub fn run(args: ValidateArgs) -> Result<()> {
    let paths = AppPaths::discover()?;
    let report = collect_report(&paths, &args.into())?;

    if report.is_ok() {
        println!("{}", report.summary());
        return Ok(());
    }

    for issue in &report.issues {
        eprintln!("- {issue}");
    }

    bail!("validation failed with {} issue(s)", report.issues.len())
}

fn collect_external_ssh_report(
    paths: &AppPaths,
    entries: &[ManagedEntry],
    issues: &mut Vec<String>,
) -> ExternalSshReport {
    let probe = openssh::OpenSshProbe::discover();
    collect_external_ssh_report_with_runner(paths, entries, issues, probe, openssh::run_ssh_g)
}

fn collect_external_ssh_report_with_runner<F>(
    paths: &AppPaths,
    entries: &[ManagedEntry],
    issues: &mut Vec<String>,
    probe: OpenSshProbe,
    mut run_ssh_g: F,
) -> ExternalSshReport
where
    F: FnMut(&Path, &str) -> Result<SshResolvedConfig>,
{
    let mut report = ExternalSshReport {
        ssh_available: probe.available(),
        ssh_version: probe.version.clone(),
        ssh_error: probe.error.clone(),
        checked_target_count: 0,
        skipped_pattern_count: 0,
        skipped_invalid_target_count: 0,
        compared_fields: compared_field_labels(),
        root_match_influenced_mismatch_count: 0,
        root_influenced_mismatch_count: 0,
        managed_semantic_mismatch_count: 0,
        unclassified_mismatch_count: 0,
    };

    if !report.ssh_available {
        issues.push(format!(
            "ssh -G checks requested but OpenSSH ssh is unavailable: {}",
            report
                .ssh_error
                .as_deref()
                .unwrap_or("no version information returned")
        ));
        return report;
    }

    let exact_entries = entries
        .iter()
        .filter(|entry| matches!(entry.entry.kind(), EntryKind::Host))
        .collect::<Vec<_>>();
    report.skipped_pattern_count = entries.len().saturating_sub(exact_entries.len());

    if exact_entries.is_empty() || !paths.root_config.exists() {
        return report;
    }

    let root_match_blocks = if paths.root_config.exists() {
        match std::fs::read_to_string(&paths.root_config) {
            Ok(content) => root_config::extract_match_blocks(&content),
            Err(err) => {
                issues.push(format!(
                    "failed to read root config while extracting Match blocks for ssh -G attribution: {err:#}"
                ));
                Vec::new()
            }
        }
    } else {
        Vec::new()
    };
    let local_user = root_config::detect_local_username();
    let local_networks = root_config::detect_local_networks();
    let normalized_ssh_match_version = probe
        .version
        .as_deref()
        .and_then(openssh::normalize_match_version_string);
    let synthetic_config =
        match write_synthetic_ssh_config(&paths.managed_config_path(), entries, &[]) {
            Ok(path) => Some(TempConfigFile { path }),
            Err(err) => {
                issues.push(format!(
                "failed to prepare synthetic managed-only config for ssh -G attribution: {err:#}"
            ));
                None
            }
        };
    let synthetic_with_match_config = if root_match_blocks.is_empty() {
        None
    } else {
        match write_synthetic_ssh_config(
            &paths.managed_match_config_path(),
            entries,
            &root_match_blocks,
        ) {
            Ok(path) => Some(TempConfigFile { path }),
            Err(err) => {
                issues.push(format!(
                    "failed to prepare synthetic managed+Match config for ssh -G attribution: {err:#}"
                ));
                None
            }
        }
    };
    let home_dir = paths.ssh_dir.parent().unwrap_or_else(|| Path::new(""));

    for entry in exact_entries {
        let target = entry.entry.primary_pattern();
        let resolved = match resolve::resolve_target_with_root_matches_and_options(
            entries,
            target,
            &root_match_blocks,
            resolve::RootMatchResolveOptions {
                local_user: (!local_user.is_empty()).then_some(local_user.as_str()),
                current_user: None,
                initial_tag: None,
                ssh_version: normalized_ssh_match_version.as_deref(),
                session_type: Some("shell"),
                command: Some(""),
                local_networks: &local_networks,
                is_canonical: false,
                is_final: true,
            },
        ) {
            Ok(resolved) => resolved,
            Err(err) => {
                issues.push(format!(
                    "failed to resolve managed preview for `{target}` before ssh -G check: {err:#}"
                ));
                continue;
            }
        };

        if !core_validate::collect_entry_issues(&resolved.merged_entry).is_empty() {
            report.skipped_invalid_target_count += 1;
            continue;
        }

        report.checked_target_count += 1;
        match run_ssh_g(&paths.root_config, target) {
            Ok(actual) => {
                let managed_only_actual = if let Some(config) = &synthetic_config {
                    match run_ssh_g(&config.path, target) {
                        Ok(actual) => Some(actual),
                        Err(err) => {
                            issues.push(format!(
                                "ssh -G failed for `{target}` with synthetic managed-only config: {err:#}"
                            ));
                            None
                        }
                    }
                } else {
                    None
                };
                let managed_with_match_actual = if let Some(config) = &synthetic_with_match_config {
                    match run_ssh_g(&config.path, target) {
                        Ok(actual) => Some(actual),
                        Err(err) => {
                            issues.push(format!(
                                "ssh -G failed for `{target}` with synthetic managed+Match config: {err:#}"
                            ));
                            None
                        }
                    }
                } else {
                    None
                };

                compare_resolved_target(
                    target,
                    &resolved.merged_entry,
                    &resolved.ignored_scalar_overrides,
                    &actual,
                    managed_only_actual.as_ref(),
                    managed_with_match_actual.as_ref(),
                    home_dir,
                    issues,
                    &mut report,
                )
            }
            Err(err) => issues.push(format!("ssh -G failed for `{target}`: {err:#}")),
        }
    }

    report
}

fn compare_resolved_target(
    target: &str,
    expected: &HostEntry,
    ignored_scalar_overrides: &[IgnoredScalarOverride],
    actual: &SshResolvedConfig,
    managed_only_actual: Option<&SshResolvedConfig>,
    managed_with_match_actual: Option<&SshResolvedConfig>,
    home_dir: &Path,
    issues: &mut Vec<String>,
    report: &mut ExternalSshReport,
) {
    compare_scalar_field(
        target,
        "HostName",
        expected.hostname.as_deref().map(normalize_plain),
        actual.get_first("hostname").map(normalize_plain),
        managed_only_actual
            .and_then(|config| config.get_first("hostname"))
            .map(normalize_plain),
        managed_with_match_actual
            .and_then(|config| config.get_first("hostname"))
            .map(normalize_plain),
        issues,
        report,
    );
    compare_scalar_field(
        target,
        "User",
        expected.user.as_deref().map(normalize_plain),
        actual.get_first("user").map(normalize_plain),
        managed_only_actual
            .and_then(|config| config.get_first("user"))
            .map(normalize_plain),
        managed_with_match_actual
            .and_then(|config| config.get_first("user"))
            .map(normalize_plain),
        issues,
        report,
    );
    compare_scalar_field(
        target,
        "Port",
        expected.port.map(|value| value.to_string()),
        actual.get_first("port").map(normalize_plain),
        managed_only_actual
            .and_then(|config| config.get_first("port"))
            .map(normalize_plain),
        managed_with_match_actual
            .and_then(|config| config.get_first("port"))
            .map(normalize_plain),
        issues,
        report,
    );
    compare_scalar_field(
        target,
        "ProxyJump",
        expected
            .proxy_jump
            .as_deref()
            .and_then(normalize_proxy_jump_value),
        actual
            .get_first("proxyjump")
            .and_then(normalize_proxy_jump_value),
        managed_only_actual
            .and_then(|config| config.get_first("proxyjump"))
            .and_then(normalize_proxy_jump_value),
        managed_with_match_actual
            .and_then(|config| config.get_first("proxyjump"))
            .and_then(normalize_proxy_jump_value),
        issues,
        report,
    );
    compare_vector_subset_field(
        target,
        "IdentityFile",
        expected
            .identity_files
            .iter()
            .map(|value| normalize_path_like(value, home_dir))
            .collect(),
        actual
            .get_all("identityfile")
            .unwrap_or(&[])
            .iter()
            .map(|value| normalize_path_like(value, home_dir))
            .collect(),
        managed_only_actual.map(|config| {
            config
                .get_all("identityfile")
                .unwrap_or(&[])
                .iter()
                .map(|value| normalize_path_like(value, home_dir))
                .collect()
        }),
        managed_with_match_actual.map(|config| {
            config
                .get_all("identityfile")
                .unwrap_or(&[])
                .iter()
                .map(|value| normalize_path_like(value, home_dir))
                .collect()
        }),
        issues,
        report,
    );
    compare_exact_vector_field(
        target,
        "LocalForward",
        expected
            .local_forwards
            .iter()
            .map(|value| normalize_local_forward_value(value))
            .collect(),
        actual
            .get_all("localforward")
            .unwrap_or(&[])
            .iter()
            .map(|value| normalize_local_forward_value(value))
            .collect(),
        managed_only_actual.map(|config| {
            config
                .get_all("localforward")
                .unwrap_or(&[])
                .iter()
                .map(|value| normalize_local_forward_value(value))
                .collect()
        }),
        managed_with_match_actual.map(|config| {
            config
                .get_all("localforward")
                .unwrap_or(&[])
                .iter()
                .map(|value| normalize_local_forward_value(value))
                .collect()
        }),
        issues,
        report,
    );
    compare_exact_vector_field(
        target,
        "RemoteForward",
        expected_remote_forward_values(expected, home_dir),
        actual
            .get_all("remoteforward")
            .unwrap_or(&[])
            .iter()
            .map(|value| normalize_remote_forward_value(value, home_dir))
            .collect(),
        managed_only_actual.map(|config| {
            config
                .get_all("remoteforward")
                .unwrap_or(&[])
                .iter()
                .map(|value| normalize_remote_forward_value(value, home_dir))
                .collect()
        }),
        managed_with_match_actual.map(|config| {
            config
                .get_all("remoteforward")
                .unwrap_or(&[])
                .iter()
                .map(|value| normalize_remote_forward_value(value, home_dir))
                .collect()
        }),
        issues,
        report,
    );
    compare_scalar_field(
        target,
        "StrictHostKeyChecking",
        expected
            .strict_host_key_checking
            .as_deref()
            .map(normalize_booleanish),
        actual
            .get_first("stricthostkeychecking")
            .map(normalize_booleanish),
        managed_only_actual
            .and_then(|config| config.get_first("stricthostkeychecking"))
            .map(normalize_booleanish),
        managed_with_match_actual
            .and_then(|config| config.get_first("stricthostkeychecking"))
            .map(normalize_booleanish),
        issues,
        report,
    );
    compare_exact_vector_field(
        target,
        "UserKnownHostsFile",
        expected
            .user_known_hosts_file
            .as_deref()
            .map(|value| normalize_path_list_value(value, home_dir))
            .unwrap_or_default(),
        actual
            .get_first("userknownhostsfile")
            .map(|value| normalize_path_list_value(value, home_dir))
            .unwrap_or_default(),
        managed_only_actual
            .and_then(|config| config.get_first("userknownhostsfile"))
            .map(|value| normalize_path_list_value(value, home_dir)),
        managed_with_match_actual
            .and_then(|config| config.get_first("userknownhostsfile"))
            .map(|value| normalize_path_list_value(value, home_dir)),
        issues,
        report,
    );
    compare_algorithm_field(
        target,
        "HostKeyAlgorithms",
        expected
            .host_key_algorithms
            .as_deref()
            .map(normalize_algorithm_value),
        actual
            .get_first("hostkeyalgorithms")
            .map(normalize_algorithm_value),
        managed_only_actual
            .and_then(|config| config.get_first("hostkeyalgorithms"))
            .map(normalize_algorithm_value),
        managed_with_match_actual
            .and_then(|config| config.get_first("hostkeyalgorithms"))
            .map(normalize_algorithm_value),
        issues,
        report,
    );
    compare_algorithm_field(
        target,
        "PubkeyAcceptedAlgorithms",
        expected
            .pubkey_accepted_algorithms
            .as_deref()
            .map(normalize_algorithm_value),
        actual
            .get_first("pubkeyacceptedalgorithms")
            .map(normalize_algorithm_value),
        managed_only_actual
            .and_then(|config| config.get_first("pubkeyacceptedalgorithms"))
            .map(normalize_algorithm_value),
        managed_with_match_actual
            .and_then(|config| config.get_first("pubkeyacceptedalgorithms"))
            .map(normalize_algorithm_value),
        issues,
        report,
    );
    compare_scalar_field(
        target,
        "ForwardAgent",
        expected
            .forward_agent
            .as_deref()
            .map(|value| normalize_forward_agent_value(value, home_dir)),
        actual
            .get_first("forwardagent")
            .map(|value| normalize_forward_agent_value(value, home_dir)),
        managed_only_actual
            .and_then(|config| config.get_first("forwardagent"))
            .map(|value| normalize_forward_agent_value(value, home_dir)),
        managed_with_match_actual
            .and_then(|config| config.get_first("forwardagent"))
            .map(|value| normalize_forward_agent_value(value, home_dir)),
        issues,
        report,
    );

    if let Some(issue) = explain_ignored_scalar_overrides(
        target,
        ignored_scalar_overrides,
        actual,
        managed_only_actual,
        home_dir,
    ) {
        issues.push(issue);
    }
}

fn compare_scalar_field(
    target: &str,
    field: &str,
    expected: Option<String>,
    actual: Option<String>,
    managed_only_actual: Option<String>,
    managed_with_match_actual: Option<String>,
    issues: &mut Vec<String>,
    report: &mut ExternalSshReport,
) {
    let Some(expected) = expected else {
        return;
    };

    let actual_matches = actual.as_ref().is_some_and(|value| value == &expected);
    if actual_matches {
        return;
    }
    let managed_matches = managed_only_actual.as_ref().map(|value| value == &expected);

    record_mismatch(
        target,
        field,
        expected,
        actual,
        managed_matches,
        managed_only_actual,
        managed_with_match_actual,
        issues,
        report,
    );
}

fn compare_vector_subset_field(
    target: &str,
    field: &str,
    expected: Vec<String>,
    actual: Vec<String>,
    managed_only_actual: Option<Vec<String>>,
    managed_with_match_actual: Option<Vec<String>>,
    issues: &mut Vec<String>,
    report: &mut ExternalSshReport,
) {
    if expected.is_empty() {
        return;
    }

    let root_matches = expected.iter().all(|value| actual.contains(value));
    if root_matches {
        return;
    }

    let managed_matches = managed_only_actual
        .as_ref()
        .map(|values| expected.iter().all(|value| values.contains(value)));
    record_mismatch(
        target,
        field,
        display_values(&expected),
        Some(display_values(&actual)),
        managed_matches,
        managed_only_actual
            .as_ref()
            .map(|values| display_values(values)),
        managed_with_match_actual
            .as_ref()
            .map(|values| display_values(values)),
        issues,
        report,
    );
}

fn compare_exact_vector_field(
    target: &str,
    field: &str,
    expected: Vec<String>,
    actual: Vec<String>,
    managed_only_actual: Option<Vec<String>>,
    managed_with_match_actual: Option<Vec<String>>,
    issues: &mut Vec<String>,
    report: &mut ExternalSshReport,
) {
    if expected.is_empty() {
        return;
    }

    if expected == actual {
        return;
    }

    let managed_matches = managed_only_actual
        .as_ref()
        .map(|values| values == &expected);
    record_mismatch(
        target,
        field,
        display_values(&expected),
        Some(display_values(&actual)),
        managed_matches,
        managed_only_actual
            .as_ref()
            .map(|values| display_values(values)),
        managed_with_match_actual
            .as_ref()
            .map(|values| display_values(values)),
        issues,
        report,
    );
}

fn compare_algorithm_field(
    target: &str,
    field: &str,
    expected: Option<String>,
    actual: Option<String>,
    managed_only_actual: Option<String>,
    managed_with_match_actual: Option<String>,
    issues: &mut Vec<String>,
    report: &mut ExternalSshReport,
) {
    let Some(expected) = expected else {
        return;
    };

    let actual_matches = actual
        .as_deref()
        .is_some_and(|value| algorithm_value_matches(&expected, value));
    if actual_matches {
        return;
    }

    let managed_matches = managed_only_actual
        .as_deref()
        .map(|value| algorithm_value_matches(&expected, value));
    record_mismatch(
        target,
        field,
        expected,
        actual,
        managed_matches,
        managed_only_actual,
        managed_with_match_actual,
        issues,
        report,
    );
}

fn record_mismatch(
    target: &str,
    field: &str,
    expected: String,
    actual: Option<String>,
    managed_matches_expected: Option<bool>,
    managed_only_actual: Option<String>,
    managed_with_match_actual: Option<String>,
    issues: &mut Vec<String>,
    report: &mut ExternalSshReport,
) {
    let actual = actual.unwrap_or_else(|| "<missing>".to_string());
    let note = match managed_matches_expected {
        Some(true) => {
            if managed_with_match_actual
                .as_ref()
                .is_some_and(|value| value == &actual)
            {
                report.root_match_influenced_mismatch_count += 1;
                format!(
                    "synthetic config with root Match blocks also resolved to `{}`; root Match blocks likely change this field beyond the current merged preview model",
                    actual
                )
            } else {
                report.root_influenced_mismatch_count += 1;
                "managed-only config matched expected; root/global config likely changes this field"
                    .to_string()
            }
        }
        Some(false) => {
            report.managed_semantic_mismatch_count += 1;
            let mut note = format!(
                "managed-only config also resolved to `{}`; managed merge/render semantics likely differ",
                managed_only_actual.unwrap_or_else(|| "<missing>".to_string())
            );
            if managed_with_match_actual
                .as_ref()
                .is_some_and(|value| value == &actual)
            {
                note.push_str(
                    "; root Match blocks also affect the final resolved value after that drift",
                );
            }
            note
        }
        None => {
            if managed_with_match_actual
                .as_ref()
                .is_some_and(|value| value == &actual)
            {
                report.root_match_influenced_mismatch_count += 1;
                format!(
                    "synthetic config with root Match blocks resolved to `{}`; root Match blocks likely change this field, but managed-only reproduction was unavailable",
                    actual
                )
            } else {
                report.unclassified_mismatch_count += 1;
                "managed-only reproduction unavailable; source of mismatch is unclear".to_string()
            }
        }
    };

    issues.push(format!(
        "ssh -G mismatch for `{target}`: {field} expected `{expected}`, got `{actual}` [{note}]"
    ));
}

fn explain_ignored_scalar_overrides(
    target: &str,
    ignored_scalar_overrides: &[IgnoredScalarOverride],
    actual: &SshResolvedConfig,
    managed_only_actual: Option<&SshResolvedConfig>,
    home_dir: &Path,
) -> Option<String> {
    let mut notes = Vec::new();

    let Some(managed_only_actual) = managed_only_actual else {
        return None;
    };

    for override_note in ignored_scalar_overrides {
        let Some(attempted) = normalize_scalar_field_value(
            &override_note.key,
            &override_note.attempted_value,
            home_dir,
        ) else {
            continue;
        };
        let Some(winning) = normalize_scalar_field_value(
            &override_note.key,
            &override_note.winning_value,
            home_dir,
        ) else {
            continue;
        };
        let Some(managed_only_value) =
            resolved_scalar_field_value(managed_only_actual, &override_note.key, home_dir)
        else {
            continue;
        };

        if managed_only_value == attempted && managed_only_value != winning {
            let root_value = resolved_scalar_field_value(actual, &override_note.key, home_dir)
                .unwrap_or_else(|| "<missing>".to_string());
            notes.push(format!(
                "{} later value seems to win under ssh -G: preview locked `{}` from {:03} {} {}, but managed-only ssh -G resolved `{}` from later {:03} {} {} (root ssh -G: `{}`)",
                override_note.key,
                override_note.winning_value,
                override_note.winning_origin.order,
                override_note.winning_origin.entry_kind.label(),
                override_note.winning_origin.host_patterns.join(","),
                override_note.attempted_value,
                override_note.attempted_origin.order,
                override_note.attempted_origin.entry_kind.label(),
                override_note.attempted_origin.host_patterns.join(","),
                root_value,
            ));
        }
    }

    if notes.is_empty() {
        None
    } else {
        Some(format!("ssh -G note for `{target}`: {}", notes.join(" | ")))
    }
}

fn normalize_scalar_field_value(field: &str, value: &str, home_dir: &Path) -> Option<String> {
    match field {
        "HostName" | "User" | "Port" => Some(normalize_plain(value)),
        "ProxyJump" => normalize_proxy_jump_value(value),
        "StrictHostKeyChecking" => Some(normalize_booleanish(value)),
        "UserKnownHostsFile" => Some(display_values(&normalize_path_list_value(value, home_dir))),
        "HostKeyAlgorithms" | "PubkeyAcceptedAlgorithms" => Some(normalize_algorithm_value(value)),
        "ForwardAgent" => Some(normalize_forward_agent_value(value, home_dir)),
        _ => None,
    }
}

fn resolved_scalar_field_value(
    config: &SshResolvedConfig,
    field: &str,
    home_dir: &Path,
) -> Option<String> {
    match field {
        "HostName" => config.get_first("hostname").map(normalize_plain),
        "User" => config.get_first("user").map(normalize_plain),
        "Port" => config.get_first("port").map(normalize_plain),
        "ProxyJump" => config
            .get_first("proxyjump")
            .and_then(normalize_proxy_jump_value),
        "StrictHostKeyChecking" => config
            .get_first("stricthostkeychecking")
            .map(normalize_booleanish),
        "UserKnownHostsFile" => config
            .get_first("userknownhostsfile")
            .map(|value| display_values(&normalize_path_list_value(value, home_dir))),
        "HostKeyAlgorithms" => config
            .get_first("hostkeyalgorithms")
            .map(normalize_algorithm_value),
        "PubkeyAcceptedAlgorithms" => config
            .get_first("pubkeyacceptedalgorithms")
            .map(normalize_algorithm_value),
        "ForwardAgent" => config
            .get_first("forwardagent")
            .map(|value| normalize_forward_agent_value(value, home_dir)),
        _ => None,
    }
}

fn normalize_plain(value: &str) -> String {
    value.trim().to_string()
}

fn expected_remote_forward_values(entry: &HostEntry, home_dir: &Path) -> Vec<String> {
    let mut values = entry
        .remote_forwards
        .iter()
        .map(|value| normalize_remote_forward_value(value, home_dir))
        .collect::<Vec<_>>();
    values.extend(
        entry
            .extra_options
            .iter()
            .filter(|(key, _)| key.eq_ignore_ascii_case("RemoteForward"))
            .map(|(_, value)| normalize_remote_forward_value(value, home_dir)),
    );
    values
}

fn normalize_proxy_jump_value(value: &str) -> Option<String> {
    let normalized = normalize_compact_whitespace(value);
    if normalized.eq_ignore_ascii_case("none") || normalized.is_empty() {
        None
    } else {
        Some(normalized)
    }
}

fn normalize_booleanish(value: &str) -> String {
    match value.trim().to_ascii_lowercase().as_str() {
        "true" | "yes" | "on" => "yes".to_string(),
        "false" | "no" | "off" => "no".to_string(),
        other => other.to_string(),
    }
}

fn normalize_path_like(value: &str, home_dir: &Path) -> String {
    let trimmed = value.trim();
    let expanded = if let Some(rest) = trimmed.strip_prefix("~/") {
        home_dir.join(rest).to_string_lossy().to_string()
    } else if let Some(rest) = trimmed.strip_prefix("~\\") {
        home_dir.join(rest).to_string_lossy().to_string()
    } else {
        trimmed.to_string()
    };

    let normalized = expanded.replace('\\', "/");
    if cfg!(windows) {
        normalized.to_ascii_lowercase()
    } else {
        normalized
    }
}

fn normalize_path_list_value(value: &str, home_dir: &Path) -> Vec<String> {
    value
        .split_whitespace()
        .map(|token| normalize_path_like(token, home_dir))
        .collect()
}

fn normalize_compact_whitespace(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn normalize_local_forward_value(value: &str) -> String {
    normalize_compact_whitespace(value)
        .split(' ')
        .map(normalize_local_forward_token)
        .collect::<Vec<_>>()
        .join(" ")
}

fn normalize_remote_forward_value(value: &str, home_dir: &Path) -> String {
    normalize_port_forward_value(value, home_dir)
}

fn normalize_port_forward_value(value: &str, home_dir: &Path) -> String {
    let tokens = normalize_compact_whitespace(value)
        .split(' ')
        .map(str::to_string)
        .collect::<Vec<_>>();

    if tokens.len() != 2 {
        return tokens.join(" ");
    }

    format!(
        "{} {}",
        normalize_local_forward_token(&tokens[0]),
        normalize_forward_target_token(&tokens[1], home_dir)
    )
}

fn normalize_forward_target_token(token: &str, home_dir: &Path) -> String {
    if looks_path_like(token) {
        normalize_path_like(token, home_dir)
    } else {
        normalize_local_forward_token(token)
    }
}

fn normalize_local_forward_token(token: &str) -> String {
    let Some(rest) = token.strip_prefix('[') else {
        return token.to_string();
    };
    let Some((host, port)) = rest.split_once("]:") else {
        return token.to_string();
    };

    if host.contains(':') {
        token.to_string()
    } else {
        format!("{host}:{port}")
    }
}

fn normalize_forward_agent_value(value: &str, home_dir: &Path) -> String {
    let normalized = normalize_booleanish(value);
    if normalized == "yes" || normalized == "no" {
        return normalized;
    }

    if looks_path_like(value) {
        return normalize_path_like(value, home_dir);
    }

    value.trim().to_string()
}

fn looks_path_like(value: &str) -> bool {
    let trimmed = value.trim();
    trimmed.starts_with("~/")
        || trimmed.starts_with("~\\")
        || trimmed.contains('/')
        || trimmed.contains('\\')
        || matches!(
            trimmed.as_bytes(),
            [drive, b':', ..] if drive.is_ascii_alphabetic()
        )
}

fn normalize_algorithm_value(value: &str) -> String {
    let trimmed = value.trim();
    let (prefix, body) = match trimmed.chars().next() {
        Some(prefix @ ('+' | '-' | '^')) => (Some(prefix), &trimmed[prefix.len_utf8()..]),
        _ => (None, trimmed),
    };

    let normalized_body = body
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .collect::<Vec<_>>()
        .join(",");

    match prefix {
        Some(prefix) => format!("{prefix}{normalized_body}"),
        None => normalized_body,
    }
}

fn algorithm_value_matches(expected: &str, actual: &str) -> bool {
    let normalized_expected = normalize_algorithm_value(expected);
    let normalized_actual = normalize_algorithm_value(actual);
    let actual_tokens = normalized_actual
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .collect::<Vec<_>>();

    match normalized_expected.chars().next() {
        Some(prefix @ ('+' | '-' | '^')) => {
            let expected_tokens = normalized_expected[prefix.len_utf8()..]
                .split(',')
                .map(str::trim)
                .filter(|item| !item.is_empty())
                .collect::<Vec<_>>();

            match prefix {
                '+' | '^' => expected_tokens
                    .iter()
                    .all(|token| actual_tokens.contains(token)),
                '-' => expected_tokens
                    .iter()
                    .all(|token| !actual_tokens.contains(token)),
                _ => false,
            }
        }
        _ => normalized_expected == normalized_actual,
    }
}

fn display_values(values: &[String]) -> String {
    if values.is_empty() {
        "<missing>".to_string()
    } else {
        values.join("; ")
    }
}

fn compared_field_labels() -> Vec<&'static str> {
    vec![
        "HostName",
        "User",
        "Port",
        "ProxyJump",
        "IdentityFile",
        "LocalForward",
        "RemoteForward",
        "StrictHostKeyChecking",
        "UserKnownHostsFile",
        "HostKeyAlgorithms",
        "PubkeyAcceptedAlgorithms",
        "ForwardAgent",
    ]
}

fn write_synthetic_ssh_config(
    path: &Path,
    entries: &[ManagedEntry],
    root_match_blocks: &[root_config::RootMatchBlock],
) -> Result<PathBuf> {
    let newline = platform_newline();
    let mut content = String::new();

    for block in root_match_blocks
        .iter()
        .filter(|block| block.appears_before_managed_anchor)
    {
        append_root_match_block(&mut content, block, newline);
    }

    for entry in entries {
        content.push_str(&render::render_host_entry(&entry.entry, newline));
        content.push_str(newline);
    }

    for block in root_match_blocks
        .iter()
        .filter(|block| !block.appears_before_managed_anchor)
    {
        append_root_match_block(&mut content, block, newline);
    }

    writer::write_text_file(path, &content)?;
    Ok(path.to_path_buf())
}

fn append_root_match_block(
    content: &mut String,
    block: &root_config::RootMatchBlock,
    newline: &str,
) {
    content.push_str(&block.raw);
    if !block.raw.ends_with(['\r', '\n']) {
        content.push_str(newline);
    }
}

struct TempConfigFile {
    path: PathBuf,
}

impl Drop for TempConfigFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use std::path::Path;

    use crate::core::model::HostEntry;
    use crate::core::openssh::{OpenSshProbe, parse_ssh_g_output};
    use crate::core::root_config;
    use crate::core::store;
    use crate::fs::layout::{AppPaths, managed_block, platform_newline};

    use super::{
        ValidateOptions, algorithm_value_matches, collect_external_ssh_report_with_runner,
        collect_report, normalize_forward_agent_value, normalize_local_forward_value,
        normalize_path_list_value, normalize_remote_forward_value, write_synthetic_ssh_config,
    };

    fn test_paths(name: &str) -> AppPaths {
        let root = std::env::current_dir()
            .unwrap()
            .join("target")
            .join("test-validate")
            .join(format!(
                "{name}-{}",
                Utc::now().timestamp_nanos_opt().unwrap_or_default()
            ));

        std::fs::create_dir_all(&root).unwrap();
        let ssh_dir = root.join(".ssh");
        let app_dir = ssh_dir.join(".sshcfg");
        AppPaths {
            ssh_dir: ssh_dir.clone(),
            root_config: ssh_dir.join("config"),
            config_d_dir: ssh_dir.join("config.d"),
            app_dir: app_dir.clone(),
            backups_dir: app_dir.join("backups"),
            state_file: app_dir.join("state.toml"),
        }
    }

    #[test]
    fn collect_report_flags_missing_include_and_invalid_entry() {
        let paths = test_paths("issues");
        paths.ensure_base_dirs().unwrap();
        std::fs::write(&paths.root_config, "Host manual\n  User root\n").unwrap();

        let entry = HostEntry {
            host_patterns: vec!["alpha".to_string()],
            ..HostEntry::default()
        };
        store::save_entry(&paths, &entry, None).unwrap();

        let report = collect_report(&paths, &ValidateOptions::default()).unwrap();

        assert_eq!(report.managed_entry_count, 1);
        assert!(report.root_config_exists);
        assert!(!report.has_managed_block);
        assert!(!report.has_include_line);
        assert_eq!(report.issues.len(), 2);
        assert!(
            report
                .issues
                .iter()
                .any(|issue| issue.contains("missing `Include ~/.ssh/config.d/*`"))
        );
        assert!(
            report
                .issues
                .iter()
                .any(|issue| issue.contains("HostName is required"))
        );
    }

    #[test]
    fn collect_report_accepts_managed_block_without_issues() {
        let paths = test_paths("clean");
        paths.ensure_base_dirs().unwrap();
        std::fs::write(&paths.root_config, managed_block(platform_newline())).unwrap();

        let entry = HostEntry {
            host_patterns: vec!["alpha".to_string()],
            hostname: Some("alpha.example.com".to_string()),
            ..HostEntry::default()
        };
        store::save_entry(&paths, &entry, None).unwrap();

        let report = collect_report(&paths, &ValidateOptions::default()).unwrap();

        assert!(report.is_ok());
        assert_eq!(report.managed_entry_count, 1);
        assert!(report.root_config_exists);
        assert!(report.has_managed_block);
        assert!(report.has_include_line);
        assert!(report.external_ssh.is_none());
    }

    #[test]
    fn collect_report_counts_root_match_blocks_in_summary() {
        let paths = test_paths("clean-with-match");
        paths.ensure_base_dirs().unwrap();
        std::fs::write(
            &paths.root_config,
            format!(
                "{}Match user ops\n  PasswordAuthentication no\n",
                managed_block(platform_newline())
            ),
        )
        .unwrap();

        let entry = HostEntry {
            host_patterns: vec!["alpha".to_string()],
            hostname: Some("alpha.example.com".to_string()),
            ..HostEntry::default()
        };
        store::save_entry(&paths, &entry, None).unwrap();

        let report = collect_report(&paths, &ValidateOptions::default()).unwrap();

        assert!(report.is_ok());
        assert_eq!(report.root_match_block_count, 1);
        assert!(report.summary().contains("root Match blocks 1"));
    }

    #[test]
    fn external_ssh_report_captures_mismatches_for_exact_hosts_only() {
        let paths = test_paths("ssh-g");
        paths.ensure_base_dirs().unwrap();
        std::fs::write(&paths.root_config, managed_block(platform_newline())).unwrap();

        let pattern = HostEntry {
            host_patterns: vec!["demo-*".to_string()],
            user: Some("builder".to_string()),
            ..HostEntry::default()
        };
        store::save_entry(&paths, &pattern, None).unwrap();

        let exact = HostEntry {
            host_patterns: vec!["demo-1".to_string()],
            hostname: Some("demo-1.example.com".to_string()),
            forward_agent: Some("no".to_string()),
            ..HostEntry::default()
        };
        store::save_entry(&paths, &exact, Some(20)).unwrap();

        let entries = store::load_managed_entries(&paths).unwrap();
        let mut issues = Vec::new();
        let report = collect_external_ssh_report_with_runner(
            &paths,
            &entries,
            &mut issues,
            OpenSshProbe {
                version: Some("OpenSSH_9.5p1".to_string()),
                error: None,
            },
            |_, target| {
                assert_eq!(target, "demo-1");
                parse_ssh_g_output(
                    "hostname demo-1.example.com\nuser builder\nport 22\nforwardagent yes\n",
                )
            },
        );

        assert!(report.ssh_available);
        assert_eq!(report.checked_target_count, 1);
        assert_eq!(report.skipped_pattern_count, 1);
        assert_eq!(report.skipped_invalid_target_count, 0);
        assert_eq!(report.root_influenced_mismatch_count, 0);
        assert_eq!(report.managed_semantic_mismatch_count, 1);
        assert!(
            issues
                .iter()
                .any(|issue| issue.contains("ForwardAgent expected `no`, got `yes`"))
        );
        assert!(
            issues
                .iter()
                .any(|issue| issue.contains("managed merge/render semantics likely differ"))
        );
    }

    #[test]
    fn external_ssh_report_explains_ignored_later_scalar_assignment() {
        let paths = test_paths("ssh-g-ignored-scalar-note");
        paths.ensure_base_dirs().unwrap();
        std::fs::write(&paths.root_config, managed_block(platform_newline())).unwrap();

        let pattern = HostEntry {
            host_patterns: vec!["demo-*".to_string()],
            user: Some("builder".to_string()),
            ..HostEntry::default()
        };
        store::save_entry(&paths, &pattern, None).unwrap();

        let exact = HostEntry {
            host_patterns: vec!["demo-1".to_string()],
            hostname: Some("demo-1.example.com".to_string()),
            user: Some("root".to_string()),
            ..HostEntry::default()
        };
        store::save_entry(&paths, &exact, Some(20)).unwrap();

        let entries = store::load_managed_entries(&paths).unwrap();
        let mut issues = Vec::new();
        let report = collect_external_ssh_report_with_runner(
            &paths,
            &entries,
            &mut issues,
            OpenSshProbe {
                version: Some("OpenSSH_9.5p1".to_string()),
                error: None,
            },
            |_, target| {
                assert_eq!(target, "demo-1");
                parse_ssh_g_output(
                    "hostname demo-1.example.com\nuser root\nport 22\nforwardagent no\n",
                )
            },
        );

        assert_eq!(report.checked_target_count, 1);
        assert_eq!(report.managed_semantic_mismatch_count, 1);
        assert!(issues.iter().any(|issue| {
            issue.contains("ssh -G note for `demo-1`: User later value seems to win under ssh -G")
        }));
    }

    #[test]
    fn external_ssh_report_checks_remote_forward_from_extra_options() {
        let paths = test_paths("ssh-g-remote-forward");
        paths.ensure_base_dirs().unwrap();
        std::fs::write(&paths.root_config, managed_block(platform_newline())).unwrap();

        let entry = HostEntry {
            host_patterns: vec!["alpha".to_string()],
            hostname: Some("alpha.example.com".to_string()),
            extra_options: vec![("RemoteForward".to_string(), "8080 127.0.0.1:80".to_string())],
            ..HostEntry::default()
        };
        store::save_entry(&paths, &entry, None).unwrap();

        let entries = store::load_managed_entries(&paths).unwrap();
        let mut issues = Vec::new();
        let report = collect_external_ssh_report_with_runner(
            &paths,
            &entries,
            &mut issues,
            OpenSshProbe {
                version: Some("OpenSSH_9.5p1".to_string()),
                error: None,
            },
            |_, target| {
                assert_eq!(target, "alpha");
                parse_ssh_g_output(
                    "hostname alpha.example.com\nuser demo\nport 22\nremoteforward 8080 [127.0.0.1]:80\n",
                )
            },
        );

        assert_eq!(report.checked_target_count, 1);
        assert!(issues.is_empty(), "{issues:?}");
    }

    #[test]
    fn external_ssh_report_checks_remote_forward_first_class_field() {
        let paths = test_paths("ssh-g-remote-forward-field");
        paths.ensure_base_dirs().unwrap();
        std::fs::write(&paths.root_config, managed_block(platform_newline())).unwrap();

        let entry = HostEntry {
            host_patterns: vec!["alpha".to_string()],
            hostname: Some("alpha.example.com".to_string()),
            remote_forwards: vec!["9090 /tmp/agent.sock".to_string()],
            ..HostEntry::default()
        };
        store::save_entry(&paths, &entry, None).unwrap();

        let entries = store::load_managed_entries(&paths).unwrap();
        let mut issues = Vec::new();
        let report = collect_external_ssh_report_with_runner(
            &paths,
            &entries,
            &mut issues,
            OpenSshProbe {
                version: Some("OpenSSH_9.5p1".to_string()),
                error: None,
            },
            |_, target| {
                assert_eq!(target, "alpha");
                parse_ssh_g_output(
                    "hostname alpha.example.com\nuser demo\nport 22\nremoteforward 9090 /tmp/agent.sock\n",
                )
            },
        );

        assert_eq!(report.checked_target_count, 1);
        assert!(issues.is_empty(), "{issues:?}");
    }

    #[test]
    fn external_ssh_report_flags_remote_forward_mismatch() {
        let paths = test_paths("ssh-g-remote-forward-mismatch");
        paths.ensure_base_dirs().unwrap();
        std::fs::write(&paths.root_config, managed_block(platform_newline())).unwrap();

        let entry = HostEntry {
            host_patterns: vec!["alpha".to_string()],
            hostname: Some("alpha.example.com".to_string()),
            extra_options: vec![("RemoteForward".to_string(), "8080 127.0.0.1:80".to_string())],
            ..HostEntry::default()
        };
        store::save_entry(&paths, &entry, None).unwrap();

        let entries = store::load_managed_entries(&paths).unwrap();
        let mut issues = Vec::new();
        let report = collect_external_ssh_report_with_runner(
            &paths,
            &entries,
            &mut issues,
            OpenSshProbe {
                version: Some("OpenSSH_9.5p1".to_string()),
                error: None,
            },
            |_, target| {
                assert_eq!(target, "alpha");
                parse_ssh_g_output(
                    "hostname alpha.example.com\nuser demo\nport 22\nremoteforward 9090 127.0.0.1:80\n",
                )
            },
        );

        assert_eq!(report.checked_target_count, 1);
        assert_eq!(report.managed_semantic_mismatch_count, 1);
        assert!(
            issues
                .iter()
                .any(|issue| issue.contains("RemoteForward expected `8080 127.0.0.1:80`"))
        );
    }

    #[test]
    fn external_ssh_report_attributes_root_global_influence() {
        let paths = test_paths("ssh-g-root-influence");
        paths.ensure_base_dirs().unwrap();
        std::fs::write(&paths.root_config, managed_block(platform_newline())).unwrap();

        let entry = HostEntry {
            host_patterns: vec!["alpha".to_string()],
            hostname: Some("alpha.example.com".to_string()),
            forward_agent: Some("no".to_string()),
            ..HostEntry::default()
        };
        store::save_entry(&paths, &entry, None).unwrap();

        let entries = store::load_managed_entries(&paths).unwrap();
        let mut issues = Vec::new();
        let report = collect_external_ssh_report_with_runner(
            &paths,
            &entries,
            &mut issues,
            OpenSshProbe {
                version: Some("OpenSSH_9.5p1".to_string()),
                error: None,
            },
            |config_path, target| {
                assert_eq!(target, "alpha");
                if config_path == paths.root_config.as_path() {
                    parse_ssh_g_output(
                        "hostname alpha.example.com\nuser root\nport 22\nforwardagent yes\n",
                    )
                } else {
                    parse_ssh_g_output(
                        "hostname alpha.example.com\nuser root\nport 22\nforwardagent no\n",
                    )
                }
            },
        );

        assert_eq!(report.checked_target_count, 1);
        assert_eq!(report.root_influenced_mismatch_count, 1);
        assert_eq!(report.managed_semantic_mismatch_count, 0);
        assert!(
            issues
                .iter()
                .any(|issue| issue.contains("root/global config likely changes this field"))
        );
    }

    #[test]
    fn external_ssh_report_attributes_root_match_influence() {
        let paths = test_paths("ssh-g-root-match-influence");
        paths.ensure_base_dirs().unwrap();
        std::fs::write(
            &paths.root_config,
            format!(
                "{}Match host alpha
  ForwardAgent yes
",
                managed_block(platform_newline())
            ),
        )
        .unwrap();

        let entry = HostEntry {
            host_patterns: vec!["alpha".to_string()],
            hostname: Some("alpha.example.com".to_string()),
            forward_agent: Some("no".to_string()),
            ..HostEntry::default()
        };
        store::save_entry(&paths, &entry, None).unwrap();

        let entries = store::load_managed_entries(&paths).unwrap();
        let mut issues = Vec::new();
        let report = collect_external_ssh_report_with_runner(
            &paths,
            &entries,
            &mut issues,
            OpenSshProbe {
                version: Some("OpenSSH_9.5p1".to_string()),
                error: None,
            },
            |config_path, target| {
                assert_eq!(target, "alpha");
                if config_path == paths.root_config.as_path()
                    || config_path == paths.managed_match_config_path().as_path()
                {
                    parse_ssh_g_output(
                        "hostname alpha.example.com\nuser root\nport 22\nforwardagent yes\n",
                    )
                } else {
                    parse_ssh_g_output(
                        "hostname alpha.example.com\nuser root\nport 22\nforwardagent no\n",
                    )
                }
            },
        );

        assert_eq!(report.checked_target_count, 1);
        assert_eq!(report.root_match_influenced_mismatch_count, 1);
        assert_eq!(report.root_influenced_mismatch_count, 0);
        assert_eq!(report.managed_semantic_mismatch_count, 0);
        assert!(
            issues
                .iter()
                .any(|issue| { issue.contains("root Match blocks likely change this field") })
        );
    }

    #[test]
    fn external_ssh_report_uses_supported_root_match_in_expected_preview() {
        let paths = test_paths("ssh-g-supported-root-match-preview");
        paths.ensure_base_dirs().unwrap();
        std::fs::write(
            &paths.root_config,
            format!(
                "{}Match host demo.example.com\n  ForwardAgent no\n",
                managed_block(platform_newline())
            ),
        )
        .unwrap();

        let entry = HostEntry {
            host_patterns: vec!["demo".to_string()],
            hostname: Some("demo.example.com".to_string()),
            ..HostEntry::default()
        };
        store::save_entry(&paths, &entry, None).unwrap();

        let entries = store::load_managed_entries(&paths).unwrap();
        let mut issues = Vec::new();
        let report = collect_external_ssh_report_with_runner(
            &paths,
            &entries,
            &mut issues,
            OpenSshProbe {
                version: Some("OpenSSH_9.5p1".to_string()),
                error: None,
            },
            |config_path, target| {
                assert_eq!(target, "demo");
                if config_path == paths.managed_config_path().as_path() {
                    parse_ssh_g_output("hostname demo.example.com\nforwardagent yes\n")
                } else {
                    parse_ssh_g_output("hostname demo.example.com\nforwardagent no\n")
                }
            },
        );

        assert_eq!(report.checked_target_count, 1);
        assert_eq!(report.root_match_influenced_mismatch_count, 0);
        assert_eq!(report.managed_semantic_mismatch_count, 0);
        assert!(issues.is_empty(), "{issues:?}");
    }

    #[test]
    fn external_ssh_report_uses_supported_root_match_version_in_expected_preview() {
        let paths = test_paths("ssh-g-supported-root-match-version-preview");
        paths.ensure_base_dirs().unwrap();
        std::fs::write(
            &paths.root_config,
            format!(
                "{}Match version OpenSSH_for_Windows_*\n  ForwardAgent no\n",
                managed_block(platform_newline())
            ),
        )
        .unwrap();

        let entry = HostEntry {
            host_patterns: vec!["demo".to_string()],
            hostname: Some("demo.example.com".to_string()),
            ..HostEntry::default()
        };
        store::save_entry(&paths, &entry, None).unwrap();

        let entries = store::load_managed_entries(&paths).unwrap();
        let mut issues = Vec::new();
        let report = collect_external_ssh_report_with_runner(
            &paths,
            &entries,
            &mut issues,
            OpenSshProbe {
                version: Some("OpenSSH_for_Windows_9.5p1, LibreSSL 3.8.2".to_string()),
                error: None,
            },
            |config_path, target| {
                assert_eq!(target, "demo");
                if config_path == paths.managed_config_path().as_path() {
                    parse_ssh_g_output("hostname demo.example.com\nforwardagent yes\n")
                } else {
                    parse_ssh_g_output("hostname demo.example.com\nforwardagent no\n")
                }
            },
        );

        assert_eq!(report.checked_target_count, 1);
        assert_eq!(report.root_match_influenced_mismatch_count, 0);
        assert_eq!(report.managed_semantic_mismatch_count, 0);
        assert!(issues.is_empty(), "{issues:?}");
    }

    #[test]
    fn external_ssh_report_uses_supported_root_match_tagged_in_expected_preview() {
        let paths = test_paths("ssh-g-supported-root-match-tagged-preview");
        paths.ensure_base_dirs().unwrap();
        std::fs::write(
            &paths.root_config,
            format!(
                "{}Match tagged ops\n  ForwardAgent no\n",
                managed_block(platform_newline())
            ),
        )
        .unwrap();

        let entry = HostEntry {
            host_patterns: vec!["demo".to_string()],
            hostname: Some("demo.example.com".to_string()),
            tag: Some("ops".to_string()),
            ..HostEntry::default()
        };
        store::save_entry(&paths, &entry, None).unwrap();

        let entries = store::load_managed_entries(&paths).unwrap();
        let mut issues = Vec::new();
        let report = collect_external_ssh_report_with_runner(
            &paths,
            &entries,
            &mut issues,
            OpenSshProbe {
                version: Some("OpenSSH_9.5p1".to_string()),
                error: None,
            },
            |config_path, target| {
                assert_eq!(target, "demo");
                if config_path == paths.managed_config_path().as_path() {
                    parse_ssh_g_output("hostname demo.example.com\nforwardagent yes\n")
                } else if config_path == paths.managed_match_config_path().as_path() {
                    parse_ssh_g_output("hostname demo.example.com\nforwardagent no\n")
                } else {
                    parse_ssh_g_output("hostname demo.example.com\nforwardagent no\n")
                }
            },
        );

        assert_eq!(report.checked_target_count, 1);
        assert_eq!(report.root_match_influenced_mismatch_count, 0);
        assert_eq!(report.managed_semantic_mismatch_count, 0);
        assert!(issues.is_empty(), "{issues:?}");
    }

    #[test]
    fn synthetic_config_preserves_root_match_order_around_managed_entries() {
        let paths = test_paths("synthetic-root-match-order");
        paths.ensure_base_dirs().unwrap();

        let entry = HostEntry {
            host_patterns: vec!["demo".to_string()],
            hostname: Some("demo.example.com".to_string()),
            ..HostEntry::default()
        };
        store::save_entry(&paths, &entry, None).unwrap();
        let entries = store::load_managed_entries(&paths).unwrap();
        let root_match_blocks = root_config::extract_match_blocks(&format!(
            "Match all\n  User root\n{}Match final\n  ForwardAgent no\n",
            managed_block(platform_newline())
        ));

        let synthetic_path = write_synthetic_ssh_config(
            &paths.managed_match_config_path(),
            &entries,
            &root_match_blocks,
        )
        .unwrap();
        let content = std::fs::read_to_string(&synthetic_path).unwrap();
        let pre_anchor_index = content.find("Match all").unwrap();
        let host_index = content.find("Host demo").unwrap();
        let post_anchor_index = content.find("Match final").unwrap();

        assert!(pre_anchor_index < host_index);
        assert!(host_index < post_anchor_index);
    }

    #[test]
    fn external_ssh_report_treats_proxyjump_none_as_absent() {
        let paths = test_paths("ssh-g-proxyjump-none");
        paths.ensure_base_dirs().unwrap();
        std::fs::write(&paths.root_config, managed_block(platform_newline())).unwrap();

        let entry = HostEntry {
            host_patterns: vec!["alpha".to_string()],
            hostname: Some("alpha.example.com".to_string()),
            proxy_jump: Some("none".to_string()),
            ..HostEntry::default()
        };
        store::save_entry(&paths, &entry, None).unwrap();

        let entries = store::load_managed_entries(&paths).unwrap();
        let mut issues = Vec::new();
        let report = collect_external_ssh_report_with_runner(
            &paths,
            &entries,
            &mut issues,
            OpenSshProbe {
                version: Some("OpenSSH_9.5p1".to_string()),
                error: None,
            },
            |_, target| {
                assert_eq!(target, "alpha");
                parse_ssh_g_output("hostname alpha.example.com\nuser demo\nport 22\n")
            },
        );

        assert_eq!(report.checked_target_count, 1);
        assert!(issues.is_empty(), "{issues:?}");
    }

    #[test]
    fn external_ssh_report_normalizes_user_known_hosts_path_lists() {
        let paths = test_paths("ssh-g-known-hosts-list");
        paths.ensure_base_dirs().unwrap();
        std::fs::write(&paths.root_config, managed_block(platform_newline())).unwrap();

        let entry = HostEntry {
            host_patterns: vec!["alpha".to_string()],
            hostname: Some("alpha.example.com".to_string()),
            user_known_hosts_file: Some("~/.ssh/known_hosts ~/.ssh/known_hosts2".to_string()),
            ..HostEntry::default()
        };
        store::save_entry(&paths, &entry, None).unwrap();

        let entries = store::load_managed_entries(&paths).unwrap();
        let home_dir = paths.ssh_dir.parent().unwrap();
        let path_list =
            normalize_path_list_value("~/.ssh/known_hosts ~/.ssh/known_hosts2", home_dir).join(" ");
        let mut issues = Vec::new();
        let report = collect_external_ssh_report_with_runner(
            &paths,
            &entries,
            &mut issues,
            OpenSshProbe {
                version: Some("OpenSSH_9.5p1".to_string()),
                error: None,
            },
            |_, target| {
                assert_eq!(target, "alpha");
                parse_ssh_g_output(&format!(
                    "hostname alpha.example.com\nuser demo\nport 22\nuserknownhostsfile {path_list}\n"
                ))
            },
        );

        assert_eq!(report.checked_target_count, 1);
        assert!(issues.is_empty(), "{issues:?}");
    }

    #[test]
    fn external_ssh_report_surfaces_missing_ssh_binary() {
        let paths = test_paths("ssh-missing");
        paths.ensure_base_dirs().unwrap();
        std::fs::write(&paths.root_config, managed_block(platform_newline())).unwrap();

        let entry = HostEntry {
            host_patterns: vec!["alpha".to_string()],
            hostname: Some("alpha.example.com".to_string()),
            ..HostEntry::default()
        };
        store::save_entry(&paths, &entry, None).unwrap();

        let entries = store::load_managed_entries(&paths).unwrap();
        let mut issues = Vec::new();
        let report = collect_external_ssh_report_with_runner(
            &paths,
            &entries,
            &mut issues,
            OpenSshProbe {
                version: None,
                error: Some("failed to launch `ssh -V`".to_string()),
            },
            |_, _| unreachable!("runner should not be called when ssh is unavailable"),
        );

        assert!(!report.ssh_available);
        assert_eq!(report.checked_target_count, 0);
        assert!(
            issues
                .iter()
                .any(|issue| issue
                    .contains("ssh -G checks requested but OpenSSH ssh is unavailable"))
        );
    }

    #[test]
    fn external_ssh_report_skips_work_when_root_config_is_missing() {
        let paths = test_paths("ssh-g-missing-root-config");
        paths.ensure_base_dirs().unwrap();

        let entry = HostEntry {
            host_patterns: vec!["alpha".to_string()],
            hostname: Some("alpha.example.com".to_string()),
            ..HostEntry::default()
        };
        store::save_entry(&paths, &entry, None).unwrap();

        let entries = store::load_managed_entries(&paths).unwrap();
        let mut issues = Vec::new();
        let report = collect_external_ssh_report_with_runner(
            &paths,
            &entries,
            &mut issues,
            OpenSshProbe {
                version: Some("OpenSSH_for_Windows_9.5p1, LibreSSL 3.8.2".to_string()),
                error: None,
            },
            |_, _| unreachable!("runner should not be called when root config is missing"),
        );

        assert_eq!(report.checked_target_count, 0);
        assert_eq!(report.skipped_pattern_count, 0);
        assert!(issues.is_empty(), "{issues:?}");
    }

    #[test]
    fn external_ssh_report_skips_synthetic_setup_when_only_patterns_exist() {
        let paths = test_paths("ssh-g-pattern-only");
        paths.ensure_base_dirs().unwrap();
        std::fs::write(&paths.root_config, managed_block(platform_newline())).unwrap();

        let entry = HostEntry {
            host_patterns: vec!["demo-*".to_string()],
            user: Some("builder".to_string()),
            ..HostEntry::default()
        };
        store::save_entry(&paths, &entry, None).unwrap();

        let entries = store::load_managed_entries(&paths).unwrap();
        let mut issues = Vec::new();
        let report = collect_external_ssh_report_with_runner(
            &paths,
            &entries,
            &mut issues,
            OpenSshProbe {
                version: Some("OpenSSH_9.5p1".to_string()),
                error: None,
            },
            |_, _| unreachable!("runner should not be called for pattern-only entries"),
        );

        assert_eq!(report.checked_target_count, 0);
        assert_eq!(report.skipped_pattern_count, 1);
        assert!(issues.is_empty(), "{issues:?}");
    }

    #[test]
    fn algorithm_value_matches_supports_modifier_semantics() {
        assert!(algorithm_value_matches("+ssh-rsa", "ssh-ed25519,ssh-rsa"));
        assert!(algorithm_value_matches(
            "-ssh-rsa",
            "ssh-ed25519,ecdsa-sha2-nistp256"
        ));
        assert!(algorithm_value_matches("^ssh-rsa", "ssh-rsa,ssh-ed25519"));
        assert!(algorithm_value_matches(
            "ssh-ed25519,ssh-rsa",
            "ssh-ed25519,ssh-rsa"
        ));
        assert!(!algorithm_value_matches("+ssh-rsa", "ssh-ed25519"));
    }

    #[test]
    fn normalize_local_forward_value_treats_bracketed_ipv4_hostports_as_equal() {
        assert_eq!(
            normalize_local_forward_value("443 127.0.0.1:443"),
            normalize_local_forward_value("443 [127.0.0.1]:443")
        );
        assert_eq!(
            normalize_local_forward_value("18789 [localhost]:18789"),
            "18789 localhost:18789"
        );
        assert_eq!(
            normalize_local_forward_value("443 [::1]:443"),
            "443 [::1]:443"
        );
    }

    #[test]
    fn normalize_forward_agent_value_preserves_env_and_normalizes_paths() {
        let home_dir = Path::new("C:/Users/demo");

        assert_eq!(normalize_forward_agent_value("yes", home_dir), "yes");
        assert_eq!(normalize_forward_agent_value("true", home_dir), "yes");
        assert_eq!(
            normalize_forward_agent_value("$SSH_AUTH_SOCK", home_dir),
            "$SSH_AUTH_SOCK"
        );
        assert_eq!(
            normalize_forward_agent_value("~/agent.sock", home_dir),
            "c:/users/demo/agent.sock"
        );
        assert_eq!(
            normalize_forward_agent_value("C:\\Temp\\Agent.sock", home_dir),
            "c:/temp/agent.sock"
        );
    }

    #[test]
    fn normalize_remote_forward_value_normalizes_paths_and_bracketed_ipv4() {
        let home_dir = Path::new("C:/Users/demo");

        assert_eq!(
            normalize_remote_forward_value("443 [127.0.0.1]:443", home_dir),
            "443 127.0.0.1:443"
        );
        assert_eq!(
            normalize_remote_forward_value("9090 ~/agent.sock", home_dir),
            "9090 c:/users/demo/agent.sock"
        );
    }
}
