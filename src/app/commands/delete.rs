use std::io::{self, IsTerminal, Write};
use std::path::PathBuf;

use anyhow::{Context, Result, bail};

use crate::app::cli::DeleteArgs;
use crate::core::model::ManagedEntry;
use crate::core::state;
use crate::core::store;
use crate::fs::backup;
use crate::fs::layout::AppPaths;

use super::init;
use super::selection::{EntryFilter, filter_entries};

#[derive(Debug, Clone)]
pub(crate) struct DeletedEntry {
    pub host: String,
    pub path: PathBuf,
}

#[derive(Debug, Clone)]
pub(crate) struct DeleteResult {
    pub deleted: Vec<DeletedEntry>,
    pub backup_path: Option<PathBuf>,
    pub include_written: bool,
}

pub fn run(args: DeleteArgs) -> Result<()> {
    let paths = AppPaths::discover()?;
    validate_delete_args(&args)?;
    let targets = resolve_targets(&paths, &args)?;
    confirm_delete_if_needed(&args, &targets)?;
    let result = delete_managed_entries(&paths, &targets)?;

    println!(
        "deleted {} managed entr{}",
        result.deleted.len(),
        if result.deleted.len() == 1 {
            "y"
        } else {
            "ies"
        }
    );
    for deleted in &result.deleted {
        println!("  - {} ({})", deleted.host, deleted.path.display());
    }
    if result.include_written {
        println!("root config include block was initialized");
    }
    if let Some(path) = result.backup_path {
        println!("backup: {}", path.display());
    }

    Ok(())
}

pub(crate) fn delete_managed_entries(
    paths: &AppPaths,
    targets: &[ManagedEntry],
) -> Result<DeleteResult> {
    if targets.is_empty() {
        bail!("no managed entries selected for delete");
    }

    let init_report = init::ensure_initialized(paths)?;
    let backup_path = backup::create_backup(paths)?;

    for target in targets {
        std::fs::remove_file(&target.path)
            .with_context(|| format!("failed to delete {}", target.path.display()))?;
    }

    state::remove_entries(paths, targets).context("failed to update state metadata")?;

    Ok(DeleteResult {
        deleted: targets
            .iter()
            .map(|target| DeletedEntry {
                host: target.entry.primary_pattern().to_string(),
                path: target.path.clone(),
            })
            .collect(),
        backup_path: init_report.backup_path.or(backup_path),
        include_written: init_report.include_written,
    })
}

fn confirm_delete_if_needed(args: &DeleteArgs, targets: &[ManagedEntry]) -> Result<()> {
    if !requires_confirmation_prompt(args) {
        return Ok(());
    }

    if !has_terminal_io() {
        bail!("delete without `--yes` requires a terminal confirmation prompt");
    }

    if targets.len() == 1 {
        let target = &targets[0];
        println!("Delete Managed SSH Entry");
        println!("==================================================");
        println!("Host: {}", target.entry.primary_pattern());
        println!(
            "HostName: {}",
            target.entry.hostname.as_deref().unwrap_or("<empty>")
        );
        println!("Order: {}", target.order);
        println!("File: {}", target.path.display());
    } else {
        println!("Delete Managed SSH Entries");
        println!("==================================================");
        println!("Matched entries: {}", targets.len());
        if let Some(summary) = selection_summary(args) {
            println!("Selector: {summary}");
        }
        for target in targets.iter().take(20) {
            println!(
                "  - {:<24} {:<24} order={} file={}",
                target.entry.primary_pattern(),
                target.entry.hostname.as_deref().unwrap_or("<empty>"),
                target.order,
                target.path.display()
            );
        }
        if targets.len() > 20 {
            println!("  ... and {} more", targets.len() - 20);
        }
    }

    println!("A backup snapshot will be created before delete.");

    let prompt = if targets.len() == 1 {
        "Confirm delete this entry?"
    } else {
        "Confirm delete these entries?"
    };
    if !confirm(prompt, false)? {
        bail!("cancelled");
    }

    Ok(())
}

fn validate_delete_args(args: &DeleteArgs) -> Result<()> {
    let filter = EntryFilter::from_args(&args.filter);
    let selector_requested = !filter.is_empty();
    if args.all && args.host.is_some() {
        bail!("cannot combine --all with a positional host");
    }
    if args.all && selector_requested {
        bail!("cannot combine --all with selector flags (--query, --tag, --has-note, --template)");
    }

    match args.host.as_deref() {
        Some(host) if host.trim().is_empty() => bail!("host cannot be empty"),
        Some(_) if selector_requested => bail!(
            "cannot combine a positional host with selector flags (--all, --query, --tag, --has-note, --template)"
        ),
        Some(_) => Ok(()),
        None if selector_requested => Ok(()),
        None => bail!(
            "delete requires either a host or a selector (--all, --query, --tag, --has-note, --template)"
        ),
    }
}

fn resolve_targets(paths: &AppPaths, args: &DeleteArgs) -> Result<Vec<ManagedEntry>> {
    let entries = store::load_managed_entries(paths)?;

    if let Some(host) = args.host.as_deref() {
        return Ok(vec![load_target(&entries, host)?.clone()]);
    }

    if args.all {
        if entries.is_empty() {
            bail!("no managed entries available for delete");
        }
        return Ok(entries);
    }

    let filter = EntryFilter::from_args(&args.filter);
    if filter.is_empty() {
        bail!(
            "bulk delete requires --all or at least one filter (--query, --tag, --has-note, --template)"
        );
    }

    let state = state::load_state(paths)?;
    let selected = filter_entries(&entries, &state, &filter);
    if selected.is_empty() {
        bail!("no managed entries matched the provided selector");
    }

    Ok(selected
        .into_iter()
        .map(|item| item.entry.clone())
        .collect())
}

fn selection_summary(args: &DeleteArgs) -> Option<String> {
    if args.host.is_some() {
        return None;
    }

    let filter = EntryFilter::from_args(&args.filter);
    if args.all && filter.is_empty() {
        return Some("all managed entries".to_string());
    }

    let mut parts = Vec::new();
    if let Some(query) = args
        .filter
        .query
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        parts.push(format!("query={query}"));
    }
    if !args.filter.tags.is_empty() {
        parts.push(format!("tags={}", args.filter.tags.join(",")));
    }
    if args.filter.has_note {
        parts.push("note=yes".to_string());
    }
    if let Some(template) = args.filter.template {
        parts.push(format!("template={}", template.cli_name()));
    }

    if parts.is_empty() {
        None
    } else {
        Some(parts.join(" | "))
    }
}

fn requires_confirmation_prompt(args: &DeleteArgs) -> bool {
    !args.yes
}

fn load_target<'a>(entries: &'a [ManagedEntry], host: &str) -> Result<&'a ManagedEntry> {
    store::find_entry_by_host(entries, host)
        .with_context(|| format!("managed entry `{host}` not found"))
}

fn has_terminal_io() -> bool {
    io::stdin().is_terminal() && io::stdout().is_terminal()
}

fn confirm(label: &str, default_yes: bool) -> Result<bool> {
    let suffix = if default_yes { "[Y/n]" } else { "[y/N]" };
    let mut stdout = io::stdout();
    write!(stdout, "> {label} {suffix} ")?;
    stdout.flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let trimmed = input.trim().to_ascii_lowercase();

    if trimmed.is_empty() {
        return Ok(default_yes);
    }

    Ok(matches!(trimmed.as_str(), "y" | "yes"))
}

#[cfg(test)]
mod tests {
    use chrono::Utc;

    use crate::app::cli::{DeleteArgs, MetadataFilterArgs};
    use crate::core::model::HostEntry;
    use crate::core::state::{self, MetadataUpdate};
    use crate::core::store;
    use crate::core::template::TemplateKind;
    use crate::fs::layout::AppPaths;

    use super::{
        delete_managed_entries, requires_confirmation_prompt, resolve_targets, validate_delete_args,
    };

    fn test_paths(name: &str) -> AppPaths {
        let root = std::env::current_dir()
            .unwrap()
            .join("target")
            .join("test-delete")
            .join(format!(
                "{name}-{}",
                Utc::now().timestamp_nanos_opt().unwrap_or_default()
            ));

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

    fn sample_host(host: &str, hostname: &str) -> HostEntry {
        HostEntry {
            host_patterns: vec![host.to_string()],
            hostname: Some(hostname.to_string()),
            ..HostEntry::default()
        }
    }

    fn selector_args() -> DeleteArgs {
        DeleteArgs {
            host: None,
            all: false,
            filter: MetadataFilterArgs::default(),
            yes: false,
        }
    }

    #[test]
    fn delete_without_yes_requires_prompt() {
        let args = DeleteArgs {
            host: Some("alpha".to_string()),
            all: false,
            filter: MetadataFilterArgs::default(),
            yes: false,
        };

        assert!(requires_confirmation_prompt(&args));
    }

    #[test]
    fn delete_with_yes_skips_prompt() {
        let args = DeleteArgs {
            host: Some("alpha".to_string()),
            all: false,
            filter: MetadataFilterArgs::default(),
            yes: true,
        };

        assert!(!requires_confirmation_prompt(&args));
    }

    #[test]
    fn validation_rejects_host_and_selector_combination() {
        let args = DeleteArgs {
            host: Some("alpha".to_string()),
            all: false,
            filter: MetadataFilterArgs {
                query: Some("prod".to_string()),
                ..MetadataFilterArgs::default()
            },
            yes: true,
        };

        let err = validate_delete_args(&args).unwrap_err();
        assert!(err.to_string().contains("cannot combine"));
    }

    #[test]
    fn validation_requires_host_or_selector() {
        let args = selector_args();

        let err = validate_delete_args(&args).unwrap_err();
        assert!(
            err.to_string()
                .contains("delete requires either a host or a selector")
        );
    }

    #[test]
    fn resolve_targets_supports_selector_filters() {
        let paths = test_paths("resolve-selector");
        paths.ensure_base_dirs().unwrap();

        let alpha =
            store::save_entry(&paths, &sample_host("alpha", "alpha.example.com"), None).unwrap();
        let beta =
            store::save_entry(&paths, &sample_host("beta", "beta.example.com"), Some(20)).unwrap();
        state::upsert_entry(
            &paths,
            &alpha,
            None,
            state::metadata_update_for_create(
                Some(TemplateKind::Legacy),
                vec!["prod".to_string()],
                None,
            ),
        )
        .unwrap();
        state::upsert_entry(
            &paths,
            &beta,
            None,
            state::metadata_update_for_create(
                Some(TemplateKind::Embedded),
                vec!["lab".to_string()],
                None,
            ),
        )
        .unwrap();

        let args = DeleteArgs {
            host: None,
            all: false,
            filter: MetadataFilterArgs {
                tags: vec!["prod".to_string()],
                ..MetadataFilterArgs::default()
            },
            yes: true,
        };

        let targets = resolve_targets(&paths, &args).unwrap();

        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].entry.primary_pattern(), "alpha");
    }

    #[test]
    fn resolve_targets_supports_delete_all() {
        let paths = test_paths("resolve-all");
        paths.ensure_base_dirs().unwrap();

        store::save_entry(&paths, &sample_host("alpha", "alpha.example.com"), None).unwrap();
        store::save_entry(&paths, &sample_host("beta", "beta.example.com"), Some(20)).unwrap();

        let args = DeleteArgs {
            host: None,
            all: true,
            filter: MetadataFilterArgs::default(),
            yes: true,
        };

        let targets = resolve_targets(&paths, &args).unwrap();

        assert_eq!(targets.len(), 2);
        assert_eq!(targets[0].entry.primary_pattern(), "alpha");
        assert_eq!(targets[1].entry.primary_pattern(), "beta");
    }

    #[test]
    fn delete_managed_entries_removes_files_and_metadata_in_batch() {
        let paths = test_paths("delete-batch");
        paths.ensure_base_dirs().unwrap();

        let alpha =
            store::save_entry(&paths, &sample_host("alpha", "alpha.example.com"), None).unwrap();
        let beta =
            store::save_entry(&paths, &sample_host("beta", "beta.example.com"), Some(20)).unwrap();
        state::upsert_entry(&paths, &alpha, None, MetadataUpdate::default()).unwrap();
        state::upsert_entry(&paths, &beta, None, MetadataUpdate::default()).unwrap();

        let result = delete_managed_entries(&paths, &[alpha.clone(), beta.clone()]).unwrap();

        assert_eq!(result.deleted.len(), 2);
        assert!(!alpha.path.exists());
        assert!(!beta.path.exists());
        assert!(state::load_state(&paths).unwrap().entries.is_empty());
        assert!(result.backup_path.is_some());
    }
}
