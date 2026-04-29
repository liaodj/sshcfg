use std::collections::HashSet;
use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

use crate::app::cli::{MetadataFilterArgs, OrderArgs};
use crate::core::model::ManagedEntry;
use crate::core::state;
use crate::core::store;
use crate::fs::backup;
use crate::fs::layout::AppPaths;

use super::init;
use super::selection::{EntryFilter, filter_entry_indices};

#[derive(Debug, Clone)]
pub(crate) struct ReorderOutcome {
    pub host: String,
    pub order: u16,
    pub metadata_id: String,
    pub backup_paths: Vec<PathBuf>,
    pub include_written: bool,
}

#[derive(Debug, Clone)]
struct ReorderedEntry {
    host: String,
    order: u16,
    metadata_id: String,
}

#[derive(Debug, Clone)]
struct BatchReorderOutcome {
    moved: Vec<ReorderedEntry>,
    backup_paths: Vec<PathBuf>,
    include_written: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum DestinationSpec {
    Before(String),
    After(String),
    First,
    Last,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DestinationKind {
    Before,
    After,
    First,
    Last,
}

pub fn run(args: OrderArgs) -> Result<()> {
    let paths = AppPaths::discover()?;
    validate_order_args(&args)?;
    let init_report = init::ensure_initialized(&paths)?;
    let entries = store::load_managed_entries(&paths)?;

    if entries.is_empty() {
        bail!("no managed entries found");
    }

    let targets = resolve_targets(&paths, &entries, &args)?;
    let args = prepare_order_args(&entries, &targets, args)?;
    let target_hosts = selected_hosts(&targets);
    let original_paths = sequence_signature(&entries);
    let reordered = reorder_entries(entries, &targets, &args)?;

    if sequence_signature(&reordered) == original_paths {
        println!("no changes in managed entry order");
        if init_report.include_written {
            println!("root config include block was initialized");
        }
        if let Some(path) = init_report.backup_path {
            println!("backup: {}", path.display());
        }
        return Ok(());
    }

    if target_hosts.len() == 1 {
        let outcome = apply_reordered_entries(&paths, &reordered, &target_hosts[0])?;

        println!(
            "moved: {} -> order {} ({})",
            outcome.host,
            outcome.order,
            describe_destination(&args)
        );
        println!("metadata id: {}", outcome.metadata_id);

        if outcome.include_written || init_report.include_written {
            println!("root config include block was initialized");
        }
        for path in merge_backup_paths(init_report.backup_path, outcome.backup_paths) {
            println!("backup: {}", path.display());
        }
        return Ok(());
    }

    let outcome = apply_reordered_entries_for_hosts(&paths, &reordered, &target_hosts)?;
    println!(
        "moved {} managed entries ({})",
        outcome.moved.len(),
        describe_destination(&args)
    );
    for moved in &outcome.moved {
        println!(
            "  - {} -> order {} (metadata id: {})",
            moved.host, moved.order, moved.metadata_id
        );
    }

    if outcome.include_written || init_report.include_written {
        println!("root config include block was initialized");
    }
    for path in merge_backup_paths(init_report.backup_path, outcome.backup_paths) {
        println!("backup: {}", path.display());
    }

    Ok(())
}

fn validate_order_args(args: &OrderArgs) -> Result<()> {
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
        None if args.all || selector_requested => Ok(()),
        None => bail!(
            "order requires either a host or a selector (--all, --query, --tag, --has-note, --template)"
        ),
    }
}

fn resolve_targets(
    paths: &AppPaths,
    entries: &[ManagedEntry],
    args: &OrderArgs,
) -> Result<Vec<ManagedEntry>> {
    if let Some(host) = args.host.as_deref() {
        return Ok(vec![load_target(entries, host)?.clone()]);
    }

    if args.all {
        return Ok(entries.to_vec());
    }

    let filter = EntryFilter::from_args(&args.filter);
    if filter.is_empty() {
        bail!(
            "bulk reorder requires --all or at least one filter (--query, --tag, --has-note, --template)"
        );
    }

    let state = state::load_state(paths)?;
    let indices = filter_entry_indices(entries, &state, &filter);
    if indices.is_empty() {
        bail!("no managed entries matched the provided selector");
    }

    Ok(indices
        .into_iter()
        .map(|index| entries[index].clone())
        .collect())
}

fn prepare_order_args(
    entries: &[ManagedEntry],
    targets: &[ManagedEntry],
    args: OrderArgs,
) -> Result<OrderArgs> {
    if args.interactive && !has_terminal_io() {
        bail!("--interactive requires a terminal");
    }

    if should_complete_interactively(&args) {
        return complete_order_args_interactively(entries, targets, &args);
    }

    if !has_requested_destination(&args) {
        bail!("order destination is required unless you run this command in a terminal");
    }

    Ok(args)
}

fn should_complete_interactively(args: &OrderArgs) -> bool {
    has_terminal_io() && (args.interactive || requires_interactive_completion(args))
}

fn requires_interactive_completion(args: &OrderArgs) -> bool {
    !has_requested_destination(args)
}

fn has_requested_destination(args: &OrderArgs) -> bool {
    destination_spec(args).is_some()
}

fn complete_order_args_interactively(
    entries: &[ManagedEntry],
    targets: &[ManagedEntry],
    args: &OrderArgs,
) -> Result<OrderArgs> {
    if targets.is_empty() {
        bail!("no managed entries selected for reorder");
    }

    let target_hosts = selected_hosts(targets);
    let target_paths = target_paths(targets);

    if targets.len() == 1 {
        println!("Reorder Managed SSH Entry");
    } else {
        println!("Reorder Managed SSH Entries");
    }
    println!("==================================================");
    println!("Current order:");
    for entry in entries {
        let marker = if target_paths.contains(entry.path.as_path()) {
            ">"
        } else {
            " "
        };
        println!(
            "  {marker} {:03} {:<24} {}",
            entry.order,
            entry.entry.primary_pattern(),
            entry.path.display()
        );
    }

    let destination = prompt_destination(entries, targets, destination_spec(args).as_ref())?;

    println!();
    println!("=== Reorder Summary ===");
    if target_hosts.len() == 1 {
        println!("Host: {}", target_hosts[0]);
    } else {
        println!("Matched entries: {}", target_hosts.len());
        println!("Targets: {}", summarize_hosts(&target_hosts, 8));
        if let Some(summary) = selection_summary(args.host.as_deref(), args.all, &args.filter) {
            println!("Selector: {summary}");
        }
    }
    println!("Destination: {}", describe_destination_spec(&destination));
    println!("=======================");

    let prompt = if target_hosts.len() == 1 {
        "Confirm reorder?"
    } else {
        "Confirm reorder these entries?"
    };
    if !confirm(prompt, true)? {
        bail!("cancelled");
    }

    Ok(build_order_args_with_destination(args, destination))
}

fn prompt_destination(
    entries: &[ManagedEntry],
    targets: &[ManagedEntry],
    default: Option<&DestinationSpec>,
) -> Result<DestinationSpec> {
    let kind = prompt_destination_kind(default.map(DestinationSpec::kind))?;

    Ok(match kind {
        DestinationKind::First => DestinationSpec::First,
        DestinationKind::Last => DestinationSpec::Last,
        DestinationKind::Before => DestinationSpec::Before(prompt_reference_host(
            entries,
            targets,
            "before",
            default.and_then(DestinationSpec::reference_host),
        )?),
        DestinationKind::After => DestinationSpec::After(prompt_reference_host(
            entries,
            targets,
            "after",
            default.and_then(DestinationSpec::reference_host),
        )?),
    })
}

fn prompt_destination_kind(default: Option<DestinationKind>) -> Result<DestinationKind> {
    loop {
        let default_label = default.map(DestinationKind::label).unwrap_or("choose");
        let input = prompt_input("Destination (first, last, before, after)", default_label)?;

        if input.is_empty() {
            if let Some(default) = default {
                return Ok(default);
            }
            println!("! Choose one of: first, last, before, after");
            continue;
        }

        if let Some(kind) = DestinationKind::parse(&input) {
            return Ok(kind);
        }

        println!("! Unknown destination `{input}`");
    }
}

fn prompt_reference_host(
    entries: &[ManagedEntry],
    targets: &[ManagedEntry],
    relation: &str,
    default: Option<&str>,
) -> Result<String> {
    let target_hosts = selected_hosts(targets);
    let selected: HashSet<_> = target_hosts.iter().map(String::as_str).collect();
    let candidates = entries
        .iter()
        .map(|entry| entry.entry.primary_pattern().to_string())
        .filter(|candidate| !selected.contains(candidate.as_str()))
        .collect::<Vec<_>>();

    if candidates.is_empty() {
        if target_hosts.len() == 1 {
            bail!(
                "no reference entries available to move `{}` {relation}",
                target_hosts[0]
            );
        }
        bail!("no reference entries available to move selected entries {relation}");
    }

    println!("Available reference hosts: {}", candidates.join(", "));

    loop {
        let input = prompt_input(
            &format!("Reference host ({relation} which host?)"),
            default.unwrap_or("choose"),
        )?;

        let value = if input.is_empty() {
            if let Some(default) = default {
                default.to_string()
            } else {
                println!("! Enter a reference host");
                continue;
            }
        } else {
            input
        };

        if selected.contains(value.as_str()) {
            if target_hosts.len() == 1 {
                println!("! Cannot move `{}` {relation} itself", target_hosts[0]);
            } else {
                println!("! Cannot move selected entries {relation} themselves");
            }
            continue;
        }

        if candidates.iter().any(|candidate| candidate == &value) {
            return Ok(value);
        }

        println!("! Reference host `{value}` not found");
    }
}

fn prompt_input(label: &str, current: &str) -> Result<String> {
    let mut stdout = io::stdout();
    write!(stdout, "> {label} [{current}]: ")?;
    stdout.flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(input.trim().to_string())
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

fn has_terminal_io() -> bool {
    io::stdin().is_terminal() && io::stdout().is_terminal()
}

fn build_order_args_with_destination(base: &OrderArgs, destination: DestinationSpec) -> OrderArgs {
    let mut args = base.clone();
    args.interactive = false;
    args.before = None;
    args.after = None;
    args.first = false;
    args.last = false;

    match destination {
        DestinationSpec::Before(host) => args.before = Some(host),
        DestinationSpec::After(host) => args.after = Some(host),
        DestinationSpec::First => args.first = true,
        DestinationSpec::Last => args.last = true,
    }

    args
}

fn reorder_entries(
    entries: Vec<ManagedEntry>,
    targets: &[ManagedEntry],
    args: &OrderArgs,
) -> Result<Vec<ManagedEntry>> {
    if targets.is_empty() {
        bail!("no managed entries selected for reorder");
    }

    let target_paths = target_paths(targets);
    let mut moving = Vec::with_capacity(targets.len());
    let mut remaining = Vec::with_capacity(entries.len().saturating_sub(targets.len()));
    for entry in entries {
        if target_paths.contains(entry.path.as_path()) {
            moving.push(entry);
        } else {
            remaining.push(entry);
        }
    }

    if moving.is_empty() {
        bail!("selected managed entries disappeared before reorder");
    }

    let destination =
        destination_spec(args).context("order destination is required before reordering")?;
    let insert_index = match destination {
        DestinationSpec::Before(host) => {
            if store::find_entry_by_host(targets, &host).is_some() {
                if targets.len() == 1 {
                    bail!(
                        "cannot move `{}` before itself",
                        targets[0].entry.primary_pattern()
                    );
                }
                bail!("cannot move selected entries before themselves");
            }
            find_entry_index(&remaining, &host)
                .with_context(|| format!("reference entry `{host}` not found"))?
        }
        DestinationSpec::After(host) => {
            if store::find_entry_by_host(targets, &host).is_some() {
                if targets.len() == 1 {
                    bail!(
                        "cannot move `{}` after itself",
                        targets[0].entry.primary_pattern()
                    );
                }
                bail!("cannot move selected entries after themselves");
            }
            find_entry_index(&remaining, &host)
                .with_context(|| format!("reference entry `{host}` not found"))?
                + 1
        }
        DestinationSpec::First => 0,
        DestinationSpec::Last => remaining.len(),
    };

    let mut tail = remaining.split_off(insert_index);
    remaining.extend(moving);
    remaining.append(&mut tail);
    Ok(remaining)
}

fn destination_spec(args: &OrderArgs) -> Option<DestinationSpec> {
    if let Some(host) = &args.before {
        Some(DestinationSpec::Before(host.clone()))
    } else if let Some(host) = &args.after {
        Some(DestinationSpec::After(host.clone()))
    } else if args.first {
        Some(DestinationSpec::First)
    } else if args.last {
        Some(DestinationSpec::Last)
    } else {
        None
    }
}

fn load_target<'a>(entries: &'a [ManagedEntry], host: &str) -> Result<&'a ManagedEntry> {
    store::find_entry_by_host(entries, host)
        .with_context(|| format!("managed entry `{host}` not found"))
}

fn find_entry_index(entries: &[ManagedEntry], host: &str) -> Option<usize> {
    entries.iter().position(|entry| {
        entry
            .entry
            .host_patterns
            .iter()
            .any(|pattern| pattern == host)
    })
}

fn selected_hosts(targets: &[ManagedEntry]) -> Vec<String> {
    targets
        .iter()
        .map(|entry| entry.entry.primary_pattern().to_string())
        .collect()
}

fn target_paths<'a>(targets: &'a [ManagedEntry]) -> HashSet<&'a Path> {
    targets.iter().map(|entry| entry.path.as_path()).collect()
}

pub(crate) fn sequence_signature(entries: &[ManagedEntry]) -> Vec<PathBuf> {
    entries.iter().map(|entry| entry.path.clone()).collect()
}

fn describe_destination(args: &OrderArgs) -> String {
    destination_spec(args)
        .map(|destination| describe_destination_spec(&destination))
        .unwrap_or_else(|| "unknown".to_string())
}

fn describe_destination_spec(destination: &DestinationSpec) -> String {
    match destination {
        DestinationSpec::Before(host) => format!("before `{host}`"),
        DestinationSpec::After(host) => format!("after `{host}`"),
        DestinationSpec::First => "first".to_string(),
        DestinationSpec::Last => "last".to_string(),
    }
}

fn selection_summary(host: Option<&str>, all: bool, filter: &MetadataFilterArgs) -> Option<String> {
    if host.is_some() {
        return None;
    }

    let entry_filter = EntryFilter::from_args(filter);
    if all && entry_filter.is_empty() {
        return Some("all managed entries".to_string());
    }

    let mut parts = Vec::new();
    if let Some(query) = filter
        .query
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        parts.push(format!("query={query}"));
    }
    if !filter.tags.is_empty() {
        parts.push(format!("tags={}", filter.tags.join(",")));
    }
    if filter.has_note {
        parts.push("note=yes".to_string());
    }
    if let Some(template) = filter.template {
        parts.push(format!("template={}", template.cli_name()));
    }

    if parts.is_empty() {
        None
    } else {
        Some(parts.join(" | "))
    }
}

fn summarize_hosts(hosts: &[String], limit: usize) -> String {
    if hosts.len() <= limit {
        return hosts.join(", ");
    }

    let mut shown = hosts.iter().take(limit).cloned().collect::<Vec<_>>();
    shown.push(format!("... and {} more", hosts.len() - limit));
    shown.join(", ")
}

fn backup_paths(first: Option<PathBuf>, second: Option<PathBuf>) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    if let Some(path) = first {
        paths.push(path);
    }
    if let Some(path) = second {
        if !paths.iter().any(|existing| existing == &path) {
            paths.push(path);
        }
    }
    paths
}

fn apply_reordered_entries_for_hosts(
    paths: &AppPaths,
    reordered: &[ManagedEntry],
    hosts: &[String],
) -> Result<BatchReorderOutcome> {
    if hosts.is_empty() {
        bail!("no managed entries selected for reorder");
    }

    let init_report = init::ensure_initialized(paths)?;
    let backup_path = backup::create_backup(paths)?;
    let saved_entries = store::rewrite_entries(paths, reordered)
        .context("failed to rewrite managed SSH entry order")?;
    let state = state::sync_entries(paths, &saved_entries, true)
        .context("failed to update state metadata")?;

    let mut moved = Vec::with_capacity(hosts.len());
    for host in hosts {
        let moved_entry = store::find_entry_by_host(&saved_entries, host)
            .with_context(|| format!("managed entry `{host}` disappeared after reorder"))?;
        let metadata = state::find_entry_metadata(&state, moved_entry)
            .context("state metadata for reordered entry is missing")?;
        moved.push(ReorderedEntry {
            host: host.clone(),
            order: moved_entry.order,
            metadata_id: metadata.id.clone(),
        });
    }
    moved.sort_by_key(|entry| entry.order);

    Ok(BatchReorderOutcome {
        moved,
        backup_paths: backup_paths(init_report.backup_path, backup_path),
        include_written: init_report.include_written,
    })
}

pub(crate) fn apply_reordered_entries(
    paths: &AppPaths,
    reordered: &[ManagedEntry],
    host: &str,
) -> Result<ReorderOutcome> {
    let outcome = apply_reordered_entries_for_hosts(paths, reordered, &[host.to_string()])?;
    let moved = outcome
        .moved
        .into_iter()
        .next()
        .context("single-entry reorder outcome is missing")?;

    Ok(ReorderOutcome {
        host: moved.host,
        order: moved.order,
        metadata_id: moved.metadata_id,
        backup_paths: outcome.backup_paths,
        include_written: outcome.include_written,
    })
}

fn merge_backup_paths(first: Option<PathBuf>, mut existing: Vec<PathBuf>) -> Vec<PathBuf> {
    if let Some(path) = first {
        if !existing.iter().any(|item| item == &path) {
            existing.insert(0, path);
        }
    }
    existing
}

impl DestinationSpec {
    fn kind(&self) -> DestinationKind {
        match self {
            Self::Before(_) => DestinationKind::Before,
            Self::After(_) => DestinationKind::After,
            Self::First => DestinationKind::First,
            Self::Last => DestinationKind::Last,
        }
    }

    fn reference_host(&self) -> Option<&str> {
        match self {
            Self::Before(host) | Self::After(host) => Some(host.as_str()),
            Self::First | Self::Last => None,
        }
    }
}

impl DestinationKind {
    fn label(self) -> &'static str {
        match self {
            Self::Before => "before",
            Self::After => "after",
            Self::First => "first",
            Self::Last => "last",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "before" | "b" => Some(Self::Before),
            "after" | "a" => Some(Self::After),
            "first" | "f" => Some(Self::First),
            "last" | "l" => Some(Self::Last),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use chrono::Utc;

    use crate::app::cli::{MetadataFilterArgs, OrderArgs};
    use crate::core::model::{HostEntry, ManagedEntry};
    use crate::core::state::{self, MetadataUpdate};
    use crate::core::store;
    use crate::core::template::TemplateKind;
    use crate::fs::layout::AppPaths;

    use super::{
        DestinationSpec, build_order_args_with_destination, has_requested_destination,
        reorder_entries, requires_interactive_completion, resolve_targets, validate_order_args,
    };

    fn test_paths(name: &str) -> AppPaths {
        let root = std::env::current_dir()
            .unwrap()
            .join("target")
            .join("test-order")
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

    fn sample_entry(order: u16, host: &str) -> ManagedEntry {
        ManagedEntry {
            order,
            slug: host.to_string(),
            path: format!("{order:03}-host-{host}.conf").into(),
            raw_content: String::new(),
            entry: HostEntry {
                host_patterns: vec![host.to_string()],
                hostname: Some(format!("{host}.example.com")),
                ..HostEntry::default()
            },
        }
    }

    fn sample_host(host: &str, hostname: &str) -> HostEntry {
        HostEntry {
            host_patterns: vec![host.to_string()],
            hostname: Some(hostname.to_string()),
            ..HostEntry::default()
        }
    }

    fn base_args(host: Option<&str>) -> OrderArgs {
        OrderArgs {
            host: host.map(ToString::to_string),
            all: false,
            filter: MetadataFilterArgs::default(),
            interactive: false,
            before: None,
            after: None,
            first: false,
            last: false,
        }
    }

    fn selector_args() -> OrderArgs {
        base_args(None)
    }

    #[test]
    fn order_without_destination_uses_interactive_completion() {
        let args = base_args(Some("gamma"));

        assert!(!has_requested_destination(&args));
        assert!(requires_interactive_completion(&args));
    }

    #[test]
    fn explicit_order_destination_skips_interactive_completion() {
        let mut args = base_args(Some("gamma"));
        args.after = Some("beta".to_string());

        assert!(has_requested_destination(&args));
        assert!(!requires_interactive_completion(&args));
    }

    #[test]
    fn builds_args_from_destination_choice() {
        let args = base_args(Some("gamma"));
        let reordered =
            build_order_args_with_destination(&args, DestinationSpec::Before("alpha".to_string()));

        assert_eq!(reordered.before.as_deref(), Some("alpha"));
        assert!(reordered.after.is_none());
        assert!(!reordered.first);
        assert!(!reordered.last);
        assert!(!reordered.interactive);
    }

    #[test]
    fn validation_rejects_host_and_selector_combination() {
        let mut args = base_args(Some("alpha"));
        args.filter.query = Some("prod".to_string());

        let err = validate_order_args(&args).unwrap_err();
        assert!(err.to_string().contains("cannot combine"));
    }

    #[test]
    fn validation_requires_host_or_selector() {
        let args = selector_args();

        let err = validate_order_args(&args).unwrap_err();
        assert!(
            err.to_string()
                .contains("order requires either a host or a selector")
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

        let mut args = selector_args();
        args.filter.tags = vec!["prod".to_string()];

        let entries = store::load_managed_entries(&paths).unwrap();
        let targets = resolve_targets(&paths, &entries, &args).unwrap();

        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].entry.primary_pattern(), "alpha");
    }

    #[test]
    fn moves_entry_before_reference() {
        let entries = vec![
            sample_entry(10, "alpha"),
            sample_entry(20, "beta"),
            sample_entry(30, "gamma"),
        ];
        let targets = vec![entries[2].clone()];
        let mut args = base_args(Some("gamma"));
        args.before = Some("alpha".to_string());

        let reordered = reorder_entries(entries, &targets, &args).unwrap();
        let hosts: Vec<_> = reordered
            .iter()
            .map(|entry| entry.entry.primary_pattern().to_string())
            .collect();

        assert_eq!(hosts, vec!["gamma", "alpha", "beta"]);
    }

    #[test]
    fn moves_selected_entries_before_reference_as_block() {
        let entries = vec![
            sample_entry(10, "alpha"),
            sample_entry(20, "beta"),
            sample_entry(30, "gamma"),
            sample_entry(40, "delta"),
        ];
        let targets = vec![entries[1].clone(), entries[3].clone()];
        let mut args = selector_args();
        args.before = Some("alpha".to_string());

        let reordered = reorder_entries(entries, &targets, &args).unwrap();
        let hosts: Vec<_> = reordered
            .iter()
            .map(|entry| entry.entry.primary_pattern().to_string())
            .collect();

        assert_eq!(hosts, vec!["beta", "delta", "alpha", "gamma"]);
    }

    #[test]
    fn moves_selected_entries_to_last_position() {
        let entries = vec![
            sample_entry(10, "alpha"),
            sample_entry(20, "beta"),
            sample_entry(30, "gamma"),
            sample_entry(40, "delta"),
        ];
        let targets = vec![entries[0].clone(), entries[2].clone()];
        let mut args = selector_args();
        args.last = true;

        let reordered = reorder_entries(entries, &targets, &args).unwrap();
        let hosts: Vec<_> = reordered
            .iter()
            .map(|entry| entry.entry.primary_pattern().to_string())
            .collect();

        assert_eq!(hosts, vec!["beta", "delta", "alpha", "gamma"]);
    }

    #[test]
    fn rejects_self_reference() {
        let entries = vec![sample_entry(10, "alpha"), sample_entry(20, "beta")];
        let targets = vec![entries[0].clone()];
        let mut args = base_args(Some("alpha"));
        args.before = Some("alpha".to_string());

        let err = reorder_entries(entries, &targets, &args).unwrap_err();
        assert!(err.to_string().contains("before itself"));
    }

    #[test]
    fn rejects_selected_block_reference() {
        let entries = vec![
            sample_entry(10, "alpha"),
            sample_entry(20, "beta"),
            sample_entry(30, "gamma"),
        ];
        let targets = vec![entries[0].clone(), entries[2].clone()];
        let mut args = selector_args();
        args.after = Some("gamma".to_string());

        let err = reorder_entries(entries, &targets, &args).unwrap_err();
        assert!(err.to_string().contains("selected entries"));
    }

    #[test]
    fn rejects_missing_destination() {
        let entries = vec![sample_entry(10, "alpha"), sample_entry(20, "beta")];
        let targets = vec![entries[0].clone()];
        let args = base_args(Some("alpha"));

        let err = reorder_entries(entries, &targets, &args).unwrap_err();
        assert!(err.to_string().contains("destination"));
    }

    #[test]
    fn resolve_targets_supports_all_selector() {
        let paths = test_paths("resolve-all");
        paths.ensure_base_dirs().unwrap();

        let alpha =
            store::save_entry(&paths, &sample_host("alpha", "alpha.example.com"), None).unwrap();
        let beta =
            store::save_entry(&paths, &sample_host("beta", "beta.example.com"), Some(20)).unwrap();
        state::upsert_entry(&paths, &alpha, None, MetadataUpdate::default()).unwrap();
        state::upsert_entry(&paths, &beta, None, MetadataUpdate::default()).unwrap();

        let mut args = selector_args();
        args.all = true;

        let entries = store::load_managed_entries(&paths).unwrap();
        let targets = resolve_targets(&paths, &entries, &args).unwrap();

        assert_eq!(targets.len(), 2);
        assert_eq!(targets[0].entry.primary_pattern(), "alpha");
        assert_eq!(targets[1].entry.primary_pattern(), "beta");
    }
}
