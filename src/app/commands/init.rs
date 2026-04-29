use std::collections::HashSet;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

use crate::app::cli::InitArgs;
use crate::core::model::{HostEntry, ManagedEntry};
use crate::core::parser;
use crate::core::state;
use crate::core::store;
use crate::core::validate;
use crate::fs::backup;
use crate::fs::layout::{
    AppPaths, MANAGED_BLOCK_END, MANAGED_BLOCK_START, MANAGED_INCLUDE_LINE, detect_newline,
    managed_block,
};
use crate::fs::writer;

#[derive(Debug, Clone)]
pub struct InitReport {
    pub include_ready: bool,
    pub include_written: bool,
    pub include_already_present: bool,
    pub backup_path: Option<std::path::PathBuf>,
}

#[derive(Debug, Clone)]
struct MigrationPlan {
    rewritten_root: String,
    ordered_entries: Vec<ManagedEntry>,
    attempted_blocks: usize,
    migrated_blocks: usize,
    migrated_entries: Vec<PlannedMigratedHostBlock>,
    skipped_blocks: Vec<SkippedHostBlock>,
    include_written: bool,
    include_already_present: bool,
}

#[derive(Debug, Clone)]
struct MigrationResult {
    init_report: InitReport,
    attempted_blocks: usize,
    migrated_blocks: usize,
    migrated_entries: Vec<MigrationEntryReport>,
    skipped_blocks: Vec<SkippedHostBlock>,
    metadata_records: usize,
}

#[derive(Debug, Clone)]
struct SkippedHostBlock {
    host: String,
    reason: String,
    source_start_line: usize,
    source_end_line: usize,
}

#[derive(Debug, Clone)]
struct PlannedMigratedHostBlock {
    host: String,
    host_patterns: Vec<String>,
    kind: String,
    source_start_line: usize,
    source_end_line: usize,
}

#[derive(Debug, Clone)]
struct MigrationEntryReport {
    host: String,
    host_patterns: Vec<String>,
    kind: String,
    source_start_line: usize,
    source_end_line: usize,
    order: u16,
    managed_path: PathBuf,
}

#[derive(Debug, Clone)]
struct ParsedRootConfig {
    segments: Vec<RootSegment>,
    anchor_index: Option<usize>,
    anchor_count: usize,
}

#[derive(Debug, Clone)]
enum RootSegment {
    Preserved(String),
    Anchor(String),
    HostBlock(RootHostBlock),
}

#[derive(Debug, Clone)]
struct RootHostBlock {
    leading_trivia: String,
    raw: String,
    start_line: usize,
    end_line: usize,
}

#[derive(Debug, Clone)]
struct ManagedAnchorPlan {
    rewritten_root: String,
    had_anchor: bool,
}

pub fn ensure_initialized(paths: &AppPaths) -> Result<InitReport> {
    paths.ensure_base_dirs()?;

    let mut include_written = false;
    let mut backup_path = None;

    let existing = if paths.root_config.exists() {
        std::fs::read_to_string(&paths.root_config)?
    } else {
        String::new()
    };

    let newline = detect_newline(&existing);
    let anchor_plan = normalize_root_with_managed_anchor(&existing, newline)?;
    let include_already_present = anchor_plan.had_anchor;

    if anchor_plan.rewritten_root != existing {
        backup_path = backup::create_backup(paths)?;
        writer::write_text_file(&paths.root_config, &anchor_plan.rewritten_root)?;
        include_written = true;
    }

    paths.ensure_state_file()?;

    Ok(InitReport {
        include_ready: true,
        include_written,
        include_already_present,
        backup_path,
    })
}

pub fn run(args: InitArgs) -> Result<()> {
    if args.migrate {
        return run_migrate();
    }

    let paths = AppPaths::discover()?;
    let report = ensure_initialized(&paths)?;
    let entries = store::load_managed_entries(&paths)?;
    let state = state::sync_entries(&paths, &entries, false)?;

    println!("ssh dir: {}", paths.ssh_dir.display());
    println!("root config: {}", paths.root_config.display());
    println!("managed dir: {}", paths.config_d_dir.display());
    println!("state file: {}", paths.state_file.display());
    println!("include ready: {}", report.include_ready);
    println!("include written: {}", report.include_written);
    println!(
        "include already present: {}",
        report.include_already_present
    );
    println!("metadata records: {}", state.entries.len());

    if let Some(path) = report.backup_path {
        println!("backup: {}", path.display());
    }

    Ok(())
}

fn run_migrate() -> Result<()> {
    let paths = AppPaths::discover()?;
    let result = migrate(&paths)?;

    println!("ssh dir: {}", paths.ssh_dir.display());
    println!("root config: {}", paths.root_config.display());
    println!("managed dir: {}", paths.config_d_dir.display());
    println!("state file: {}", paths.state_file.display());
    println!("include ready: {}", result.init_report.include_ready);
    println!("include written: {}", result.init_report.include_written);
    println!(
        "include already present: {}",
        result.init_report.include_already_present
    );
    println!("root host blocks scanned: {}", result.attempted_blocks);
    println!("root host blocks migrated: {}", result.migrated_blocks);
    println!("root host blocks skipped: {}", result.skipped_blocks.len());
    println!("metadata records: {}", result.metadata_records);

    for migrated in &result.migrated_entries {
        println!(
            "migrated lines {}-{} `{}` [{}] -> {:03} {}{}",
            migrated.source_start_line,
            migrated.source_end_line,
            migrated.host,
            migrated.kind,
            migrated.order,
            migrated.managed_path.display(),
            if migrated.host_patterns.len() > 1 {
                format!(" | patterns {}", migrated.host_patterns.join(","))
            } else {
                String::new()
            }
        );
    }

    for skipped in &result.skipped_blocks {
        println!(
            "skipped lines {}-{} `{}`: {}",
            skipped.source_start_line, skipped.source_end_line, skipped.host, skipped.reason
        );
    }

    if let Some(path) = result.init_report.backup_path {
        println!("backup: {}", path.display());
    }

    Ok(())
}

fn migrate(paths: &AppPaths) -> Result<MigrationResult> {
    paths.ensure_base_dirs()?;

    let existing_root = if paths.root_config.exists() {
        std::fs::read_to_string(&paths.root_config)
            .with_context(|| format!("failed to read {}", paths.root_config.display()))?
    } else {
        String::new()
    };
    let existing_entries = store::load_managed_entries(paths)?;
    let plan = plan_root_migration(&existing_root, &existing_entries)?;
    let root_changed = plan.rewritten_root != existing_root;
    let entries_changed = plan.migrated_blocks > 0;

    let backup_path = if root_changed || entries_changed {
        backup::create_backup(paths)?
    } else {
        None
    };

    if root_changed {
        writer::write_text_file(&paths.root_config, &plan.rewritten_root)?;
    }

    let final_entries = if entries_changed {
        store::rewrite_entries(paths, &plan.ordered_entries)
            .context("failed to rewrite managed entries during migration")?
    } else {
        existing_entries
    };
    let migrated_entries = build_migrated_entry_reports(&plan.migrated_entries, &final_entries)?;
    let state = state::sync_entries(paths, &final_entries, entries_changed)
        .context("failed to sync state metadata after migration")?;

    Ok(MigrationResult {
        init_report: InitReport {
            include_ready: true,
            include_written: plan.include_written,
            include_already_present: plan.include_already_present,
            backup_path,
        },
        attempted_blocks: plan.attempted_blocks,
        migrated_blocks: plan.migrated_blocks,
        migrated_entries,
        skipped_blocks: plan.skipped_blocks,
        metadata_records: state.entries.len(),
    })
}

fn plan_root_migration(content: &str, existing_entries: &[ManagedEntry]) -> Result<MigrationPlan> {
    let parsed = parse_root_config(content)?;
    if parsed.anchor_count > 1 {
        bail!("root config contains multiple include anchors; migration is not safe");
    }

    let newline = detect_newline(content);
    let anchor_plan = normalize_root_with_managed_anchor(content, newline)?;
    let mut existing_patterns = HashSet::new();
    for entry in existing_entries {
        for pattern in &entry.entry.host_patterns {
            existing_patterns.insert(pattern.clone());
        }
    }

    let mut migrated_entries = Vec::new();
    let mut migrated_before_anchor = Vec::new();
    let mut migrated_after_anchor = Vec::new();
    let mut migrated_reports = Vec::new();
    let mut seen_patterns = HashSet::new();
    let mut skipped_blocks = Vec::new();
    let mut attempted_blocks = 0;
    let mut root_output = String::new();

    for (index, segment) in parsed.segments.iter().enumerate() {
        match segment {
            RootSegment::Preserved(raw) => root_output.push_str(raw),
            RootSegment::Anchor(_raw) => {}
            RootSegment::HostBlock(block) => {
                attempted_blocks += 1;
                match evaluate_host_block(block, &existing_patterns, &mut seen_patterns) {
                    Ok(entry) => {
                        trim_trailing_suffix(&mut root_output, &block.leading_trivia)
                            .with_context(|| {
                                format!(
                                    "failed to trim leading trivia for migrated host `{}`",
                                    entry.primary_pattern()
                                )
                            })?;
                        migrated_reports.push(PlannedMigratedHostBlock {
                            host: entry.primary_pattern().to_string(),
                            host_patterns: entry.host_patterns.clone(),
                            kind: entry.kind().label().to_string(),
                            source_start_line: block.start_line,
                            source_end_line: block.end_line,
                        });
                        let managed = unmanaged_entry_to_managed(
                            entry.clone(),
                            format!("{}{}", block.leading_trivia, block.raw),
                        );
                        if parsed.anchor_index.is_some() {
                            if Some(index) < parsed.anchor_index {
                                migrated_before_anchor.push(managed.clone());
                            } else {
                                migrated_after_anchor.push(managed.clone());
                            }
                        } else {
                            migrated_entries.push(managed.clone());
                        }

                        if parsed.anchor_index.is_some() {
                            migrated_entries.push(managed);
                        }
                    }
                    Err(skipped) => {
                        skipped_blocks.push(skipped);
                        root_output.push_str(&block.raw);
                    }
                }
            }
        }
    }

    let rewritten_root = insert_managed_block_before_first_conditional(&root_output, newline);

    let ordered_entries = if parsed.anchor_index.is_some() {
        migrated_before_anchor
            .into_iter()
            .chain(existing_entries.iter().cloned())
            .chain(migrated_after_anchor)
            .collect::<Vec<_>>()
    } else {
        migrated_entries
            .into_iter()
            .chain(existing_entries.iter().cloned())
            .collect::<Vec<_>>()
    };

    let migrated_blocks = migrated_entries_len(&parsed, &ordered_entries, existing_entries.len());

    Ok(MigrationPlan {
        rewritten_root,
        ordered_entries,
        attempted_blocks,
        migrated_blocks,
        migrated_entries: migrated_reports,
        skipped_blocks,
        include_written: anchor_plan.rewritten_root != content,
        include_already_present: anchor_plan.had_anchor,
    })
}

fn migrated_entries_len(
    parsed: &ParsedRootConfig,
    ordered_entries: &[ManagedEntry],
    existing_entry_count: usize,
) -> usize {
    if parsed.anchor_index.is_some() {
        ordered_entries.len().saturating_sub(existing_entry_count)
    } else {
        ordered_entries
            .len()
            .saturating_sub(existing_entry_count.min(ordered_entries.len()))
    }
}

fn parse_root_config(content: &str) -> Result<ParsedRootConfig> {
    let lines: Vec<&str> = if content.is_empty() {
        Vec::new()
    } else {
        content.split_inclusive('\n').collect()
    };
    let mut segments = Vec::new();
    let mut preserved = String::new();
    let mut anchor_index = None;
    let mut anchor_count = 0;
    let mut index = 0;

    while index < lines.len() {
        let trimmed = lines[index].trim();

        if trimmed == MANAGED_BLOCK_START {
            flush_preserved(&mut segments, &mut preserved);
            let mut raw = String::new();
            let mut found_end = false;

            while index < lines.len() {
                raw.push_str(lines[index]);
                if lines[index].trim() == MANAGED_BLOCK_END {
                    found_end = true;
                    index += 1;
                    break;
                }
                index += 1;
            }

            if !found_end {
                bail!("managed include block is not closed");
            }

            anchor_index.get_or_insert(segments.len());
            anchor_count += 1;
            segments.push(RootSegment::Anchor(raw));
            continue;
        }

        if trimmed.eq_ignore_ascii_case(MANAGED_INCLUDE_LINE) {
            flush_preserved(&mut segments, &mut preserved);
            anchor_index.get_or_insert(segments.len());
            anchor_count += 1;
            segments.push(RootSegment::Anchor(lines[index].to_string()));
            index += 1;
            continue;
        }

        if directive_key(trimmed).is_some_and(|key| key.eq_ignore_ascii_case("Host")) {
            let leading_trivia = leading_trivia_suffix(&preserved);
            flush_preserved(&mut segments, &mut preserved);
            let mut raw = String::new();
            let mut trailing_trivia = String::new();
            let start_line = index + 1;
            let mut end_line = start_line;

            while index < lines.len() {
                let candidate = lines[index].trim();
                if !raw.is_empty() && is_segment_boundary(candidate) {
                    break;
                }

                if !raw.is_empty() && is_trivia_line(lines[index]) {
                    trailing_trivia.push_str(lines[index]);
                    index += 1;
                    continue;
                }

                if !trailing_trivia.is_empty() {
                    raw.push_str(&trailing_trivia);
                    trailing_trivia.clear();
                }

                raw.push_str(lines[index]);
                end_line = index + 1;
                index += 1;
            }

            if index >= lines.len() && !trailing_trivia.is_empty() {
                raw.push_str(&trailing_trivia);
            } else {
                preserved.push_str(&trailing_trivia);
            }

            segments.push(RootSegment::HostBlock(RootHostBlock {
                leading_trivia,
                raw,
                start_line,
                end_line,
            }));
            continue;
        }

        preserved.push_str(lines[index]);
        index += 1;
    }

    flush_preserved(&mut segments, &mut preserved);

    Ok(ParsedRootConfig {
        segments,
        anchor_index,
        anchor_count,
    })
}

fn flush_preserved(segments: &mut Vec<RootSegment>, preserved: &mut String) {
    if preserved.is_empty() {
        return;
    }

    segments.push(RootSegment::Preserved(std::mem::take(preserved)));
}

fn leading_trivia_suffix(content: &str) -> String {
    let lines: Vec<&str> = if content.is_empty() {
        Vec::new()
    } else {
        content.split_inclusive('\n').collect()
    };
    let mut start = lines.len();

    while start > 0 && is_trivia_line(lines[start - 1]) {
        start -= 1;
    }

    lines[start..].concat()
}

fn is_trivia_line(line: &str) -> bool {
    let trimmed = line.trim();
    trimmed.is_empty() || trimmed.starts_with('#')
}

fn is_segment_boundary(line: &str) -> bool {
    line == MANAGED_BLOCK_START
        || line.eq_ignore_ascii_case(MANAGED_INCLUDE_LINE)
        || directive_key(line).is_some_and(|key| {
            key.eq_ignore_ascii_case("Host") || key.eq_ignore_ascii_case("Match")
        })
}

fn trim_trailing_suffix(content: &mut String, suffix: &str) -> Result<()> {
    if suffix.is_empty() {
        return Ok(());
    }

    if !content.ends_with(suffix) {
        bail!("expected content to end with tracked leading trivia");
    }

    let new_len = content.len() - suffix.len();
    content.truncate(new_len);
    Ok(())
}

fn directive_key(line: &str) -> Option<&str> {
    let (key, value) = line.split_once(char::is_whitespace)?;
    (!value.trim().is_empty()).then_some(key)
}

fn evaluate_host_block(
    block: &RootHostBlock,
    existing_patterns: &HashSet<String>,
    seen_patterns: &mut HashSet<String>,
) -> std::result::Result<HostEntry, SkippedHostBlock> {
    let host_label = summarize_host_block(&block.raw);
    let entry = parser::parse_host_entry(Path::new("root-config"), &block.raw).map_err(|err| {
        SkippedHostBlock {
            host: host_label.clone(),
            reason: err.to_string(),
            source_start_line: block.start_line,
            source_end_line: block.end_line,
        }
    })?;

    validate::validate_entry(&entry).map_err(|err| SkippedHostBlock {
        host: host_label.clone(),
        reason: err.to_string(),
        source_start_line: block.start_line,
        source_end_line: block.end_line,
    })?;

    for pattern in &entry.host_patterns {
        if existing_patterns.contains(pattern) {
            return Err(SkippedHostBlock {
                host: host_label,
                reason: format!("host pattern `{pattern}` already exists in managed config"),
                source_start_line: block.start_line,
                source_end_line: block.end_line,
            });
        }

        if !seen_patterns.insert(pattern.clone()) {
            return Err(SkippedHostBlock {
                host: pattern.clone(),
                reason: "host pattern is duplicated within migrated root config".to_string(),
                source_start_line: block.start_line,
                source_end_line: block.end_line,
            });
        }
    }

    Ok(entry)
}

fn summarize_host_block(raw: &str) -> String {
    raw.lines()
        .find_map(|line| {
            let trimmed = line.trim();
            directive_key(trimmed)
                .filter(|key| key.eq_ignore_ascii_case("Host"))
                .map(|_| {
                    trimmed
                        .split_once(char::is_whitespace)
                        .map(|(_, value)| value.trim().to_string())
                        .unwrap_or_else(|| "<unknown>".to_string())
                })
        })
        .unwrap_or_else(|| "<unknown>".to_string())
}

fn unmanaged_entry_to_managed(entry: HostEntry, raw_content: String) -> ManagedEntry {
    ManagedEntry {
        order: 0,
        slug: store::slugify_host_pattern(entry.primary_pattern()),
        path: PathBuf::new(),
        raw_content,
        entry,
    }
}

fn build_migrated_entry_reports(
    planned: &[PlannedMigratedHostBlock],
    final_entries: &[ManagedEntry],
) -> Result<Vec<MigrationEntryReport>> {
    planned
        .iter()
        .map(|planned_entry| {
            let managed = final_entries
                .iter()
                .find(|entry| entry.entry.host_patterns == planned_entry.host_patterns)
                .with_context(|| {
                    format!(
                        "migrated entry `{}` disappeared before report generation",
                        planned_entry.host
                    )
                })?;

            Ok(MigrationEntryReport {
                host: planned_entry.host.clone(),
                host_patterns: planned_entry.host_patterns.clone(),
                kind: planned_entry.kind.clone(),
                source_start_line: planned_entry.source_start_line,
                source_end_line: planned_entry.source_end_line,
                order: managed.order,
                managed_path: managed.path.clone(),
            })
        })
        .collect()
}

fn normalize_root_with_managed_anchor(content: &str, newline: &str) -> Result<ManagedAnchorPlan> {
    let parsed = parse_root_config(content)?;
    if parsed.anchor_count > 1 {
        bail!("root config contains multiple include anchors; initialization is not safe");
    }

    let mut without_anchor = String::new();
    for segment in parsed.segments {
        match segment {
            RootSegment::Preserved(raw) => without_anchor.push_str(&raw),
            RootSegment::HostBlock(block) => without_anchor.push_str(&block.raw),
            RootSegment::Anchor(_) => {}
        }
    }

    Ok(ManagedAnchorPlan {
        rewritten_root: insert_managed_block_before_first_conditional(&without_anchor, newline),
        had_anchor: parsed.anchor_index.is_some(),
    })
}

fn insert_managed_block_before_first_conditional(existing: &str, newline: &str) -> String {
    if existing.trim().is_empty() {
        return managed_block(newline);
    }

    let offset = first_conditional_offset(existing).unwrap_or(existing.len());
    let (prefix, suffix) = existing.split_at(offset);
    let mut rewritten = String::new();

    rewritten.push_str(prefix);
    if !prefix.is_empty() && !prefix.ends_with(['\r', '\n']) {
        rewritten.push_str(newline);
    }
    rewritten.push_str(&managed_block(newline));
    rewritten.push_str(suffix);
    rewritten
}

fn first_conditional_offset(content: &str) -> Option<usize> {
    let lines: Vec<&str> = if content.is_empty() {
        Vec::new()
    } else {
        content.split_inclusive('\n').collect()
    };
    let mut offsets = Vec::with_capacity(lines.len());
    let mut offset = 0;

    for line in &lines {
        offsets.push(offset);
        offset += line.len();
    }

    for index in 0..lines.len() {
        let trimmed = lines[index].trim();
        if directive_key(trimmed).is_some_and(|key| {
            key.eq_ignore_ascii_case("Host") || key.eq_ignore_ascii_case("Match")
        }) {
            let mut start = index;
            while start > 0 && is_trivia_line(lines[start - 1]) {
                start -= 1;
            }
            return offsets.get(start).copied();
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use chrono::Utc;

    use crate::core::model::HostEntry;
    use crate::fs::layout::AppPaths;

    use super::{ensure_initialized, migrate, parse_root_config};

    fn test_paths(name: &str) -> AppPaths {
        let root = std::env::current_dir()
            .unwrap()
            .join("target")
            .join("test-init")
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

    fn host_entry(host: &str) -> HostEntry {
        HostEntry {
            host_patterns: vec![host.to_string()],
            hostname: Some(format!("{host}.example.com")),
            ..HostEntry::default()
        }
    }

    #[test]
    fn migrate_moves_safe_host_blocks_and_keeps_unsupported_content() {
        let paths = test_paths("migrate-safe");
        std::fs::create_dir_all(&paths.ssh_dir).unwrap();
        std::fs::write(
            &paths.root_config,
            "\
ServerAliveInterval 30

Host alpha
  HostName alpha.example.com
  User root

Host broken
  User root

Match user ops
  PasswordAuthentication no
",
        )
        .unwrap();

        let result = migrate(&paths).unwrap();
        let root = std::fs::read_to_string(&paths.root_config).unwrap();
        let entries = crate::core::store::load_managed_entries(&paths).unwrap();

        assert!(root.contains("ServerAliveInterval 30"));
        assert!(root.contains(crate::fs::layout::MANAGED_BLOCK_START));
        assert!(!root.contains("Host alpha"));
        assert!(root.contains("Host broken"));
        assert!(root.contains("Match user ops"));
        assert_eq!(result.attempted_blocks, 2);
        assert_eq!(result.migrated_blocks, 1);
        assert_eq!(result.migrated_entries.len(), 1);
        assert_eq!(result.skipped_blocks.len(), 1);
        assert_eq!(result.migrated_entries[0].source_start_line, 3);
        assert_eq!(result.migrated_entries[0].source_end_line, 5);
        assert_eq!(result.migrated_entries[0].host, "alpha");
        assert_eq!(result.migrated_entries[0].kind, "host");
        assert_eq!(result.migrated_entries[0].order, 10);
        assert!(
            result.migrated_entries[0]
                .managed_path
                .file_name()
                .and_then(|value| value.to_str())
                .is_some_and(|value| value.contains("alpha"))
        );
        assert!(result.skipped_blocks[0].reason.contains("HostName"));
        assert_eq!(result.skipped_blocks[0].source_start_line, 7);
        assert_eq!(result.skipped_blocks[0].source_end_line, 8);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].entry.primary_pattern(), "alpha");
    }

    #[test]
    fn migrate_places_root_entries_around_existing_include_anchor() {
        let paths = test_paths("migrate-anchor");
        paths.ensure_base_dirs().unwrap();
        crate::core::store::save_entry(&paths, &host_entry("managed"), Some(10)).unwrap();
        std::fs::write(
            &paths.root_config,
            format!(
                "\
Host before
  HostName before.example.com

{}

Host after
  HostName after.example.com
",
                crate::fs::layout::managed_block("\n").trim_end()
            ),
        )
        .unwrap();

        let result = migrate(&paths).unwrap();
        let root = std::fs::read_to_string(&paths.root_config).unwrap();
        let entries = crate::core::store::load_managed_entries(&paths).unwrap();
        let hosts: Vec<_> = entries
            .iter()
            .map(|entry| entry.entry.primary_pattern().to_string())
            .collect();

        assert!(root.contains(crate::fs::layout::MANAGED_BLOCK_START));
        assert!(!root.contains("Host before"));
        assert!(!root.contains("Host after"));
        assert_eq!(result.migrated_blocks, 2);
        assert_eq!(result.migrated_entries.len(), 2);
        assert_eq!(hosts, vec!["before", "managed", "after"]);
    }

    #[test]
    fn parse_root_config_counts_single_anchor_block() {
        let parsed = parse_root_config(&crate::fs::layout::managed_block("\n")).unwrap();

        assert_eq!(parsed.anchor_count, 1);
        assert_eq!(parsed.anchor_index, Some(0));
        assert_eq!(parsed.segments.len(), 1);
    }

    #[test]
    fn ensure_initialized_moves_anchor_before_host_blocks() {
        let paths = test_paths("init-anchor-reposition");
        paths.ensure_base_dirs().unwrap();
        std::fs::write(
            &paths.root_config,
            format!(
                "\
Host leftover
  HostName leftover.example.com

{}
",
                crate::fs::layout::managed_block("\n").trim_end()
            ),
        )
        .unwrap();

        let report = ensure_initialized(&paths).unwrap();
        let root = std::fs::read_to_string(&paths.root_config).unwrap();

        assert!(report.include_already_present);
        assert!(report.include_written);
        assert!(root.starts_with(crate::fs::layout::MANAGED_BLOCK_START));
        assert!(root.contains("Host leftover"));
    }

    #[test]
    fn migrate_places_anchor_before_skipped_root_host_blocks() {
        let paths = test_paths("migrate-skipped-anchor");
        paths.ensure_base_dirs().unwrap();
        std::fs::write(
            &paths.root_config,
            "\
Host duplicate
  HostName 10.0.0.1

Host duplicate
  HostName 10.0.0.2
",
        )
        .unwrap();

        let result = migrate(&paths).unwrap();
        let root = std::fs::read_to_string(&paths.root_config).unwrap();

        assert_eq!(result.migrated_blocks, 1);
        assert_eq!(result.skipped_blocks.len(), 1);
        assert_eq!(result.skipped_blocks[0].source_start_line, 4);
        assert_eq!(result.skipped_blocks[0].source_end_line, 5);
        assert!(root.starts_with(crate::fs::layout::MANAGED_BLOCK_START));
        assert!(root.contains("Host duplicate"));
    }

    #[test]
    fn migrate_preserves_internal_comments_and_spacing_in_managed_file() {
        let paths = test_paths("migrate-preserve-raw");
        std::fs::create_dir_all(&paths.ssh_dir).unwrap();
        std::fs::write(
            &paths.root_config,
            "\
Host alpha
  # keep this comment
  HostName alpha.example.com

  User root
",
        )
        .unwrap();

        let result = migrate(&paths).unwrap();
        let entries = crate::core::store::load_managed_entries(&paths).unwrap();

        assert_eq!(result.migrated_blocks, 1);
        assert_eq!(entries.len(), 1);
        let managed_content = std::fs::read_to_string(&entries[0].path).unwrap();
        assert!(managed_content.contains("# keep this comment"));
        assert!(managed_content.contains("HostName alpha.example.com\n\n  User root"));
        assert_eq!(entries[0].raw_content, managed_content);
    }

    #[test]
    fn migrate_preserves_leading_trivia_with_host_block() {
        let paths = test_paths("migrate-leading-trivia");
        std::fs::create_dir_all(&paths.ssh_dir).unwrap();
        std::fs::write(
            &paths.root_config,
            "\
ServerAliveInterval 30

# keep this comment
# and this one
Host alpha
  HostName alpha.example.com
",
        )
        .unwrap();

        let result = migrate(&paths).unwrap();
        let root = std::fs::read_to_string(&paths.root_config).unwrap();
        let entries = crate::core::store::load_managed_entries(&paths).unwrap();
        let managed_content = std::fs::read_to_string(&entries[0].path).unwrap();

        assert_eq!(result.migrated_blocks, 1);
        assert_eq!(entries.len(), 1);
        assert!(root.contains("ServerAliveInterval 30"));
        assert!(!root.contains("# keep this comment"));
        assert!(!root.contains("# and this one"));
        assert!(managed_content.starts_with("\n# keep this comment\n# and this one\nHost alpha\n"));
        assert!(managed_content.contains("HostName alpha.example.com"));
        assert_eq!(entries[0].raw_content, managed_content);
    }

    #[test]
    fn migrate_keeps_comments_before_match_in_root_config() {
        let paths = test_paths("migrate-comment-before-match");
        std::fs::create_dir_all(&paths.ssh_dir).unwrap();
        std::fs::write(
            &paths.root_config,
            "\
Host alpha
  HostName alpha.example.com

# comment for match
Match user ops
  PasswordAuthentication no
",
        )
        .unwrap();

        let result = migrate(&paths).unwrap();
        let root = std::fs::read_to_string(&paths.root_config).unwrap();
        let entries = crate::core::store::load_managed_entries(&paths).unwrap();
        let managed_content = std::fs::read_to_string(&entries[0].path).unwrap();

        assert_eq!(result.migrated_blocks, 1);
        assert!(root.contains("# comment for match"));
        assert!(root.contains("Match user ops"));
        assert!(!managed_content.contains("# comment for match"));
    }

    #[test]
    fn migrate_attaches_boundary_trivia_to_following_host_block() {
        let paths = test_paths("migrate-boundary-trivia-following-host");
        std::fs::create_dir_all(&paths.ssh_dir).unwrap();
        std::fs::write(
            &paths.root_config,
            "\
Host alpha
  HostName alpha.example.com

# belongs to beta
Host beta
  HostName beta.example.com
",
        )
        .unwrap();

        let result = migrate(&paths).unwrap();
        let entries = crate::core::store::load_managed_entries(&paths).unwrap();

        assert_eq!(result.migrated_blocks, 2);
        assert_eq!(entries.len(), 2);
        let alpha_content = std::fs::read_to_string(&entries[0].path).unwrap();
        let beta_content = std::fs::read_to_string(&entries[1].path).unwrap();

        assert!(!alpha_content.contains("# belongs to beta"));
        assert!(beta_content.starts_with("\n# belongs to beta\nHost beta\n"));
    }
}
