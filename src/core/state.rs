use std::collections::HashSet;
use std::path::Path;

use anyhow::{Context, Result, bail};
use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::core::model::ManagedEntry;
use crate::core::template::TemplateKind;
use crate::fs::layout::AppPaths;
use crate::fs::writer;

pub const STATE_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppState {
    #[serde(default = "default_state_version")]
    pub version: u32,
    #[serde(default)]
    pub entries: Vec<EntryMetadata>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntryMetadata {
    pub id: String,
    pub primary_pattern: String,
    #[serde(default)]
    pub host_patterns: Vec<String>,
    pub order: u16,
    pub entry_kind: String,
    pub managed_filename: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub template_source: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_os: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_user_home: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorized_keys_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssh_dir_mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorized_keys_mode: Option<String>,
}

#[derive(Debug, Clone, Copy)]
pub struct StateSummary {
    pub metadata_entry_count: usize,
    pub missing_metadata_count: usize,
    pub stale_metadata_count: usize,
}

#[derive(Debug, Clone, Default)]
pub struct MetadataUpdate {
    pub template_source: Option<Option<String>>,
    pub tags: Option<Vec<String>>,
    pub note: Option<Option<String>>,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            version: STATE_VERSION,
            entries: Vec::new(),
        }
    }
}

pub fn load_state(paths: &AppPaths) -> Result<AppState> {
    if !paths.state_file.exists() {
        return Ok(AppState::default());
    }

    let content = std::fs::read_to_string(&paths.state_file)
        .with_context(|| format!("failed to read state file {}", paths.state_file.display()))?;
    if content.trim().is_empty() {
        return Ok(AppState::default());
    }

    let mut state: AppState = toml::from_str(&content)
        .with_context(|| format!("failed to parse state file {}", paths.state_file.display()))?;
    if state.version == 0 {
        state.version = STATE_VERSION;
    }
    Ok(state)
}

pub fn save_state(paths: &AppPaths, state: &AppState) -> Result<()> {
    let mut state = state.clone();
    state.version = STATE_VERSION;
    state.entries.sort_by(|left, right| {
        left.order
            .cmp(&right.order)
            .then_with(|| left.primary_pattern.cmp(&right.primary_pattern))
    });

    let content = toml::to_string_pretty(&state).context("failed to serialize state file")?;
    writer::write_text_file(&paths.state_file, &content)?;
    Ok(())
}

pub fn upsert_entry(
    paths: &AppPaths,
    saved: &ManagedEntry,
    previous: Option<&ManagedEntry>,
    update: MetadataUpdate,
) -> Result<EntryMetadata> {
    let mut state = load_state(paths)?;
    let now = now_string();
    let record_index = previous
        .and_then(|current| find_matching_index(&state.entries, current))
        .or_else(|| find_matching_index(&state.entries, saved));

    let metadata = if let Some(index) = record_index {
        let metadata = state
            .entries
            .get_mut(index)
            .context("metadata index disappeared during update")?;
        apply_entry(metadata, saved, update.clone(), &now, true)?;
        metadata.clone()
    } else {
        let metadata = new_entry_metadata(saved, update.clone(), &now)?;
        state.entries.push(metadata.clone());
        metadata
    };

    save_state(paths, &state)?;
    Ok(metadata)
}

pub fn remove_entries(paths: &AppPaths, targets: &[ManagedEntry]) -> Result<usize> {
    if targets.is_empty() {
        return Ok(0);
    }

    let mut state = load_state(paths)?;
    let original_len = state.entries.len();
    state.entries.retain(|metadata| {
        !targets
            .iter()
            .any(|target| metadata_matches_entry(metadata, target))
    });

    let removed = original_len.saturating_sub(state.entries.len());
    if removed == 0 {
        return Ok(0);
    }

    save_state(paths, &state)?;
    Ok(removed)
}

pub fn sync_entries(
    paths: &AppPaths,
    entries: &[ManagedEntry],
    update_timestamps: bool,
) -> Result<AppState> {
    let state = merge_entries(load_state(paths)?, entries, update_timestamps)?;
    save_state(paths, &state)?;
    Ok(state)
}

pub fn summarize_state(state: &AppState, entries: &[ManagedEntry]) -> StateSummary {
    let mut matched_metadata = HashSet::new();
    let mut missing_metadata_count = 0;

    for entry in entries {
        if let Some(index) = find_matching_index(&state.entries, entry) {
            matched_metadata.insert(index);
        } else {
            missing_metadata_count += 1;
        }
    }

    StateSummary {
        metadata_entry_count: state.entries.len(),
        missing_metadata_count,
        stale_metadata_count: state.entries.len().saturating_sub(matched_metadata.len()),
    }
}

pub fn find_entry_metadata<'a>(
    state: &'a AppState,
    entry: &ManagedEntry,
) -> Option<&'a EntryMetadata> {
    state
        .entries
        .iter()
        .find(|metadata| metadata_matches_entry(metadata, entry))
}

pub fn find_metadata_by_host<'a>(state: &'a AppState, host: &str) -> Option<&'a EntryMetadata> {
    state.entries.iter().find(|metadata| {
        metadata.primary_pattern == host
            || metadata.host_patterns.iter().any(|pattern| pattern == host)
    })
}

pub fn update_metadata_by_host(
    paths: &AppPaths,
    host: &str,
    updater: impl FnOnce(&mut EntryMetadata) -> Result<()>,
) -> Result<EntryMetadata> {
    let mut state = load_state(paths)?;
    let metadata = state
        .entries
        .iter_mut()
        .find(|metadata| {
            metadata.primary_pattern == host
                || metadata.host_patterns.iter().any(|pattern| pattern == host)
        })
        .with_context(|| format!("metadata for managed entry `{host}` not found"))?;

    updater(metadata)?;
    metadata.updated_at = now_string();
    let updated = metadata.clone();
    save_state(paths, &state)?;
    Ok(updated)
}

pub fn update_metadata_by_ids(
    paths: &AppPaths,
    ids: &[String],
    mut updater: impl FnMut(&mut EntryMetadata) -> Result<()>,
) -> Result<Vec<EntryMetadata>> {
    if ids.is_empty() {
        return Ok(Vec::new());
    }

    let mut state = load_state(paths)?;
    let wanted: HashSet<_> = ids.iter().map(String::as_str).collect();
    let now = now_string();
    let mut updated = Vec::new();

    for metadata in &mut state.entries {
        if wanted.contains(metadata.id.as_str()) {
            updater(metadata)?;
            metadata.updated_at = now.clone();
            updated.push(metadata.clone());
        }
    }

    if updated.len() != wanted.len() {
        bail!(
            "failed to update all selected metadata records (matched {}, expected {})",
            updated.len(),
            wanted.len()
        );
    }

    save_state(paths, &state)?;
    Ok(updated)
}

fn merge_entries(
    mut state: AppState,
    entries: &[ManagedEntry],
    update_timestamps: bool,
) -> Result<AppState> {
    let now = now_string();
    let mut remaining = std::mem::take(&mut state.entries);
    let mut merged = Vec::with_capacity(entries.len());

    for entry in entries {
        if let Some(index) = find_matching_index(&remaining, entry) {
            let mut metadata = remaining.remove(index);
            apply_entry(
                &mut metadata,
                entry,
                MetadataUpdate::default(),
                &now,
                update_timestamps,
            )?;
            merged.push(metadata);
        } else {
            merged.push(new_entry_metadata(entry, MetadataUpdate::default(), &now)?);
        }
    }

    state.entries = merged;
    Ok(state)
}

pub fn metadata_update_for_create(
    template: Option<TemplateKind>,
    tags: Vec<String>,
    note: Option<String>,
) -> MetadataUpdate {
    MetadataUpdate {
        template_source: template.map(|value| Some(value.cli_name().to_string())),
        tags: Some(normalize_tags(tags)),
        note: Some(normalize_note(note)),
    }
}

pub fn metadata_update_for_edit(
    template: Option<Option<TemplateKind>>,
    tags: Option<Vec<String>>,
    note: Option<Option<String>>,
) -> MetadataUpdate {
    MetadataUpdate {
        template_source: template.map(|value| value.map(|kind| kind.cli_name().to_string())),
        tags: tags.map(normalize_tags),
        note: note.map(normalize_note),
    }
}

fn apply_entry(
    metadata: &mut EntryMetadata,
    entry: &ManagedEntry,
    update: MetadataUpdate,
    now: &str,
    update_timestamp: bool,
) -> Result<()> {
    metadata.primary_pattern = entry.entry.primary_pattern().to_string();
    metadata.host_patterns = entry.entry.host_patterns.clone();
    metadata.order = entry.order;
    metadata.entry_kind = entry.entry.kind().label().to_string();
    metadata.managed_filename = managed_filename(&entry.path)?;
    if let Some(template_source) = update.template_source {
        metadata.template_source = template_source;
    }
    if let Some(tags) = update.tags {
        metadata.tags = tags;
    }
    if let Some(note) = update.note {
        metadata.note = note;
    }
    if update_timestamp {
        metadata.updated_at = now.to_string();
    }
    Ok(())
}

fn new_entry_metadata(
    entry: &ManagedEntry,
    update: MetadataUpdate,
    now: &str,
) -> Result<EntryMetadata> {
    let primary_pattern = entry.entry.primary_pattern().to_string();
    Ok(EntryMetadata {
        id: generate_id(entry.entry.primary_pattern()),
        primary_pattern,
        host_patterns: entry.entry.host_patterns.clone(),
        order: entry.order,
        entry_kind: entry.entry.kind().label().to_string(),
        managed_filename: managed_filename(&entry.path)?,
        template_source: update.template_source.unwrap_or(None),
        tags: update.tags.unwrap_or_default(),
        note: update.note.unwrap_or(None),
        created_at: now.to_string(),
        updated_at: now.to_string(),
        target_os: None,
        remote_user_home: None,
        authorized_keys_path: None,
        ssh_dir_mode: None,
        authorized_keys_mode: None,
    })
}

fn find_matching_index(entries: &[EntryMetadata], target: &ManagedEntry) -> Option<usize> {
    entries
        .iter()
        .position(|metadata| metadata_matches_entry(metadata, target))
}

fn metadata_matches_entry(metadata: &EntryMetadata, target: &ManagedEntry) -> bool {
    let file_name = target
        .path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or_default();

    metadata.managed_filename == file_name
        || metadata.primary_pattern == target.entry.primary_pattern()
        || metadata.host_patterns == target.entry.host_patterns
}

fn managed_filename(path: &Path) -> Result<String> {
    path.file_name()
        .and_then(|value| value.to_str())
        .map(ToString::to_string)
        .with_context(|| format!("invalid managed entry file name {}", path.display()))
}

fn default_state_version() -> u32 {
    STATE_VERSION
}

fn generate_id(primary_pattern: &str) -> String {
    format!(
        "entry-{}-{}-{}",
        sanitize_id_fragment(primary_pattern),
        std::process::id(),
        Utc::now().timestamp_nanos_opt().unwrap_or_default()
    )
}

fn sanitize_id_fragment(value: &str) -> String {
    let mut sanitized = String::new();
    let mut last_dash = false;

    for ch in value.chars() {
        let normalized = match ch {
            'a'..='z' | '0'..='9' => Some(ch),
            'A'..='Z' => Some(ch.to_ascii_lowercase()),
            _ => None,
        };

        if let Some(ch) = normalized {
            sanitized.push(ch);
            last_dash = false;
        } else if !last_dash {
            sanitized.push('-');
            last_dash = true;
        }
    }

    let sanitized = sanitized.trim_matches('-');
    if sanitized.is_empty() {
        "entry".to_string()
    } else {
        sanitized.to_string()
    }
}

fn now_string() -> String {
    Utc::now().to_rfc3339()
}

fn normalize_tags(tags: Vec<String>) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut normalized = Vec::new();

    for tag in tags {
        let trimmed = tag.trim();
        if trimmed.is_empty() {
            continue;
        }

        let normalized_tag = trimmed.to_ascii_lowercase();
        if seen.insert(normalized_tag.clone()) {
            normalized.push(normalized_tag);
        }
    }

    normalized
}

fn normalize_note(note: Option<String>) -> Option<String> {
    note.and_then(|value| {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    })
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use chrono::Utc;

    use crate::core::model::{HostEntry, ManagedEntry};
    use crate::core::template::TemplateKind;
    use crate::fs::layout::AppPaths;

    use super::{
        MetadataUpdate, find_entry_metadata, find_metadata_by_host, load_state,
        metadata_update_for_create, metadata_update_for_edit, remove_entries, summarize_state,
        sync_entries, update_metadata_by_host, update_metadata_by_ids, upsert_entry,
    };

    fn test_paths(name: &str) -> AppPaths {
        let root = std::env::current_dir()
            .unwrap()
            .join("target")
            .join("test-state")
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

    fn sample_entry(order: u16, host: &str, file_name: &str) -> ManagedEntry {
        ManagedEntry {
            order,
            slug: host.to_string(),
            path: PathBuf::from(file_name),
            raw_content: String::new(),
            entry: HostEntry {
                host_patterns: vec![host.to_string()],
                hostname: Some(format!("{host}.example.com")),
                ..HostEntry::default()
            },
        }
    }

    #[test]
    fn preserves_metadata_id_across_host_rename() {
        let paths = test_paths("rename");
        paths.ensure_base_dirs().unwrap();

        let original = sample_entry(10, "alpha", "010-host-alpha.conf");
        let created = upsert_entry(
            &paths,
            &original,
            None,
            metadata_update_for_create(
                Some(TemplateKind::Legacy),
                vec!["Prod".to_string()],
                Some("important".to_string()),
            ),
        )
        .unwrap();

        let renamed = sample_entry(20, "beta", "020-host-beta.conf");
        let updated = upsert_entry(
            &paths,
            &renamed,
            Some(&original),
            metadata_update_for_edit(None, None, None),
        )
        .unwrap();

        assert_eq!(created.id, updated.id);
        assert_eq!(updated.primary_pattern, "beta");
        assert_eq!(updated.template_source.as_deref(), Some("legacy"));
        assert_eq!(updated.tags, vec!["prod"]);
        assert_eq!(updated.note.as_deref(), Some("important"));
    }

    #[test]
    fn sync_entries_removes_stale_metadata() {
        let paths = test_paths("sync");
        paths.ensure_base_dirs().unwrap();

        let alpha = sample_entry(10, "alpha", "010-host-alpha.conf");
        let beta = sample_entry(20, "beta", "020-host-beta.conf");
        upsert_entry(&paths, &alpha, None, MetadataUpdate::default()).unwrap();
        upsert_entry(&paths, &beta, None, MetadataUpdate::default()).unwrap();

        let state = sync_entries(&paths, std::slice::from_ref(&beta), true).unwrap();
        let summary = summarize_state(&state, std::slice::from_ref(&beta));

        assert_eq!(state.entries.len(), 1);
        assert_eq!(summary.metadata_entry_count, 1);
        assert_eq!(summary.missing_metadata_count, 0);
        assert_eq!(summary.stale_metadata_count, 0);
        assert!(find_entry_metadata(&state, &beta).is_some());
        assert!(find_entry_metadata(&state, &alpha).is_none());
    }

    #[test]
    fn remove_entries_can_delete_single_metadata_record() {
        let paths = test_paths("remove");
        paths.ensure_base_dirs().unwrap();

        let alpha = sample_entry(10, "alpha", "010-host-alpha.conf");
        upsert_entry(&paths, &alpha, None, MetadataUpdate::default()).unwrap();

        assert_eq!(
            remove_entries(&paths, std::slice::from_ref(&alpha)).unwrap(),
            1
        );
        assert!(load_state(&paths).unwrap().entries.is_empty());
    }

    #[test]
    fn remove_entries_deletes_multiple_metadata_records() {
        let paths = test_paths("remove-many");
        paths.ensure_base_dirs().unwrap();

        let alpha = sample_entry(10, "alpha", "010-host-alpha.conf");
        let beta = sample_entry(20, "beta", "020-host-beta.conf");
        upsert_entry(&paths, &alpha, None, MetadataUpdate::default()).unwrap();
        upsert_entry(&paths, &beta, None, MetadataUpdate::default()).unwrap();

        let removed = remove_entries(&paths, &[alpha.clone(), beta.clone()]).unwrap();

        assert_eq!(removed, 2);
        assert!(load_state(&paths).unwrap().entries.is_empty());
    }

    #[test]
    fn edit_update_can_replace_tags_and_clear_note() {
        let paths = test_paths("edit-metadata");
        paths.ensure_base_dirs().unwrap();

        let alpha = sample_entry(10, "alpha", "010-host-alpha.conf");
        upsert_entry(
            &paths,
            &alpha,
            None,
            metadata_update_for_create(None, vec!["prod".to_string()], Some("initial".to_string())),
        )
        .unwrap();

        let updated = upsert_entry(
            &paths,
            &alpha,
            Some(&alpha),
            metadata_update_for_edit(
                Some(Some(TemplateKind::Embedded)),
                Some(vec![
                    "Ops".to_string(),
                    "ops".to_string(),
                    "edge".to_string(),
                ]),
                Some(None),
            ),
        )
        .unwrap();

        assert_eq!(updated.tags, vec!["ops", "edge"]);
        assert_eq!(updated.note, None);
        assert_eq!(updated.template_source.as_deref(), Some("embedded"));
    }

    #[test]
    fn edit_update_can_clear_template_source() {
        let paths = test_paths("edit-clear-template");
        paths.ensure_base_dirs().unwrap();

        let alpha = sample_entry(10, "alpha", "010-host-alpha.conf");
        upsert_entry(
            &paths,
            &alpha,
            None,
            metadata_update_for_create(Some(TemplateKind::Legacy), Vec::new(), None),
        )
        .unwrap();

        let updated = upsert_entry(
            &paths,
            &alpha,
            Some(&alpha),
            metadata_update_for_edit(Some(None), None, None),
        )
        .unwrap();

        assert_eq!(updated.template_source, None);
    }

    #[test]
    fn find_metadata_by_host_matches_aliases() {
        let paths = test_paths("find-host");
        paths.ensure_base_dirs().unwrap();

        let mut alpha = sample_entry(10, "alpha", "010-host-alpha.conf");
        alpha.entry.host_patterns = vec!["alpha".to_string(), "alpha-alt".to_string()];
        upsert_entry(
            &paths,
            &alpha,
            None,
            metadata_update_for_create(None, vec!["lab".to_string()], None),
        )
        .unwrap();

        let state = load_state(&paths).unwrap();
        let found = find_metadata_by_host(&state, "alpha-alt").unwrap();
        assert_eq!(found.primary_pattern, "alpha");
    }

    #[test]
    fn update_metadata_by_host_can_mutate_note_and_tags() {
        let paths = test_paths("update-host");
        paths.ensure_base_dirs().unwrap();

        let alpha = sample_entry(10, "alpha", "010-host-alpha.conf");
        upsert_entry(
            &paths,
            &alpha,
            None,
            metadata_update_for_create(None, vec!["lab".to_string()], None),
        )
        .unwrap();

        let updated = update_metadata_by_host(&paths, "alpha", |metadata| {
            metadata.tags.push("ops".to_string());
            metadata.tags.sort();
            metadata.note = Some("managed".to_string());
            Ok(())
        })
        .unwrap();

        assert_eq!(updated.tags, vec!["lab", "ops"]);
        assert_eq!(updated.note.as_deref(), Some("managed"));
    }

    #[test]
    fn update_metadata_by_ids_mutates_multiple_records() {
        let paths = test_paths("update-ids");
        paths.ensure_base_dirs().unwrap();

        let alpha = sample_entry(10, "alpha", "010-host-alpha.conf");
        let beta = sample_entry(20, "beta", "020-host-beta.conf");
        let alpha_metadata = upsert_entry(
            &paths,
            &alpha,
            None,
            metadata_update_for_create(None, vec!["prod".to_string()], None),
        )
        .unwrap();
        let beta_metadata = upsert_entry(
            &paths,
            &beta,
            None,
            metadata_update_for_create(None, vec!["lab".to_string()], None),
        )
        .unwrap();

        let updated = update_metadata_by_ids(
            &paths,
            &[alpha_metadata.id.clone(), beta_metadata.id.clone()],
            |metadata| {
                metadata.note = Some("bulk-updated".to_string());
                Ok(())
            },
        )
        .unwrap();

        assert_eq!(updated.len(), 2);
        assert!(
            updated
                .iter()
                .all(|metadata| metadata.note.as_deref() == Some("bulk-updated"))
        );
    }

    #[test]
    fn update_metadata_by_ids_errors_for_missing_records() {
        let paths = test_paths("update-ids-missing");
        paths.ensure_base_dirs().unwrap();

        let alpha = sample_entry(10, "alpha", "010-host-alpha.conf");
        let alpha_metadata = upsert_entry(&paths, &alpha, None, MetadataUpdate::default()).unwrap();

        let err = update_metadata_by_ids(
            &paths,
            &[alpha_metadata.id, "missing".to_string()],
            |_metadata| Ok(()),
        )
        .unwrap_err();

        assert!(
            err.to_string()
                .contains("failed to update all selected metadata")
        );
    }
}
