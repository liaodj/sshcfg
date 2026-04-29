use std::collections::HashSet;

use crate::app::cli::MetadataFilterArgs;
use crate::core::model::ManagedEntry;
use crate::core::state::{AppState, EntryMetadata};

#[derive(Debug, Clone, Default)]
pub(crate) struct EntryFilter {
    query: Option<String>,
    tags: Vec<String>,
    has_note: bool,
    template: Option<String>,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct SelectedEntry<'a> {
    pub entry: &'a ManagedEntry,
    pub metadata: Option<&'a EntryMetadata>,
}

impl EntryFilter {
    pub(crate) fn from_args(args: &MetadataFilterArgs) -> Self {
        Self::from_parts(
            args.query.clone(),
            args.tags.clone(),
            args.has_note,
            args.template
                .map(|template| template.cli_name().to_string()),
        )
    }

    pub(crate) fn from_parts(
        query: Option<String>,
        tags: Vec<String>,
        has_note: bool,
        template: Option<String>,
    ) -> Self {
        Self {
            query: normalize_optional(query),
            tags: normalize_tags(tags),
            has_note,
            template: normalize_optional(template),
        }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.query.is_none() && self.tags.is_empty() && !self.has_note && self.template.is_none()
    }

    fn matches(&self, entry: &ManagedEntry, metadata: Option<&EntryMetadata>) -> bool {
        let query_match = self.query.as_ref().is_none_or(|query| {
            let host_match = entry
                .entry
                .host_patterns
                .iter()
                .any(|pattern| pattern.to_ascii_lowercase().contains(query));
            let hostname_match = entry
                .entry
                .hostname
                .as_ref()
                .is_some_and(|hostname| hostname.to_ascii_lowercase().contains(query));
            let tag_match = metadata.is_some_and(|item| {
                item.tags
                    .iter()
                    .any(|tag| tag.to_ascii_lowercase().contains(query))
            });
            let note_match = metadata
                .and_then(|item| item.note.as_ref())
                .is_some_and(|note| note.to_ascii_lowercase().contains(query));

            host_match || hostname_match || tag_match || note_match
        });

        let tag_match = self.tags.is_empty()
            || metadata.is_some_and(|item| {
                self.tags
                    .iter()
                    .all(|expected| item.tags.iter().any(|tag| tag == expected))
            });

        let note_match = !self.has_note
            || metadata
                .and_then(|item| item.note.as_ref())
                .is_some_and(|note| !note.trim().is_empty());

        let template_match = self.template.as_ref().is_none_or(|expected| {
            metadata
                .and_then(|item| item.template_source.as_deref())
                .is_some_and(|template| template.eq_ignore_ascii_case(expected))
        });

        query_match && tag_match && note_match && template_match
    }
}

fn normalize_optional(value: Option<String>) -> Option<String> {
    value
        .map(|value| value.trim().to_ascii_lowercase())
        .filter(|value| !value.is_empty())
}

fn normalize_tags(tags: Vec<String>) -> Vec<String> {
    let mut seen = HashSet::new();
    tags.into_iter()
        .map(|tag| tag.trim().to_ascii_lowercase())
        .filter(|tag| !tag.is_empty())
        .filter(|tag| seen.insert(tag.clone()))
        .collect()
}

pub(crate) fn filter_entries<'a>(
    entries: &'a [ManagedEntry],
    state: &'a AppState,
    filter: &EntryFilter,
) -> Vec<SelectedEntry<'a>> {
    filter_entry_indices(entries, state, filter)
        .into_iter()
        .map(|index| {
            let entry = &entries[index];
            let metadata = crate::core::state::find_entry_metadata(state, entry);
            SelectedEntry { entry, metadata }
        })
        .collect()
}

pub(crate) fn filter_entry_indices(
    entries: &[ManagedEntry],
    state: &AppState,
    filter: &EntryFilter,
) -> Vec<usize> {
    entries
        .iter()
        .enumerate()
        .filter_map(|entry| {
            let (index, entry) = entry;
            let metadata = crate::core::state::find_entry_metadata(state, entry);
            filter.matches(entry, metadata).then_some(index)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use crate::app::cli::MetadataFilterArgs;
    use crate::core::model::{HostEntry, ManagedEntry};
    use crate::core::state::{AppState, EntryMetadata};
    use crate::core::template::TemplateKind;

    use super::{EntryFilter, filter_entries};

    fn sample_entry(order: u16, host: &str, hostname: &str, file_name: &str) -> ManagedEntry {
        ManagedEntry {
            order,
            slug: host.to_string(),
            path: PathBuf::from(file_name),
            raw_content: String::new(),
            entry: HostEntry {
                host_patterns: vec![host.to_string()],
                hostname: Some(hostname.to_string()),
                ..HostEntry::default()
            },
        }
    }

    fn sample_metadata(
        id: &str,
        host: &str,
        order: u16,
        file_name: &str,
        template_source: Option<&str>,
        tags: &[&str],
        note: Option<&str>,
    ) -> EntryMetadata {
        EntryMetadata {
            id: id.to_string(),
            primary_pattern: host.to_string(),
            host_patterns: vec![host.to_string()],
            order,
            entry_kind: "host".to_string(),
            managed_filename: file_name.to_string(),
            template_source: template_source.map(ToString::to_string),
            tags: tags.iter().map(|tag| tag.to_string()).collect(),
            note: note.map(ToString::to_string),
            created_at: "2026-04-21T00:00:00Z".to_string(),
            updated_at: "2026-04-21T00:00:00Z".to_string(),
            target_os: None,
            remote_user_home: None,
            authorized_keys_path: None,
            ssh_dir_mode: None,
            authorized_keys_mode: None,
        }
    }

    #[test]
    fn query_matches_entry_and_metadata_fields() {
        let entries = vec![
            sample_entry(10, "alpha", "alpha.example.com", "010-host-alpha.conf"),
            sample_entry(20, "beta", "db.internal", "020-host-beta.conf"),
        ];
        let state = AppState {
            version: 1,
            entries: vec![
                sample_metadata(
                    "entry-alpha",
                    "alpha",
                    10,
                    "010-host-alpha.conf",
                    Some("legacy"),
                    &["prod"],
                    Some("important edge host"),
                ),
                sample_metadata(
                    "entry-beta",
                    "beta",
                    20,
                    "020-host-beta.conf",
                    Some("embedded"),
                    &["lab"],
                    None,
                ),
            ],
        };

        let query_filter = EntryFilter::from_args(&MetadataFilterArgs {
            query: Some("edge".to_string()),
            ..MetadataFilterArgs::default()
        });
        let query_matches = filter_entries(&entries, &state, &query_filter);
        assert_eq!(query_matches.len(), 1);
        assert_eq!(query_matches[0].entry.entry.primary_pattern(), "alpha");

        let hostname_filter = EntryFilter::from_args(&MetadataFilterArgs {
            query: Some("db.internal".to_string()),
            ..MetadataFilterArgs::default()
        });
        let hostname_matches = filter_entries(&entries, &state, &hostname_filter);
        assert_eq!(hostname_matches.len(), 1);
        assert_eq!(hostname_matches[0].entry.entry.primary_pattern(), "beta");
    }

    #[test]
    fn tag_note_and_template_filters_are_combined() {
        let entries = vec![
            sample_entry(10, "alpha", "alpha.example.com", "010-host-alpha.conf"),
            sample_entry(20, "beta", "beta.example.com", "020-host-beta.conf"),
        ];
        let state = AppState {
            version: 1,
            entries: vec![
                sample_metadata(
                    "entry-alpha",
                    "alpha",
                    10,
                    "010-host-alpha.conf",
                    Some("legacy"),
                    &["prod", "ops"],
                    Some("needs migration"),
                ),
                sample_metadata(
                    "entry-beta",
                    "beta",
                    20,
                    "020-host-beta.conf",
                    Some("embedded"),
                    &["prod"],
                    None,
                ),
            ],
        };

        let filter = EntryFilter::from_args(&MetadataFilterArgs {
            tags: vec!["prod".to_string(), "ops".to_string()],
            has_note: true,
            template: Some(TemplateKind::Legacy),
            ..MetadataFilterArgs::default()
        });
        let matches = filter_entries(&entries, &state, &filter);

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].entry.entry.primary_pattern(), "alpha");
    }

    #[test]
    fn from_parts_normalizes_query_tags_and_template() {
        let filter = EntryFilter::from_parts(
            Some("  Alpha  ".to_string()),
            vec![
                " Prod ".to_string(),
                "prod".to_string(),
                String::new(),
                "Ops".to_string(),
            ],
            true,
            Some(" Legacy ".to_string()),
        );

        assert_eq!(filter.query.as_deref(), Some("alpha"));
        assert_eq!(filter.tags, vec!["prod", "ops"]);
        assert!(filter.has_note);
        assert_eq!(filter.template.as_deref(), Some("legacy"));
    }
}
