use std::path::PathBuf;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HostEntry {
    pub host_patterns: Vec<String>,
    pub hostname: Option<String>,
    pub user: Option<String>,
    pub port: Option<u16>,
    pub proxy_jump: Option<String>,
    pub identity_files: Vec<String>,
    pub local_forwards: Vec<String>,
    pub remote_forwards: Vec<String>,
    pub strict_host_key_checking: Option<String>,
    pub user_known_hosts_file: Option<String>,
    pub host_key_algorithms: Option<String>,
    pub pubkey_accepted_algorithms: Option<String>,
    pub forward_agent: Option<String>,
    pub tag: Option<String>,
    pub extra_options: Vec<(String, String)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    Host,
    Pattern,
}

impl EntryKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Host => "host",
            Self::Pattern => "pattern",
        }
    }
}

impl HostEntry {
    pub fn primary_pattern(&self) -> &str {
        self.host_patterns
            .first()
            .map(String::as_str)
            .unwrap_or_default()
    }

    pub fn kind(&self) -> EntryKind {
        if self.host_patterns.iter().any(|pattern| {
            pattern.contains('*') || pattern.contains('?') || pattern.starts_with('!')
        }) {
            EntryKind::Pattern
        } else {
            EntryKind::Host
        }
    }
}

#[derive(Debug, Clone)]
pub struct ManagedEntry {
    pub order: u16,
    pub slug: String,
    pub path: PathBuf,
    pub raw_content: String,
    pub entry: HostEntry,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectiveOrigin {
    pub order: u16,
    pub entry_kind: EntryKind,
    pub host_patterns: Vec<String>,
    pub path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedDirectiveSource {
    pub key: String,
    pub value: String,
    pub origin: DirectiveOrigin,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IgnoredScalarOverride {
    pub key: String,
    pub attempted_value: String,
    pub attempted_origin: DirectiveOrigin,
    pub winning_value: String,
    pub winning_origin: DirectiveOrigin,
}

#[derive(Debug, Clone)]
pub struct ResolvedEntry {
    pub target: String,
    pub matched_entries: Vec<ManagedEntry>,
    pub merged_entry: HostEntry,
    pub directive_sources: Vec<ResolvedDirectiveSource>,
    pub ignored_scalar_overrides: Vec<IgnoredScalarOverride>,
    pub root_match_notes: Vec<String>,
}
