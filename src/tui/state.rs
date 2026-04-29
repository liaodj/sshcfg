use anyhow::{Context, Result, bail};

use crate::app::cli::{AddArgs, EditArgs};
use crate::app::commands::add::create_managed_entry;
use crate::app::commands::delete::delete_managed_entries;
use crate::app::commands::doctor;
use crate::app::commands::edit::edit_managed_entry;
use crate::app::commands::order::{apply_reordered_entries, sequence_signature};
use crate::app::commands::selection::{EntryFilter, filter_entry_indices};
use crate::app::commands::validate;
use crate::core::model::ManagedEntry;
use crate::core::resolve;
use crate::core::root_config;
use crate::core::state::{self as metadata, AppState as MetadataState, EntryMetadata};
use crate::core::store;
use crate::core::template::{self, TemplateKind};
use crate::fs::backup;
use crate::fs::layout::AppPaths;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputMode {
    Normal,
    Search,
    Filter,
    Inspect,
    BackupCatalog,
    ConfirmDelete,
    ConfirmRestore,
    Edit,
    Reorder,
}

impl InputMode {
    pub fn label(self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::Search => "search",
            Self::Filter => "filter",
            Self::Inspect => "inspect",
            Self::BackupCatalog => "backups",
            Self::ConfirmDelete => "confirm-delete",
            Self::ConfirmRestore => "confirm-restore",
            Self::Edit => "edit",
            Self::Reorder => "reorder",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetailMode {
    Raw,
    Merged,
}

impl DetailMode {
    pub fn toggle(&mut self) {
        *self = match self {
            Self::Raw => Self::Merged,
            Self::Merged => Self::Raw,
        };
    }

    pub fn title(self) -> &'static str {
        match self {
            Self::Raw => "Raw File",
            Self::Merged => "Merged Preview",
        }
    }

    pub fn short_label(self) -> &'static str {
        match self {
            Self::Raw => "raw",
            Self::Merged => "merged",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaneFocus {
    HostList,
    Detail,
}

impl PaneFocus {
    pub fn label(self) -> &'static str {
        match self {
            Self::HostList => "hosts",
            Self::Detail => "detail",
        }
    }

    fn toggle(&mut self) {
        *self = match self {
            Self::HostList => Self::Detail,
            Self::Detail => Self::HostList,
        };
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormMode {
    Create,
    Edit,
}

impl FormMode {
    pub fn title(self) -> &'static str {
        match self {
            Self::Create => "Create Entry",
            Self::Edit => "Edit Entry",
        }
    }

    pub fn verb(self) -> &'static str {
        match self {
            Self::Create => "Created",
            Self::Edit => "Saved",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormField {
    Host,
    HostName,
    User,
    Port,
    ProxyJump,
    IdentityFiles,
    LocalForwards,
    RemoteForwards,
    StrictHostKeyChecking,
    UserKnownHostsFile,
    HostKeyAlgorithms,
    PubkeyAcceptedAlgorithms,
    ForwardAgent,
    SshTag,
    Tags,
    Note,
    Template,
}

impl FormField {
    pub fn label(self) -> &'static str {
        match self {
            Self::Host => "Host",
            Self::HostName => "HostName",
            Self::User => "User",
            Self::Port => "Port",
            Self::ProxyJump => "ProxyJump",
            Self::IdentityFiles => "IdentityFile(s)",
            Self::LocalForwards => "LocalForward(s)",
            Self::RemoteForwards => "RemoteForward(s)",
            Self::StrictHostKeyChecking => "StrictHostKeyChecking",
            Self::UserKnownHostsFile => "UserKnownHostsFile",
            Self::HostKeyAlgorithms => "HostKeyAlgorithms",
            Self::PubkeyAcceptedAlgorithms => "PubkeyAcceptedAlgorithms",
            Self::ForwardAgent => "ForwardAgent",
            Self::SshTag => "SSH Tag",
            Self::Tags => "Tags",
            Self::Note => "Note",
            Self::Template => "Template",
        }
    }

    fn next(self) -> Self {
        match self {
            Self::Host => Self::HostName,
            Self::HostName => Self::User,
            Self::User => Self::Port,
            Self::Port => Self::ProxyJump,
            Self::ProxyJump => Self::IdentityFiles,
            Self::IdentityFiles => Self::LocalForwards,
            Self::LocalForwards => Self::RemoteForwards,
            Self::RemoteForwards => Self::StrictHostKeyChecking,
            Self::StrictHostKeyChecking => Self::UserKnownHostsFile,
            Self::UserKnownHostsFile => Self::HostKeyAlgorithms,
            Self::HostKeyAlgorithms => Self::PubkeyAcceptedAlgorithms,
            Self::PubkeyAcceptedAlgorithms => Self::ForwardAgent,
            Self::ForwardAgent => Self::SshTag,
            Self::SshTag => Self::Tags,
            Self::Tags => Self::Note,
            Self::Note => Self::Template,
            Self::Template => Self::Host,
        }
    }

    fn previous(self) -> Self {
        match self {
            Self::Host => Self::Template,
            Self::HostName => Self::Host,
            Self::User => Self::HostName,
            Self::Port => Self::User,
            Self::ProxyJump => Self::Port,
            Self::IdentityFiles => Self::ProxyJump,
            Self::LocalForwards => Self::IdentityFiles,
            Self::RemoteForwards => Self::LocalForwards,
            Self::StrictHostKeyChecking => Self::RemoteForwards,
            Self::UserKnownHostsFile => Self::StrictHostKeyChecking,
            Self::HostKeyAlgorithms => Self::UserKnownHostsFile,
            Self::PubkeyAcceptedAlgorithms => Self::HostKeyAlgorithms,
            Self::ForwardAgent => Self::PubkeyAcceptedAlgorithms,
            Self::SshTag => Self::ForwardAgent,
            Self::Tags => Self::SshTag,
            Self::Note => Self::Tags,
            Self::Template => Self::Note,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterField {
    Query,
    Tags,
    HasNote,
    Template,
}

impl FilterField {
    pub fn label(self) -> &'static str {
        match self {
            Self::Query => "Query",
            Self::Tags => "Tags",
            Self::HasNote => "HasNote",
            Self::Template => "Template",
        }
    }

    pub fn all() -> [Self; 4] {
        [Self::Query, Self::Tags, Self::HasNote, Self::Template]
    }

    fn next(self) -> Self {
        match self {
            Self::Query => Self::Tags,
            Self::Tags => Self::HasNote,
            Self::HasNote => Self::Template,
            Self::Template => Self::Query,
        }
    }

    fn previous(self) -> Self {
        match self {
            Self::Query => Self::Template,
            Self::Tags => Self::Query,
            Self::HasNote => Self::Tags,
            Self::Template => Self::HasNote,
        }
    }
}

#[derive(Debug, Clone)]
pub struct FilterForm {
    query: String,
    tags: String,
    has_note: bool,
    template: String,
    active_field: FilterField,
}

impl FilterForm {
    fn new(query: &str, tags: &str, has_note: bool, template: &str) -> Self {
        Self {
            query: query.to_string(),
            tags: tags.to_string(),
            has_note,
            template: template.to_string(),
            active_field: FilterField::Query,
        }
    }

    pub fn active_field(&self) -> FilterField {
        self.active_field
    }

    pub fn next_field(&mut self) {
        self.active_field = self.active_field.next();
    }

    pub fn previous_field(&mut self) {
        self.active_field = self.active_field.previous();
    }

    pub fn display_value(&self, field: FilterField) -> String {
        match field {
            FilterField::Query => display_filter_value(&self.query, "<any>"),
            FilterField::Tags => display_filter_value(&self.tags, "<any>"),
            FilterField::HasNote => {
                if self.has_note {
                    "yes".to_string()
                } else {
                    "no".to_string()
                }
            }
            FilterField::Template => display_filter_value(&self.template, "<any>"),
        }
    }

    pub fn push_char(&mut self, ch: char) {
        if let Some(value) = self.active_value_mut() {
            value.push(ch);
        }
    }

    pub fn backspace(&mut self) {
        if let Some(value) = self.active_value_mut() {
            value.pop();
        }
    }

    pub fn clear_active_field(&mut self) {
        match self.active_field {
            FilterField::Query | FilterField::Tags | FilterField::Template => {
                if let Some(value) = self.active_value_mut() {
                    value.clear();
                }
            }
            FilterField::HasNote => self.has_note = false,
        }
    }

    pub fn toggle_has_note(&mut self) {
        if matches!(self.active_field, FilterField::HasNote) {
            self.has_note = !self.has_note;
        }
    }

    pub fn cycle_template_next(&mut self) {
        if matches!(self.active_field, FilterField::Template) {
            self.template = next_template_name(&self.template, true);
        }
    }

    pub fn cycle_template_previous(&mut self) {
        if matches!(self.active_field, FilterField::Template) {
            self.template = next_template_name(&self.template, false);
        }
    }

    fn into_parts(self) -> (String, String, bool, String) {
        (self.query, self.tags, self.has_note, self.template)
    }

    fn active_value_mut(&mut self) -> Option<&mut String> {
        match self.active_field {
            FilterField::Query => Some(&mut self.query),
            FilterField::Tags => Some(&mut self.tags),
            FilterField::HasNote => None,
            FilterField::Template => Some(&mut self.template),
        }
    }
}

#[derive(Debug, Clone)]
pub struct EntryForm {
    mode: FormMode,
    original_host: Option<String>,
    original_host_label: String,
    host: String,
    hostname: String,
    user: String,
    port: String,
    proxy_jump: String,
    identity_files: String,
    local_forwards: String,
    remote_forwards: String,
    strict_host_key_checking: String,
    user_known_hosts_file: String,
    host_key_algorithms: String,
    pubkey_accepted_algorithms: String,
    forward_agent: String,
    ssh_tag: String,
    tags: String,
    note: String,
    template: String,
    active_field: FormField,
}

impl EntryForm {
    fn new_create() -> Self {
        Self {
            mode: FormMode::Create,
            original_host: None,
            original_host_label: "<new>".to_string(),
            host: String::new(),
            hostname: String::new(),
            user: String::new(),
            port: String::new(),
            proxy_jump: String::new(),
            identity_files: String::new(),
            local_forwards: String::new(),
            remote_forwards: String::new(),
            strict_host_key_checking: String::new(),
            user_known_hosts_file: String::new(),
            host_key_algorithms: String::new(),
            pubkey_accepted_algorithms: String::new(),
            forward_agent: String::new(),
            ssh_tag: String::new(),
            tags: String::new(),
            note: String::new(),
            template: String::new(),
            active_field: FormField::Host,
        }
    }

    fn from_entry(entry: &ManagedEntry, metadata: Option<&EntryMetadata>) -> Self {
        Self {
            mode: FormMode::Edit,
            original_host: Some(entry.entry.primary_pattern().to_string()),
            original_host_label: entry.entry.host_patterns.join(","),
            host: entry.entry.primary_pattern().to_string(),
            hostname: entry.entry.hostname.clone().unwrap_or_default(),
            user: entry.entry.user.clone().unwrap_or_default(),
            port: entry
                .entry
                .port
                .map(|value| value.to_string())
                .unwrap_or_default(),
            proxy_jump: entry.entry.proxy_jump.clone().unwrap_or_default(),
            identity_files: entry.entry.identity_files.join("; "),
            local_forwards: entry.entry.local_forwards.join("; "),
            remote_forwards: entry.entry.remote_forwards.join("; "),
            strict_host_key_checking: entry
                .entry
                .strict_host_key_checking
                .clone()
                .unwrap_or_default(),
            user_known_hosts_file: entry
                .entry
                .user_known_hosts_file
                .clone()
                .unwrap_or_default(),
            host_key_algorithms: entry.entry.host_key_algorithms.clone().unwrap_or_default(),
            pubkey_accepted_algorithms: entry
                .entry
                .pubkey_accepted_algorithms
                .clone()
                .unwrap_or_default(),
            forward_agent: entry.entry.forward_agent.clone().unwrap_or_default(),
            ssh_tag: entry.entry.tag.clone().unwrap_or_default(),
            tags: metadata
                .map(|metadata| metadata.tags.join(","))
                .unwrap_or_default(),
            note: metadata
                .and_then(|metadata| metadata.note.clone())
                .unwrap_or_default(),
            template: metadata
                .and_then(|metadata| metadata.template_source.clone())
                .unwrap_or_default(),
            active_field: FormField::Host,
        }
    }

    pub fn mode(&self) -> FormMode {
        self.mode
    }

    pub fn original_host(&self) -> Option<&str> {
        self.original_host.as_deref()
    }

    pub fn original_host_label(&self) -> &str {
        &self.original_host_label
    }

    pub fn active_field(&self) -> FormField {
        self.active_field
    }

    pub fn next_field(&mut self) {
        self.active_field = self.active_field.next();
    }

    pub fn previous_field(&mut self) {
        self.active_field = self.active_field.previous();
    }

    pub fn fields(&self) -> [(FormField, &str); 17] {
        [
            (FormField::Host, &self.host),
            (FormField::HostName, &self.hostname),
            (FormField::User, &self.user),
            (FormField::Port, &self.port),
            (FormField::ProxyJump, &self.proxy_jump),
            (FormField::IdentityFiles, &self.identity_files),
            (FormField::LocalForwards, &self.local_forwards),
            (FormField::RemoteForwards, &self.remote_forwards),
            (
                FormField::StrictHostKeyChecking,
                &self.strict_host_key_checking,
            ),
            (FormField::UserKnownHostsFile, &self.user_known_hosts_file),
            (FormField::HostKeyAlgorithms, &self.host_key_algorithms),
            (
                FormField::PubkeyAcceptedAlgorithms,
                &self.pubkey_accepted_algorithms,
            ),
            (FormField::ForwardAgent, &self.forward_agent),
            (FormField::SshTag, &self.ssh_tag),
            (FormField::Tags, &self.tags),
            (FormField::Note, &self.note),
            (FormField::Template, &self.template),
        ]
    }

    pub fn push_char(&mut self, ch: char) {
        self.active_value_mut().push(ch);
    }

    pub fn backspace(&mut self) {
        self.active_value_mut().pop();
    }

    pub fn clear_active_field(&mut self) {
        self.active_value_mut().clear();
    }

    pub fn cycle_template_next(&mut self) {
        self.template = next_template_name(&self.template, true);
    }

    pub fn cycle_template_previous(&mut self) {
        self.template = next_template_name(&self.template, false);
    }

    pub fn build_add_args(&self) -> Result<AddArgs> {
        let host = self.host.trim();
        if host.is_empty() {
            bail!("Host cannot be empty");
        }

        Ok(AddArgs {
            host: host.to_string(),
            interactive: false,
            hostname: trim_to_option(&self.hostname),
            user: trim_to_option(&self.user),
            port: parse_port(&self.port)?,
            proxy_jump: trim_to_option(&self.proxy_jump),
            identity_files: split_multi_value(&self.identity_files),
            local_forwards: split_multi_value(&self.local_forwards),
            remote_forwards: split_multi_value(&self.remote_forwards),
            strict_host_key_checking: trim_to_option(&self.strict_host_key_checking),
            user_known_hosts_file: trim_to_option(&self.user_known_hosts_file),
            host_key_algorithms: trim_to_option(&self.host_key_algorithms),
            pubkey_accepted_algorithms: trim_to_option(&self.pubkey_accepted_algorithms),
            forward_agent: trim_to_option(&self.forward_agent),
            ssh_tag: trim_to_option(&self.ssh_tag),
            template: parse_template(&self.template)?,
            order: None,
            extras: Vec::new(),
            tags: split_multi_value(&self.tags),
            note: trim_to_option(&self.note),
        })
    }

    pub fn build_edit_args(&self) -> Result<EditArgs> {
        let original_host = self
            .original_host
            .as_ref()
            .context("edit form is missing the original host")?;
        let host = self.host.trim();
        if host.is_empty() {
            bail!("Host cannot be empty");
        }

        Ok(EditArgs {
            host: original_host.clone(),
            interactive: false,
            new_host: (host != original_host).then(|| host.to_string()),
            hostname: trim_to_option(&self.hostname),
            clear_hostname: self.hostname.trim().is_empty(),
            user: trim_to_option(&self.user),
            clear_user: self.user.trim().is_empty(),
            port: parse_port(&self.port)?,
            clear_port: self.port.trim().is_empty(),
            proxy_jump: trim_to_option(&self.proxy_jump),
            clear_proxy_jump: self.proxy_jump.trim().is_empty(),
            identity_files: split_multi_value(&self.identity_files),
            clear_identity_files: self.identity_files.trim().is_empty(),
            local_forwards: split_multi_value(&self.local_forwards),
            clear_local_forwards: self.local_forwards.trim().is_empty(),
            remote_forwards: split_multi_value(&self.remote_forwards),
            clear_remote_forwards: self.remote_forwards.trim().is_empty(),
            strict_host_key_checking: trim_to_option(&self.strict_host_key_checking),
            clear_strict_host_key_checking: self.strict_host_key_checking.trim().is_empty(),
            user_known_hosts_file: trim_to_option(&self.user_known_hosts_file),
            clear_user_known_hosts_file: self.user_known_hosts_file.trim().is_empty(),
            host_key_algorithms: trim_to_option(&self.host_key_algorithms),
            clear_host_key_algorithms: self.host_key_algorithms.trim().is_empty(),
            pubkey_accepted_algorithms: trim_to_option(&self.pubkey_accepted_algorithms),
            clear_pubkey_accepted_algorithms: self.pubkey_accepted_algorithms.trim().is_empty(),
            forward_agent: trim_to_option(&self.forward_agent),
            clear_forward_agent: self.forward_agent.trim().is_empty(),
            ssh_tag: trim_to_option(&self.ssh_tag),
            clear_ssh_tag: self.ssh_tag.trim().is_empty(),
            template: parse_template(&self.template)?,
            clear_template: self.template.trim().is_empty(),
            order: None,
            extras: Vec::new(),
            clear_extras: false,
            tags: split_multi_value(&self.tags),
            clear_tags: self.tags.trim().is_empty(),
            note: trim_to_option(&self.note),
            clear_note: self.note.trim().is_empty(),
        })
    }

    fn active_value_mut(&mut self) -> &mut String {
        match self.active_field {
            FormField::Host => &mut self.host,
            FormField::HostName => &mut self.hostname,
            FormField::User => &mut self.user,
            FormField::Port => &mut self.port,
            FormField::ProxyJump => &mut self.proxy_jump,
            FormField::IdentityFiles => &mut self.identity_files,
            FormField::LocalForwards => &mut self.local_forwards,
            FormField::RemoteForwards => &mut self.remote_forwards,
            FormField::StrictHostKeyChecking => &mut self.strict_host_key_checking,
            FormField::UserKnownHostsFile => &mut self.user_known_hosts_file,
            FormField::HostKeyAlgorithms => &mut self.host_key_algorithms,
            FormField::PubkeyAcceptedAlgorithms => &mut self.pubkey_accepted_algorithms,
            FormField::ForwardAgent => &mut self.forward_agent,
            FormField::SshTag => &mut self.ssh_tag,
            FormField::Tags => &mut self.tags,
            FormField::Note => &mut self.note,
            FormField::Template => &mut self.template,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ReorderSession {
    original_entries: Vec<ManagedEntry>,
    original_raw_contents: Vec<String>,
    moved_host: String,
}

#[derive(Debug, Clone)]
pub struct BackupCatalogState {
    snapshots: Vec<backup::BackupSnapshot>,
    selected_index: usize,
    list_offset: usize,
    viewport_items: usize,
}

impl BackupCatalogState {
    fn new(snapshots: Vec<backup::BackupSnapshot>) -> Self {
        Self {
            snapshots,
            selected_index: 0,
            list_offset: 0,
            viewport_items: 1,
        }
    }

    pub fn snapshots(&self) -> &[backup::BackupSnapshot] {
        &self.snapshots
    }

    pub fn selected_snapshot(&self) -> Option<&backup::BackupSnapshot> {
        self.snapshots.get(self.selected_index)
    }

    pub fn selected_visible_index(&self) -> Option<usize> {
        (!self.snapshots.is_empty()).then_some(self.selected_index)
    }

    pub fn list_offset(&self) -> usize {
        self.list_offset
    }

    pub fn page_step(&self) -> usize {
        page_step(self.viewport_items)
    }

    pub fn position_label(&self) -> String {
        format!(
            "{} | sel {}/{}",
            format_visible_window(
                "snapshots",
                self.snapshots.len(),
                self.list_offset,
                self.viewport_items,
            ),
            self.selected_visible_index()
                .map(|value| value + 1)
                .unwrap_or(0),
            self.snapshots.len()
        )
    }

    pub fn detail_lines(&self) -> Vec<String> {
        let mut lines = vec![
            format!(
                "Retention: keep latest {} snapshot(s). Older backups are pruned automatically when a new snapshot is created.",
                backup::retention_limit()
            ),
            String::new(),
        ];

        let Some(snapshot) = self.selected_snapshot() else {
            lines.push("No backups found.".to_string());
            lines.push(String::new());
            lines.push(
                "Backups are created before write operations that change root config or managed entries."
                    .to_string(),
            );
            return lines;
        };

        lines.push(format!("Selected snapshot {}", snapshot.label));
        lines.push(format!("  path: {}", snapshot.path.display()));
        lines.push(format!(
            "  root config: {}",
            if snapshot.has_root_config {
                "yes"
            } else {
                "no"
            }
        ));
        lines.push(format!("  managed files: {}", snapshot.managed_file_count));
        lines.push(String::new());
        lines.push("Restore behavior".to_string());
        lines.push("  - create a fresh backup of the current state first".to_string());
        lines.push("  - replace root config and config.d from the selected snapshot".to_string());
        lines.push("  - reload entries and resync state.toml metadata".to_string());

        lines
    }

    pub fn summary(&self) -> String {
        match self.selected_snapshot() {
            Some(snapshot) => format!(
                "Backup catalog | {} snapshot(s) | selected {}",
                self.snapshots.len(),
                snapshot.label
            ),
            None => format!(
                "Backup catalog | 0 snapshot(s) | keep latest {}",
                backup::retention_limit()
            ),
        }
    }

    fn sync_viewport(&mut self, area_height: u16) {
        self.viewport_items = block_viewport_lines(area_height);
        self.clamp_viewport();
    }

    fn select_next(&mut self) {
        if self.snapshots.is_empty() {
            return;
        }

        self.selected_index = (self.selected_index + 1).min(self.snapshots.len() - 1);
        self.clamp_viewport();
    }

    fn select_previous(&mut self) {
        if self.snapshots.is_empty() {
            return;
        }

        self.selected_index = self.selected_index.saturating_sub(1);
        self.clamp_viewport();
    }

    fn select_next_page(&mut self) {
        if self.snapshots.is_empty() {
            return;
        }

        self.selected_index = self
            .selected_index
            .saturating_add(self.page_step())
            .min(self.snapshots.len() - 1);
        self.clamp_viewport();
    }

    fn select_previous_page(&mut self) {
        if self.snapshots.is_empty() {
            return;
        }

        self.selected_index = self.selected_index.saturating_sub(self.page_step());
        self.clamp_viewport();
    }

    fn select_first(&mut self) {
        if self.snapshots.is_empty() {
            return;
        }

        self.selected_index = 0;
        self.clamp_viewport();
    }

    fn select_last(&mut self) {
        if self.snapshots.is_empty() {
            return;
        }

        self.selected_index = self.snapshots.len() - 1;
        self.clamp_viewport();
    }

    fn clamp_viewport(&mut self) {
        if self.snapshots.is_empty() {
            self.selected_index = 0;
            self.list_offset = 0;
            return;
        }

        self.selected_index = self.selected_index.min(self.snapshots.len() - 1);

        let page_size = self.viewport_items.max(1);
        let max_offset = self.snapshots.len().saturating_sub(page_size);
        self.list_offset = self.list_offset.min(max_offset);

        if self.selected_index < self.list_offset {
            self.list_offset = self.selected_index;
        }

        let window_end = self.list_offset.saturating_add(page_size);
        if self.selected_index >= window_end {
            self.list_offset = self.selected_index + 1 - page_size;
        }

        self.list_offset = self.list_offset.min(max_offset);
    }
}

#[derive(Debug, Clone)]
pub struct InspectionReport {
    title: String,
    summary: String,
    lines: Vec<String>,
    scroll: u16,
    viewport_lines: usize,
    is_alert: bool,
}

impl InspectionReport {
    fn from_help() -> Self {
        let lines = vec![
            "Quick Start".to_string(),
            "  1. Use Up / Down (or j / k) to pick a managed host entry.".to_string(),
            "  2. Press Tab to switch between the host list and the detail pane.".to_string(),
            "  3. Press / to search, f to edit filters, and x to clear filters.".to_string(),
            "  4. Press a / e / d / r to add, edit, delete, or reorder entries.".to_string(),
            "  5. Press v to switch raw / merged view, and V / D for diagnostics.".to_string(),
            String::new(),
            "Global".to_string(),
            "  q / Ctrl+C          quit TUI".to_string(),
            "  Tab                 switch focus between host list and detail".to_string(),
            "  ?                   open this help".to_string(),
            "  /                   start inline search".to_string(),
            "  f                   edit filters".to_string(),
            "  x                   clear all filters".to_string(),
            "  t                   open template catalog".to_string(),
            "  b                   open backup catalog (Enter/r restores selected)".to_string(),
            "  V                   open validate report".to_string(),
            "  D                   open doctor report".to_string(),
            "  Ctrl+R              reload managed entries".to_string(),
            String::new(),
            "Host List Focus".to_string(),
            "  j / k, Up / Down    move selection".to_string(),
            "  PgUp / PgDn         jump selection by page".to_string(),
            "  Home / End          first / last entry".to_string(),
            "  g / G               first / last entry".to_string(),
            "  a                   create entry".to_string(),
            "  e                   edit selected entry".to_string(),
            "  d                   delete selected entry".to_string(),
            "  r                   reorder entries (requires clear filters)".to_string(),
            "  v                   toggle raw / merged detail".to_string(),
            String::new(),
            "Detail Focus".to_string(),
            "  j / k, Up / Down    scroll content".to_string(),
            "  PgUp / PgDn         page scroll".to_string(),
            "  Home / End          top / bottom".to_string(),
            "  g / G               top / bottom".to_string(),
            "  v                   toggle raw / merged detail".to_string(),
            String::new(),
            "Modals".to_string(),
            "  Inspect: Esc / q closes, j/k or arrows scroll, PgUp/PgDn page".to_string(),
            "  Filter: Enter applies, Esc cancels, Tab moves fields".to_string(),
            "  Form: Enter saves, Esc cancels, Tab moves fields".to_string(),
            "  Delete: y / Enter confirms, n / Esc cancels".to_string(),
            "  Reorder: j/k moves item, Enter saves, Esc cancels".to_string(),
        ];

        Self {
            title: "Help".to_string(),
            summary: "Keyboard help | Tab switches focus between hosts and detail".to_string(),
            lines,
            scroll: 0,
            viewport_lines: 1,
            is_alert: false,
        }
    }

    fn from_validation(report: validate::ValidationReport) -> Self {
        Self {
            title: "Validate".to_string(),
            summary: report.summary(),
            lines: report.detail_lines(),
            scroll: 0,
            viewport_lines: 1,
            is_alert: !report.is_ok(),
        }
    }

    fn from_doctor(report: doctor::DoctorReport) -> Self {
        Self {
            title: "Doctor".to_string(),
            summary: report.summary(),
            lines: report.detail_lines(),
            scroll: 0,
            viewport_lines: 1,
            is_alert: false,
        }
    }

    fn from_template_catalog() -> Self {
        let mut lines = Vec::new();

        for info in template::template_infos() {
            let status = if info.directives.is_empty() {
                "placeholder"
            } else {
                "available"
            };
            lines.push(format!("{} [{}]", info.kind.cli_name(), status));
            lines.push(format!("  {}", info.summary));

            if info.directives.is_empty() {
                lines.push("  defaults: -".to_string());
            } else {
                lines.push("  defaults:".to_string());
                lines.extend(
                    info.directives
                        .iter()
                        .map(|(key, value)| format!("    - {key} {value}")),
                );
            }

            lines.push(String::new());
        }

        while lines.last().is_some_and(|line| line.is_empty()) {
            lines.pop();
        }

        Self {
            title: "Templates".to_string(),
            summary: format!(
                "Template catalog | {} built-in template(s)",
                template::template_infos().len()
            ),
            lines,
            scroll: 0,
            viewport_lines: 1,
            is_alert: false,
        }
    }

    pub fn title(&self) -> &str {
        &self.title
    }

    pub fn summary(&self) -> &str {
        &self.summary
    }

    pub fn body(&self) -> String {
        self.lines.join("\n")
    }

    pub fn scroll(&self) -> u16 {
        self.scroll
    }

    pub fn position_label(&self) -> String {
        format_visible_window(
            "lines",
            self.lines.len().max(1),
            self.scroll as usize,
            self.viewport_lines,
        )
    }

    pub fn page_step(&self) -> u16 {
        page_step(self.viewport_lines) as u16
    }

    pub fn is_alert(&self) -> bool {
        self.is_alert
    }

    fn set_viewport_height(&mut self, area_height: u16) {
        self.viewport_lines = block_viewport_lines(area_height);
        self.clamp_scroll();
    }

    fn scroll_up(&mut self, amount: u16) {
        self.scroll = self.scroll.saturating_sub(amount);
    }

    fn scroll_down(&mut self, amount: u16) {
        self.scroll = self.scroll.saturating_add(amount).min(self.max_scroll());
    }

    fn scroll_home(&mut self) {
        self.scroll = 0;
    }

    fn scroll_end(&mut self) {
        self.scroll = self.max_scroll();
    }

    fn clamp_scroll(&mut self) {
        self.scroll = self.scroll.min(self.max_scroll());
    }

    fn max_scroll(&self) -> u16 {
        max_scroll_offset(self.lines.len().max(1), self.viewport_lines)
    }
}

#[derive(Debug)]
pub struct TuiState {
    paths: AppPaths,
    entries: Vec<ManagedEntry>,
    raw_contents: Vec<String>,
    metadata_state: MetadataState,
    filtered_indices: Vec<usize>,
    selected_filtered_index: usize,
    list_offset: usize,
    list_viewport_items: usize,
    query: String,
    tag_filter: String,
    has_note_filter: bool,
    template_filter: String,
    input_mode: InputMode,
    detail_mode: DetailMode,
    pane_focus: PaneFocus,
    detail_scroll: u16,
    detail_viewport_lines: usize,
    detail_content_line_count: usize,
    backup_catalog: Option<BackupCatalogState>,
    pending_restore_snapshot: Option<backup::BackupSnapshot>,
    pending_delete_host: Option<String>,
    filter_form: Option<FilterForm>,
    entry_form: Option<EntryForm>,
    inspection_report: Option<InspectionReport>,
    reorder_session: Option<ReorderSession>,
    status_message: Option<String>,
}

impl TuiState {
    pub fn load() -> Result<Self> {
        let paths = AppPaths::discover()?;
        let (entries, raw_contents, metadata_state) = load_snapshot(&paths)?;

        let mut state = Self {
            paths,
            entries,
            raw_contents,
            metadata_state,
            filtered_indices: Vec::new(),
            selected_filtered_index: 0,
            list_offset: 0,
            list_viewport_items: 1,
            query: String::new(),
            tag_filter: String::new(),
            has_note_filter: false,
            template_filter: String::new(),
            input_mode: InputMode::Normal,
            detail_mode: DetailMode::Raw,
            pane_focus: PaneFocus::HostList,
            detail_scroll: 0,
            detail_viewport_lines: 1,
            detail_content_line_count: 1,
            backup_catalog: None,
            pending_restore_snapshot: None,
            pending_delete_host: None,
            filter_form: None,
            entry_form: None,
            inspection_report: None,
            reorder_session: None,
            status_message: None,
        };
        state.refresh_filter_preserving(None);
        Ok(state)
    }

    pub fn input_mode(&self) -> InputMode {
        self.input_mode
    }

    pub fn detail_mode(&self) -> DetailMode {
        self.detail_mode
    }

    pub fn pane_focus(&self) -> PaneFocus {
        self.pane_focus
    }

    pub fn list_is_focused(&self) -> bool {
        matches!(self.pane_focus, PaneFocus::HostList)
    }

    pub fn detail_is_focused(&self) -> bool {
        matches!(self.pane_focus, PaneFocus::Detail)
    }

    pub fn detail_scroll(&self) -> u16 {
        self.detail_scroll
    }

    pub fn filter_form(&self) -> Option<&FilterForm> {
        self.filter_form.as_ref()
    }

    pub fn active_filter_summary(&self) -> Option<String> {
        let mut parts = Vec::new();

        if !self.query.trim().is_empty() {
            parts.push(format!("/{}", self.query.trim()));
        }

        let tags = split_multi_value(&self.tag_filter);
        if !tags.is_empty() {
            parts.push(format!("tag={}", tags.join(",")));
        }

        if self.has_note_filter {
            parts.push("note=yes".to_string());
        }

        let template = self.template_filter.trim();
        if !template.is_empty() {
            parts.push(format!("tmpl={template}"));
        }

        (!parts.is_empty()).then(|| parts.join("  "))
    }

    pub fn has_active_filters(&self) -> bool {
        self.active_filter_summary().is_some()
    }

    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    pub fn filtered_count(&self) -> usize {
        self.filtered_indices.len()
    }

    pub fn filtered_indices(&self) -> &[usize] {
        &self.filtered_indices
    }

    pub fn selected_visible_index(&self) -> Option<usize> {
        (!self.filtered_indices.is_empty()).then_some(self.selected_filtered_index)
    }

    pub fn list_offset(&self) -> usize {
        self.list_offset
    }

    pub fn list_page_step(&self) -> usize {
        page_step(self.list_viewport_items)
    }

    pub fn detail_page_step(&self) -> u16 {
        page_step(self.detail_viewport_lines) as u16
    }

    pub fn inspection_page_step(&self) -> u16 {
        self.inspection_report
            .as_ref()
            .map(InspectionReport::page_step)
            .unwrap_or(1)
    }

    pub fn list_position_label(&self) -> Option<String> {
        if self.filtered_indices.is_empty() {
            return None;
        }

        Some(format!(
            "{} | sel {}/{}",
            format_visible_window(
                "view",
                self.filtered_indices.len(),
                self.list_offset,
                self.list_viewport_items,
            ),
            self.selected_filtered_index + 1,
            self.filtered_indices.len()
        ))
    }

    pub fn detail_position_label(&self) -> String {
        format_visible_window(
            "lines",
            self.detail_content_line_count,
            self.detail_scroll as usize,
            self.detail_viewport_lines,
        )
    }

    pub fn entry(&self, index: usize) -> &ManagedEntry {
        &self.entries[index]
    }

    pub fn metadata(&self, index: usize) -> Option<&EntryMetadata> {
        metadata::find_entry_metadata(&self.metadata_state, &self.entries[index])
    }

    pub fn selected_entry_index(&self) -> Option<usize> {
        self.selected_visible_index()
            .and_then(|index| self.filtered_indices.get(index).copied())
            .filter(|index| *index < self.entries.len())
    }

    pub fn selected_entry(&self) -> Option<&ManagedEntry> {
        self.selected_entry_index()
            .map(|index| &self.entries[index])
    }

    pub fn selected_metadata(&self) -> Option<&EntryMetadata> {
        self.selected_entry_index()
            .and_then(|index| self.metadata(index))
    }

    pub fn status_message(&self) -> Option<&str> {
        self.status_message.as_deref()
    }

    pub fn pending_delete_host(&self) -> Option<&str> {
        self.pending_delete_host.as_deref()
    }

    pub fn entry_form(&self) -> Option<&EntryForm> {
        self.entry_form.as_ref()
    }

    pub fn inspection_report(&self) -> Option<&InspectionReport> {
        self.inspection_report.as_ref()
    }

    pub fn backup_catalog(&self) -> Option<&BackupCatalogState> {
        self.backup_catalog.as_ref()
    }

    pub fn pending_restore_snapshot(&self) -> Option<&backup::BackupSnapshot> {
        self.pending_restore_snapshot.as_ref()
    }

    pub fn reorder_host(&self) -> Option<&str> {
        self.reorder_session
            .as_ref()
            .map(|session| session.moved_host.as_str())
    }

    pub fn reorder_dirty(&self) -> bool {
        self.reorder_session.as_ref().is_some_and(|session| {
            sequence_signature(&self.entries) != sequence_signature(&session.original_entries)
        })
    }

    pub fn set_status(&mut self, message: impl Into<String>) {
        self.status_message = Some(message.into());
    }

    pub fn selected_content_title(&self) -> String {
        let base = self.detail_mode.title();
        match self.selected_entry() {
            Some(entry) if matches!(self.detail_mode, DetailMode::Merged) => {
                format!("{base} [{}]", entry.entry.primary_pattern())
            }
            Some(entry) => format!("{base} [{}]", entry.path.display()),
            None => base.to_string(),
        }
    }

    pub fn selected_content(&self) -> String {
        let Some(index) = self.selected_entry_index() else {
            if self.entries.is_empty() {
                return "No managed entries found.\n\nRun `sshcfg init` and `sshcfg add ...` to create entries.".to_string();
            }

            let filter_summary = self
                .active_filter_summary()
                .unwrap_or_else(|| "<none>".to_string());
            return format!(
                "No entries match the current filters.\n\nActive filters: {filter_summary}"
            );
        };

        match self.detail_mode {
            DetailMode::Raw => self.raw_contents[index].clone(),
            DetailMode::Merged => self.render_merged_preview(index),
        }
    }

    pub fn sync_list_viewport(&mut self, area_height: u16) {
        self.list_viewport_items = host_list_viewport_items(area_height);
        self.clamp_list_viewport();
    }

    pub fn sync_detail_viewport(&mut self, area_height: u16, content_line_count: usize) {
        self.detail_viewport_lines = block_viewport_lines(area_height);
        self.detail_content_line_count = content_line_count.max(1);
        self.clamp_detail_scroll();
    }

    pub fn sync_backup_catalog_viewport(&mut self, area_height: u16) {
        if let Some(catalog) = &mut self.backup_catalog {
            catalog.sync_viewport(area_height);
        }
    }

    pub fn sync_inspection_viewport(&mut self, area_height: u16) {
        if let Some(report) = &mut self.inspection_report {
            report.set_viewport_height(area_height);
        }
    }

    pub fn start_search(&mut self) {
        self.input_mode = InputMode::Search;
    }

    pub fn finish_search(&mut self) {
        self.input_mode = InputMode::Normal;
    }

    pub fn cancel_search(&mut self) {
        self.clear_search();
        self.input_mode = InputMode::Normal;
    }

    pub fn push_search(&mut self, ch: char) {
        self.query.push(ch);
        let current_host = self.selected_host();
        self.refresh_filter_preserving(current_host.as_deref());
    }

    pub fn pop_search(&mut self) {
        self.query.pop();
        let current_host = self.selected_host();
        self.refresh_filter_preserving(current_host.as_deref());
    }

    pub fn clear_search(&mut self) {
        self.query.clear();
        let current_host = self.selected_host();
        self.refresh_filter_preserving(current_host.as_deref());
    }

    pub fn toggle_detail_mode(&mut self) {
        self.detail_mode.toggle();
        self.reset_detail_scroll();
    }

    pub fn toggle_pane_focus(&mut self) {
        self.pane_focus.toggle();
    }

    pub fn start_filter_edit(&mut self) {
        self.filter_form = Some(FilterForm::new(
            &self.query,
            &self.tag_filter,
            self.has_note_filter,
            &self.template_filter,
        ));
        self.input_mode = InputMode::Filter;
    }

    pub fn cancel_filter_edit(&mut self) {
        self.filter_form = None;
        self.input_mode = InputMode::Normal;
    }

    pub fn save_filter_edit(&mut self) {
        let Some(form) = self.filter_form.take() else {
            self.input_mode = InputMode::Normal;
            return;
        };

        let selected_host = self.selected_host();
        let (query, tags, has_note, template) = form.into_parts();
        self.query = query;
        self.tag_filter = tags;
        self.has_note_filter = has_note;
        self.template_filter = template;
        self.input_mode = InputMode::Normal;
        self.refresh_filter_preserving(selected_host.as_deref());

        if let Some(summary) = self.active_filter_summary() {
            self.set_status(format!("Applied filters | {summary}"));
        } else {
            self.set_status("Cleared all filters");
        }
    }

    pub fn clear_all_filters(&mut self) {
        let selected_host = self.selected_host();
        self.query.clear();
        self.tag_filter.clear();
        self.has_note_filter = false;
        self.template_filter.clear();
        self.filter_form = None;
        self.refresh_filter_preserving(selected_host.as_deref());
        self.set_status("Cleared all filters");
    }

    pub fn filter_next_field(&mut self) {
        if let Some(form) = &mut self.filter_form {
            form.next_field();
        }
    }

    pub fn filter_previous_field(&mut self) {
        if let Some(form) = &mut self.filter_form {
            form.previous_field();
        }
    }

    pub fn push_filter_char(&mut self, ch: char) {
        if let Some(form) = &mut self.filter_form {
            form.push_char(ch);
        }
    }

    pub fn handle_filter_space(&mut self) {
        if let Some(form) = &mut self.filter_form {
            match form.active_field() {
                FilterField::HasNote => form.toggle_has_note(),
                FilterField::Template => form.cycle_template_next(),
                FilterField::Query | FilterField::Tags => form.push_char(' '),
            }
        }
    }

    pub fn pop_filter_char(&mut self) {
        if let Some(form) = &mut self.filter_form {
            form.backspace();
        }
    }

    pub fn clear_filter_field(&mut self) {
        if let Some(form) = &mut self.filter_form {
            form.clear_active_field();
        }
    }

    pub fn toggle_filter_has_note(&mut self) {
        if let Some(form) = &mut self.filter_form {
            form.toggle_has_note();
        }
    }

    pub fn cycle_filter_template_next(&mut self) {
        if let Some(form) = &mut self.filter_form {
            form.cycle_template_next();
        }
    }

    pub fn cycle_filter_template_previous(&mut self) {
        if let Some(form) = &mut self.filter_form {
            form.cycle_template_previous();
        }
    }

    pub fn open_validation_report(&mut self) -> Result<()> {
        let report = validate::collect_report(&self.paths, &validate::ValidateOptions::default())?;
        self.inspection_report = Some(InspectionReport::from_validation(report));
        self.input_mode = InputMode::Inspect;
        Ok(())
    }

    pub fn open_doctor_report(&mut self) -> Result<()> {
        let report = doctor::collect_report(&self.paths)?;
        self.inspection_report = Some(InspectionReport::from_doctor(report));
        self.input_mode = InputMode::Inspect;
        Ok(())
    }

    pub fn open_template_catalog(&mut self) {
        self.inspection_report = Some(InspectionReport::from_template_catalog());
        self.input_mode = InputMode::Inspect;
    }

    pub fn open_backup_catalog(&mut self) -> Result<()> {
        let backups = backup::list_backups(&self.paths)?;
        self.backup_catalog = Some(BackupCatalogState::new(backups));
        self.pending_restore_snapshot = None;
        self.input_mode = InputMode::BackupCatalog;
        Ok(())
    }

    pub fn open_help(&mut self) {
        self.inspection_report = Some(InspectionReport::from_help());
        self.input_mode = InputMode::Inspect;
    }

    pub fn close_backup_catalog(&mut self) {
        self.backup_catalog = None;
        self.pending_restore_snapshot = None;
        self.input_mode = InputMode::Normal;
    }

    pub fn backup_select_next(&mut self) {
        if let Some(catalog) = &mut self.backup_catalog {
            catalog.select_next();
        }
    }

    pub fn backup_select_previous(&mut self) {
        if let Some(catalog) = &mut self.backup_catalog {
            catalog.select_previous();
        }
    }

    pub fn backup_select_next_page(&mut self) {
        if let Some(catalog) = &mut self.backup_catalog {
            catalog.select_next_page();
        }
    }

    pub fn backup_select_previous_page(&mut self) {
        if let Some(catalog) = &mut self.backup_catalog {
            catalog.select_previous_page();
        }
    }

    pub fn backup_select_first(&mut self) {
        if let Some(catalog) = &mut self.backup_catalog {
            catalog.select_first();
        }
    }

    pub fn backup_select_last(&mut self) {
        if let Some(catalog) = &mut self.backup_catalog {
            catalog.select_last();
        }
    }

    pub fn start_restore_confirmation(&mut self) {
        let Some(snapshot) = self
            .backup_catalog
            .as_ref()
            .and_then(BackupCatalogState::selected_snapshot)
            .cloned()
        else {
            self.set_status("No backup snapshot selected");
            return;
        };

        self.pending_restore_snapshot = Some(snapshot);
        self.input_mode = InputMode::ConfirmRestore;
    }

    pub fn cancel_restore_confirmation(&mut self) {
        self.pending_restore_snapshot = None;
        self.input_mode = InputMode::BackupCatalog;
    }

    pub fn confirm_restore(&mut self) -> Result<()> {
        let Some(snapshot) = self.pending_restore_snapshot.take() else {
            self.input_mode = InputMode::BackupCatalog;
            return Ok(());
        };

        let preferred_host = self.selected_host();
        let outcome = backup::restore_backup(&self.paths, &snapshot)?;
        let restored_entries = store::load_managed_entries(&self.paths)?;
        self.metadata_state = metadata::sync_entries(&self.paths, &restored_entries, true)?;

        self.input_mode = InputMode::Normal;
        self.reload_preserving(preferred_host.as_deref())?;

        let mut message = format!("Restored backup `{}`", outcome.restored_snapshot.label);
        if let Some(path) = outcome.pre_restore_backup_path {
            message.push_str(&format!(" | current state saved to {}", path.display()));
        }
        self.set_status(message);
        Ok(())
    }

    pub fn close_inspection_report(&mut self) {
        self.inspection_report = None;
        self.input_mode = InputMode::Normal;
    }

    pub fn scroll_inspection_up(&mut self, amount: u16) {
        if let Some(report) = &mut self.inspection_report {
            report.scroll_up(amount);
        }
    }

    pub fn scroll_inspection_down(&mut self, amount: u16) {
        if let Some(report) = &mut self.inspection_report {
            report.scroll_down(amount);
        }
    }

    pub fn scroll_inspection_home(&mut self) {
        if let Some(report) = &mut self.inspection_report {
            report.scroll_home();
        }
    }

    pub fn scroll_inspection_end(&mut self) {
        if let Some(report) = &mut self.inspection_report {
            report.scroll_end();
        }
    }

    pub fn start_add(&mut self) {
        self.entry_form = Some(EntryForm::new_create());
        self.input_mode = InputMode::Edit;
    }

    pub fn start_edit(&mut self) {
        let Some(index) = self.selected_entry_index() else {
            self.set_status("No selected entry to edit");
            return;
        };

        let entry = self.entries[index].clone();
        let metadata = self.metadata(index).cloned();
        self.entry_form = Some(EntryForm::from_entry(&entry, metadata.as_ref()));
        self.input_mode = InputMode::Edit;
    }

    pub fn form_next_field(&mut self) {
        if let Some(form) = &mut self.entry_form {
            form.next_field();
        }
    }

    pub fn form_previous_field(&mut self) {
        if let Some(form) = &mut self.entry_form {
            form.previous_field();
        }
    }

    pub fn push_form_char(&mut self, ch: char) {
        if let Some(form) = &mut self.entry_form {
            form.push_char(ch);
        }
    }

    pub fn handle_form_space(&mut self) {
        if let Some(form) = &mut self.entry_form {
            if matches!(form.active_field(), FormField::Template) {
                form.cycle_template_next();
            } else {
                form.push_char(' ');
            }
        }
    }

    pub fn pop_form_char(&mut self) {
        if let Some(form) = &mut self.entry_form {
            form.backspace();
        }
    }

    pub fn clear_form_field(&mut self) {
        if let Some(form) = &mut self.entry_form {
            form.clear_active_field();
        }
    }

    pub fn cycle_form_template_next(&mut self) {
        if let Some(form) = &mut self.entry_form {
            if matches!(form.active_field(), FormField::Template) {
                form.cycle_template_next();
            }
        }
    }

    pub fn cycle_form_template_previous(&mut self) {
        if let Some(form) = &mut self.entry_form {
            if matches!(form.active_field(), FormField::Template) {
                form.cycle_template_previous();
            }
        }
    }

    pub fn cancel_form(&mut self) {
        self.entry_form = None;
        self.input_mode = InputMode::Normal;
    }

    pub fn save_form(&mut self) -> Result<()> {
        let Some(form) = self.entry_form.as_ref() else {
            self.input_mode = InputMode::Normal;
            return Ok(());
        };

        let mode = form.mode();
        match mode {
            FormMode::Create => {
                let args = form.build_add_args()?;
                let outcome = create_managed_entry(&self.paths, &args)?;
                let preferred_host = outcome.host_patterns.first().cloned();
                self.entry_form = None;
                self.input_mode = InputMode::Normal;
                self.reload_preserving(preferred_host.as_deref())?;

                let mut message = format!(
                    "{} `{}`",
                    mode.verb(),
                    preferred_host.unwrap_or_else(|| args.host.clone())
                );
                if let Some(path) = outcome.backup_path {
                    message.push_str(&format!(" | backup {}", path.display()));
                }
                self.set_status(message);
            }
            FormMode::Edit => {
                let args = form.build_edit_args()?;
                let fallback_host = form.original_host().unwrap_or_default().to_string();
                let outcome = edit_managed_entry(&self.paths, &args)?;
                let preferred_host = outcome.host_patterns.first().cloned();
                self.entry_form = None;
                self.input_mode = InputMode::Normal;
                self.reload_preserving(preferred_host.as_deref())?;

                let mut message = format!(
                    "{} `{}`",
                    mode.verb(),
                    preferred_host.unwrap_or(fallback_host)
                );
                if let Some(path) = outcome.backup_path {
                    message.push_str(&format!(" | backup {}", path.display()));
                }
                self.set_status(message);
            }
        }

        Ok(())
    }

    pub fn reload(&mut self) -> Result<()> {
        let current_host = self.selected_host();
        self.reload_preserving(current_host.as_deref())?;
        self.set_status("Reloaded managed entries from disk");
        Ok(())
    }

    pub fn start_delete_confirmation(&mut self) {
        if let Some(host) = self.selected_host() {
            self.pending_delete_host = Some(host);
            self.input_mode = InputMode::ConfirmDelete;
        } else {
            self.set_status("No selected entry to delete");
        }
    }

    pub fn cancel_delete_confirmation(&mut self) {
        self.pending_delete_host = None;
        self.input_mode = InputMode::Normal;
    }

    pub fn confirm_delete(&mut self) -> Result<()> {
        let Some(host) = self.pending_delete_host.take() else {
            self.input_mode = InputMode::Normal;
            return Ok(());
        };

        let target = store::find_entry_by_host(&self.entries, &host)
            .with_context(|| format!("managed entry `{host}` not found"))?
            .clone();
        let result = delete_managed_entries(&self.paths, &[target])?;
        self.input_mode = InputMode::Normal;
        self.reload_preserving(None)?;

        let mut message = format!("Deleted `{host}`");
        if let Some(path) = result.backup_path {
            message.push_str(&format!(" | backup {}", path.display()));
        }
        self.set_status(message);
        Ok(())
    }

    pub fn start_reorder(&mut self) {
        if self.has_active_filters() {
            self.set_status("Clear active filters before reordering");
            return;
        }

        let Some(host) = self.selected_host() else {
            self.set_status("No selected entry to reorder");
            return;
        };

        self.reorder_session = Some(ReorderSession {
            original_entries: self.entries.clone(),
            original_raw_contents: self.raw_contents.clone(),
            moved_host: host,
        });
        self.input_mode = InputMode::Reorder;
    }

    pub fn cancel_reorder(&mut self) {
        let Some(session) = self.reorder_session.take() else {
            self.input_mode = InputMode::Normal;
            return;
        };

        self.entries = session.original_entries;
        self.raw_contents = session.original_raw_contents;
        self.input_mode = InputMode::Normal;
        self.refresh_filter_preserving(Some(&session.moved_host));
        self.set_status("Cancelled reorder changes");
    }

    pub fn save_reorder(&mut self) -> Result<()> {
        let Some(session) = self.reorder_session.take() else {
            self.input_mode = InputMode::Normal;
            return Ok(());
        };

        if sequence_signature(&self.entries) == sequence_signature(&session.original_entries) {
            self.input_mode = InputMode::Normal;
            self.set_status("No order changes to save");
            return Ok(());
        }

        let outcome = apply_reordered_entries(&self.paths, &self.entries, &session.moved_host)?;
        self.input_mode = InputMode::Normal;
        self.reload_preserving(Some(&session.moved_host))?;

        let mut message = format!("Moved `{}` -> order {}", outcome.host, outcome.order);
        if let Some(path) = outcome.backup_paths.first() {
            message.push_str(&format!(" | backup {}", path.display()));
        }
        self.set_status(message);
        Ok(())
    }

    pub fn reorder_up(&mut self) {
        self.shift_selected_entry(-1);
    }

    pub fn reorder_down(&mut self) {
        self.shift_selected_entry(1);
    }

    pub fn select_next(&mut self) {
        if self.filtered_indices.is_empty() {
            return;
        }

        self.selected_filtered_index =
            (self.selected_filtered_index + 1).min(self.filtered_indices.len() - 1);
        self.clamp_list_viewport();
        self.reset_detail_scroll();
    }

    pub fn select_previous(&mut self) {
        if self.filtered_indices.is_empty() {
            return;
        }

        self.selected_filtered_index = self.selected_filtered_index.saturating_sub(1);
        self.clamp_list_viewport();
        self.reset_detail_scroll();
    }

    pub fn select_next_page(&mut self, amount: usize) {
        if self.filtered_indices.is_empty() {
            return;
        }

        self.selected_filtered_index = self
            .selected_filtered_index
            .saturating_add(amount)
            .min(self.filtered_indices.len() - 1);
        self.clamp_list_viewport();
        self.reset_detail_scroll();
    }

    pub fn select_previous_page(&mut self, amount: usize) {
        if self.filtered_indices.is_empty() {
            return;
        }

        self.selected_filtered_index = self.selected_filtered_index.saturating_sub(amount);
        self.clamp_list_viewport();
        self.reset_detail_scroll();
    }

    pub fn select_first(&mut self) {
        if self.filtered_indices.is_empty() {
            return;
        }

        self.selected_filtered_index = 0;
        self.clamp_list_viewport();
        self.reset_detail_scroll();
    }

    pub fn select_last(&mut self) {
        if self.filtered_indices.is_empty() {
            return;
        }

        self.selected_filtered_index = self.filtered_indices.len() - 1;
        self.clamp_list_viewport();
        self.reset_detail_scroll();
    }

    pub fn scroll_detail_up(&mut self, amount: u16) {
        self.detail_scroll = self.detail_scroll.saturating_sub(amount);
    }

    pub fn scroll_detail_down(&mut self, amount: u16) {
        self.detail_scroll = self
            .detail_scroll
            .saturating_add(amount)
            .min(self.max_detail_scroll());
    }

    pub fn scroll_detail_home(&mut self) {
        self.detail_scroll = 0;
    }

    pub fn scroll_detail_end(&mut self) {
        self.detail_scroll = self.max_detail_scroll();
    }

    fn reload_preserving(&mut self, preferred_host: Option<&str>) -> Result<()> {
        let preserved_host = preferred_host
            .map(ToString::to_string)
            .or_else(|| self.selected_host());
        let (entries, raw_contents, metadata_state) = load_snapshot(&self.paths)?;
        self.entries = entries;
        self.raw_contents = raw_contents;
        self.metadata_state = metadata_state;
        self.backup_catalog = None;
        self.pending_restore_snapshot = None;
        self.filter_form = None;
        self.entry_form = None;
        self.inspection_report = None;
        self.reorder_session = None;
        self.refresh_filter_preserving(preserved_host.as_deref());
        Ok(())
    }

    fn refresh_filter_preserving(&mut self, preferred_host: Option<&str>) {
        let selected_host = preferred_host
            .map(ToString::to_string)
            .or_else(|| self.selected_host());
        let filter = EntryFilter::from_parts(
            Some(self.query.clone()),
            split_multi_value(&self.tag_filter),
            self.has_note_filter,
            trim_to_option(&self.template_filter),
        );
        self.filtered_indices = filter_entry_indices(&self.entries, &self.metadata_state, &filter);

        if self.filtered_indices.is_empty() {
            self.selected_filtered_index = 0;
            self.list_offset = 0;
            self.reset_detail_scroll();
            return;
        }

        if let Some(host) = selected_host {
            if let Some(entry_index) = self.entries.iter().position(|entry| {
                entry
                    .entry
                    .host_patterns
                    .iter()
                    .any(|pattern| pattern == &host)
            }) {
                if let Some(position) = self
                    .filtered_indices
                    .iter()
                    .position(|index| *index == entry_index)
                {
                    self.selected_filtered_index = position;
                    self.clamp_list_viewport();
                    self.reset_detail_scroll();
                    return;
                }
            }
        }

        self.selected_filtered_index = self
            .selected_filtered_index
            .min(self.filtered_indices.len() - 1);
        self.clamp_list_viewport();
        self.reset_detail_scroll();
    }

    fn selected_host(&self) -> Option<String> {
        self.selected_entry()
            .map(|entry| entry.entry.primary_pattern().to_string())
    }

    fn render_merged_preview(&self, index: usize) -> String {
        let entry = &self.entries[index];
        let target = entry.entry.primary_pattern();
        let root_match_blocks = self.load_root_match_blocks();

        match if root_match_blocks.is_empty() {
            resolve::resolve_target(&self.entries, target)
        } else {
            resolve::resolve_target_with_root_matches(&self.entries, target, &root_match_blocks)
        } {
            Ok(resolved) if resolved.matched_entries.is_empty() => {
                format!("No merged preview available for `{target}`.")
            }
            Ok(resolved) => {
                let mut lines = resolve::describe_resolved_target_lines(&resolved);

                if !matches!(entry.entry.kind(), crate::core::model::EntryKind::Host) {
                    lines.insert(
                        1,
                        "preview note: wildcard and negated patterns are resolved against the literal primary pattern."
                            .to_string(),
                    );
                    lines.insert(2, String::new());
                }

                lines.join("\n").trim_end().to_string()
            }
            Err(err) => format!("Failed to resolve merged preview for `{target}`:\n{err:#}"),
        }
    }

    fn load_root_match_blocks(&self) -> Vec<root_config::RootMatchBlock> {
        if !self.paths.root_config.exists() {
            return Vec::new();
        }

        match std::fs::read_to_string(&self.paths.root_config) {
            Ok(content) => root_config::extract_match_blocks(&content),
            Err(_) => Vec::new(),
        }
    }

    fn shift_selected_entry(&mut self, direction: isize) {
        if !matches!(self.input_mode, InputMode::Reorder) {
            return;
        }

        let Some(current_index) = self.selected_entry_index() else {
            return;
        };
        let Some(session) = self.reorder_session.as_ref() else {
            return;
        };

        let Some(target_index) = offset_index(current_index, direction, self.entries.len()) else {
            self.set_status("Cannot move beyond the list boundary");
            return;
        };

        let host = session.moved_host.clone();
        move_item(&mut self.entries, current_index, target_index);
        move_item(&mut self.raw_contents, current_index, target_index);
        self.preview_reorder_orders();
        self.refresh_filter_preserving(Some(&host));
    }

    fn preview_reorder_orders(&mut self) {
        for (index, entry) in self.entries.iter_mut().enumerate() {
            entry.order = ((index + 1) as u16) * 10;
        }
    }

    fn reset_detail_scroll(&mut self) {
        self.detail_scroll = 0;
    }

    fn clamp_list_viewport(&mut self) {
        if self.filtered_indices.is_empty() {
            self.list_offset = 0;
            return;
        }

        self.selected_filtered_index = self
            .selected_filtered_index
            .min(self.filtered_indices.len() - 1);

        let page_size = self.list_viewport_items.max(1);
        let max_offset = self.filtered_indices.len().saturating_sub(page_size);
        self.list_offset = self.list_offset.min(max_offset);

        if self.selected_filtered_index < self.list_offset {
            self.list_offset = self.selected_filtered_index;
        }

        let window_end = self.list_offset.saturating_add(page_size);
        if self.selected_filtered_index >= window_end {
            self.list_offset = self.selected_filtered_index + 1 - page_size;
        }

        self.list_offset = self.list_offset.min(max_offset);
    }

    fn clamp_detail_scroll(&mut self) {
        self.detail_scroll = self.detail_scroll.min(self.max_detail_scroll());
    }

    fn max_detail_scroll(&self) -> u16 {
        max_scroll_offset(self.detail_content_line_count, self.detail_viewport_lines)
    }
}

fn load_snapshot(paths: &AppPaths) -> Result<(Vec<ManagedEntry>, Vec<String>, MetadataState)> {
    let entries = store::load_managed_entries(paths)?;
    let metadata_state = metadata::load_state(paths)?;
    let raw_contents = entries
        .iter()
        .map(|entry| {
            std::fs::read_to_string(&entry.path)
                .with_context(|| format!("failed to read managed entry {}", entry.path.display()))
        })
        .collect::<Result<Vec<_>>>()?;

    Ok((entries, raw_contents, metadata_state))
}

fn display_filter_value(value: &str, empty: &str) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        empty.to_string()
    } else {
        trimmed.to_string()
    }
}

fn split_multi_value(value: &str) -> Vec<String> {
    value
        .split([';', ','])
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(ToString::to_string)
        .collect()
}

fn trim_to_option(value: &str) -> Option<String> {
    let trimmed = value.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

fn parse_port(value: &str) -> Result<Option<u16>> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        Ok(None)
    } else {
        Ok(Some(
            trimmed
                .parse::<u16>()
                .with_context(|| format!("invalid Port `{trimmed}`"))?,
        ))
    }
}

fn parse_template(value: &str) -> Result<Option<TemplateKind>> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("none") {
        return Ok(None);
    }

    template::parse_cli_name(trimmed)
        .map(Some)
        .with_context(|| format!("unknown Template `{trimmed}`"))
}

fn offset_index(current: usize, direction: isize, len: usize) -> Option<usize> {
    if direction < 0 {
        current.checked_sub(direction.unsigned_abs())
    } else {
        let next = current.checked_add(direction as usize)?;
        (next < len).then_some(next)
    }
}

fn move_item<T>(items: &mut Vec<T>, from: usize, to: usize) {
    if from == to {
        return;
    }

    let item = items.remove(from);
    items.insert(to, item);
}

fn next_template_name(current: &str, forward: bool) -> String {
    let options = [
        "",
        TemplateKind::Embedded.cli_name(),
        TemplateKind::Legacy.cli_name(),
        TemplateKind::Vps.cli_name(),
        TemplateKind::Jump.cli_name(),
        TemplateKind::Forward.cli_name(),
    ];
    let current = current.trim();
    let index = options
        .iter()
        .position(|item| item.eq_ignore_ascii_case(current))
        .unwrap_or(0);

    let next_index = if forward {
        (index + 1) % options.len()
    } else if index == 0 {
        options.len() - 1
    } else {
        index - 1
    };

    options[next_index].to_string()
}

fn host_list_viewport_items(area_height: u16) -> usize {
    let line_capacity = block_viewport_lines(area_height);
    (line_capacity / 2).max(1)
}

fn block_viewport_lines(area_height: u16) -> usize {
    area_height.saturating_sub(2).max(1) as usize
}

fn page_step(viewport: usize) -> usize {
    viewport.saturating_sub(1).max(1)
}

fn max_scroll_offset(total_lines: usize, viewport_lines: usize) -> u16 {
    total_lines
        .saturating_sub(viewport_lines.max(1))
        .min(u16::MAX as usize) as u16
}

fn visible_window(total: usize, offset: usize, viewport: usize) -> Option<(usize, usize)> {
    if total == 0 {
        return None;
    }

    let start = offset.min(total - 1);
    let end = start.saturating_add(viewport.max(1)).min(total);
    Some((start, end))
}

fn format_visible_window(label: &str, total: usize, offset: usize, viewport: usize) -> String {
    match visible_window(total, offset, viewport) {
        Some((start, end)) => format!("{label} {}-{end}/{total}", start + 1),
        None => format!("{label} 0/0"),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        DetailMode, EntryForm, FormField, InputMode, InspectionReport, PaneFocus, TuiState,
        format_visible_window, host_list_viewport_items, load_snapshot, max_scroll_offset,
    };
    use crate::core::model::{HostEntry, ManagedEntry};
    use crate::core::state::AppState as MetadataState;
    use crate::core::store;
    use crate::fs::layout::AppPaths;
    use chrono::Utc;

    fn test_paths(name: &str) -> AppPaths {
        let root = std::env::current_dir()
            .unwrap()
            .join("target")
            .join("test-tui-state")
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

    fn test_state(paths: AppPaths) -> TuiState {
        let (entries, raw_contents, metadata_state) = load_snapshot(&paths).unwrap();
        let mut state = TuiState {
            paths,
            entries,
            raw_contents,
            metadata_state,
            filtered_indices: Vec::new(),
            selected_filtered_index: 0,
            list_offset: 0,
            list_viewport_items: 1,
            query: String::new(),
            tag_filter: String::new(),
            has_note_filter: false,
            template_filter: String::new(),
            input_mode: InputMode::Normal,
            detail_mode: DetailMode::Raw,
            pane_focus: PaneFocus::HostList,
            detail_scroll: 0,
            detail_viewport_lines: 1,
            detail_content_line_count: 1,
            backup_catalog: None,
            pending_restore_snapshot: None,
            pending_delete_host: None,
            filter_form: None,
            entry_form: None,
            inspection_report: None,
            reorder_session: None,
            status_message: None,
        };
        state.refresh_filter_preserving(None);
        state
    }

    #[test]
    fn template_catalog_report_lists_defaults() {
        let report = InspectionReport::from_template_catalog();
        let body = report.body();

        assert_eq!(report.title(), "Templates");
        assert!(body.contains("embedded [available]"));
        assert!(body.contains("legacy [available]"));
        assert!(body.contains("StrictHostKeyChecking no"));
        assert!(body.contains("PubkeyAcceptedAlgorithms +ssh-rsa"));
        assert!(body.contains("vps [placeholder]"));
    }

    #[test]
    fn help_report_mentions_focus_switching() {
        let report = InspectionReport::from_help();
        let body = report.body();

        assert_eq!(report.title(), "Help");
        assert!(body.contains("Tab                 switch focus"));
        assert!(body.contains("Host List Focus"));
        assert!(body.contains("Detail Focus"));
        assert!(body.contains("Ctrl+R              reload managed entries"));
    }

    #[test]
    fn visible_window_summary_uses_human_readable_bounds() {
        assert_eq!(format_visible_window("view", 42, 10, 12), "view 11-22/42");
        assert_eq!(format_visible_window("lines", 0, 0, 20), "lines 0/0");
    }

    #[test]
    fn max_scroll_uses_last_page_instead_of_last_line() {
        assert_eq!(max_scroll_offset(120, 20), 100);
        assert_eq!(max_scroll_offset(8, 20), 0);
    }

    #[test]
    fn inspection_report_scroll_end_respects_viewport_height() {
        let mut report = InspectionReport::from_help();
        report.set_viewport_height(8);
        report.scroll_end();

        assert_eq!(report.scroll(), max_scroll_offset(report.lines.len(), 6));
        assert_eq!(
            report.position_label(),
            format_visible_window("lines", report.lines.len(), report.scroll() as usize, 6)
        );
    }

    #[test]
    fn host_list_viewport_items_tracks_two_line_rows() {
        assert_eq!(host_list_viewport_items(12), 5);
        assert_eq!(host_list_viewport_items(3), 1);
    }

    #[test]
    fn entry_form_build_add_args_carries_ssh_tag() {
        let mut form = EntryForm::new_create();
        form.host = "demo".to_string();
        form.hostname = "demo.example.com".to_string();
        form.ssh_tag = "ops".to_string();

        let args = form.build_add_args().unwrap();
        assert_eq!(args.ssh_tag.as_deref(), Some("ops"));
    }

    #[test]
    fn entry_form_build_edit_args_clears_ssh_tag_when_field_is_empty() {
        let entry = ManagedEntry {
            order: 10,
            slug: "demo".to_string(),
            path: "010-host-demo.conf".into(),
            raw_content: String::new(),
            entry: HostEntry {
                host_patterns: vec!["demo".to_string()],
                hostname: Some("demo.example.com".to_string()),
                tag: Some("ops".to_string()),
                ..HostEntry::default()
            },
        };
        let mut form = EntryForm::from_entry(&entry, None);
        form.active_field = FormField::SshTag;
        form.clear_active_field();

        let args = form.build_edit_args().unwrap();
        assert_eq!(args.ssh_tag, None);
        assert!(args.clear_ssh_tag);
    }

    #[test]
    fn selected_entry_ignores_stale_filtered_indices() {
        let mut state = test_state(test_paths("stale-selection"));
        state.entries = vec![ManagedEntry {
            order: 10,
            slug: "alpha".to_string(),
            path: "010-host-alpha.conf".into(),
            raw_content: String::new(),
            entry: sample_host("alpha", "alpha.example.com"),
        }];
        state.raw_contents = vec![String::new()];
        state.metadata_state = MetadataState::default();
        state.filtered_indices = vec![1];
        state.selected_filtered_index = 0;

        assert_eq!(state.selected_entry_index(), None);
        assert!(state.selected_entry().is_none());
    }

    #[test]
    fn reload_preserving_keeps_selected_host_across_reorder() {
        let paths = test_paths("reload-preserve-host");
        paths.ensure_base_dirs().unwrap();

        store::save_entry(&paths, &sample_host("alpha", "alpha.example.com"), Some(10)).unwrap();
        store::save_entry(&paths, &sample_host("beta", "beta.example.com"), Some(20)).unwrap();

        let mut state = test_state(paths.clone());
        state.select_last();
        assert_eq!(state.selected_host().as_deref(), Some("beta"));

        let reordered = state.entries.iter().rev().cloned().collect::<Vec<_>>();
        store::rewrite_entries(&paths, &reordered).unwrap();

        state.reload_preserving(None).unwrap();

        assert_eq!(state.selected_host().as_deref(), Some("beta"));
        assert_eq!(state.selected_visible_index(), Some(0));
    }
}
