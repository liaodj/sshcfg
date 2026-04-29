use std::collections::{BTreeMap, VecDeque};

use anyhow::Result;
use glob::Pattern;

use crate::core::model::{
    DirectiveOrigin, HostEntry, IgnoredScalarOverride, ManagedEntry, ResolvedDirectiveSource,
    ResolvedEntry,
};
use crate::core::openssh;
use crate::core::render;
use crate::core::root_config::{MatchContext, RootMatchBlock};

#[derive(Debug, Clone, Copy, Default)]
pub struct RootMatchResolveOptions<'a> {
    pub local_user: Option<&'a str>,
    pub current_user: Option<&'a str>,
    pub initial_tag: Option<&'a str>,
    pub ssh_version: Option<&'a str>,
    pub session_type: Option<&'a str>,
    pub command: Option<&'a str>,
    pub local_networks: &'a [String],
    pub is_canonical: bool,
    pub is_final: bool,
}

pub fn resolve_target(entries: &[ManagedEntry], target: &str) -> Result<ResolvedEntry> {
    resolve_target_with_root_matches(entries, target, &[])
}

pub fn resolve_target_with_root_matches(
    entries: &[ManagedEntry],
    target: &str,
    root_match_blocks: &[RootMatchBlock],
) -> Result<ResolvedEntry> {
    let local_user = crate::core::root_config::detect_local_username();
    let local_networks = crate::core::root_config::detect_local_networks();
    let ssh_version = root_match_blocks
        .iter()
        .any(crate::core::root_config::block_uses_ssh_version)
        .then(openssh::detect_match_version_string)
        .flatten();
    resolve_target_with_root_matches_and_options(
        entries,
        target,
        root_match_blocks,
        RootMatchResolveOptions {
            local_user: (!local_user.is_empty()).then_some(local_user.as_str()),
            current_user: None,
            initial_tag: None,
            ssh_version: ssh_version.as_deref(),
            session_type: Some("shell"),
            command: Some(""),
            local_networks: &local_networks,
            is_canonical: false,
            is_final: true,
        },
    )
}

pub fn resolve_target_with_root_matches_and_options(
    entries: &[ManagedEntry],
    target: &str,
    root_match_blocks: &[RootMatchBlock],
    options: RootMatchResolveOptions<'_>,
) -> Result<ResolvedEntry> {
    let mut matched_entries = Vec::new();
    let mut merged_entry = HostEntry {
        host_patterns: vec![target.to_string()],
        ..HostEntry::default()
    };
    let mut raw_sources = Vec::new();
    let mut ignored_scalar_overrides = Vec::new();
    let mut root_match_notes = Vec::new();

    let mut hostname_source = None;
    let mut user_source = None;
    let mut port_source = None;
    let mut proxy_jump_source = None;
    let mut strict_host_key_checking_source = None;
    let mut user_known_hosts_file_source = None;
    let mut host_key_algorithms_source = None;
    let mut pubkey_accepted_algorithms_source = None;
    let mut forward_agent_source = None;
    let mut tag_source = None;

    for block in root_match_blocks
        .iter()
        .filter(|block| block.appears_before_managed_anchor)
    {
        apply_root_match_block(
            block,
            target,
            &mut merged_entry,
            &mut hostname_source,
            &mut user_source,
            &mut port_source,
            &mut proxy_jump_source,
            &mut strict_host_key_checking_source,
            &mut user_known_hosts_file_source,
            &mut host_key_algorithms_source,
            &mut pubkey_accepted_algorithms_source,
            &mut forward_agent_source,
            &mut tag_source,
            &mut raw_sources,
            &mut ignored_scalar_overrides,
            &mut root_match_notes,
            options,
        )?;
    }

    for entry in entries {
        if !entry_matches_target(&entry.entry, target)? {
            continue;
        }

        matched_entries.push(entry.clone());

        apply_scalar_string(
            &mut merged_entry.hostname,
            entry.entry.hostname.as_ref(),
            "HostName",
            entry,
            &mut hostname_source,
            &mut raw_sources,
            &mut ignored_scalar_overrides,
        );
        apply_scalar_string(
            &mut merged_entry.user,
            entry.entry.user.as_ref(),
            "User",
            entry,
            &mut user_source,
            &mut raw_sources,
            &mut ignored_scalar_overrides,
        );
        apply_scalar_u16(
            &mut merged_entry.port,
            entry.entry.port,
            "Port",
            entry,
            &mut port_source,
            &mut raw_sources,
            &mut ignored_scalar_overrides,
        );
        apply_scalar_string(
            &mut merged_entry.proxy_jump,
            entry.entry.proxy_jump.as_ref(),
            "ProxyJump",
            entry,
            &mut proxy_jump_source,
            &mut raw_sources,
            &mut ignored_scalar_overrides,
        );
        apply_scalar_string(
            &mut merged_entry.strict_host_key_checking,
            entry.entry.strict_host_key_checking.as_ref(),
            "StrictHostKeyChecking",
            entry,
            &mut strict_host_key_checking_source,
            &mut raw_sources,
            &mut ignored_scalar_overrides,
        );
        apply_scalar_string(
            &mut merged_entry.user_known_hosts_file,
            entry.entry.user_known_hosts_file.as_ref(),
            "UserKnownHostsFile",
            entry,
            &mut user_known_hosts_file_source,
            &mut raw_sources,
            &mut ignored_scalar_overrides,
        );
        apply_scalar_string(
            &mut merged_entry.host_key_algorithms,
            entry.entry.host_key_algorithms.as_ref(),
            "HostKeyAlgorithms",
            entry,
            &mut host_key_algorithms_source,
            &mut raw_sources,
            &mut ignored_scalar_overrides,
        );
        apply_scalar_string(
            &mut merged_entry.pubkey_accepted_algorithms,
            entry.entry.pubkey_accepted_algorithms.as_ref(),
            "PubkeyAcceptedAlgorithms",
            entry,
            &mut pubkey_accepted_algorithms_source,
            &mut raw_sources,
            &mut ignored_scalar_overrides,
        );
        apply_scalar_string(
            &mut merged_entry.forward_agent,
            entry.entry.forward_agent.as_ref(),
            "ForwardAgent",
            entry,
            &mut forward_agent_source,
            &mut raw_sources,
            &mut ignored_scalar_overrides,
        );
        apply_scalar_string(
            &mut merged_entry.tag,
            entry.entry.tag.as_ref(),
            "Tag",
            entry,
            &mut tag_source,
            &mut raw_sources,
            &mut ignored_scalar_overrides,
        );

        append_values(
            &mut merged_entry.identity_files,
            &entry.entry.identity_files,
            "IdentityFile",
            entry,
            &mut raw_sources,
        );
        append_values(
            &mut merged_entry.local_forwards,
            &entry.entry.local_forwards,
            "LocalForward",
            entry,
            &mut raw_sources,
        );
        append_values(
            &mut merged_entry.remote_forwards,
            &entry.entry.remote_forwards,
            "RemoteForward",
            entry,
            &mut raw_sources,
        );
        for (key, value) in &entry.entry.extra_options {
            merged_entry
                .extra_options
                .push((key.clone(), value.clone()));
            raw_sources.push(make_source(key, value, entry));
        }
    }

    for block in root_match_blocks
        .iter()
        .filter(|block| !block.appears_before_managed_anchor)
    {
        apply_root_match_block(
            block,
            target,
            &mut merged_entry,
            &mut hostname_source,
            &mut user_source,
            &mut port_source,
            &mut proxy_jump_source,
            &mut strict_host_key_checking_source,
            &mut user_known_hosts_file_source,
            &mut host_key_algorithms_source,
            &mut pubkey_accepted_algorithms_source,
            &mut forward_agent_source,
            &mut tag_source,
            &mut raw_sources,
            &mut ignored_scalar_overrides,
            &mut root_match_notes,
            options,
        )?;
    }

    let directive_sources = order_directive_sources(&merged_entry, raw_sources);

    Ok(ResolvedEntry {
        target: target.to_string(),
        matched_entries,
        merged_entry,
        directive_sources,
        ignored_scalar_overrides,
        root_match_notes,
    })
}

#[allow(clippy::too_many_arguments)]
fn apply_root_match_block(
    block: &RootMatchBlock,
    target: &str,
    merged_entry: &mut HostEntry,
    hostname_source: &mut Option<ResolvedDirectiveSource>,
    user_source: &mut Option<ResolvedDirectiveSource>,
    port_source: &mut Option<ResolvedDirectiveSource>,
    proxy_jump_source: &mut Option<ResolvedDirectiveSource>,
    strict_host_key_checking_source: &mut Option<ResolvedDirectiveSource>,
    user_known_hosts_file_source: &mut Option<ResolvedDirectiveSource>,
    host_key_algorithms_source: &mut Option<ResolvedDirectiveSource>,
    pubkey_accepted_algorithms_source: &mut Option<ResolvedDirectiveSource>,
    forward_agent_source: &mut Option<ResolvedDirectiveSource>,
    tag_source: &mut Option<ResolvedDirectiveSource>,
    raw_sources: &mut Vec<ResolvedDirectiveSource>,
    ignored_scalar_overrides: &mut Vec<IgnoredScalarOverride>,
    root_match_notes: &mut Vec<String>,
    options: RootMatchResolveOptions<'_>,
) -> Result<()> {
    if !block.unsupported_conditions.is_empty() {
        root_match_notes.push(format!(
            "root Match lines {}-{} skipped: unsupported conditions {}",
            block.start_line,
            block.end_line,
            block.unsupported_conditions.join(", ")
        ));
        return Ok(());
    }

    if crate::core::root_config::block_uses_ssh_version(block) && options.ssh_version.is_none() {
        root_match_notes.push(format!(
            "root Match lines {}-{} skipped: ssh version unavailable for Match version evaluation",
            block.start_line, block.end_line
        ));
        return Ok(());
    }

    let context = MatchContext::new(
        target,
        merged_entry.hostname.as_deref().unwrap_or(target),
        merged_entry
            .user
            .as_deref()
            .or(options.current_user)
            .or(options.local_user),
        options.local_user,
        merged_entry.tag.as_deref().or(options.initial_tag),
        options.ssh_version,
        options.session_type,
        options.command,
        options.local_networks,
        options.is_canonical,
        options.is_final,
    );

    if !crate::core::root_config::match_block_applies(block, &context)? {
        return Ok(());
    }

    root_match_notes.push(format!(
        "root Match lines {}-{} applied: {}",
        block.start_line,
        block.end_line,
        block.raw.lines().next().unwrap_or("Match <unknown>").trim()
    ));

    apply_root_match_scalar_string(
        &mut merged_entry.hostname,
        block.entry.hostname.as_ref(),
        hostname_source,
        raw_sources,
        ignored_scalar_overrides,
        block,
        "HostName",
    );
    apply_root_match_scalar_string(
        &mut merged_entry.user,
        block.entry.user.as_ref(),
        user_source,
        raw_sources,
        ignored_scalar_overrides,
        block,
        "User",
    );
    apply_root_match_scalar_u16(
        &mut merged_entry.port,
        block.entry.port,
        port_source,
        raw_sources,
        ignored_scalar_overrides,
        block,
        "Port",
    );
    apply_root_match_scalar_string(
        &mut merged_entry.proxy_jump,
        block.entry.proxy_jump.as_ref(),
        proxy_jump_source,
        raw_sources,
        ignored_scalar_overrides,
        block,
        "ProxyJump",
    );
    apply_root_match_scalar_string(
        &mut merged_entry.strict_host_key_checking,
        block.entry.strict_host_key_checking.as_ref(),
        strict_host_key_checking_source,
        raw_sources,
        ignored_scalar_overrides,
        block,
        "StrictHostKeyChecking",
    );
    apply_root_match_scalar_string(
        &mut merged_entry.user_known_hosts_file,
        block.entry.user_known_hosts_file.as_ref(),
        user_known_hosts_file_source,
        raw_sources,
        ignored_scalar_overrides,
        block,
        "UserKnownHostsFile",
    );
    apply_root_match_scalar_string(
        &mut merged_entry.host_key_algorithms,
        block.entry.host_key_algorithms.as_ref(),
        host_key_algorithms_source,
        raw_sources,
        ignored_scalar_overrides,
        block,
        "HostKeyAlgorithms",
    );
    apply_root_match_scalar_string(
        &mut merged_entry.pubkey_accepted_algorithms,
        block.entry.pubkey_accepted_algorithms.as_ref(),
        pubkey_accepted_algorithms_source,
        raw_sources,
        ignored_scalar_overrides,
        block,
        "PubkeyAcceptedAlgorithms",
    );
    apply_root_match_scalar_string(
        &mut merged_entry.forward_agent,
        block.entry.forward_agent.as_ref(),
        forward_agent_source,
        raw_sources,
        ignored_scalar_overrides,
        block,
        "ForwardAgent",
    );
    apply_root_match_scalar_string(
        &mut merged_entry.tag,
        block.entry.tag.as_ref(),
        tag_source,
        raw_sources,
        ignored_scalar_overrides,
        block,
        "Tag",
    );

    append_root_match_values(
        &mut merged_entry.identity_files,
        &block.entry.identity_files,
        "IdentityFile",
        block,
        raw_sources,
    );
    append_root_match_values(
        &mut merged_entry.local_forwards,
        &block.entry.local_forwards,
        "LocalForward",
        block,
        raw_sources,
    );
    append_root_match_values(
        &mut merged_entry.remote_forwards,
        &block.entry.remote_forwards,
        "RemoteForward",
        block,
        raw_sources,
    );
    for (key, value) in &block.entry.extra_options {
        merged_entry
            .extra_options
            .push((key.clone(), value.clone()));
        raw_sources.push(make_root_match_source(key, value, block));
    }

    Ok(())
}

pub fn describe_resolved_target(resolved: &ResolvedEntry) -> String {
    describe_resolved_target_lines(resolved)
        .join("\n")
        .trim_end()
        .to_string()
}

pub fn describe_resolved_target_lines(resolved: &ResolvedEntry) -> Vec<String> {
    let mut lines = Vec::new();
    lines.push(format!("target: {}", resolved.target));
    lines.push("matched entries:".to_string());
    for entry in &resolved.matched_entries {
        lines.push(format!(
            "  - order={} kind={} host={} file={}",
            entry.order,
            entry.entry.kind().label(),
            entry.entry.host_patterns.join(","),
            entry.path.display()
        ));
    }

    lines.push(String::new());
    lines.push("merged view:".to_string());
    lines.extend(
        render::render_host_entry(&resolved.merged_entry, "\n")
            .trim_end()
            .lines()
            .map(ToString::to_string),
    );

    if !resolved.directive_sources.is_empty() {
        lines.push(String::new());
        lines.push("field sources:".to_string());
        for source in &resolved.directive_sources {
            lines.push(format!(
                "  - {} = {} <- {:03} {} {} ({})",
                source.key,
                source.value,
                source.origin.order,
                source.origin.entry_kind.label(),
                source.origin.host_patterns.join(","),
                source.origin.path.display()
            ));
        }
    }

    if !resolved.ignored_scalar_overrides.is_empty() {
        lines.push(String::new());
        lines.push("ignored scalar assignments:".to_string());
        for override_note in &resolved.ignored_scalar_overrides {
            lines.push(format!(
                "  - {} = {} from {:03} {} {} ({}) ignored; locked by {:03} {} {} ({}) -> {}",
                override_note.key,
                override_note.attempted_value,
                override_note.attempted_origin.order,
                override_note.attempted_origin.entry_kind.label(),
                override_note.attempted_origin.host_patterns.join(","),
                override_note.attempted_origin.path.display(),
                override_note.winning_origin.order,
                override_note.winning_origin.entry_kind.label(),
                override_note.winning_origin.host_patterns.join(","),
                override_note.winning_origin.path.display(),
                override_note.winning_value,
            ));
        }
    }

    if !resolved.root_match_notes.is_empty() {
        lines.push(String::new());
        lines.push("root Match notes:".to_string());
        for note in &resolved.root_match_notes {
            lines.push(format!("  - {note}"));
        }
    }

    lines
}

fn order_directive_sources(
    merged_entry: &HostEntry,
    raw_sources: Vec<ResolvedDirectiveSource>,
) -> Vec<ResolvedDirectiveSource> {
    let mut lookup = BTreeMap::<(String, String), VecDeque<ResolvedDirectiveSource>>::new();

    for source in raw_sources {
        lookup
            .entry((source.key.to_ascii_lowercase(), source.value.clone()))
            .or_default()
            .push_back(source);
    }

    let mut ordered = Vec::new();
    for (key, value) in render::directives(merged_entry) {
        if key.eq_ignore_ascii_case("Host") {
            continue;
        }

        if let Some(source) = lookup
            .get_mut(&(key.to_ascii_lowercase(), value.clone()))
            .and_then(VecDeque::pop_front)
        {
            ordered.push(source);
        }
    }

    ordered
}

fn apply_scalar_string(
    slot: &mut Option<String>,
    candidate: Option<&String>,
    key: &str,
    entry: &ManagedEntry,
    winning_source: &mut Option<ResolvedDirectiveSource>,
    raw_sources: &mut Vec<ResolvedDirectiveSource>,
    ignored_scalar_overrides: &mut Vec<IgnoredScalarOverride>,
) {
    let Some(value) = candidate else {
        return;
    };

    let source = make_source(key, value, entry);
    if slot.is_none() {
        *slot = Some(value.clone());
        raw_sources.push(source.clone());
        *winning_source = Some(source);
    } else if let Some(winning_source) = winning_source.as_ref() {
        ignored_scalar_overrides.push(IgnoredScalarOverride {
            key: key.to_string(),
            attempted_value: value.clone(),
            attempted_origin: source.origin,
            winning_value: winning_source.value.clone(),
            winning_origin: winning_source.origin.clone(),
        });
    }
}

fn apply_scalar_u16(
    slot: &mut Option<u16>,
    candidate: Option<u16>,
    key: &str,
    entry: &ManagedEntry,
    winning_source: &mut Option<ResolvedDirectiveSource>,
    raw_sources: &mut Vec<ResolvedDirectiveSource>,
    ignored_scalar_overrides: &mut Vec<IgnoredScalarOverride>,
) {
    let Some(value) = candidate else {
        return;
    };

    let rendered = value.to_string();
    let source = make_source(key, &rendered, entry);
    if slot.is_none() {
        *slot = Some(value);
        raw_sources.push(source.clone());
        *winning_source = Some(source);
    } else if let Some(winning_source) = winning_source.as_ref() {
        ignored_scalar_overrides.push(IgnoredScalarOverride {
            key: key.to_string(),
            attempted_value: rendered,
            attempted_origin: source.origin,
            winning_value: winning_source.value.clone(),
            winning_origin: winning_source.origin.clone(),
        });
    }
}

fn append_values(
    target: &mut Vec<String>,
    values: &[String],
    key: &str,
    entry: &ManagedEntry,
    raw_sources: &mut Vec<ResolvedDirectiveSource>,
) {
    for value in values {
        target.push(value.clone());
        raw_sources.push(make_source(key, value, entry));
    }
}

fn apply_root_match_scalar_string(
    slot: &mut Option<String>,
    candidate: Option<&String>,
    winning_source: &mut Option<ResolvedDirectiveSource>,
    raw_sources: &mut Vec<ResolvedDirectiveSource>,
    ignored_scalar_overrides: &mut Vec<IgnoredScalarOverride>,
    block: &RootMatchBlock,
    key: &str,
) {
    let Some(value) = candidate else {
        return;
    };

    let source = make_root_match_source(key, value, block);
    if slot.is_none() {
        *slot = Some(value.clone());
        raw_sources.push(source.clone());
        *winning_source = Some(source);
    } else if let Some(winning_source) = winning_source.as_ref() {
        ignored_scalar_overrides.push(IgnoredScalarOverride {
            key: key.to_string(),
            attempted_value: value.clone(),
            attempted_origin: source.origin,
            winning_value: winning_source.value.clone(),
            winning_origin: winning_source.origin.clone(),
        });
    }
}

fn apply_root_match_scalar_u16(
    slot: &mut Option<u16>,
    candidate: Option<u16>,
    winning_source: &mut Option<ResolvedDirectiveSource>,
    raw_sources: &mut Vec<ResolvedDirectiveSource>,
    ignored_scalar_overrides: &mut Vec<IgnoredScalarOverride>,
    block: &RootMatchBlock,
    key: &str,
) {
    let Some(value) = candidate else {
        return;
    };

    let rendered = value.to_string();
    let source = make_root_match_source(key, &rendered, block);
    if slot.is_none() {
        *slot = Some(value);
        raw_sources.push(source.clone());
        *winning_source = Some(source);
    } else if let Some(winning_source) = winning_source.as_ref() {
        ignored_scalar_overrides.push(IgnoredScalarOverride {
            key: key.to_string(),
            attempted_value: rendered,
            attempted_origin: source.origin,
            winning_value: winning_source.value.clone(),
            winning_origin: winning_source.origin.clone(),
        });
    }
}

fn append_root_match_values(
    target: &mut Vec<String>,
    values: &[String],
    key: &str,
    block: &RootMatchBlock,
    raw_sources: &mut Vec<ResolvedDirectiveSource>,
) {
    for value in values {
        target.push(value.clone());
        raw_sources.push(make_root_match_source(key, value, block));
    }
}

fn make_source(key: &str, value: &str, entry: &ManagedEntry) -> ResolvedDirectiveSource {
    ResolvedDirectiveSource {
        key: key.to_string(),
        value: value.to_string(),
        origin: DirectiveOrigin {
            order: entry.order,
            entry_kind: entry.entry.kind(),
            host_patterns: entry.entry.host_patterns.clone(),
            path: entry.path.clone(),
        },
    }
}

fn make_root_match_source(
    key: &str,
    value: &str,
    block: &RootMatchBlock,
) -> ResolvedDirectiveSource {
    ResolvedDirectiveSource {
        key: key.to_string(),
        value: value.to_string(),
        origin: DirectiveOrigin {
            order: u16::try_from(block.start_line).unwrap_or(u16::MAX),
            entry_kind: crate::core::model::EntryKind::Pattern,
            host_patterns: vec![
                block
                    .raw
                    .lines()
                    .next()
                    .unwrap_or("Match <unknown>")
                    .trim()
                    .to_string(),
            ],
            path: format!("<root-config:{}-{}>", block.start_line, block.end_line).into(),
        },
    }
}

fn entry_matches_target(entry: &HostEntry, target: &str) -> Result<bool> {
    let mut positive_match = false;

    for raw_pattern in &entry.host_patterns {
        if let Some(pattern) = raw_pattern.strip_prefix('!') {
            if Pattern::new(pattern)?.matches(target) {
                return Ok(false);
            }
            continue;
        }

        if Pattern::new(raw_pattern)?.matches(target) {
            positive_match = true;
        }
    }

    Ok(positive_match)
}

#[cfg(test)]
mod tests {
    use crate::core::model::{HostEntry, ManagedEntry};
    use crate::core::root_config;
    use crate::fs::layout::managed_block;

    use super::{
        RootMatchResolveOptions, describe_resolved_target, resolve_target,
        resolve_target_with_root_matches, resolve_target_with_root_matches_and_options,
    };

    #[test]
    fn resolves_pattern_then_exact_entry() {
        let pattern = ManagedEntry {
            order: 10,
            slug: "bs-star".to_string(),
            path: "010-pattern-bs-star.conf".into(),
            raw_content: String::new(),
            entry: HostEntry {
                host_patterns: vec!["bs-*".to_string()],
                user: Some("builder".to_string()),
                remote_forwards: vec!["9090 127.0.0.1:90".to_string()],
                ..HostEntry::default()
            },
        };
        let exact = ManagedEntry {
            order: 20,
            slug: "bs-215".to_string(),
            path: "020-host-bs-215.conf".into(),
            raw_content: String::new(),
            entry: HostEntry {
                host_patterns: vec!["bs-215".to_string()],
                hostname: Some("172.16.0.215".to_string()),
                ..HostEntry::default()
            },
        };

        let resolved = resolve_target(&[pattern, exact], "bs-215").unwrap();

        assert_eq!(resolved.matched_entries.len(), 2);
        assert_eq!(resolved.merged_entry.user.as_deref(), Some("builder"));
        assert_eq!(
            resolved.merged_entry.hostname.as_deref(),
            Some("172.16.0.215")
        );
        assert_eq!(
            resolved.merged_entry.remote_forwards,
            vec!["9090 127.0.0.1:90"]
        );
        assert!(
            resolved
                .directive_sources
                .iter()
                .any(|source| source.key == "HostName" && source.origin.order == 20)
        );
    }

    #[test]
    fn captures_ignored_scalar_overrides_and_describes_them() {
        let pattern = ManagedEntry {
            order: 10,
            slug: "bs-star".to_string(),
            path: "010-pattern-bs-star.conf".into(),
            raw_content: String::new(),
            entry: HostEntry {
                host_patterns: vec!["bs-*".to_string()],
                user: Some("builder".to_string()),
                ..HostEntry::default()
            },
        };
        let exact = ManagedEntry {
            order: 20,
            slug: "bs-215".to_string(),
            path: "020-host-bs-215.conf".into(),
            raw_content: String::new(),
            entry: HostEntry {
                host_patterns: vec!["bs-215".to_string()],
                user: Some("root".to_string()),
                hostname: Some("172.16.0.215".to_string()),
                ..HostEntry::default()
            },
        };

        let resolved = resolve_target(&[pattern, exact], "bs-215").unwrap();
        let rendered = describe_resolved_target(&resolved);

        assert_eq!(resolved.ignored_scalar_overrides.len(), 1);
        assert_eq!(resolved.ignored_scalar_overrides[0].key, "User");
        assert_eq!(
            resolved.ignored_scalar_overrides[0].attempted_value,
            "root".to_string()
        );
        assert!(rendered.contains("ignored scalar assignments:"));
        assert!(rendered.contains("locked by 010 pattern bs-*"));
    }

    #[test]
    fn applies_root_match_all_after_managed_entries_in_preview() {
        let exact = ManagedEntry {
            order: 20,
            slug: "demo".to_string(),
            path: "020-host-demo.conf".into(),
            raw_content: String::new(),
            entry: HostEntry {
                host_patterns: vec!["demo".to_string()],
                hostname: Some("demo.example.com".to_string()),
                ..HostEntry::default()
            },
        };
        let root_match_blocks = root_config::extract_match_blocks(&format!(
            "{}Match all\n  ForwardAgent no\n",
            managed_block("\n")
        ));

        let resolved =
            resolve_target_with_root_matches(&[exact], "demo", &root_match_blocks).unwrap();

        assert_eq!(resolved.merged_entry.forward_agent.as_deref(), Some("no"));
        assert!(
            resolved
                .root_match_notes
                .iter()
                .any(|note| note.contains("Match all"))
        );
    }

    #[test]
    fn root_match_before_anchor_can_lock_scalar_before_managed_entries() {
        let exact = ManagedEntry {
            order: 20,
            slug: "demo".to_string(),
            path: "020-host-demo.conf".into(),
            raw_content: String::new(),
            entry: HostEntry {
                host_patterns: vec!["demo".to_string()],
                hostname: Some("demo.example.com".to_string()),
                user: Some("builder".to_string()),
                ..HostEntry::default()
            },
        };
        let root_match_blocks = root_config::extract_match_blocks(
            "\
Match host demo
  User root
",
        );

        let resolved =
            resolve_target_with_root_matches(&[exact], "demo", &root_match_blocks).unwrap();

        assert_eq!(resolved.merged_entry.user.as_deref(), Some("root"));
        assert!(
            resolved
                .ignored_scalar_overrides
                .iter()
                .any(|item| item.key == "User" && item.attempted_value == "builder")
        );
    }

    #[test]
    fn root_match_host_uses_current_hostname_context() {
        let exact = ManagedEntry {
            order: 20,
            slug: "demo".to_string(),
            path: "020-host-demo.conf".into(),
            raw_content: String::new(),
            entry: HostEntry {
                host_patterns: vec!["demo".to_string()],
                hostname: Some("demo.example.com".to_string()),
                ..HostEntry::default()
            },
        };
        let root_match_blocks = root_config::extract_match_blocks(&format!(
            "{}Match host demo.example.com\n  ForwardAgent no\n",
            managed_block("\n")
        ));

        let resolved =
            resolve_target_with_root_matches(&[exact], "demo", &root_match_blocks).unwrap();

        assert_eq!(resolved.merged_entry.forward_agent.as_deref(), Some("no"));
        assert!(
            resolved
                .root_match_notes
                .iter()
                .any(|note| note.contains("Match host demo.example.com"))
        );
    }

    #[test]
    fn root_match_user_can_use_managed_user_current_user_or_local_user_context() {
        let exact = ManagedEntry {
            order: 20,
            slug: "demo".to_string(),
            path: "020-host-demo.conf".into(),
            raw_content: String::new(),
            entry: HostEntry {
                host_patterns: vec!["demo".to_string()],
                user: Some("builder".to_string()),
                ..HostEntry::default()
            },
        };
        let root_match_blocks = root_config::extract_match_blocks(&format!(
            "{}Match user builder\n  ForwardAgent no\n",
            managed_block("\n")
        ));

        let resolved = resolve_target_with_root_matches_and_options(
            &[exact],
            "demo",
            &root_match_blocks,
            RootMatchResolveOptions {
                local_user: Some("alice"),
                current_user: None,
                initial_tag: None,
                ssh_version: Some("OpenSSH_for_Windows_9.5p1"),
                session_type: Some("shell"),
                command: Some(""),
                local_networks: &[],
                is_canonical: false,
                is_final: true,
            },
        )
        .unwrap();

        assert_eq!(resolved.merged_entry.forward_agent.as_deref(), Some("no"));

        let current_user_only_blocks = root_config::extract_match_blocks(
            "\
Match user deploy
  ForwardAgent ask
",
        );
        let resolved = resolve_target_with_root_matches_and_options(
            &[],
            "demo",
            &current_user_only_blocks,
            RootMatchResolveOptions {
                local_user: Some("alice"),
                current_user: Some("deploy"),
                initial_tag: None,
                ssh_version: Some("OpenSSH_for_Windows_9.5p1"),
                session_type: Some("shell"),
                command: Some(""),
                local_networks: &[],
                is_canonical: false,
                is_final: true,
            },
        )
        .unwrap();

        assert_eq!(resolved.merged_entry.forward_agent.as_deref(), Some("ask"));

        let local_user_only_blocks = root_config::extract_match_blocks(
            "\
Match localuser alice
  ProxyJump jump-box
",
        );
        let resolved = resolve_target_with_root_matches_and_options(
            &[],
            "demo",
            &local_user_only_blocks,
            RootMatchResolveOptions {
                local_user: Some("alice"),
                current_user: None,
                initial_tag: None,
                ssh_version: Some("OpenSSH_for_Windows_9.5p1"),
                session_type: Some("shell"),
                command: Some(""),
                local_networks: &[],
                is_canonical: false,
                is_final: true,
            },
        )
        .unwrap();

        assert_eq!(
            resolved.merged_entry.proxy_jump.as_deref(),
            Some("jump-box")
        );
    }

    #[test]
    fn root_match_version_uses_ssh_version_context() {
        let exact = ManagedEntry {
            order: 20,
            slug: "demo".to_string(),
            path: "020-host-demo.conf".into(),
            raw_content: String::new(),
            entry: HostEntry {
                host_patterns: vec!["demo".to_string()],
                hostname: Some("demo.example.com".to_string()),
                ..HostEntry::default()
            },
        };
        let root_match_blocks = root_config::extract_match_blocks(&format!(
            "{}Match version OpenSSH_for_Windows_* !version OpenSSH_for_Windows_8.*\n  ForwardAgent no\n",
            managed_block("\n")
        ));

        let resolved = resolve_target_with_root_matches_and_options(
            &[exact.clone()],
            "demo",
            &root_match_blocks,
            RootMatchResolveOptions {
                local_user: Some("alice"),
                current_user: None,
                initial_tag: None,
                ssh_version: Some("OpenSSH_for_Windows_9.5p1"),
                session_type: Some("shell"),
                command: Some(""),
                local_networks: &[],
                is_canonical: false,
                is_final: true,
            },
        )
        .unwrap();
        assert_eq!(resolved.merged_entry.forward_agent.as_deref(), Some("no"));

        let not_matching = resolve_target_with_root_matches_and_options(
            &[exact],
            "demo",
            &root_match_blocks,
            RootMatchResolveOptions {
                local_user: Some("alice"),
                current_user: None,
                initial_tag: None,
                ssh_version: Some("OpenSSH_for_Windows_8.9p1"),
                session_type: Some("shell"),
                command: Some(""),
                local_networks: &[],
                is_canonical: false,
                is_final: true,
            },
        )
        .unwrap();
        assert_eq!(not_matching.merged_entry.forward_agent, None);

        let missing_version = resolve_target_with_root_matches_and_options(
            &[],
            "demo",
            &root_match_blocks,
            RootMatchResolveOptions {
                local_user: Some("alice"),
                current_user: None,
                initial_tag: None,
                ssh_version: None,
                session_type: Some("shell"),
                command: Some(""),
                local_networks: &[],
                is_canonical: false,
                is_final: true,
            },
        )
        .unwrap();
        assert!(
            missing_version
                .root_match_notes
                .iter()
                .any(|note| note.contains("ssh version unavailable"))
        );
    }

    #[test]
    fn root_match_canonical_uses_options_context() {
        let exact = ManagedEntry {
            order: 20,
            slug: "demo".to_string(),
            path: "020-host-demo.conf".into(),
            raw_content: String::new(),
            entry: HostEntry {
                host_patterns: vec!["demo".to_string()],
                hostname: Some("demo.example.com".to_string()),
                ..HostEntry::default()
            },
        };
        let root_match_blocks = root_config::extract_match_blocks(&format!(
            "{}Match canonical\n  ForwardAgent no\n",
            managed_block("\n")
        ));

        let resolved = resolve_target_with_root_matches_and_options(
            &[exact.clone()],
            "demo",
            &root_match_blocks,
            RootMatchResolveOptions {
                local_user: Some("alice"),
                current_user: None,
                initial_tag: None,
                ssh_version: Some("OpenSSH_for_Windows_9.5p1"),
                session_type: Some("shell"),
                command: Some(""),
                local_networks: &[],
                is_canonical: true,
                is_final: true,
            },
        )
        .unwrap();
        assert_eq!(resolved.merged_entry.forward_agent.as_deref(), Some("no"));

        let not_matching = resolve_target_with_root_matches_and_options(
            &[exact],
            "demo",
            &root_match_blocks,
            RootMatchResolveOptions {
                local_user: Some("alice"),
                current_user: None,
                initial_tag: None,
                ssh_version: Some("OpenSSH_for_Windows_9.5p1"),
                session_type: Some("shell"),
                command: Some(""),
                local_networks: &[],
                is_canonical: false,
                is_final: true,
            },
        )
        .unwrap();
        assert_eq!(not_matching.merged_entry.forward_agent, None);
    }

    #[test]
    fn root_match_tagged_uses_current_tag_from_prior_entries() {
        let pattern = ManagedEntry {
            order: 10,
            slug: "demo-star".to_string(),
            path: "010-pattern-demo-star.conf".into(),
            raw_content: String::new(),
            entry: HostEntry {
                host_patterns: vec!["demo-*".to_string()],
                tag: Some("ops".to_string()),
                ..HostEntry::default()
            },
        };
        let exact = ManagedEntry {
            order: 20,
            slug: "demo".to_string(),
            path: "020-host-demo.conf".into(),
            raw_content: String::new(),
            entry: HostEntry {
                host_patterns: vec!["demo-1".to_string()],
                hostname: Some("demo.example.com".to_string()),
                ..HostEntry::default()
            },
        };
        let root_match_blocks = root_config::extract_match_blocks(&format!(
            "{}Match tagged ops\n  ForwardAgent no\nMatch tagged \"\"\n  ProxyJump jump-box\n",
            managed_block("\n")
        ));

        let resolved = resolve_target_with_root_matches_and_options(
            &[pattern, exact],
            "demo-1",
            &root_match_blocks,
            RootMatchResolveOptions {
                local_user: Some("alice"),
                current_user: None,
                initial_tag: None,
                ssh_version: Some("OpenSSH_for_Windows_9.5p1"),
                session_type: Some("shell"),
                command: Some(""),
                local_networks: &[],
                is_canonical: false,
                is_final: true,
            },
        )
        .unwrap();

        assert_eq!(resolved.merged_entry.tag.as_deref(), Some("ops"));
        assert_eq!(resolved.merged_entry.forward_agent.as_deref(), Some("no"));
        assert_eq!(resolved.merged_entry.proxy_jump, None);
    }

    #[test]
    fn root_match_sessiontype_and_command_use_options_context() {
        let exact = ManagedEntry {
            order: 20,
            slug: "demo".to_string(),
            path: "020-host-demo.conf".into(),
            raw_content: String::new(),
            entry: HostEntry {
                host_patterns: vec!["demo".to_string()],
                hostname: Some("demo.example.com".to_string()),
                ..HostEntry::default()
            },
        };
        let root_match_blocks = root_config::extract_match_blocks(&format!(
            "{}Match sessiontype shell command \"git status\"\n  ForwardAgent no\n",
            managed_block("\n")
        ));

        let resolved = resolve_target_with_root_matches_and_options(
            &[exact.clone()],
            "demo",
            &root_match_blocks,
            RootMatchResolveOptions {
                local_user: Some("alice"),
                current_user: None,
                initial_tag: None,
                ssh_version: Some("OpenSSH_for_Windows_9.5p1"),
                session_type: Some("shell"),
                command: Some("git status"),
                local_networks: &[],
                is_canonical: false,
                is_final: true,
            },
        )
        .unwrap();
        assert_eq!(resolved.merged_entry.forward_agent.as_deref(), Some("no"));

        let not_matching = resolve_target_with_root_matches_and_options(
            &[exact],
            "demo",
            &root_match_blocks,
            RootMatchResolveOptions {
                local_user: Some("alice"),
                current_user: None,
                initial_tag: None,
                ssh_version: Some("OpenSSH_for_Windows_9.5p1"),
                session_type: Some("exec"),
                command: Some("git fetch"),
                local_networks: &[],
                is_canonical: false,
                is_final: true,
            },
        )
        .unwrap();
        assert_eq!(not_matching.merged_entry.forward_agent, None);
    }

    #[test]
    fn root_match_localnetwork_uses_options_context() {
        let exact = ManagedEntry {
            order: 20,
            slug: "demo".to_string(),
            path: "020-host-demo.conf".into(),
            raw_content: String::new(),
            entry: HostEntry {
                host_patterns: vec!["demo".to_string()],
                hostname: Some("demo.example.com".to_string()),
                ..HostEntry::default()
            },
        };
        let root_match_blocks = root_config::extract_match_blocks(&format!(
            "{}Match localnetwork 192.168.1.0/24\n  ForwardAgent no\n",
            managed_block("\n")
        ));
        let local_networks = vec!["192.168.1.42".to_string()];

        let resolved = resolve_target_with_root_matches_and_options(
            &[exact.clone()],
            "demo",
            &root_match_blocks,
            RootMatchResolveOptions {
                local_user: Some("alice"),
                current_user: None,
                initial_tag: None,
                ssh_version: Some("OpenSSH_for_Windows_9.5p1"),
                session_type: Some("shell"),
                command: Some(""),
                local_networks: &local_networks,
                is_canonical: false,
                is_final: true,
            },
        )
        .unwrap();
        assert_eq!(resolved.merged_entry.forward_agent.as_deref(), Some("no"));

        let other_networks = vec!["10.0.0.2".to_string()];
        let not_matching = resolve_target_with_root_matches_and_options(
            &[exact],
            "demo",
            &root_match_blocks,
            RootMatchResolveOptions {
                local_user: Some("alice"),
                current_user: None,
                initial_tag: None,
                ssh_version: Some("OpenSSH_for_Windows_9.5p1"),
                session_type: Some("shell"),
                command: Some(""),
                local_networks: &other_networks,
                is_canonical: false,
                is_final: true,
            },
        )
        .unwrap();
        assert_eq!(not_matching.merged_entry.forward_agent, None);
    }
}
