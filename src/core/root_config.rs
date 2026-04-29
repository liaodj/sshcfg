use crate::fs::layout::{MANAGED_BLOCK_END, MANAGED_BLOCK_START, MANAGED_INCLUDE_LINE};
use anyhow::{Context, Result};
use glob::Pattern;
use std::net::IpAddr;
use std::process::Command;

use crate::core::model::HostEntry;
use crate::core::parser;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchContext<'a> {
    pub original_host: &'a str,
    pub current_host: &'a str,
    pub current_user: Option<&'a str>,
    pub local_user: Option<&'a str>,
    pub current_tag: Option<&'a str>,
    pub current_ssh_version: Option<&'a str>,
    pub session_type: Option<&'a str>,
    pub command: Option<&'a str>,
    pub local_networks: &'a [String],
    pub is_canonical: bool,
    pub is_final: bool,
}

impl<'a> MatchContext<'a> {
    pub fn new(
        original_host: &'a str,
        current_host: &'a str,
        current_user: Option<&'a str>,
        local_user: Option<&'a str>,
        current_tag: Option<&'a str>,
        current_ssh_version: Option<&'a str>,
        session_type: Option<&'a str>,
        command: Option<&'a str>,
        local_networks: &'a [String],
        is_canonical: bool,
        is_final: bool,
    ) -> Self {
        Self {
            original_host,
            current_host,
            current_user,
            local_user,
            current_tag,
            current_ssh_version,
            session_type,
            command,
            local_networks,
            is_canonical,
            is_final,
        }
    }

    #[cfg(test)]
    pub fn new_basic(
        original_host: &'a str,
        current_host: &'a str,
        current_user: Option<&'a str>,
        local_user: Option<&'a str>,
        current_tag: Option<&'a str>,
        current_ssh_version: Option<&'a str>,
        is_canonical: bool,
        is_final: bool,
    ) -> Self {
        Self::new(
            original_host,
            current_host,
            current_user,
            local_user,
            current_tag,
            current_ssh_version,
            None,
            None,
            &[],
            is_canonical,
            is_final,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootMatchBlock {
    pub raw: String,
    pub start_line: usize,
    pub end_line: usize,
    pub condition: MatchCondition,
    pub entry: HostEntry,
    pub unsupported_conditions: Vec<String>,
    pub appears_before_managed_anchor: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MatchCondition {
    Criteria(Vec<MatchCriterion>),
    Unsupported,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MatchCriterion {
    All {
        negated: bool,
    },
    Host {
        patterns: Vec<String>,
        negated: bool,
    },
    OriginalHost {
        patterns: Vec<String>,
        negated: bool,
    },
    User {
        patterns: Vec<String>,
        negated: bool,
    },
    LocalUser {
        patterns: Vec<String>,
        negated: bool,
    },
    Tagged {
        patterns: Vec<String>,
        negated: bool,
    },
    Version {
        patterns: Vec<String>,
        negated: bool,
    },
    Command {
        patterns: Vec<String>,
        negated: bool,
    },
    SessionType {
        patterns: Vec<String>,
        negated: bool,
    },
    LocalNetwork {
        patterns: Vec<String>,
        negated: bool,
    },
    Canonical {
        negated: bool,
    },
    Final {
        negated: bool,
    },
}

pub fn extract_match_blocks(content: &str) -> Vec<RootMatchBlock> {
    let lines: Vec<&str> = if content.is_empty() {
        Vec::new()
    } else {
        content.split_inclusive('\n').collect()
    };
    let mut blocks = Vec::new();
    let mut index = 0;
    let mut inside_managed_block = false;
    let mut saw_managed_anchor = false;

    while index < lines.len() {
        let trimmed = lines[index].trim();

        if inside_managed_block {
            if trimmed == MANAGED_BLOCK_END {
                inside_managed_block = false;
                saw_managed_anchor = true;
            }
            index += 1;
            continue;
        }

        if trimmed == MANAGED_BLOCK_START {
            inside_managed_block = true;
            index += 1;
            continue;
        }

        if trimmed.eq_ignore_ascii_case(MANAGED_INCLUDE_LINE) {
            saw_managed_anchor = true;
            index += 1;
            continue;
        }

        if directive_key(trimmed).is_some_and(|key| key.eq_ignore_ascii_case("Match")) {
            let mut raw = String::new();
            let start_line = index + 1;
            let mut end_line = start_line;
            let header = lines[index].trim().to_string();

            while index < lines.len() {
                let candidate = lines[index].trim();
                if !raw.is_empty()
                    && (candidate == MANAGED_BLOCK_START
                        || candidate.eq_ignore_ascii_case(MANAGED_INCLUDE_LINE)
                        || directive_key(candidate).is_some_and(|key| {
                            key.eq_ignore_ascii_case("Host") || key.eq_ignore_ascii_case("Match")
                        }))
                {
                    break;
                }

                raw.push_str(lines[index]);
                end_line = index + 1;
                index += 1;
            }

            let (condition, unsupported_conditions, entry) = match parse_match_block(&header, &raw)
            {
                Ok(value) => value,
                Err(err) => (
                    MatchCondition::Unsupported,
                    vec![err.to_string()],
                    HostEntry::default(),
                ),
            };

            blocks.push(RootMatchBlock {
                raw,
                start_line,
                end_line,
                condition,
                entry,
                unsupported_conditions,
                appears_before_managed_anchor: !saw_managed_anchor,
            });
            continue;
        }

        index += 1;
    }

    blocks
}

fn directive_key(line: &str) -> Option<&str> {
    let (key, value) = line.split_once(char::is_whitespace)?;
    (!value.trim().is_empty()).then_some(key)
}

fn parse_match_block(header: &str, raw: &str) -> Result<(MatchCondition, Vec<String>, HostEntry)> {
    let (key, body) = split_key_value(header).context("invalid Match header")?;
    if !key.eq_ignore_ascii_case("Match") {
        anyhow::bail!("not a Match header");
    }

    let (condition, unsupported_conditions) = parse_match_condition(body)?;
    let entry = parse_match_body(raw)?;
    Ok((condition, unsupported_conditions, entry))
}

fn parse_match_condition(header_body: &str) -> Result<(MatchCondition, Vec<String>)> {
    let owned_tokens = tokenize_match_header(header_body);
    let tokens: Vec<&str> = owned_tokens.iter().map(String::as_str).collect();
    if tokens.is_empty() {
        anyhow::bail!("empty Match condition");
    }

    let mut criteria = Vec::new();
    let mut unsupported_conditions = Vec::new();
    let mut index = 0;

    while index < tokens.len() {
        let token = tokens[index];
        match match_keyword(token) {
            Some(MatchKeyword::All) => {
                criteria.push(MatchCriterion::All {
                    negated: is_negated(token),
                });
                index += 1;
            }
            Some(MatchKeyword::Host) => {
                let patterns = collect_match_patterns(&tokens, &mut index)?;
                criteria.push(MatchCriterion::Host {
                    patterns,
                    negated: is_negated(token),
                });
            }
            Some(MatchKeyword::OriginalHost) => {
                let patterns = collect_match_patterns(&tokens, &mut index)?;
                criteria.push(MatchCriterion::OriginalHost {
                    patterns,
                    negated: is_negated(token),
                });
            }
            Some(MatchKeyword::User) => {
                let patterns = collect_match_patterns(&tokens, &mut index)?;
                criteria.push(MatchCriterion::User {
                    patterns,
                    negated: is_negated(token),
                });
            }
            Some(MatchKeyword::LocalUser) => {
                let patterns = collect_match_patterns(&tokens, &mut index)?;
                criteria.push(MatchCriterion::LocalUser {
                    patterns,
                    negated: is_negated(token),
                });
            }
            Some(MatchKeyword::Tagged) => {
                let patterns = collect_single_match_patterns_preserving_empty(&tokens, &mut index)?;
                criteria.push(MatchCriterion::Tagged {
                    patterns,
                    negated: is_negated(token),
                });
            }
            Some(MatchKeyword::Version) => {
                let patterns = collect_single_match_patterns(&tokens, &mut index)?;
                criteria.push(MatchCriterion::Version {
                    patterns,
                    negated: is_negated(token),
                });
            }
            Some(MatchKeyword::Command) => {
                let patterns = collect_single_match_patterns_preserving_empty(&tokens, &mut index)?;
                criteria.push(MatchCriterion::Command {
                    patterns,
                    negated: is_negated(token),
                });
            }
            Some(MatchKeyword::SessionType) => {
                let patterns = collect_single_match_patterns(&tokens, &mut index)?;
                criteria.push(MatchCriterion::SessionType {
                    patterns,
                    negated: is_negated(token),
                });
            }
            Some(MatchKeyword::LocalNetwork) => {
                let patterns = collect_single_match_patterns(&tokens, &mut index)?;
                criteria.push(MatchCriterion::LocalNetwork {
                    patterns,
                    negated: is_negated(token),
                });
            }
            Some(MatchKeyword::Canonical) => {
                criteria.push(MatchCriterion::Canonical {
                    negated: is_negated(token),
                });
                index += 1;
            }
            Some(MatchKeyword::Final) => {
                criteria.push(MatchCriterion::Final {
                    negated: is_negated(token),
                });
                index += 1;
            }
            Some(MatchKeyword::Unsupported) => {
                let mut chunk = vec![token.to_string()];
                index += 1;
                while index < tokens.len() && !is_match_keyword(tokens[index]) {
                    chunk.push(tokens[index].to_string());
                    index += 1;
                }
                unsupported_conditions.push(chunk.join(" "));
            }
            None => {
                let mut chunk = vec![token.to_string()];
                index += 1;
                while index < tokens.len() && !is_match_keyword(tokens[index]) {
                    chunk.push(tokens[index].to_string());
                    index += 1;
                }
                unsupported_conditions.push(chunk.join(" "));
            }
        }
    }

    if criteria.is_empty() {
        return Ok((MatchCondition::Unsupported, unsupported_conditions));
    }

    Ok((MatchCondition::Criteria(criteria), unsupported_conditions))
}

fn tokenize_match_header(input: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut quote: Option<char> = None;

    for ch in input.chars() {
        match quote {
            Some(active) => {
                current.push(ch);
                if ch == active {
                    quote = None;
                }
            }
            None if ch == '"' || ch == '\'' => {
                current.push(ch);
                quote = Some(ch);
            }
            None if ch.is_whitespace() => {
                if !current.is_empty() {
                    tokens.push(std::mem::take(&mut current));
                }
            }
            None => current.push(ch),
        }
    }

    if !current.is_empty() {
        tokens.push(current);
    }

    tokens
}

fn collect_match_patterns(tokens: &[&str], index: &mut usize) -> Result<Vec<String>> {
    collect_match_patterns_with_options(tokens, index, false)
}

fn collect_single_match_patterns(tokens: &[&str], index: &mut usize) -> Result<Vec<String>> {
    collect_single_match_patterns_with_options(tokens, index, false)
}

fn collect_single_match_patterns_preserving_empty(
    tokens: &[&str],
    index: &mut usize,
) -> Result<Vec<String>> {
    collect_single_match_patterns_with_options(tokens, index, true)
}

fn collect_match_patterns_with_options(
    tokens: &[&str],
    index: &mut usize,
    preserve_empty: bool,
) -> Result<Vec<String>> {
    *index += 1;
    let mut patterns = Vec::new();
    while *index < tokens.len() && !is_match_keyword(tokens[*index]) {
        patterns.extend(split_pattern_list(tokens[*index], preserve_empty));
        *index += 1;
    }

    if patterns.is_empty() {
        anyhow::bail!("Match criterion is missing patterns");
    }

    Ok(patterns)
}

fn collect_single_match_patterns_with_options(
    tokens: &[&str],
    index: &mut usize,
    preserve_empty: bool,
) -> Result<Vec<String>> {
    *index += 1;
    let Some(token) = tokens.get(*index) else {
        anyhow::bail!("Match criterion is missing patterns");
    };

    if is_supported_match_keyword(token) {
        anyhow::bail!("Match criterion is missing patterns");
    }

    let patterns = split_pattern_list(token, preserve_empty);
    if patterns.is_empty() {
        anyhow::bail!("Match criterion is missing patterns");
    }

    *index += 1;
    Ok(patterns)
}

fn split_pattern_list(token: &str, preserve_empty: bool) -> Vec<String> {
    token
        .split(',')
        .map(str::trim)
        .map(normalize_match_pattern_value)
        .filter(|value| preserve_empty || !value.is_empty())
        .collect()
}

fn normalize_match_pattern_value(value: &str) -> String {
    if value.len() >= 2 {
        let first = value.as_bytes()[0];
        let last = value.as_bytes()[value.len() - 1];
        if (first == b'"' && last == b'"') || (first == b'\'' && last == b'\'') {
            return value[1..value.len() - 1].to_string();
        }
    }

    value.to_string()
}

fn split_match_keyword(token: &str) -> (&str, bool) {
    if let Some(stripped) = token.strip_prefix('!') {
        (stripped, true)
    } else {
        (token, false)
    }
}

fn is_negated(token: &str) -> bool {
    split_match_keyword(token).1
}

fn is_supported_match_keyword(token: &str) -> bool {
    matches!(
        match_keyword(token),
        Some(MatchKeyword::All)
            | Some(MatchKeyword::Host)
            | Some(MatchKeyword::OriginalHost)
            | Some(MatchKeyword::User)
            | Some(MatchKeyword::LocalUser)
            | Some(MatchKeyword::Tagged)
            | Some(MatchKeyword::Version)
            | Some(MatchKeyword::Command)
            | Some(MatchKeyword::SessionType)
            | Some(MatchKeyword::LocalNetwork)
            | Some(MatchKeyword::Canonical)
            | Some(MatchKeyword::Final)
    )
}

fn is_match_keyword(token: &str) -> bool {
    match match_keyword(token) {
        Some(MatchKeyword::All)
        | Some(MatchKeyword::Host)
        | Some(MatchKeyword::OriginalHost)
        | Some(MatchKeyword::User)
        | Some(MatchKeyword::LocalUser)
        | Some(MatchKeyword::Tagged)
        | Some(MatchKeyword::Version)
        | Some(MatchKeyword::Command)
        | Some(MatchKeyword::SessionType)
        | Some(MatchKeyword::LocalNetwork)
        | Some(MatchKeyword::Canonical)
        | Some(MatchKeyword::Final)
        | Some(MatchKeyword::Unsupported) => true,
        None => false,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MatchKeyword {
    All,
    Host,
    OriginalHost,
    User,
    LocalUser,
    Tagged,
    Version,
    Command,
    SessionType,
    LocalNetwork,
    Canonical,
    Final,
    Unsupported,
}

fn match_keyword(token: &str) -> Option<MatchKeyword> {
    let (keyword, _) = split_match_keyword(token);
    match keyword.to_ascii_lowercase().as_str() {
        "all" => Some(MatchKeyword::All),
        "host" => Some(MatchKeyword::Host),
        "originalhost" => Some(MatchKeyword::OriginalHost),
        "user" => Some(MatchKeyword::User),
        "localuser" => Some(MatchKeyword::LocalUser),
        "tagged" => Some(MatchKeyword::Tagged),
        "version" => Some(MatchKeyword::Version),
        "command" => Some(MatchKeyword::Command),
        "sessiontype" => Some(MatchKeyword::SessionType),
        "localnetwork" => Some(MatchKeyword::LocalNetwork),
        "canonical" => Some(MatchKeyword::Canonical),
        "final" => Some(MatchKeyword::Final),
        "exec" | "address" => Some(MatchKeyword::Unsupported),
        _ => None,
    }
}

fn parse_match_body(raw: &str) -> Result<HostEntry> {
    let body = raw.lines().skip(1).collect::<Vec<_>>().join("\n");
    parser::parse_match_entry(std::path::Path::new("root-match"), &body)
}

fn split_key_value(line: &str) -> Option<(&str, &str)> {
    let idx = line.find(char::is_whitespace)?;
    let key = &line[..idx];
    let value = line[idx..].trim();
    if value.is_empty() {
        None
    } else {
        Some((key, value))
    }
}

pub fn match_block_applies(block: &RootMatchBlock, context: &MatchContext<'_>) -> Result<bool> {
    if !block.unsupported_conditions.is_empty() {
        return Ok(false);
    }

    match &block.condition {
        MatchCondition::Criteria(criteria) => criteria_match(criteria, context),
        MatchCondition::Unsupported => Ok(false),
    }
}

fn criteria_match(criteria: &[MatchCriterion], context: &MatchContext<'_>) -> Result<bool> {
    for criterion in criteria {
        if !criterion_matches(criterion, context)? {
            return Ok(false);
        }
    }

    Ok(true)
}

fn criterion_matches(criterion: &MatchCriterion, context: &MatchContext<'_>) -> Result<bool> {
    match criterion {
        MatchCriterion::All { negated } => Ok(apply_negation(true, *negated)),
        MatchCriterion::Host { patterns, negated } => {
            pattern_list_matches(patterns, context.current_host)
                .map(|matched| apply_negation(matched, *negated))
        }
        MatchCriterion::OriginalHost { patterns, negated } => {
            pattern_list_matches(patterns, context.original_host)
                .map(|matched| apply_negation(matched, *negated))
        }
        MatchCriterion::User { patterns, negated } => {
            pattern_list_matches_optional(patterns, context.current_user)
                .map(|matched| apply_negation(matched, *negated))
        }
        MatchCriterion::LocalUser { patterns, negated } => {
            pattern_list_matches_optional(patterns, context.local_user)
                .map(|matched| apply_negation(matched, *negated))
        }
        MatchCriterion::Tagged { patterns, negated } => {
            pattern_list_matches(patterns, context.current_tag.unwrap_or(""))
                .map(|matched| apply_negation(matched, *negated))
        }
        MatchCriterion::Version { patterns, negated } => {
            pattern_list_matches_optional(patterns, context.current_ssh_version)
                .map(|matched| apply_negation(matched, *negated))
        }
        MatchCriterion::Command { patterns, negated } => {
            pattern_list_matches(patterns, context.command.unwrap_or(""))
                .map(|matched| apply_negation(matched, *negated))
        }
        MatchCriterion::SessionType { patterns, negated } => {
            pattern_list_matches_optional(patterns, context.session_type)
                .map(|matched| apply_negation(matched, *negated))
        }
        MatchCriterion::LocalNetwork { patterns, negated } => {
            local_network_matches(patterns, context.local_networks)
                .map(|matched| apply_negation(matched, *negated))
        }
        MatchCriterion::Canonical { negated } => Ok(apply_negation(context.is_canonical, *negated)),
        MatchCriterion::Final { negated } => Ok(apply_negation(context.is_final, *negated)),
    }
}

pub fn block_uses_ssh_version(block: &RootMatchBlock) -> bool {
    match &block.condition {
        MatchCondition::Criteria(criteria) => criteria
            .iter()
            .any(|criterion| matches!(criterion, MatchCriterion::Version { .. })),
        MatchCondition::Unsupported => false,
    }
}

pub fn unsupported_match_block_count(blocks: &[RootMatchBlock]) -> usize {
    blocks
        .iter()
        .filter(|block| !block.unsupported_conditions.is_empty())
        .count()
}

pub fn unsupported_match_conditions(blocks: &[RootMatchBlock]) -> Vec<String> {
    let mut values = Vec::new();
    for block in blocks {
        for condition in &block.unsupported_conditions {
            if !values.contains(condition) {
                values.push(condition.clone());
            }
        }
    }
    values
}

fn apply_negation(value: bool, negated: bool) -> bool {
    if negated { !value } else { value }
}

fn pattern_list_matches(patterns: &[String], target: &str) -> Result<bool> {
    let mut positive_match = false;

    for raw_pattern in patterns {
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

fn pattern_list_matches_optional(patterns: &[String], target: Option<&str>) -> Result<bool> {
    let Some(target) = target else {
        return Ok(false);
    };

    pattern_list_matches(patterns, target)
}

fn local_network_matches(patterns: &[String], local_networks: &[String]) -> Result<bool> {
    let mut positive_match = false;

    for raw_pattern in patterns {
        let (pattern, negated) = if let Some(stripped) = raw_pattern.strip_prefix('!') {
            (stripped, true)
        } else {
            (raw_pattern.as_str(), false)
        };

        let matched = network_spec_matches_any(pattern, local_networks)?;
        if negated {
            if matched {
                return Ok(false);
            }
            continue;
        }

        if matched {
            positive_match = true;
        }
    }

    Ok(positive_match)
}

fn network_spec_matches_any(spec: &str, local_networks: &[String]) -> Result<bool> {
    let Some((network, prefix_len_text)) = spec.split_once('/') else {
        anyhow::bail!("invalid localnetwork pattern `{spec}`");
    };
    let prefix_len: u8 = prefix_len_text
        .parse()
        .with_context(|| format!("invalid CIDR prefix in `{spec}`"))?;
    let network_ip: IpAddr = network
        .parse()
        .with_context(|| format!("invalid network address in `{spec}`"))?;

    for local in local_networks {
        let Ok(local_ip) = local.parse::<IpAddr>() else {
            continue;
        };
        if ip_in_network(local_ip, network_ip, prefix_len)? {
            return Ok(true);
        }
    }

    Ok(false)
}

fn ip_in_network(ip: IpAddr, network: IpAddr, prefix_len: u8) -> Result<bool> {
    match (ip, network) {
        (IpAddr::V4(ip), IpAddr::V4(network)) => {
            if prefix_len > 32 {
                anyhow::bail!("IPv4 CIDR prefix `{prefix_len}` is out of range");
            }
            let mask = if prefix_len == 0 {
                0
            } else {
                u32::MAX << (32 - prefix_len)
            };
            Ok((u32::from(ip) & mask) == (u32::from(network) & mask))
        }
        (IpAddr::V6(ip), IpAddr::V6(network)) => {
            if prefix_len > 128 {
                anyhow::bail!("IPv6 CIDR prefix `{prefix_len}` is out of range");
            }
            let ip = u128::from_be_bytes(ip.octets());
            let network = u128::from_be_bytes(network.octets());
            let mask = if prefix_len == 0 {
                0
            } else {
                u128::MAX << (128 - prefix_len)
            };
            Ok((ip & mask) == (network & mask))
        }
        _ => Ok(false),
    }
}

pub fn detect_local_username() -> String {
    std::env::var("USERNAME")
        .or_else(|_| std::env::var("USER"))
        .or_else(|_| std::env::var("LOGNAME"))
        .unwrap_or_default()
}

pub fn detect_local_networks() -> Vec<String> {
    detect_local_networks_from_command("ipconfig", &[]).unwrap_or_else(|| {
        detect_local_networks_from_command("ip", &["-o", "addr", "show"])
            .or_else(|| detect_local_networks_from_command("ifconfig", &[]))
            .unwrap_or_default()
    })
}

fn detect_local_networks_from_command(program: &str, args: &[&str]) -> Option<Vec<String>> {
    let output = Command::new(program).args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    Some(extract_local_networks_from_output(program, &stdout))
}

fn extract_local_networks_from_output(program: &str, stdout: &str) -> Vec<String> {
    let mut values = Vec::new();

    match program {
        "ipconfig" => {
            for line in stdout.lines() {
                let Some((label, value)) = line.split_once(':') else {
                    continue;
                };
                let label = label.trim();
                if !(label.contains("IPv4") || label.contains("IPv6")) || !label.contains("Address")
                {
                    continue;
                }
                push_local_ip(&mut values, value.trim());
            }
        }
        "ip" => {
            for line in stdout.lines() {
                let tokens: Vec<&str> = line.split_whitespace().collect();
                for index in 0..tokens.len() {
                    if matches!(tokens[index], "inet" | "inet6") {
                        if let Some(candidate) = tokens.get(index + 1) {
                            push_local_ip(&mut values, candidate);
                        }
                    }
                }
            }
        }
        "ifconfig" => {
            for line in stdout.lines() {
                let tokens: Vec<&str> = line.split_whitespace().collect();
                for index in 0..tokens.len() {
                    if matches!(tokens[index], "inet" | "inet6") {
                        if let Some(candidate) = tokens.get(index + 1).and_then(|next| {
                            if *next == "addr:" {
                                tokens.get(index + 2).copied()
                            } else {
                                Some(*next)
                            }
                        }) {
                            push_local_ip(&mut values, candidate);
                        }
                    }
                }
            }
        }
        _ => {
            for token in stdout.split_whitespace() {
                push_local_ip(&mut values, token);
            }
        }
    }

    sort_and_dedup_ips(values)
}

fn push_local_ip(values: &mut Vec<String>, token: &str) {
    let normalized = token
        .trim_matches(|ch: char| matches!(ch, '(' | ')' | '[' | ']' | ',' | ';'))
        .trim_end_matches(':');

    let normalized = normalized.strip_prefix("addr:").unwrap_or(normalized);
    let normalized = normalized.split('%').next().unwrap_or(normalized);
    let candidate = normalized
        .split_once('/')
        .map(|(ip, _)| ip)
        .unwrap_or(normalized);

    let Ok(ip) = candidate.parse::<IpAddr>() else {
        return;
    };
    if ip.is_loopback() {
        return;
    }

    values.push(ip.to_string());
}

fn sort_and_dedup_ips(mut values: Vec<String>) -> Vec<String> {
    values.sort();
    values.dedup();
    values
}

#[cfg(test)]
mod tests {
    use crate::fs::layout::managed_block;

    use super::{
        MatchCondition, MatchContext, MatchCriterion, block_uses_ssh_version,
        extract_local_networks_from_output, extract_match_blocks, match_block_applies,
    };

    #[test]
    fn extracts_match_blocks_and_preserves_raw_text() {
        let blocks = extract_match_blocks(
            "\
Host alpha
  HostName alpha.example.com

Match host *.example.com
  User root

Match all
  ForwardAgent no
",
        );

        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[0].start_line, 4);
        assert_eq!(blocks[0].end_line, 6);
        assert!(blocks[0].raw.contains("Match host *.example.com"));
        assert!(blocks[0].raw.contains("  User root"));
        assert_eq!(
            blocks[0].condition,
            MatchCondition::Criteria(vec![MatchCriterion::Host {
                patterns: vec!["*.example.com".to_string()],
                negated: false,
            }])
        );
        assert!(blocks[0].unsupported_conditions.is_empty());
        assert_eq!(blocks[0].entry.user.as_deref(), Some("root"));
        assert!(blocks[0].appears_before_managed_anchor);
        assert_eq!(blocks[1].start_line, 7);
        assert_eq!(blocks[1].end_line, 8);
        assert!(blocks[1].raw.contains("Match all"));
        assert_eq!(
            blocks[1].condition,
            MatchCondition::Criteria(vec![MatchCriterion::All { negated: false }])
        );
    }

    #[test]
    fn ignores_managed_include_block_lines() {
        let blocks = extract_match_blocks(&format!(
            "\
{}
Match all
  ForwardAgent no
",
            managed_block("\n")
        ));

        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].start_line, 5);
        assert_eq!(blocks[0].end_line, 6);
        assert!(!blocks[0].appears_before_managed_anchor);
    }

    #[test]
    fn skips_unsupported_match_conditions_for_now() {
        let blocks = extract_match_blocks(
            "\
Match exec \"echo hi\" host alpha
  ForwardAgent no
",
        );

        assert_eq!(blocks.len(), 1);
        assert_eq!(
            blocks[0].unsupported_conditions,
            vec!["exec \"echo hi\"".to_string()]
        );
        let context = MatchContext::new_basic(
            "alpha",
            "alpha",
            Some("builder"),
            Some("builder"),
            None,
            Some("OpenSSH_9.5p1"),
            false,
            true,
        );
        assert!(!match_block_applies(&blocks[0], &context).unwrap());
    }

    #[test]
    fn host_match_supports_negation_patterns() {
        let blocks = extract_match_blocks(
            "\
Match host *.example.com !banned.example.com
  User root
",
        );

        assert_eq!(blocks.len(), 1);
        let allowed = MatchContext::new_basic(
            "alpha.example.com",
            "alpha.example.com",
            Some("builder"),
            Some("builder"),
            None,
            Some("OpenSSH_9.5p1"),
            false,
            true,
        );
        let denied = MatchContext::new_basic(
            "banned.example.com",
            "banned.example.com",
            Some("builder"),
            Some("builder"),
            None,
            Some("OpenSSH_9.5p1"),
            false,
            true,
        );

        assert!(match_block_applies(&blocks[0], &allowed).unwrap());
        assert!(!match_block_applies(&blocks[0], &denied).unwrap());
    }

    #[test]
    fn originalhost_user_and_localuser_criteria_use_current_context() {
        let blocks = extract_match_blocks(
            "\
Match originalhost alpha user builder localuser alice
  ForwardAgent no
",
        );

        assert_eq!(blocks.len(), 1);
        let matching = MatchContext::new_basic(
            "alpha",
            "alpha.example.com",
            Some("builder"),
            Some("alice"),
            None,
            Some("OpenSSH_9.5p1"),
            false,
            true,
        );
        let wrong_user = MatchContext::new_basic(
            "alpha",
            "alpha.example.com",
            Some("root"),
            Some("alice"),
            None,
            Some("OpenSSH_9.5p1"),
            false,
            true,
        );
        let wrong_local_user = MatchContext::new_basic(
            "alpha",
            "alpha.example.com",
            Some("builder"),
            Some("bob"),
            None,
            Some("OpenSSH_9.5p1"),
            false,
            true,
        );

        assert!(match_block_applies(&blocks[0], &matching).unwrap());
        assert!(!match_block_applies(&blocks[0], &wrong_user).unwrap());
        assert!(!match_block_applies(&blocks[0], &wrong_local_user).unwrap());
    }

    #[test]
    fn criterion_negation_inverts_supported_matches() {
        let blocks = extract_match_blocks(
            "\
Match !host banned.example.com !user root
  ForwardAgent no
",
        );

        assert_eq!(blocks.len(), 1);
        let allowed = MatchContext::new_basic(
            "alpha.example.com",
            "alpha.example.com",
            Some("builder"),
            Some("builder"),
            None,
            Some("OpenSSH_9.5p1"),
            false,
            true,
        );
        let banned = MatchContext::new_basic(
            "banned.example.com",
            "banned.example.com",
            Some("builder"),
            Some("builder"),
            None,
            Some("OpenSSH_9.5p1"),
            false,
            true,
        );
        let wrong_user = MatchContext::new_basic(
            "alpha.example.com",
            "alpha.example.com",
            Some("root"),
            Some("builder"),
            None,
            Some("OpenSSH_9.5p1"),
            false,
            true,
        );

        assert!(match_block_applies(&blocks[0], &allowed).unwrap());
        assert!(!match_block_applies(&blocks[0], &banned).unwrap());
        assert!(!match_block_applies(&blocks[0], &wrong_user).unwrap());
    }

    #[test]
    fn final_criteria_match_the_final_pass() {
        let blocks = extract_match_blocks(
            "\
Match final
  ForwardAgent no
",
        );

        assert_eq!(blocks.len(), 1);
        let final_pass = MatchContext::new_basic(
            "alpha",
            "alpha",
            Some("builder"),
            Some("builder"),
            None,
            Some("OpenSSH_9.5p1"),
            false,
            true,
        );
        let non_final_pass = MatchContext::new_basic(
            "alpha",
            "alpha",
            Some("builder"),
            Some("builder"),
            None,
            Some("OpenSSH_9.5p1"),
            false,
            false,
        );

        assert!(match_block_applies(&blocks[0], &final_pass).unwrap());
        assert!(!match_block_applies(&blocks[0], &non_final_pass).unwrap());
    }

    #[test]
    fn canonical_criteria_match_the_canonical_pass() {
        let blocks = extract_match_blocks(
            "\
Match canonical
  ForwardAgent no
",
        );

        assert_eq!(blocks.len(), 1);
        let canonical_pass = MatchContext::new_basic(
            "alpha",
            "alpha",
            Some("builder"),
            Some("builder"),
            None,
            Some("OpenSSH_9.5p1"),
            true,
            true,
        );
        let non_canonical_pass = MatchContext::new_basic(
            "alpha",
            "alpha",
            Some("builder"),
            Some("builder"),
            None,
            Some("OpenSSH_9.5p1"),
            false,
            true,
        );

        assert!(match_block_applies(&blocks[0], &canonical_pass).unwrap());
        assert!(!match_block_applies(&blocks[0], &non_canonical_pass).unwrap());
    }

    #[test]
    fn version_criteria_use_current_context() {
        let blocks = extract_match_blocks(
            "\
Match version OpenSSH_for_Windows_* !version OpenSSH_for_Windows_8.*
  ForwardAgent no
",
        );

        assert_eq!(blocks.len(), 1);
        let matching = MatchContext::new_basic(
            "alpha",
            "alpha",
            Some("builder"),
            Some("builder"),
            None,
            Some("OpenSSH_for_Windows_9.5p1"),
            false,
            true,
        );
        let wrong_version = MatchContext::new_basic(
            "alpha",
            "alpha",
            Some("builder"),
            Some("builder"),
            None,
            Some("OpenSSH_for_Windows_8.9p1"),
            false,
            true,
        );

        assert!(match_block_applies(&blocks[0], &matching).unwrap());
        assert!(!match_block_applies(&blocks[0], &wrong_version).unwrap());
        assert!(block_uses_ssh_version(&blocks[0]));
    }

    #[test]
    fn command_and_sessiontype_criteria_use_current_context() {
        let blocks = extract_match_blocks(
            "\
Match command \"git status\" sessiontype shell
  ForwardAgent no

Match command \"\" sessiontype exec
  ProxyJump jump-box
",
        );

        assert_eq!(blocks.len(), 2);
        let matching = MatchContext::new(
            "alpha",
            "alpha",
            Some("builder"),
            Some("builder"),
            None,
            Some("OpenSSH_9.5p1"),
            Some("shell"),
            Some("git status"),
            &[],
            false,
            true,
        );
        let wrong_command = MatchContext::new(
            "alpha",
            "alpha",
            Some("builder"),
            Some("builder"),
            None,
            Some("OpenSSH_9.5p1"),
            Some("shell"),
            Some("git fetch"),
            &[],
            false,
            true,
        );
        let wrong_session = MatchContext::new(
            "alpha",
            "alpha",
            Some("builder"),
            Some("builder"),
            None,
            Some("OpenSSH_9.5p1"),
            Some("exec"),
            Some("git status"),
            &[],
            false,
            true,
        );
        let exec_without_command = MatchContext::new(
            "alpha",
            "alpha",
            Some("builder"),
            Some("builder"),
            None,
            Some("OpenSSH_9.5p1"),
            Some("exec"),
            None,
            &[],
            false,
            true,
        );

        assert!(match_block_applies(&blocks[0], &matching).unwrap());
        assert!(!match_block_applies(&blocks[0], &wrong_command).unwrap());
        assert!(!match_block_applies(&blocks[0], &wrong_session).unwrap());
        assert!(match_block_applies(&blocks[1], &exec_without_command).unwrap());
    }

    #[test]
    fn localnetwork_criteria_use_current_context() {
        let blocks = extract_match_blocks(
            "\
Match localnetwork 192.168.1.0/24,!10.0.0.0/8
  ForwardAgent no
",
        );

        assert_eq!(blocks.len(), 1);
        let matching_networks = vec!["192.168.1.42".to_string()];
        let matching = MatchContext::new(
            "alpha",
            "alpha",
            Some("builder"),
            Some("builder"),
            None,
            Some("OpenSSH_9.5p1"),
            Some("shell"),
            Some(""),
            &matching_networks,
            false,
            true,
        );
        let blocked_networks = vec!["10.0.0.12".to_string()];
        let blocked = MatchContext::new(
            "alpha",
            "alpha",
            Some("builder"),
            Some("builder"),
            None,
            Some("OpenSSH_9.5p1"),
            Some("shell"),
            Some(""),
            &blocked_networks,
            false,
            true,
        );
        let missing = MatchContext::new(
            "alpha",
            "alpha",
            Some("builder"),
            Some("builder"),
            None,
            Some("OpenSSH_9.5p1"),
            Some("shell"),
            Some(""),
            &[],
            false,
            true,
        );

        assert!(match_block_applies(&blocks[0], &matching).unwrap());
        assert!(!match_block_applies(&blocks[0], &blocked).unwrap());
        assert!(!match_block_applies(&blocks[0], &missing).unwrap());
    }

    #[test]
    fn localnetwork_detection_parses_ipconfig_output() {
        let values = extract_local_networks_from_output(
            "ipconfig",
            "\
Windows IP Configuration

Ethernet adapter Ethernet:
   IPv4 Address. . . . . . . . . . . : 192.168.1.42
   Link-local IPv6 Address . . . . . : fe80::1111:2222:3333:4444%4
   Default Gateway . . . . . . . . . : 192.168.1.1
",
        );

        assert_eq!(
            values,
            vec![
                "192.168.1.42".to_string(),
                "fe80::1111:2222:3333:4444".to_string()
            ]
        );
    }

    #[test]
    fn localnetwork_detection_parses_ip_addr_output() {
        let values = extract_local_networks_from_output(
            "ip",
            "\
2: eth0    inet 192.168.56.10/24 brd 192.168.56.255 scope global dynamic eth0
2: eth0    inet6 fe80::a00:27ff:fe4e:66a1/64 scope link
",
        );

        assert_eq!(
            values,
            vec![
                "192.168.56.10".to_string(),
                "fe80::a00:27ff:fe4e:66a1".to_string()
            ]
        );
    }

    #[test]
    fn localnetwork_detection_parses_ifconfig_output() {
        let values = extract_local_networks_from_output(
            "ifconfig",
            "\
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.0.2.15  netmask 255.255.255.0  broadcast 10.0.2.255
        inet6 fe80::a00:27ff:fe4e:66a1  prefixlen 64  scopeid 0x20<link>
lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
",
        );

        assert_eq!(
            values,
            vec![
                "10.0.2.15".to_string(),
                "fe80::a00:27ff:fe4e:66a1".to_string()
            ]
        );
    }

    #[test]
    fn tagged_criteria_use_current_tag_context_and_support_empty_string() {
        let blocks = extract_match_blocks(
            "\
Match tagged ops
  ForwardAgent no

Match tagged \"\"
  ProxyJump jump-box
",
        );

        assert_eq!(blocks.len(), 2);
        let tagged = MatchContext::new_basic(
            "alpha",
            "alpha",
            Some("builder"),
            Some("builder"),
            Some("ops"),
            Some("OpenSSH_9.5p1"),
            false,
            true,
        );
        let untagged = MatchContext::new_basic(
            "alpha",
            "alpha",
            Some("builder"),
            Some("builder"),
            None,
            Some("OpenSSH_9.5p1"),
            false,
            true,
        );

        assert!(match_block_applies(&blocks[0], &tagged).unwrap());
        assert!(!match_block_applies(&blocks[0], &untagged).unwrap());
        assert!(!match_block_applies(&blocks[1], &tagged).unwrap());
        assert!(match_block_applies(&blocks[1], &untagged).unwrap());
    }
}
