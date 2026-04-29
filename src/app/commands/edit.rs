use std::io::{self, IsTerminal, Write};
use std::path::PathBuf;

use anyhow::{Context, Result, bail};

use crate::app::cli::EditArgs;
use crate::core::model::{HostEntry, ManagedEntry};
use crate::core::state::{self, EntryMetadata};
use crate::core::store;
use crate::core::template::{self, TemplateKind};
use crate::core::validate;
use crate::fs::backup;
use crate::fs::layout::AppPaths;

use super::{init, parse_extras};

#[derive(Debug, Clone)]
pub(crate) struct EditOutcome {
    pub saved_path: PathBuf,
    pub previous_path: PathBuf,
    pub order: u16,
    pub host_patterns: Vec<String>,
    pub metadata_id: String,
    pub backup_path: Option<PathBuf>,
    pub include_written: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum PromptValue<T> {
    Keep,
    Set(T),
    Clear,
}

#[derive(Debug, Clone)]
struct InteractiveEditSeed {
    host: String,
    hostname: Option<String>,
    user: Option<String>,
    port: Option<u16>,
    proxy_jump: Option<String>,
    local_forwards: Vec<String>,
    remote_forwards: Vec<String>,
    ssh_tag: Option<String>,
    template: Option<TemplateKind>,
    tags: Vec<String>,
    note: Option<String>,
}

#[derive(Debug, Clone)]
struct InteractiveEditValues {
    host: String,
    hostname: Option<String>,
    user: Option<String>,
    port: Option<u16>,
    proxy_jump: Option<String>,
    ssh_tag: Option<String>,
    template: Option<TemplateKind>,
    tags: Vec<String>,
    note: Option<String>,
}

pub fn run(args: EditArgs) -> Result<()> {
    let paths = AppPaths::discover()?;
    let args = prepare_edit_args(&paths, args)?;
    let outcome = edit_managed_entry(&paths, &args)?;

    println!("updated: {}", outcome.saved_path.display());
    if outcome.saved_path != outcome.previous_path {
        println!("previous file: {}", outcome.previous_path.display());
    }
    println!("order: {}", outcome.order);
    println!("host: {}", outcome.host_patterns.join(","));
    println!("metadata id: {}", outcome.metadata_id);

    if outcome.include_written {
        println!("root config include block was initialized");
    }

    if let Some(path) = outcome.backup_path {
        println!("backup: {}", path.display());
    }

    Ok(())
}

pub(crate) fn edit_managed_entry(paths: &AppPaths, args: &EditArgs) -> Result<EditOutcome> {
    let init_report = init::ensure_initialized(paths)?;
    let entries = store::load_managed_entries(paths)?;
    let current = store::find_entry_by_host(&entries, &args.host)
        .with_context(|| format!("managed entry `{}` not found", args.host))?
        .clone();

    let updated = build_updated_entry(&current.entry, args)?;
    validate::validate_entry(&updated)?;

    let desired_order = args.order.unwrap_or(current.order);
    if updated == current.entry && desired_order == current.order {
        bail!("no changes for: {}", current.path.display());
    }

    let backup_path = backup::create_backup(paths)?;
    let saved = store::replace_entry(paths, &current, &updated, args.order)
        .context("failed to update managed SSH entry")?;
    let metadata = state::upsert_entry(
        paths,
        &saved,
        Some(&current),
        state::metadata_update_for_edit(
            template_update(args),
            tags_update(args),
            note_update(args),
        ),
    )
    .context("failed to update state metadata")?;

    Ok(EditOutcome {
        saved_path: saved.path,
        previous_path: current.path,
        order: saved.order,
        host_patterns: saved.entry.host_patterns,
        metadata_id: metadata.id,
        backup_path: init_report.backup_path.or(backup_path),
        include_written: init_report.include_written,
    })
}

fn prepare_edit_args(paths: &AppPaths, args: EditArgs) -> Result<EditArgs> {
    if should_complete_interactively(&args) {
        complete_edit_args_interactively(paths, &args)
    } else {
        Ok(args)
    }
}

fn build_updated_entry(current: &HostEntry, args: &EditArgs) -> Result<HostEntry> {
    let mut updated = current.clone();

    if let Some(host) = &args.new_host {
        updated.host_patterns = vec![host.clone()];
    }

    apply_optional_string(
        &mut updated.hostname,
        args.hostname.clone(),
        args.clear_hostname,
        "hostname",
    )?;
    apply_optional_string(
        &mut updated.user,
        args.user.clone(),
        args.clear_user,
        "user",
    )?;
    apply_optional_u16(&mut updated.port, args.port, args.clear_port, "port")?;
    apply_optional_string(
        &mut updated.proxy_jump,
        args.proxy_jump.clone(),
        args.clear_proxy_jump,
        "proxy-jump",
    )?;
    apply_vec(
        &mut updated.identity_files,
        args.identity_files.clone(),
        args.clear_identity_files,
        "identity-file",
    )?;
    apply_vec(
        &mut updated.local_forwards,
        args.local_forwards.clone(),
        args.clear_local_forwards,
        "local-forward",
    )?;
    apply_vec(
        &mut updated.remote_forwards,
        args.remote_forwards.clone(),
        args.clear_remote_forwards,
        "remote-forward",
    )?;
    apply_optional_string(
        &mut updated.strict_host_key_checking,
        args.strict_host_key_checking.clone(),
        args.clear_strict_host_key_checking,
        "strict-host-key-checking",
    )?;
    apply_optional_string(
        &mut updated.user_known_hosts_file,
        args.user_known_hosts_file.clone(),
        args.clear_user_known_hosts_file,
        "user-known-hosts-file",
    )?;
    apply_optional_string(
        &mut updated.host_key_algorithms,
        args.host_key_algorithms.clone(),
        args.clear_host_key_algorithms,
        "host-key-algorithms",
    )?;
    apply_optional_string(
        &mut updated.pubkey_accepted_algorithms,
        args.pubkey_accepted_algorithms.clone(),
        args.clear_pubkey_accepted_algorithms,
        "pubkey-accepted-algorithms",
    )?;
    apply_optional_string(
        &mut updated.forward_agent,
        args.forward_agent.clone(),
        args.clear_forward_agent,
        "forward-agent",
    )?;
    apply_optional_string(
        &mut updated.tag,
        args.ssh_tag.clone(),
        args.clear_ssh_tag,
        "ssh-tag",
    )?;

    if args.clear_extras && !args.extras.is_empty() {
        bail!("cannot use --extra with --clear-extra");
    }
    if args.clear_tags && !args.tags.is_empty() {
        bail!("cannot use --tag with --clear-tags");
    }
    if args.clear_note && args.note.is_some() {
        bail!("cannot use --note with --clear-note");
    }
    if args.clear_template && args.template.is_some() {
        bail!("cannot use --template with --clear-template");
    }
    if args.clear_extras {
        updated.extra_options.clear();
    } else if !args.extras.is_empty() {
        updated.extra_options = parse_extras(&args.extras)?;
    }

    if let Some(template) = args.template {
        template::apply_template(&mut updated, template);
    }

    Ok(updated)
}

fn should_complete_interactively(args: &EditArgs) -> bool {
    has_terminal_io() && (args.interactive || requires_interactive_completion(args))
}

fn requires_interactive_completion(args: &EditArgs) -> bool {
    !has_requested_changes(args)
}

fn has_requested_changes(args: &EditArgs) -> bool {
    args.new_host.is_some()
        || args.hostname.is_some()
        || args.clear_hostname
        || args.user.is_some()
        || args.clear_user
        || args.port.is_some()
        || args.clear_port
        || args.proxy_jump.is_some()
        || args.clear_proxy_jump
        || !args.identity_files.is_empty()
        || args.clear_identity_files
        || !args.local_forwards.is_empty()
        || args.clear_local_forwards
        || !args.remote_forwards.is_empty()
        || args.clear_remote_forwards
        || args.strict_host_key_checking.is_some()
        || args.clear_strict_host_key_checking
        || args.user_known_hosts_file.is_some()
        || args.clear_user_known_hosts_file
        || args.host_key_algorithms.is_some()
        || args.clear_host_key_algorithms
        || args.pubkey_accepted_algorithms.is_some()
        || args.clear_pubkey_accepted_algorithms
        || args.forward_agent.is_some()
        || args.clear_forward_agent
        || args.ssh_tag.is_some()
        || args.clear_ssh_tag
        || args.template.is_some()
        || args.clear_template
        || args.order.is_some()
        || !args.extras.is_empty()
        || args.clear_extras
        || !args.tags.is_empty()
        || args.clear_tags
        || args.note.is_some()
        || args.clear_note
}

fn complete_edit_args_interactively(paths: &AppPaths, args: &EditArgs) -> Result<EditArgs> {
    if !has_terminal_io() {
        bail!("--interactive requires a terminal");
    }

    let (current, metadata) = load_current_entry(paths, &args.host)?;
    let seed = build_interactive_seed(&current, metadata.as_ref(), args)?;

    println!("Edit Managed SSH Entry");
    println!("==================================================");
    println!("Current file: {}", current.path.display());
    println!("Current order: {}", current.order);
    println!("Press Enter to keep the shown value. Type - to clear an optional field.");
    println!(
        "Repeatable forwards and other advanced directives stay unchanged unless you pass explicit flags."
    );

    let host = prompt_host("Host", &seed.host)?;
    let hostname = apply_prompt_value(
        seed.hostname.clone(),
        prompt_optional_string("HostName", seed.hostname.as_deref())?,
    );
    let user = apply_prompt_value(
        seed.user.clone(),
        prompt_optional_string("User (opt.)", seed.user.as_deref())?,
    );
    let port = apply_prompt_value(seed.port, prompt_optional_port(seed.port)?);
    let proxy_jump = apply_prompt_value(
        seed.proxy_jump.clone(),
        prompt_optional_string("ProxyJump (opt.)", seed.proxy_jump.as_deref())?,
    );
    let ssh_tag = apply_prompt_value(
        seed.ssh_tag.clone(),
        prompt_optional_string("SSH Tag (opt.)", seed.ssh_tag.as_deref())?,
    );
    let template = apply_prompt_value(seed.template, prompt_optional_template(seed.template)?);
    let note = apply_prompt_value(
        seed.note.clone(),
        prompt_optional_string("Note (opt.)", seed.note.as_deref())?,
    );
    let tags = apply_prompt_vec(seed.tags.clone(), prompt_optional_tags(&seed.tags)?);

    let values = InteractiveEditValues {
        host,
        hostname,
        user,
        port,
        proxy_jump,
        ssh_tag,
        template,
        tags,
        note,
    };

    println!();
    println!("=== Entry Summary ===");
    println!("Host: {}", values.host);
    println!("HostName: {}", display_optional(values.hostname.as_deref()));
    println!("User: {}", display_optional(values.user.as_deref()));
    println!(
        "Port: {}",
        values
            .port
            .map(|value| value.to_string())
            .unwrap_or_else(|| "<empty>".to_string())
    );
    println!(
        "ProxyJump: {}",
        display_optional(values.proxy_jump.as_deref())
    );
    println!("SSH Tag: {}", display_optional(values.ssh_tag.as_deref()));
    println!(
        "LocalForward(s): {}",
        display_repeatable_values(&seed.local_forwards)
    );
    println!(
        "RemoteForward(s): {}",
        display_repeatable_values(&seed.remote_forwards)
    );
    println!(
        "Template: {}",
        values
            .template
            .map(|value| value.cli_name())
            .unwrap_or("<none>")
    );
    println!(
        "Tags: {}",
        if values.tags.is_empty() {
            "<none>".to_string()
        } else {
            values.tags.join(",")
        }
    );
    println!("Note: {}", display_optional(values.note.as_deref()));
    println!("=====================");

    if !confirm("Confirm save changes?", true)? {
        bail!("cancelled");
    }

    Ok(build_interactive_args(
        args,
        &current,
        metadata.as_ref(),
        values,
    ))
}

fn build_interactive_seed(
    current: &ManagedEntry,
    metadata: Option<&EntryMetadata>,
    args: &EditArgs,
) -> Result<InteractiveEditSeed> {
    let updated = build_updated_entry(&current.entry, args)?;
    let current_template = metadata_template(metadata);

    Ok(InteractiveEditSeed {
        host: updated.primary_pattern().to_string(),
        hostname: updated.hostname.clone(),
        user: updated.user.clone(),
        port: updated.port,
        proxy_jump: updated.proxy_jump.clone(),
        local_forwards: updated.local_forwards.clone(),
        remote_forwards: updated.remote_forwards.clone(),
        ssh_tag: updated.tag.clone(),
        template: template_update(args).flatten().or(current_template),
        tags: tags_update(args)
            .unwrap_or_else(|| metadata.map(|entry| entry.tags.clone()).unwrap_or_default()),
        note: note_update(args).unwrap_or_else(|| metadata.and_then(|entry| entry.note.clone())),
    })
}

fn build_interactive_args(
    base: &EditArgs,
    current: &ManagedEntry,
    metadata: Option<&EntryMetadata>,
    values: InteractiveEditValues,
) -> EditArgs {
    let InteractiveEditValues {
        host,
        hostname,
        user,
        port,
        proxy_jump,
        ssh_tag,
        template,
        tags,
        note,
    } = values;
    let current_host = current.entry.primary_pattern().to_string();
    let current_template = metadata_template(metadata);
    let current_ssh_tag = current.entry.tag.clone();
    let current_tags = metadata.map(|entry| entry.tags.clone()).unwrap_or_default();
    let current_note = metadata.and_then(|entry| entry.note.clone());
    let clear_tags = !current_tags.is_empty() && tags.is_empty();
    let tags = if tags != current_tags {
        tags
    } else {
        Vec::new()
    };

    EditArgs {
        host: base.host.clone(),
        interactive: false,
        new_host: (host != current_host).then_some(host),
        hostname: changed_option_string(&current.entry.hostname, &hostname),
        clear_hostname: current.entry.hostname.is_some() && hostname.is_none(),
        user: changed_option_string(&current.entry.user, &user),
        clear_user: current.entry.user.is_some() && user.is_none(),
        port: changed_option_u16(current.entry.port, port),
        clear_port: current.entry.port.is_some() && port.is_none(),
        proxy_jump: changed_option_string(&current.entry.proxy_jump, &proxy_jump),
        clear_proxy_jump: current.entry.proxy_jump.is_some() && proxy_jump.is_none(),
        identity_files: base.identity_files.clone(),
        clear_identity_files: base.clear_identity_files,
        local_forwards: base.local_forwards.clone(),
        clear_local_forwards: base.clear_local_forwards,
        remote_forwards: base.remote_forwards.clone(),
        clear_remote_forwards: base.clear_remote_forwards,
        strict_host_key_checking: base.strict_host_key_checking.clone(),
        clear_strict_host_key_checking: base.clear_strict_host_key_checking,
        user_known_hosts_file: base.user_known_hosts_file.clone(),
        clear_user_known_hosts_file: base.clear_user_known_hosts_file,
        host_key_algorithms: base.host_key_algorithms.clone(),
        clear_host_key_algorithms: base.clear_host_key_algorithms,
        pubkey_accepted_algorithms: base.pubkey_accepted_algorithms.clone(),
        clear_pubkey_accepted_algorithms: base.clear_pubkey_accepted_algorithms,
        forward_agent: base.forward_agent.clone(),
        clear_forward_agent: base.clear_forward_agent,
        ssh_tag: changed_option_string(&current_ssh_tag, &ssh_tag),
        clear_ssh_tag: current_ssh_tag.is_some() && ssh_tag.is_none(),
        template: template.filter(|value| Some(*value) != current_template),
        clear_template: current_template.is_some() && template.is_none(),
        order: base.order,
        extras: base.extras.clone(),
        clear_extras: base.clear_extras,
        tags,
        clear_tags,
        note: changed_option_string(&current_note, &note),
        clear_note: current_note.is_some() && note.is_none(),
    }
}

fn load_current_entry(
    paths: &AppPaths,
    host: &str,
) -> Result<(ManagedEntry, Option<EntryMetadata>)> {
    let entries = store::load_managed_entries(paths)?;
    let current = store::find_entry_by_host(&entries, host)
        .with_context(|| format!("managed entry `{host}` not found"))?
        .clone();
    let state = state::load_state(paths)?;
    let metadata = state::find_entry_metadata(&state, &current).cloned();
    Ok((current, metadata))
}

fn template_update(args: &EditArgs) -> Option<Option<TemplateKind>> {
    if args.clear_template {
        Some(None)
    } else {
        args.template.map(Some)
    }
}

fn tags_update(args: &EditArgs) -> Option<Vec<String>> {
    if args.clear_tags {
        Some(Vec::new())
    } else if args.tags.is_empty() {
        None
    } else {
        Some(args.tags.clone())
    }
}

fn note_update(args: &EditArgs) -> Option<Option<String>> {
    if args.clear_note {
        Some(None)
    } else {
        args.note.clone().map(Some)
    }
}

fn metadata_template(metadata: Option<&EntryMetadata>) -> Option<TemplateKind> {
    metadata
        .and_then(|entry| entry.template_source.as_deref())
        .and_then(template::parse_cli_name)
}

fn changed_option_string(current: &Option<String>, updated: &Option<String>) -> Option<String> {
    (updated != current).then(|| updated.clone()).flatten()
}

fn changed_option_u16(current: Option<u16>, updated: Option<u16>) -> Option<u16> {
    (updated != current).then_some(updated).flatten()
}

fn apply_prompt_value<T>(current: Option<T>, prompted: PromptValue<T>) -> Option<T> {
    match prompted {
        PromptValue::Keep => current,
        PromptValue::Set(value) => Some(value),
        PromptValue::Clear => None,
    }
}

fn apply_prompt_vec<T>(current: Vec<T>, prompted: PromptValue<Vec<T>>) -> Vec<T> {
    match prompted {
        PromptValue::Keep => current,
        PromptValue::Set(value) => value,
        PromptValue::Clear => Vec::new(),
    }
}

fn apply_optional_string(
    slot: &mut Option<String>,
    value: Option<String>,
    clear: bool,
    flag_name: &str,
) -> Result<()> {
    if clear && value.is_some() {
        bail!("cannot use --{flag_name} with --clear-{flag_name}");
    }

    if clear {
        *slot = None;
    } else if let Some(value) = value {
        *slot = Some(value);
    }

    Ok(())
}

fn apply_optional_u16(
    slot: &mut Option<u16>,
    value: Option<u16>,
    clear: bool,
    flag_name: &str,
) -> Result<()> {
    if clear && value.is_some() {
        bail!("cannot use --{flag_name} with --clear-{flag_name}");
    }

    if clear {
        *slot = None;
    } else if let Some(value) = value {
        *slot = Some(value);
    }

    Ok(())
}

fn apply_vec<T>(slot: &mut Vec<T>, values: Vec<T>, clear: bool, flag_name: &str) -> Result<()> {
    if clear && !values.is_empty() {
        bail!("cannot use --{flag_name} with --clear-{flag_name}s");
    }

    if clear {
        slot.clear();
    } else if !values.is_empty() {
        *slot = values;
    }

    Ok(())
}

fn has_terminal_io() -> bool {
    io::stdin().is_terminal() && io::stdout().is_terminal()
}

fn prompt_host(label: &str, current: &str) -> Result<String> {
    let input = prompt_input(label, current)?;
    if input.is_empty() {
        Ok(current.to_string())
    } else {
        Ok(input)
    }
}

fn prompt_optional_string(label: &str, current: Option<&str>) -> Result<PromptValue<String>> {
    let input = prompt_input(
        &format!("{label} [Enter keeps, - clears]"),
        &display_optional(current),
    )?;

    if input.is_empty() {
        Ok(PromptValue::Keep)
    } else if input == "-" {
        Ok(PromptValue::Clear)
    } else {
        Ok(PromptValue::Set(input))
    }
}

fn prompt_optional_port(current: Option<u16>) -> Result<PromptValue<u16>> {
    loop {
        let default = current
            .map(|value| value.to_string())
            .unwrap_or_else(|| "<empty>".to_string());
        let input = prompt_input("Port (opt.) [Enter keeps, - clears]", &default)?;

        if input.is_empty() {
            return Ok(PromptValue::Keep);
        }
        if input == "-" {
            return Ok(PromptValue::Clear);
        }

        match input.parse::<u16>() {
            Ok(port) if port > 0 => return Ok(PromptValue::Set(port)),
            _ => println!("! Port must be a number between 1 and 65535"),
        }
    }
}

fn prompt_optional_template(current: Option<TemplateKind>) -> Result<PromptValue<TemplateKind>> {
    let choices = template::template_infos()
        .iter()
        .map(|info| info.kind.cli_name())
        .collect::<Vec<_>>()
        .join(", ");

    loop {
        let input = prompt_input(
            &format!("Template (opt.: {choices}) [Enter keeps, - clears]"),
            current.map(|value| value.cli_name()).unwrap_or("<none>"),
        )?;

        if input.is_empty() {
            return Ok(PromptValue::Keep);
        }
        if input == "-" {
            return Ok(PromptValue::Clear);
        }
        if let Some(template) = template::parse_cli_name(&input) {
            return Ok(PromptValue::Set(template));
        }

        println!("! Unknown template `{input}`");
    }
}

fn prompt_optional_tags(current: &[String]) -> Result<PromptValue<Vec<String>>> {
    let default = if current.is_empty() {
        "<none>".to_string()
    } else {
        current.join(",")
    };
    let input = prompt_input(
        "Tags (opt., comma-separated) [Enter keeps, - clears]",
        &default,
    )?;

    if input.is_empty() {
        return Ok(PromptValue::Keep);
    }
    if input == "-" {
        return Ok(PromptValue::Clear);
    }

    Ok(PromptValue::Set(
        input
            .split([',', ';'])
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToString::to_string)
            .collect(),
    ))
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

fn display_optional(value: Option<&str>) -> String {
    value
        .filter(|value| !value.is_empty())
        .unwrap_or("<empty>")
        .to_string()
}

fn display_repeatable_values(values: &[String]) -> String {
    if values.is_empty() {
        "<none>".to_string()
    } else {
        values.join(" | ")
    }
}

#[cfg(test)]
mod tests {
    use crate::app::cli::EditArgs;
    use crate::core::model::{HostEntry, ManagedEntry};
    use crate::core::template::TemplateKind;

    use super::{
        InteractiveEditValues, build_interactive_args, build_interactive_seed, build_updated_entry,
        has_requested_changes, requires_interactive_completion,
    };

    fn base_args(host: &str) -> EditArgs {
        EditArgs {
            host: host.to_string(),
            interactive: false,
            new_host: None,
            hostname: None,
            clear_hostname: false,
            user: None,
            clear_user: false,
            port: None,
            clear_port: false,
            proxy_jump: None,
            clear_proxy_jump: false,
            identity_files: Vec::new(),
            clear_identity_files: false,
            local_forwards: Vec::new(),
            clear_local_forwards: false,
            remote_forwards: Vec::new(),
            clear_remote_forwards: false,
            strict_host_key_checking: None,
            clear_strict_host_key_checking: false,
            user_known_hosts_file: None,
            clear_user_known_hosts_file: false,
            host_key_algorithms: None,
            clear_host_key_algorithms: false,
            pubkey_accepted_algorithms: None,
            clear_pubkey_accepted_algorithms: false,
            forward_agent: None,
            clear_forward_agent: false,
            ssh_tag: None,
            clear_ssh_tag: false,
            template: None,
            clear_template: false,
            order: None,
            extras: Vec::new(),
            clear_extras: false,
            tags: Vec::new(),
            clear_tags: false,
            note: None,
            clear_note: false,
        }
    }

    #[test]
    fn edits_selected_fields_without_clobbering_others() {
        let current = HostEntry {
            host_patterns: vec!["bs-215".to_string()],
            hostname: Some("172.16.0.215".to_string()),
            user: Some("root".to_string()),
            tag: Some("legacy".to_string()),
            identity_files: vec!["~/.ssh/id_ed25519".to_string()],
            ..HostEntry::default()
        };
        let mut args = base_args("bs-215");
        args.new_host = Some("bs-216".to_string());
        args.hostname = Some("172.16.0.216".to_string());
        args.clear_user = true;
        args.ssh_tag = Some("ops".to_string());
        args.identity_files = vec!["~/.ssh/id_builder".to_string()];
        args.remote_forwards = vec!["9090 127.0.0.1:90".to_string()];
        args.template = Some(TemplateKind::Legacy);
        args.extras = vec!["ServerAliveInterval=30".to_string()];
        args.tags = vec!["Prod".to_string()];
        args.note = Some("builder".to_string());

        let updated = build_updated_entry(&current, &args).unwrap();

        assert_eq!(updated.host_patterns, vec!["bs-216"]);
        assert_eq!(updated.hostname.as_deref(), Some("172.16.0.216"));
        assert_eq!(updated.user, None);
        assert_eq!(updated.tag.as_deref(), Some("ops"));
        assert_eq!(updated.identity_files, vec!["~/.ssh/id_builder"]);
        assert_eq!(updated.remote_forwards, vec!["9090 127.0.0.1:90"]);
        assert_eq!(updated.strict_host_key_checking.as_deref(), Some("no"));
        assert_eq!(
            updated.pubkey_accepted_algorithms.as_deref(),
            Some("+ssh-rsa")
        );
        assert_eq!(
            updated.extra_options,
            vec![("ServerAliveInterval".to_string(), "30".to_string())]
        );
    }

    #[test]
    fn rejects_conflicting_scalar_flags() {
        let current = HostEntry {
            host_patterns: vec!["bs-215".to_string()],
            ..HostEntry::default()
        };
        let mut args = base_args("bs-215");
        args.hostname = Some("172.16.0.216".to_string());
        args.clear_hostname = true;

        let err = build_updated_entry(&current, &args).unwrap_err();
        assert!(err.to_string().contains("--hostname"));
    }

    #[test]
    fn rejects_conflicting_vector_flags() {
        let current = HostEntry {
            host_patterns: vec!["bs-215".to_string()],
            ..HostEntry::default()
        };
        let mut args = base_args("bs-215");
        args.identity_files = vec!["~/.ssh/id_builder".to_string()];
        args.clear_identity_files = true;

        let err = build_updated_entry(&current, &args).unwrap_err();
        assert!(err.to_string().contains("--identity-file"));
    }

    #[test]
    fn rejects_conflicting_note_flags() {
        let current = HostEntry {
            host_patterns: vec!["bs-215".to_string()],
            ..HostEntry::default()
        };
        let mut args = base_args("bs-215");
        args.note = Some("x".to_string());
        args.clear_note = true;

        let err = build_updated_entry(&current, &args).unwrap_err();
        assert!(err.to_string().contains("--note"));
    }

    #[test]
    fn clears_ssh_tag_when_requested() {
        let current = HostEntry {
            host_patterns: vec!["bs-215".to_string()],
            tag: Some("ops".to_string()),
            ..HostEntry::default()
        };
        let mut args = base_args("bs-215");
        args.clear_ssh_tag = true;

        let updated = build_updated_entry(&current, &args).unwrap();
        assert_eq!(updated.tag, None);
    }

    #[test]
    fn interactive_seed_carries_current_ssh_tag() {
        let current = ManagedEntry {
            order: 10,
            slug: "bs-215".to_string(),
            path: "010-host-bs-215.conf".into(),
            raw_content: String::new(),
            entry: HostEntry {
                host_patterns: vec!["bs-215".to_string()],
                hostname: Some("172.16.0.215".to_string()),
                tag: Some("ops".to_string()),
                ..HostEntry::default()
            },
        };

        let seed = build_interactive_seed(&current, None, &base_args("bs-215")).unwrap();
        assert_eq!(seed.ssh_tag.as_deref(), Some("ops"));
    }

    #[test]
    fn interactive_args_update_and_clear_ssh_tag_based_on_prompted_value() {
        let current = ManagedEntry {
            order: 10,
            slug: "bs-215".to_string(),
            path: "010-host-bs-215.conf".into(),
            raw_content: String::new(),
            entry: HostEntry {
                host_patterns: vec!["bs-215".to_string()],
                hostname: Some("172.16.0.215".to_string()),
                tag: Some("ops".to_string()),
                ..HostEntry::default()
            },
        };

        let changed = build_interactive_args(
            &base_args("bs-215"),
            &current,
            None,
            InteractiveEditValues {
                host: "bs-215".to_string(),
                hostname: current.entry.hostname.clone(),
                user: current.entry.user.clone(),
                port: current.entry.port,
                proxy_jump: current.entry.proxy_jump.clone(),
                ssh_tag: Some("prod".to_string()),
                template: None,
                tags: Vec::new(),
                note: None,
            },
        );
        assert_eq!(changed.ssh_tag.as_deref(), Some("prod"));
        assert!(!changed.clear_ssh_tag);

        let cleared = build_interactive_args(
            &base_args("bs-215"),
            &current,
            None,
            InteractiveEditValues {
                host: "bs-215".to_string(),
                hostname: current.entry.hostname.clone(),
                user: current.entry.user.clone(),
                port: current.entry.port,
                proxy_jump: current.entry.proxy_jump.clone(),
                ssh_tag: None,
                template: None,
                tags: Vec::new(),
                note: None,
            },
        );
        assert_eq!(cleared.ssh_tag, None);
        assert!(cleared.clear_ssh_tag);
    }

    #[test]
    fn rejects_conflicting_template_flags() {
        let current = HostEntry {
            host_patterns: vec!["bs-215".to_string()],
            ..HostEntry::default()
        };
        let mut args = base_args("bs-215");
        args.template = Some(TemplateKind::Embedded);
        args.clear_template = true;

        let err = build_updated_entry(&current, &args).unwrap_err();
        assert!(err.to_string().contains("--template"));
    }

    #[test]
    fn exact_edit_without_flags_uses_interactive_completion() {
        let args = base_args("server-a");

        assert!(!has_requested_changes(&args));
        assert!(requires_interactive_completion(&args));
    }

    #[test]
    fn explicit_edit_flags_skip_interactive_completion() {
        let mut args = base_args("server-a");
        args.user = Some("builder".to_string());

        assert!(has_requested_changes(&args));
        assert!(!requires_interactive_completion(&args));
    }
}
