use std::io::{self, IsTerminal, Write};
use std::path::PathBuf;

use anyhow::{Context, Result, bail};

use crate::app::cli::AddArgs;
use crate::core::model::HostEntry;
use crate::core::state;
use crate::core::store;
use crate::core::template::{self, TemplateKind};
use crate::core::validate;
use crate::fs::backup;
use crate::fs::layout::AppPaths;

use super::{init, parse_extras};

#[derive(Debug, Clone)]
pub(crate) struct AddOutcome {
    pub saved_path: PathBuf,
    pub order: u16,
    pub host_patterns: Vec<String>,
    pub metadata_id: String,
    pub backup_path: Option<PathBuf>,
    pub include_written: bool,
}

pub fn run(args: AddArgs) -> Result<()> {
    let paths = AppPaths::discover()?;
    let args = prepare_add_args(args)?;
    let outcome = create_managed_entry(&paths, &args)?;

    println!("created: {}", outcome.saved_path.display());
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

pub(crate) fn create_managed_entry(paths: &AppPaths, args: &AddArgs) -> Result<AddOutcome> {
    let init_report = init::ensure_initialized(paths)?;

    let mut entry = HostEntry {
        host_patterns: vec![args.host.clone()],
        hostname: args.hostname.clone(),
        user: args.user.clone(),
        port: args.port,
        proxy_jump: args.proxy_jump.clone(),
        identity_files: args.identity_files.clone(),
        local_forwards: args.local_forwards.clone(),
        remote_forwards: args.remote_forwards.clone(),
        strict_host_key_checking: args.strict_host_key_checking.clone(),
        user_known_hosts_file: args.user_known_hosts_file.clone(),
        host_key_algorithms: args.host_key_algorithms.clone(),
        pubkey_accepted_algorithms: args.pubkey_accepted_algorithms.clone(),
        forward_agent: args.forward_agent.clone(),
        tag: args.ssh_tag.clone(),
        extra_options: parse_extras(&args.extras)?,
    };

    if let Some(template) = args.template {
        template::apply_template(&mut entry, template);
    }

    validate::validate_entry(&entry)?;

    let existing = store::load_managed_entries(paths)?;
    if store::find_entry_by_host(&existing, entry.primary_pattern()).is_some() {
        bail!("managed entry `{}` already exists", entry.primary_pattern());
    }

    if let Some(order) = args.order {
        if existing.iter().any(|item| item.order == order) {
            bail!("order `{order}` is already in use");
        }
    }

    let backup_path = backup::create_backup(paths)?;
    let saved =
        store::save_entry(paths, &entry, args.order).context("failed to save managed SSH entry")?;
    let metadata = state::upsert_entry(
        paths,
        &saved,
        None,
        state::metadata_update_for_create(args.template, args.tags.clone(), args.note.clone()),
    )
    .context("failed to update state metadata")?;

    Ok(AddOutcome {
        saved_path: saved.path,
        order: saved.order,
        host_patterns: saved.entry.host_patterns,
        metadata_id: metadata.id,
        backup_path: init_report.backup_path.or(backup_path),
        include_written: init_report.include_written,
    })
}

fn prepare_add_args(mut args: AddArgs) -> Result<AddArgs> {
    apply_smart_defaults(&mut args);

    if should_complete_interactively(&args) {
        complete_add_args_interactively(&mut args)?;
    }

    Ok(args)
}

fn apply_smart_defaults(args: &mut AddArgs) {
    if args.hostname.is_none() && looks_like_host_target(&args.host) {
        args.hostname = Some(args.host.clone());
    }
}

fn complete_add_args_interactively(args: &mut AddArgs) -> Result<()> {
    if !has_terminal_io() {
        bail!("--interactive requires a terminal");
    }

    println!("Add Managed SSH Entry");
    println!("==================================================");
    println!("Repeatable forwards can be passed with --local-forward / --remote-forward.");

    if args.hostname.is_none() && !looks_like_pattern(&args.host) {
        args.hostname = prompt_optional_with_default(
            "HostName",
            if looks_like_host_target(&args.host) {
                Some(args.host.as_str())
            } else {
                None
            },
        )?;
    }

    if args.user.is_none() {
        args.user = prompt_optional("User (opt.)")?;
    }

    if args.port.is_none() {
        args.port = prompt_optional_port("Port (opt.)")?;
    }

    if args.proxy_jump.is_none() {
        args.proxy_jump = prompt_optional("ProxyJump (opt.)")?;
    }

    if args.template.is_none() {
        args.template = prompt_optional_template()?;
    }

    if args.ssh_tag.is_none() {
        args.ssh_tag = prompt_optional("SSH Tag (opt.)")?;
    }

    if args.note.is_none() {
        args.note = prompt_optional("Note (opt.)")?;
    }

    if args.tags.is_empty() {
        args.tags = prompt_optional_tags()?;
    }

    println!();
    println!("=== Entry Summary ===");
    println!("Host: {}", args.host);
    println!(
        "HostName: {}",
        args.hostname.as_deref().unwrap_or("<empty>")
    );
    println!("User: {}", args.user.as_deref().unwrap_or("<empty>"));
    println!(
        "Port: {}",
        args.port
            .map(|value| value.to_string())
            .unwrap_or_else(|| "<empty>".to_string())
    );
    println!(
        "ProxyJump: {}",
        args.proxy_jump.as_deref().unwrap_or("<empty>")
    );
    println!(
        "LocalForward(s): {}",
        display_repeatable_values(&args.local_forwards)
    );
    println!(
        "RemoteForward(s): {}",
        display_repeatable_values(&args.remote_forwards)
    );
    println!(
        "Template: {}",
        args.template
            .map(|value| value.cli_name())
            .unwrap_or("<none>")
    );
    println!("SSH Tag: {}", args.ssh_tag.as_deref().unwrap_or("<empty>"));
    println!(
        "Tags: {}",
        if args.tags.is_empty() {
            "<none>".to_string()
        } else {
            args.tags.join(",")
        }
    );
    println!("Note: {}", args.note.as_deref().unwrap_or("<empty>"));
    println!("=====================");

    if !confirm("Confirm create this entry?", true)? {
        bail!("cancelled");
    }

    Ok(())
}

fn should_complete_interactively(args: &AddArgs) -> bool {
    has_terminal_io() && (args.interactive || requires_interactive_completion(args))
}

fn looks_like_pattern(host: &str) -> bool {
    host.contains('*') || host.contains('?') || host.starts_with('!')
}

fn requires_interactive_completion(args: &AddArgs) -> bool {
    !looks_like_pattern(&args.host) && args.hostname.as_deref().is_none_or(str::is_empty)
}

fn looks_like_ip_address(value: &str) -> bool {
    value.parse::<std::net::IpAddr>().is_ok()
}

fn looks_like_host_target(value: &str) -> bool {
    looks_like_ip_address(value) || value.contains('.') || value.contains(':')
}

fn has_terminal_io() -> bool {
    io::stdin().is_terminal() && io::stdout().is_terminal()
}

fn prompt_optional(label: &str) -> Result<Option<String>> {
    prompt_optional_with_default(label, None)
}

fn prompt_optional_with_default(label: &str, default: Option<&str>) -> Result<Option<String>> {
    let mut stdout = io::stdout();
    if let Some(default) = default {
        write!(stdout, "> {label} [{default}]: ")?;
    } else {
        write!(stdout, "> {label}: ")?;
    }
    stdout.flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let trimmed = input.trim();

    if trimmed.is_empty() {
        Ok(default
            .map(ToString::to_string)
            .filter(|value| !value.is_empty()))
    } else {
        Ok(Some(trimmed.to_string()))
    }
}

fn prompt_optional_port(label: &str) -> Result<Option<u16>> {
    loop {
        let Some(value) = prompt_optional(label)? else {
            return Ok(None);
        };

        match value.parse::<u16>() {
            Ok(port) if port > 0 => return Ok(Some(port)),
            _ => println!("! Port must be a number between 1 and 65535"),
        }
    }
}

fn prompt_optional_template() -> Result<Option<TemplateKind>> {
    let choices = template::template_infos()
        .iter()
        .map(|info| info.kind.cli_name())
        .collect::<Vec<_>>()
        .join(", ");

    loop {
        let Some(value) =
            prompt_optional_with_default(&format!("Template (opt.: {choices})"), Some("none"))?
        else {
            return Ok(None);
        };

        if value.eq_ignore_ascii_case("none") {
            return Ok(None);
        }

        if let Some(template) = template::parse_cli_name(&value) {
            return Ok(Some(template));
        }

        println!("! Unknown template `{value}`");
    }
}

fn prompt_optional_tags() -> Result<Vec<String>> {
    let Some(value) = prompt_optional("Tags (opt., comma-separated)")? else {
        return Ok(Vec::new());
    };

    Ok(value
        .split([',', ';'])
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(ToString::to_string)
        .collect())
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

fn display_repeatable_values(values: &[String]) -> String {
    if values.is_empty() {
        "<none>".to_string()
    } else {
        values.join(" | ")
    }
}

#[cfg(test)]
mod tests {
    use crate::app::cli::AddArgs;

    use super::{
        apply_smart_defaults, looks_like_host_target, looks_like_pattern,
        requires_interactive_completion,
    };

    fn base_args(host: &str) -> AddArgs {
        AddArgs {
            host: host.to_string(),
            interactive: false,
            hostname: None,
            user: None,
            port: None,
            proxy_jump: None,
            identity_files: Vec::new(),
            local_forwards: Vec::new(),
            remote_forwards: Vec::new(),
            strict_host_key_checking: None,
            user_known_hosts_file: None,
            host_key_algorithms: None,
            pubkey_accepted_algorithms: None,
            forward_agent: None,
            ssh_tag: None,
            template: None,
            order: None,
            extras: Vec::new(),
            tags: Vec::new(),
            note: None,
        }
    }

    #[test]
    fn smart_defaults_fill_hostname_for_ip_target() {
        let mut args = base_args("172.16.7.226");

        apply_smart_defaults(&mut args);

        assert_eq!(args.hostname.as_deref(), Some("172.16.7.226"));
    }

    #[test]
    fn smart_defaults_do_not_fill_hostname_for_alias() {
        let mut args = base_args("server-a");

        apply_smart_defaults(&mut args);

        assert!(args.hostname.is_none());
    }

    #[test]
    fn detects_pattern_and_host_target_inputs() {
        assert!(looks_like_pattern("web-*"));
        assert!(looks_like_host_target("172.16.7.226"));
        assert!(looks_like_host_target("db.internal"));
        assert!(!looks_like_host_target("server-a"));
    }

    #[test]
    fn exact_alias_without_hostname_needs_interactive_completion() {
        assert!(requires_interactive_completion(&base_args("server-a")));

        let mut args = base_args("server-a");
        args.hostname = Some("172.16.7.226".to_string());
        assert!(!requires_interactive_completion(&args));

        assert!(!requires_interactive_completion(&base_args("web-*")));
    }
}
