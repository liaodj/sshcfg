use anyhow::{Context, Result, bail};

use crate::app::cli::ShowArgs;
use crate::core::model::{HostEntry, ManagedEntry};
use crate::core::openssh;
use crate::core::render;
use crate::core::resolve;
use crate::core::root_config;
use crate::core::state;
use crate::core::store;
use crate::fs::layout::AppPaths;

pub fn run(args: ShowArgs) -> Result<()> {
    let paths = AppPaths::discover()?;
    let entries = store::load_managed_entries(&paths)?;
    let state = state::load_state(&paths)?;

    if args.merged {
        println!("{}", render_merged_output(&paths, &entries, &args)?);
        return Ok(());
    }

    let entry = store::find_entry_by_host(&entries, &args.host)
        .with_context(|| format!("managed entry `{}` not found", args.host))?;

    println!("order: {}", entry.order);
    println!("slug: {}", entry.slug);
    println!("kind: {}", entry.entry.kind().label());
    println!("file: {}", entry.path.display());
    if let Some(metadata) = state::find_entry_metadata(&state, entry) {
        println!("metadata id: {}", metadata.id);
        if let Some(template) = &metadata.template_source {
            println!("template source: {}", template);
        }
        if metadata.tags.is_empty() {
            println!("tags: -");
        } else {
            println!("tags: {}", metadata.tags.join(","));
        }
        println!("note: {}", metadata.note.as_deref().unwrap_or("-"));
        println!("updated at: {}", metadata.updated_at);
    }
    println!();
    print_entry(entry);

    Ok(())
}

fn print_entry(entry: &ManagedEntry) {
    print_host_entry(&entry.entry);
}

fn print_host_entry(entry: &HostEntry) {
    for (key, value) in render::directives(entry) {
        println!("{:<28} {}", key, value);
    }
}

fn render_merged_output(
    paths: &AppPaths,
    entries: &[ManagedEntry],
    args: &ShowArgs,
) -> Result<String> {
    let root_match_blocks = load_root_match_blocks(paths)?;
    let detected_local_user = root_config::detect_local_username();
    let local_user = args
        .match_local_user
        .as_deref()
        .or((!detected_local_user.is_empty()).then_some(detected_local_user.as_str()));
    let local_networks = if args.match_local_networks.is_empty() {
        root_config::detect_local_networks()
    } else {
        args.match_local_networks.clone()
    };
    let detected_ssh_version = if root_match_blocks
        .iter()
        .any(root_config::block_uses_ssh_version)
    {
        openssh::detect_match_version_string()
    } else {
        None
    };
    let ssh_version = args
        .match_ssh_version
        .as_deref()
        .or(detected_ssh_version.as_deref());
    let session_type = args.match_session_type.as_deref().unwrap_or("shell");
    let command = args.match_command.as_deref().unwrap_or("");
    let resolved = resolve::resolve_target_with_root_matches_and_options(
        entries,
        &args.host,
        &root_match_blocks,
        resolve::RootMatchResolveOptions {
            local_user,
            current_user: args.match_user.as_deref(),
            initial_tag: args.match_tag.as_deref(),
            ssh_version,
            session_type: Some(session_type),
            command: Some(command),
            local_networks: &local_networks,
            is_canonical: args.match_canonical,
            is_final: !args.match_non_final,
        },
    )?;

    if resolved.matched_entries.is_empty() {
        bail!("no matching entries for target `{}`", args.host);
    }

    Ok(resolve::describe_resolved_target(&resolved))
}

fn load_root_match_blocks(paths: &AppPaths) -> Result<Vec<root_config::RootMatchBlock>> {
    if !paths.root_config.exists() {
        return Ok(Vec::new());
    }

    let content = std::fs::read_to_string(&paths.root_config)
        .with_context(|| format!("failed to read {}", paths.root_config.display()))?;
    Ok(root_config::extract_match_blocks(&content))
}

#[cfg(test)]
mod tests {
    use chrono::Utc;

    use crate::app::cli::ShowArgs;
    use crate::core::model::HostEntry;
    use crate::core::store;
    use crate::fs::layout::AppPaths;

    use super::render_merged_output;

    fn test_paths(name: &str) -> AppPaths {
        let root = std::env::current_dir()
            .unwrap()
            .join("target")
            .join("test-show")
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

    fn show_args(host: &str) -> ShowArgs {
        ShowArgs {
            host: host.to_string(),
            merged: true,
            match_tag: None,
            match_ssh_version: None,
            match_user: None,
            match_local_user: None,
            match_session_type: None,
            match_command: None,
            match_local_networks: Vec::new(),
            match_canonical: false,
            match_non_final: false,
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
    fn merged_show_can_override_sessiontype_and_command_context() {
        let paths = test_paths("merged-command-sessiontype");
        paths.ensure_base_dirs().unwrap();
        std::fs::write(
            &paths.root_config,
            "Match sessiontype exec command \"git fetch\"\n  ForwardAgent no\n",
        )
        .unwrap();
        store::save_entry(&paths, &host_entry("demo"), None).unwrap();
        let entries = store::load_managed_entries(&paths).unwrap();

        let mut args = show_args("demo");
        args.match_session_type = Some("exec".to_string());
        args.match_command = Some("git fetch".to_string());
        let output = render_merged_output(&paths, &entries, &args).unwrap();

        assert!(output.contains("ForwardAgent no"));
        assert!(output.contains("Match sessiontype exec command \"git fetch\""));
    }

    #[test]
    fn merged_show_can_override_tag_and_localnetwork_context() {
        let paths = test_paths("merged-tag-localnetwork");
        paths.ensure_base_dirs().unwrap();
        std::fs::write(
            &paths.root_config,
            "\
Match tagged ops localnetwork 192.168.1.0/24
  ForwardAgent no
",
        )
        .unwrap();
        store::save_entry(&paths, &host_entry("demo"), None).unwrap();
        let entries = store::load_managed_entries(&paths).unwrap();

        let mut args = show_args("demo");
        args.match_tag = Some("ops".to_string());
        args.match_local_networks = vec!["192.168.1.42".to_string()];
        let output = render_merged_output(&paths, &entries, &args).unwrap();

        assert!(output.contains("ForwardAgent no"));
        assert!(output.contains("Match tagged ops localnetwork 192.168.1.0/24"));
    }

    #[test]
    fn merged_show_can_override_localuser_context() {
        let paths = test_paths("merged-localuser");
        paths.ensure_base_dirs().unwrap();
        std::fs::write(
            &paths.root_config,
            "\
Match localuser ubuntu
  User local-user
",
        )
        .unwrap();
        store::save_entry(&paths, &host_entry("demo"), None).unwrap();
        let entries = store::load_managed_entries(&paths).unwrap();

        let mut args = show_args("demo");
        args.match_local_user = Some("ubuntu".to_string());
        let output = render_merged_output(&paths, &entries, &args).unwrap();

        assert!(output.contains("User local-user"));
        assert!(output.contains("Match localuser ubuntu"));
    }

    #[test]
    fn merged_show_can_override_user_context() {
        let paths = test_paths("merged-user");
        paths.ensure_base_dirs().unwrap();
        std::fs::write(
            &paths.root_config,
            "\
Match user deploy
  ForwardAgent no
",
        )
        .unwrap();
        store::save_entry(&paths, &host_entry("demo"), None).unwrap();
        let entries = store::load_managed_entries(&paths).unwrap();

        let mut args = show_args("demo");
        args.match_user = Some("deploy".to_string());
        let output = render_merged_output(&paths, &entries, &args).unwrap();

        assert!(output.contains("ForwardAgent no"));
        assert!(output.contains("Match user deploy"));
    }

    #[test]
    fn merged_show_can_override_version_context() {
        let paths = test_paths("merged-version");
        paths.ensure_base_dirs().unwrap();
        std::fs::write(
            &paths.root_config,
            "\
Match version FakeSSH_1.2
  ForwardAgent no
",
        )
        .unwrap();
        store::save_entry(&paths, &host_entry("demo"), None).unwrap();
        let entries = store::load_managed_entries(&paths).unwrap();

        let mut args = show_args("demo");
        args.match_ssh_version = Some("FakeSSH_1.2".to_string());
        let output = render_merged_output(&paths, &entries, &args).unwrap();

        assert!(output.contains("ForwardAgent no"));
        assert!(output.contains("Match version FakeSSH_1.2"));
    }

    #[test]
    fn merged_show_can_override_canonical_and_final_context() {
        let paths = test_paths("merged-canonical-final");
        paths.ensure_base_dirs().unwrap();
        std::fs::write(
            &paths.root_config,
            "\
Match canonical
  User canonical-user
Match final
  ForwardAgent no
",
        )
        .unwrap();
        store::save_entry(&paths, &host_entry("demo"), None).unwrap();
        let entries = store::load_managed_entries(&paths).unwrap();

        let mut args = show_args("demo");
        args.match_canonical = true;
        args.match_non_final = true;
        let output = render_merged_output(&paths, &entries, &args).unwrap();

        assert!(output.contains("User canonical-user"));
        assert!(!output.contains("ForwardAgent no"));
        assert!(output.contains("Match canonical"));
    }
}
