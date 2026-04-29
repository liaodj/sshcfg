use std::path::PathBuf;

use crate::app::cli::DuplicateArgs;
use crate::core::model::HostEntry;
use crate::core::state::{self, EntryMetadata};
use crate::core::store;
use crate::core::validate;
use crate::fs::backup;
use crate::fs::layout::AppPaths;
use anyhow::{Context, Result, bail};

use super::init;

#[derive(Debug, Clone)]
pub(crate) struct DuplicateOutcome {
    pub source_path: PathBuf,
    pub saved_path: PathBuf,
    pub order: u16,
    pub host_patterns: Vec<String>,
    pub metadata_id: String,
    pub backup_path: Option<PathBuf>,
    pub include_written: bool,
}

pub fn run(args: DuplicateArgs) -> Result<()> {
    let paths = AppPaths::discover()?;
    let outcome = duplicate_managed_entry(&paths, &args)?;

    println!("duplicated from: {}", outcome.source_path.display());
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

pub(crate) fn duplicate_managed_entry(
    paths: &AppPaths,
    args: &DuplicateArgs,
) -> Result<DuplicateOutcome> {
    validate_duplicate_args(args)?;

    let init_report = init::ensure_initialized(paths)?;
    let entries = store::load_managed_entries(paths)?;
    let source = store::find_entry_by_host(&entries, &args.source)
        .with_context(|| format!("managed entry `{}` not found", args.source))?
        .clone();

    if args.host == source.entry.primary_pattern() {
        bail!("duplicate target must differ from source `{}`", args.source);
    }

    let duplicated = build_duplicate_entry(&source.entry, args)?;
    validate::validate_entry(&duplicated)?;

    if store::find_entry_by_host(&entries, duplicated.primary_pattern()).is_some() {
        bail!(
            "managed entry `{}` already exists",
            duplicated.primary_pattern()
        );
    }

    if let Some(order) = args.order {
        if entries.iter().any(|entry| entry.order == order) {
            bail!("order {order} is already in use");
        }
    }

    let source_state = state::load_state(paths)?;
    let source_metadata = state::find_entry_metadata(&source_state, &source).cloned();

    let backup_path = backup::create_backup(paths)?;
    let saved = store::save_entry(paths, &duplicated, args.order)
        .context("failed to save duplicated managed SSH entry")?;
    let mut metadata = state::upsert_entry(
        paths,
        &saved,
        None,
        state::metadata_update_for_create(None, Vec::new(), None),
    )
    .context("failed to create duplicated metadata")?;

    if let Some(source_metadata) = source_metadata.as_ref() {
        metadata = copy_metadata_from_source(paths, saved.entry.primary_pattern(), source_metadata)
            .context("failed to copy source metadata to duplicated entry")?;
    }

    Ok(DuplicateOutcome {
        source_path: source.path,
        saved_path: saved.path,
        order: saved.order,
        host_patterns: saved.entry.host_patterns,
        metadata_id: metadata.id,
        backup_path: init_report.backup_path.or(backup_path),
        include_written: init_report.include_written,
    })
}

fn validate_duplicate_args(args: &DuplicateArgs) -> Result<()> {
    if args.keep_hostname && args.hostname.is_some() {
        bail!("cannot use --hostname with --keep-hostname");
    }

    Ok(())
}

fn build_duplicate_entry(source: &HostEntry, args: &DuplicateArgs) -> Result<HostEntry> {
    let mut duplicated = source.clone();
    duplicated.host_patterns = vec![args.host.clone()];
    duplicated.hostname = select_duplicate_hostname(source, args)?;
    Ok(duplicated)
}

fn select_duplicate_hostname(source: &HostEntry, args: &DuplicateArgs) -> Result<Option<String>> {
    if let Some(hostname) = &args.hostname {
        return Ok(Some(hostname.clone()));
    }

    if args.keep_hostname {
        return Ok(source.hostname.clone());
    }

    if looks_like_host_target(&args.host) {
        return Ok(Some(args.host.clone()));
    }

    if source.hostname.is_none() || looks_like_pattern(&args.host) {
        return Ok(source.hostname.clone());
    }

    bail!(
        "duplicating `{}` to alias `{}` requires --hostname or --keep-hostname",
        source.primary_pattern(),
        args.host
    )
}

fn copy_metadata_from_source(
    paths: &AppPaths,
    host: &str,
    source: &EntryMetadata,
) -> Result<EntryMetadata> {
    state::update_metadata_by_host(paths, host, |metadata| {
        metadata.template_source = source.template_source.clone();
        metadata.tags = source.tags.clone();
        metadata.note = source.note.clone();
        metadata.target_os = source.target_os.clone();
        metadata.remote_user_home = source.remote_user_home.clone();
        metadata.authorized_keys_path = source.authorized_keys_path.clone();
        metadata.ssh_dir_mode = source.ssh_dir_mode.clone();
        metadata.authorized_keys_mode = source.authorized_keys_mode.clone();
        Ok(())
    })
}

fn looks_like_pattern(host: &str) -> bool {
    host.contains('*') || host.contains('?') || host.starts_with('!')
}

fn looks_like_host_target(value: &str) -> bool {
    value.parse::<std::net::IpAddr>().is_ok() || value.contains('.') || value.contains(':')
}

#[cfg(test)]
mod tests {
    use chrono::Utc;

    use crate::app::cli::DuplicateArgs;
    use crate::core::model::HostEntry;
    use crate::core::state::{self, metadata_update_for_create};
    use crate::core::store;
    use crate::core::template::TemplateKind;
    use crate::fs::layout::AppPaths;

    use super::{build_duplicate_entry, duplicate_managed_entry, validate_duplicate_args};

    fn test_paths(name: &str) -> AppPaths {
        let root = std::env::current_dir()
            .unwrap()
            .join("target")
            .join("test-duplicate")
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

    fn duplicate_args(source: &str, host: &str) -> DuplicateArgs {
        DuplicateArgs {
            source: source.to_string(),
            host: host.to_string(),
            hostname: None,
            keep_hostname: false,
            order: None,
        }
    }

    fn host_entry(host: &str, hostname: Option<&str>) -> HostEntry {
        HostEntry {
            host_patterns: vec![host.to_string()],
            hostname: hostname.map(ToString::to_string),
            user: Some("root".to_string()),
            port: Some(22),
            proxy_jump: Some("jump-a".to_string()),
            identity_files: vec!["~/.ssh/id_ed25519".to_string()],
            local_forwards: vec!["8080 127.0.0.1:80".to_string()],
            remote_forwards: vec!["9090 127.0.0.1:90".to_string()],
            strict_host_key_checking: Some("no".to_string()),
            tag: Some("ops".to_string()),
            extra_options: vec![("ServerAliveInterval".to_string(), "30".to_string())],
            ..HostEntry::default()
        }
    }

    #[test]
    fn rejects_conflicting_hostname_flags() {
        let mut args = duplicate_args("alpha", "beta");
        args.hostname = Some("10.0.0.2".to_string());
        args.keep_hostname = true;

        let err = validate_duplicate_args(&args).unwrap_err();
        assert!(err.to_string().contains("--hostname"));
    }

    #[test]
    fn smart_defaults_hostname_for_host_targets() {
        let source = host_entry("alpha", Some("10.0.0.1"));
        let duplicated =
            build_duplicate_entry(&source, &duplicate_args("alpha", "10.0.0.2")).unwrap();

        assert_eq!(duplicated.host_patterns, vec!["10.0.0.2"]);
        assert_eq!(duplicated.hostname.as_deref(), Some("10.0.0.2"));
        assert_eq!(duplicated.user.as_deref(), Some("root"));
    }

    #[test]
    fn alias_duplicate_requires_explicit_hostname_decision() {
        let source = host_entry("alpha", Some("10.0.0.1"));
        let err = build_duplicate_entry(&source, &duplicate_args("alpha", "beta")).unwrap_err();

        assert!(err.to_string().contains("--hostname or --keep-hostname"));
    }

    #[test]
    fn duplicate_command_copies_entry_and_metadata() {
        let paths = test_paths("copy-entry-and-metadata");
        paths.ensure_base_dirs().unwrap();

        let source = host_entry("alpha", Some("10.0.0.1"));
        let saved = store::save_entry(&paths, &source, Some(10)).unwrap();
        state::upsert_entry(
            &paths,
            &saved,
            None,
            metadata_update_for_create(
                Some(TemplateKind::Legacy),
                vec!["Prod".to_string(), "edge".to_string()],
                Some("important".to_string()),
            ),
        )
        .unwrap();
        let original_metadata = state::update_metadata_by_host(&paths, "alpha", |metadata| {
            metadata.target_os = Some("ubuntu".to_string());
            metadata.remote_user_home = Some("/home/builder".to_string());
            metadata.authorized_keys_path = Some("/home/builder/.ssh/authorized_keys".to_string());
            metadata.ssh_dir_mode = Some("700".to_string());
            metadata.authorized_keys_mode = Some("600".to_string());
            Ok(())
        })
        .unwrap();

        let mut args = duplicate_args("alpha", "beta");
        args.hostname = Some("10.0.0.2".to_string());
        args.order = Some(20);

        let outcome = duplicate_managed_entry(&paths, &args).unwrap();
        let entries = store::load_managed_entries(&paths).unwrap();
        let duplicated = store::find_entry_by_host(&entries, "beta").unwrap();
        let state = state::load_state(&paths).unwrap();
        let duplicated_metadata = state::find_metadata_by_host(&state, "beta").unwrap();

        assert_eq!(outcome.order, 20);
        assert_eq!(duplicated.entry.hostname.as_deref(), Some("10.0.0.2"));
        assert_eq!(duplicated.entry.user.as_deref(), Some("root"));
        assert_eq!(duplicated.entry.tag.as_deref(), Some("ops"));
        assert_eq!(
            duplicated.entry.extra_options,
            vec![("ServerAliveInterval".to_string(), "30".to_string())]
        );
        assert_ne!(duplicated_metadata.id, original_metadata.id);
        assert_eq!(
            duplicated_metadata.template_source.as_deref(),
            Some("legacy")
        );
        assert_eq!(duplicated_metadata.tags, vec!["prod", "edge"]);
        assert_eq!(duplicated_metadata.note.as_deref(), Some("important"));
        assert_eq!(duplicated_metadata.target_os.as_deref(), Some("ubuntu"));
        assert_eq!(
            duplicated_metadata.remote_user_home.as_deref(),
            Some("/home/builder")
        );
        assert_eq!(
            duplicated_metadata.authorized_keys_path.as_deref(),
            Some("/home/builder/.ssh/authorized_keys")
        );
        assert_eq!(duplicated_metadata.ssh_dir_mode.as_deref(), Some("700"));
        assert_eq!(
            duplicated_metadata.authorized_keys_mode.as_deref(),
            Some("600")
        );
    }

    #[test]
    fn duplicate_command_can_keep_original_hostname() {
        let paths = test_paths("keep-hostname");
        paths.ensure_base_dirs().unwrap();

        let source = host_entry("alpha", Some("10.0.0.1"));
        let saved = store::save_entry(&paths, &source, Some(10)).unwrap();
        state::upsert_entry(
            &paths,
            &saved,
            None,
            metadata_update_for_create(None, Vec::new(), None),
        )
        .unwrap();

        let mut args = duplicate_args("alpha", "beta");
        args.keep_hostname = true;

        duplicate_managed_entry(&paths, &args).unwrap();

        let entries = store::load_managed_entries(&paths).unwrap();
        let duplicated = store::find_entry_by_host(&entries, "beta").unwrap();
        assert_eq!(duplicated.entry.hostname.as_deref(), Some("10.0.0.1"));
    }
}
