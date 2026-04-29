use anyhow::{Context, Result, bail};
use chrono::Utc;

use crate::core::model::{HostEntry, ManagedEntry};
use crate::core::parser;
use crate::core::render;
use crate::fs::layout::{AppPaths, platform_newline};
use crate::fs::writer;

pub fn load_managed_entries(paths: &AppPaths) -> Result<Vec<ManagedEntry>> {
    if !paths.config_d_dir.exists() {
        return Ok(Vec::new());
    }

    let mut entries = Vec::new();

    for path in paths.managed_entry_files()? {
        let file_name = path
            .file_name()
            .and_then(|value| value.to_str())
            .with_context(|| format!("invalid file name: {}", path.display()))?;

        let (order, slug) = parse_order_and_slug(file_name)?;
        let content = std::fs::read_to_string(&path)?;
        let entry = parser::parse_host_entry(&path, &content)?;

        entries.push(ManagedEntry {
            order,
            slug,
            path,
            raw_content: content,
            entry,
        });
    }

    entries.sort_by_key(|entry| entry.order);
    Ok(entries)
}

pub fn save_entry(
    paths: &AppPaths,
    entry: &HostEntry,
    requested_order: Option<u16>,
) -> Result<ManagedEntry> {
    let existing = load_managed_entries(paths)?;
    let order = requested_order.unwrap_or_else(|| next_order(&existing));

    if existing.iter().any(|item| item.order == order) {
        bail!("order {order} is already in use");
    }

    let (slug, path) = managed_entry_target(&paths.config_d_dir, order, entry);

    if path.exists() {
        bail!("target file already exists: {}", path.display());
    }

    let rendered = render::render_host_entry(entry, platform_newline());
    writer::write_text_file(&path, &rendered)?;

    Ok(ManagedEntry {
        order,
        slug,
        path,
        raw_content: rendered,
        entry: entry.clone(),
    })
}

pub fn replace_entry(
    paths: &AppPaths,
    current: &ManagedEntry,
    entry: &HostEntry,
    requested_order: Option<u16>,
) -> Result<ManagedEntry> {
    let existing = load_managed_entries(paths)?;
    let order = requested_order.unwrap_or(current.order);

    if existing
        .iter()
        .any(|item| item.order == order && item.path != current.path)
    {
        bail!("order {order} is already in use");
    }

    if let Some(conflict) = find_entry_by_host(&existing, entry.primary_pattern()) {
        if conflict.path != current.path {
            bail!("managed entry `{}` already exists", entry.primary_pattern());
        }
    }

    let (slug, path) = managed_entry_target(&paths.config_d_dir, order, entry);
    if path != current.path && path.exists() {
        bail!("target file already exists: {}", path.display());
    }

    let rendered = render::render_host_entry(entry, platform_newline());
    writer::write_text_file(&path, &rendered)?;

    if path != current.path && current.path.exists() {
        std::fs::remove_file(&current.path)?;
    }

    Ok(ManagedEntry {
        order,
        slug,
        path,
        raw_content: rendered,
        entry: entry.clone(),
    })
}

pub fn rewrite_entries(paths: &AppPaths, entries: &[ManagedEntry]) -> Result<Vec<ManagedEntry>> {
    paths.ensure_base_dirs()?;

    let parent = paths
        .config_d_dir
        .parent()
        .context("managed config directory has no parent")?;
    let stamp = Utc::now().timestamp_nanos_opt().unwrap_or_default();
    let staging_dir = parent.join(format!(".config.d.staging-{}-{stamp}", std::process::id()));
    let retired_dir = parent.join(format!(".config.d.retired-{}-{stamp}", std::process::id()));

    std::fs::create_dir_all(&staging_dir)?;

    let mut saved_entries = Vec::with_capacity(entries.len());
    for (index, managed) in entries.iter().enumerate() {
        let order = normalized_order(index)?;
        let (slug, staged_path) = managed_entry_target(&staging_dir, order, &managed.entry);
        writer::write_text_file(&staged_path, &managed.raw_content)?;

        let final_path = paths.config_d_dir.join(
            staged_path
                .file_name()
                .context("managed entry file name is missing")?,
        );
        saved_entries.push(ManagedEntry {
            order,
            slug,
            path: final_path,
            raw_content: managed.raw_content.clone(),
            entry: managed.entry.clone(),
        });
    }

    if paths.config_d_dir.exists() {
        std::fs::rename(&paths.config_d_dir, &retired_dir)?;
        if let Err(err) = std::fs::rename(&staging_dir, &paths.config_d_dir) {
            let _ = std::fs::rename(&retired_dir, &paths.config_d_dir);
            return Err(err.into());
        }
        std::fs::remove_dir_all(&retired_dir)?;
    } else {
        std::fs::rename(&staging_dir, &paths.config_d_dir)?;
    }

    Ok(saved_entries)
}

pub fn find_entry_by_host<'a>(entries: &'a [ManagedEntry], host: &str) -> Option<&'a ManagedEntry> {
    entries.iter().find(|entry| {
        entry
            .entry
            .host_patterns
            .iter()
            .any(|pattern| pattern == host)
    })
}

pub fn next_order(entries: &[ManagedEntry]) -> u16 {
    entries.last().map(|entry| entry.order + 10).unwrap_or(10)
}

pub fn slugify_host_pattern(pattern: &str) -> String {
    let mut slug = String::new();
    let mut last_dash = false;

    for ch in pattern.chars() {
        let normalized = match ch {
            'a'..='z' | '0'..='9' => Some(ch),
            'A'..='Z' => Some(ch.to_ascii_lowercase()),
            '?' => Some('q'),
            '*' => None,
            _ => None,
        };

        if let Some(ch) = normalized {
            slug.push(ch);
            last_dash = false;
        } else if !last_dash {
            slug.push('-');
            last_dash = true;
        }
    }

    let slug = slug.trim_matches('-').to_string();
    if slug.is_empty() {
        "entry".to_string()
    } else {
        slug
    }
}

fn managed_entry_target(
    base_dir: &std::path::Path,
    order: u16,
    entry: &HostEntry,
) -> (String, std::path::PathBuf) {
    let slug = slugify_host_pattern(entry.primary_pattern());
    let file_name = format!("{order:03}-{}-{slug}.conf", entry.kind().label());
    let path = base_dir.join(file_name);
    (slug, path)
}

fn normalized_order(index: usize) -> Result<u16> {
    let slot = index
        .checked_add(1)
        .context("managed entry index overflowed")?;
    let raw = slot
        .checked_mul(10)
        .context("managed entry order overflowed")?;
    u16::try_from(raw).context("managed entry order exceeds u16")
}

fn parse_order_and_slug(file_name: &str) -> Result<(u16, String)> {
    let stem = file_name
        .strip_suffix(".conf")
        .with_context(|| format!("unsupported managed file name `{file_name}`"))?;
    let mut parts = stem.splitn(3, '-');
    let order = parts
        .next()
        .with_context(|| format!("missing order in `{file_name}`"))?
        .parse()
        .with_context(|| format!("invalid order in `{file_name}`"))?;
    let _kind = parts
        .next()
        .with_context(|| format!("missing kind in `{file_name}`"))?;
    let slug = parts
        .next()
        .with_context(|| format!("missing slug in `{file_name}`"))?
        .to_string();
    Ok((order, slug))
}

#[cfg(test)]
mod tests {
    use super::slugify_host_pattern;

    #[test]
    fn slugifies_pattern_names() {
        assert_eq!(slugify_host_pattern("bs-*"), "bs");
        assert_eq!(slugify_host_pattern("Home.Router?"), "home-routerq");
    }
}
