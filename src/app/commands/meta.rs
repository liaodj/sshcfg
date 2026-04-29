use anyhow::{Context, Result, bail};

use crate::app::cli::{
    MetaArgs, MetaBulkArgs, MetaBulkCommands, MetaBulkNoteArgs, MetaBulkSelectorArgs,
    MetaBulkTagArgs, MetaBulkTargetArgs, MetaCommands, MetaNoteArgs, MetaShowArgs, MetaTagArgs,
    MetaTargetArgs,
};
use crate::core::state::{self, EntryMetadata};
use crate::core::store;
use crate::fs::layout::AppPaths;

use super::selection::{EntryFilter, filter_entries};

pub fn run(args: MetaArgs) -> Result<()> {
    match args.command {
        MetaCommands::Show(args) => show(args),
        MetaCommands::SetNote(args) => set_note(args),
        MetaCommands::ClearNote(args) => clear_note(args),
        MetaCommands::AddTag(args) => add_tag(args),
        MetaCommands::RemoveTag(args) => remove_tag(args),
        MetaCommands::ClearTags(args) => clear_tags(args),
        MetaCommands::Bulk(args) => bulk(args),
    }
}

fn show(args: MetaShowArgs) -> Result<()> {
    let paths = AppPaths::discover()?;
    let state = state::load_state(&paths)?;
    let metadata = state::find_metadata_by_host(&state, &args.host)
        .with_context(|| format!("metadata for managed entry `{}` not found", args.host))?;

    print_metadata(metadata);
    Ok(())
}

fn set_note(args: MetaNoteArgs) -> Result<()> {
    let paths = AppPaths::discover()?;
    let note = args.note.trim();
    if note.is_empty() {
        bail!("note cannot be empty");
    }

    let metadata = state::update_metadata_by_host(&paths, &args.host, |metadata| {
        metadata.note = Some(note.to_string());
        Ok(())
    })?;

    println!("updated metadata note for `{}`", args.host);
    print_metadata(&metadata);
    Ok(())
}

fn clear_note(args: MetaTargetArgs) -> Result<()> {
    let paths = AppPaths::discover()?;
    let metadata = state::update_metadata_by_host(&paths, &args.host, |metadata| {
        metadata.note = None;
        Ok(())
    })?;

    println!("cleared metadata note for `{}`", args.host);
    print_metadata(&metadata);
    Ok(())
}

fn add_tag(args: MetaTagArgs) -> Result<()> {
    let paths = AppPaths::discover()?;
    let tag = normalize_tag(&args.tag)?;

    let metadata = state::update_metadata_by_host(&paths, &args.host, |metadata| {
        if !metadata.tags.iter().any(|existing| existing == &tag) {
            metadata.tags.push(tag.clone());
            metadata.tags.sort();
        }
        Ok(())
    })?;

    println!("added metadata tag `{}` to `{}`", tag, args.host);
    print_metadata(&metadata);
    Ok(())
}

fn remove_tag(args: MetaTagArgs) -> Result<()> {
    let paths = AppPaths::discover()?;
    let tag = normalize_tag(&args.tag)?;

    let metadata = state::update_metadata_by_host(&paths, &args.host, |metadata| {
        metadata.tags.retain(|existing| existing != &tag);
        Ok(())
    })?;

    println!("removed metadata tag `{}` from `{}`", tag, args.host);
    print_metadata(&metadata);
    Ok(())
}

fn clear_tags(args: MetaTargetArgs) -> Result<()> {
    let paths = AppPaths::discover()?;
    let metadata = state::update_metadata_by_host(&paths, &args.host, |metadata| {
        metadata.tags.clear();
        Ok(())
    })?;

    println!("cleared metadata tags for `{}`", args.host);
    print_metadata(&metadata);
    Ok(())
}

fn bulk(args: MetaBulkArgs) -> Result<()> {
    match args.command {
        MetaBulkCommands::SetNote(args) => bulk_set_note(args),
        MetaBulkCommands::ClearNote(args) => bulk_clear_note(args),
        MetaBulkCommands::AddTag(args) => bulk_add_tag(args),
        MetaBulkCommands::RemoveTag(args) => bulk_remove_tag(args),
        MetaBulkCommands::ClearTags(args) => bulk_clear_tags(args),
    }
}

fn bulk_set_note(args: MetaBulkNoteArgs) -> Result<()> {
    let note = args.note.trim();
    if note.is_empty() {
        bail!("note cannot be empty");
    }

    let paths = AppPaths::discover()?;
    let selected_ids = select_metadata_ids(&paths, &args.selector)?;
    let updated = state::update_metadata_by_ids(&paths, &selected_ids, |metadata| {
        metadata.note = Some(note.to_string());
        Ok(())
    })?;

    print_bulk_summary(
        &format!("set metadata note for {}", updated.len()),
        &updated,
    );
    Ok(())
}

fn bulk_clear_note(args: MetaBulkTargetArgs) -> Result<()> {
    let paths = AppPaths::discover()?;
    let selected_ids = select_metadata_ids(&paths, &args.selector)?;
    let updated = state::update_metadata_by_ids(&paths, &selected_ids, |metadata| {
        metadata.note = None;
        Ok(())
    })?;

    print_bulk_summary(
        &format!("cleared metadata note for {}", updated.len()),
        &updated,
    );
    Ok(())
}

fn bulk_add_tag(args: MetaBulkTagArgs) -> Result<()> {
    let paths = AppPaths::discover()?;
    let tag = normalize_tag(&args.tag)?;
    let selected_ids = select_metadata_ids(&paths, &args.selector)?;
    let updated = state::update_metadata_by_ids(&paths, &selected_ids, |metadata| {
        if !metadata.tags.iter().any(|existing| existing == &tag) {
            metadata.tags.push(tag.clone());
            metadata.tags.sort();
        }
        Ok(())
    })?;

    print_bulk_summary(
        &format!("added metadata tag `{tag}` to {}", updated.len()),
        &updated,
    );
    Ok(())
}

fn bulk_remove_tag(args: MetaBulkTagArgs) -> Result<()> {
    let paths = AppPaths::discover()?;
    let tag = normalize_tag(&args.tag)?;
    let selected_ids = select_metadata_ids(&paths, &args.selector)?;
    let updated = state::update_metadata_by_ids(&paths, &selected_ids, |metadata| {
        metadata.tags.retain(|existing| existing != &tag);
        Ok(())
    })?;

    print_bulk_summary(
        &format!("removed metadata tag `{tag}` from {}", updated.len()),
        &updated,
    );
    Ok(())
}

fn bulk_clear_tags(args: MetaBulkTargetArgs) -> Result<()> {
    let paths = AppPaths::discover()?;
    let selected_ids = select_metadata_ids(&paths, &args.selector)?;
    let updated = state::update_metadata_by_ids(&paths, &selected_ids, |metadata| {
        metadata.tags.clear();
        Ok(())
    })?;

    print_bulk_summary(
        &format!("cleared metadata tags for {}", updated.len()),
        &updated,
    );
    Ok(())
}

fn select_metadata_ids(paths: &AppPaths, selector: &MetaBulkSelectorArgs) -> Result<Vec<String>> {
    let filter = EntryFilter::from_args(&selector.filter);
    if !selector.all && filter.is_empty() {
        bail!(
            "bulk selection requires --all or at least one filter (--query, --tag, --has-note, --template)"
        );
    }

    let entries = store::load_managed_entries(paths)?;
    let state = state::load_state(paths)?;
    let selected = filter_entries(&entries, &state, &filter);

    if selected.is_empty() {
        bail!("no managed entries matched the provided selector");
    }

    let missing_metadata: Vec<_> = selected
        .iter()
        .filter(|item| item.metadata.is_none())
        .map(|item| item.entry.entry.primary_pattern().to_string())
        .collect();
    if !missing_metadata.is_empty() {
        bail!(
            "selected managed entries are missing metadata: {}",
            missing_metadata.join(", ")
        );
    }

    Ok(selected
        .iter()
        .filter_map(|item| item.metadata.map(|metadata| metadata.id.clone()))
        .collect())
}

fn normalize_tag(tag: &str) -> Result<String> {
    let tag = tag.trim().to_ascii_lowercase();
    if tag.is_empty() {
        bail!("tag cannot be empty");
    }
    Ok(tag)
}

fn print_metadata(metadata: &EntryMetadata) {
    println!("id: {}", metadata.id);
    println!("host: {}", metadata.primary_pattern);
    println!("hosts: {}", metadata.host_patterns.join(","));
    println!("order: {}", metadata.order);
    println!("kind: {}", metadata.entry_kind);
    println!("file: {}", metadata.managed_filename);
    println!(
        "template source: {}",
        metadata.template_source.as_deref().unwrap_or("-")
    );
    if metadata.tags.is_empty() {
        println!("tags: -");
    } else {
        println!("tags: {}", metadata.tags.join(","));
    }
    println!("note: {}", metadata.note.as_deref().unwrap_or("-"));
    println!("created at: {}", metadata.created_at);
    println!("updated at: {}", metadata.updated_at);
}

fn print_bulk_summary(action: &str, updated: &[EntryMetadata]) {
    println!(
        "{action} managed entr{}",
        if updated.len() == 1 { "y" } else { "ies" }
    );
    for metadata in updated {
        println!("  - {}", metadata.primary_pattern);
    }
}
