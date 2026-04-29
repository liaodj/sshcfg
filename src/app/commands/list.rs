use anyhow::Result;

use crate::app::cli::ListArgs;
use crate::core::state;
use crate::core::store;
use crate::fs::layout::AppPaths;

use super::selection::{EntryFilter, filter_entries};

pub fn run(args: ListArgs) -> Result<()> {
    let paths = AppPaths::discover()?;
    let entries = store::load_managed_entries(&paths)?;
    let state = state::load_state(&paths)?;
    let filter = EntryFilter::from_args(&args.filter);

    let filtered = filter_entries(&entries, &state, &filter);

    if filtered.is_empty() {
        println!("no managed entries found");
        return Ok(());
    }

    println!(
        "{:<6} {:<8} {:<24} {:<24} {:<16} NOTE",
        "ORDER", "TYPE", "HOST", "HOSTNAME", "TAGS"
    );

    for selected in filtered {
        let hostname = selected.entry.entry.hostname.as_deref().unwrap_or("-");
        let metadata = selected.metadata;
        let tags = metadata
            .map(|item| {
                if item.tags.is_empty() {
                    "-".to_string()
                } else {
                    item.tags.join(",")
                }
            })
            .unwrap_or_else(|| "-".to_string());
        let note = metadata
            .and_then(|item| item.note.as_deref())
            .unwrap_or("-");
        println!(
            "{:<6} {:<8} {:<24} {:<24} {:<16} {}",
            selected.entry.order,
            selected.entry.entry.kind().label(),
            selected.entry.entry.host_patterns.join(","),
            hostname,
            tags,
            note
        );
    }

    Ok(())
}
