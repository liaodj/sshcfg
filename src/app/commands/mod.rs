use anyhow::{Context, Result, bail};

pub mod add;
pub mod delete;
pub mod doctor;
pub mod duplicate;
pub mod edit;
pub mod init;
pub mod list;
pub mod meta;
pub mod order;
pub(crate) mod selection;
pub mod show;
pub mod template;
pub mod tui;
pub mod validate;

pub(super) fn parse_extras(items: &[String]) -> Result<Vec<(String, String)>> {
    let mut extras = Vec::new();

    for item in items {
        let (key, value) = item
            .split_once('=')
            .with_context(|| format!("invalid --extra `{item}`, expected KEY=VALUE"))?;
        let key = key.trim();
        let value = value.trim();

        if key.is_empty() || value.is_empty() {
            bail!("invalid --extra `{item}`, expected non-empty KEY=VALUE");
        }

        extras.push((key.to_string(), value.to_string()));
    }

    Ok(extras)
}
