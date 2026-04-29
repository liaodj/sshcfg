use anyhow::Result;

use crate::app::cli::{TemplateArgs, TemplateCommands};
use crate::core::template;

pub fn run(args: TemplateArgs) -> Result<()> {
    match args.command {
        TemplateCommands::List => list_templates(),
    }
}

fn list_templates() -> Result<()> {
    println!(
        "{:<10} {:<12} {:<44} DEFAULTS",
        "TEMPLATE", "STATUS", "SUMMARY"
    );

    for info in template::template_infos() {
        let status = if info.directives.is_empty() {
            "placeholder"
        } else {
            "available"
        };
        let defaults = if info.directives.is_empty() {
            "-".to_string()
        } else {
            info.directives
                .iter()
                .map(|(key, value)| format!("{key}={value}"))
                .collect::<Vec<_>>()
                .join("; ")
        };

        println!(
            "{:<10} {:<12} {:<44} {}",
            info.kind.cli_name(),
            status,
            info.summary,
            defaults
        );
    }

    Ok(())
}
