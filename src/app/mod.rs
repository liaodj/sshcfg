pub mod cli;
pub mod commands;

use anyhow::Result;
use clap::Parser;

use self::cli::{Cli, Commands};

pub fn run() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Init(args)) => commands::init::run(args),
        Some(Commands::List(args)) => commands::list::run(args),
        Some(Commands::Show(args)) => commands::show::run(args),
        Some(Commands::Meta(args)) => commands::meta::run(args),
        Some(Commands::Add(args)) => commands::add::run(args),
        Some(Commands::Edit(args)) => commands::edit::run(args),
        Some(Commands::Duplicate(args)) => commands::duplicate::run(args),
        Some(Commands::Order(args)) => commands::order::run(args),
        Some(Commands::Delete(args)) => commands::delete::run(args),
        Some(Commands::Template(args)) => commands::template::run(args),
        Some(Commands::Validate(args)) => commands::validate::run(args),
        Some(Commands::Doctor) => commands::doctor::run(),
        Some(Commands::Tui) | None => commands::tui::run(),
    }
}
