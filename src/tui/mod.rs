mod app;
mod state;
mod views;

use anyhow::Result;

pub fn run() -> Result<()> {
    app::run()
}
