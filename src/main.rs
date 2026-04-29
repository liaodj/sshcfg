mod app;
mod core;
mod fs;
mod tui;

fn main() {
    if let Err(err) = app::run() {
        eprintln!("error: {err:#}");
        std::process::exit(1);
    }
}
