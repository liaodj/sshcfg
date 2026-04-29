use std::io;
use std::time::Duration;

use anyhow::Result;
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;

use crate::tui::state::{InputMode, TuiState};
use crate::tui::views;

type AppTerminal = Terminal<CrosstermBackend<io::Stdout>>;

pub fn run() -> Result<()> {
    let mut app = TuiState::load()?;
    let mut terminal = init_terminal()?;

    let result = run_event_loop(&mut terminal, &mut app);
    restore_terminal(&mut terminal)?;
    result
}

fn init_terminal() -> Result<AppTerminal> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    terminal.hide_cursor()?;
    Ok(terminal)
}

fn restore_terminal(terminal: &mut AppTerminal) -> Result<()> {
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    Ok(())
}

fn run_event_loop(terminal: &mut AppTerminal, app: &mut TuiState) -> Result<()> {
    loop {
        terminal.draw(|frame| views::render(frame, app))?;

        if !event::poll(Duration::from_millis(250))? {
            continue;
        }

        if let Event::Key(key) = event::read()? {
            if key.kind != KeyEventKind::Press {
                continue;
            }

            if handle_key_event(app, key)? {
                break;
            }
        }
    }

    Ok(())
}

fn handle_key_event(app: &mut TuiState, key: KeyEvent) -> Result<bool> {
    match app.input_mode() {
        InputMode::Normal => handle_normal_mode(app, key),
        InputMode::Search => handle_search_mode(app, key),
        InputMode::Filter => handle_filter_mode(app, key),
        InputMode::Inspect => handle_inspect_mode(app, key),
        InputMode::BackupCatalog => handle_backup_catalog_mode(app, key),
        InputMode::ConfirmDelete => handle_confirm_delete_mode(app, key),
        InputMode::ConfirmRestore => handle_confirm_restore_mode(app, key),
        InputMode::Edit => handle_edit_mode(app, key),
        InputMode::Reorder => handle_reorder_mode(app, key),
    }
}

fn handle_normal_mode(app: &mut TuiState, key: KeyEvent) -> Result<bool> {
    if matches!(key.code, KeyCode::Tab) {
        app.toggle_pane_focus();
        return Ok(false);
    }

    match key.code {
        KeyCode::Char('q') => return Ok(true),
        KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => return Ok(true),
        KeyCode::Char('?') => app.open_help(),
        KeyCode::Char('/') => app.start_search(),
        KeyCode::Char('b') => {
            if let Err(err) = app.open_backup_catalog() {
                app.set_status(format!("Backups failed: {err:#}"));
            }
        }
        KeyCode::Char('f') => app.start_filter_edit(),
        KeyCode::Char('t') => app.open_template_catalog(),
        KeyCode::Char('v') => app.toggle_detail_mode(),
        KeyCode::Char('x') => app.clear_all_filters(),
        KeyCode::Char('a') => app.start_add(),
        KeyCode::Char('e') => app.start_edit(),
        KeyCode::Char('d') => app.start_delete_confirmation(),
        KeyCode::Char('V') => {
            if let Err(err) = app.open_validation_report() {
                app.set_status(format!("Validate failed: {err:#}"));
            }
        }
        KeyCode::Char('D') => {
            if let Err(err) = app.open_doctor_report() {
                app.set_status(format!("Doctor failed: {err:#}"));
            }
        }
        KeyCode::Char('r') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            if let Err(err) = app.reload() {
                app.set_status(format!("Reload failed: {err:#}"));
            }
        }
        KeyCode::Char('r') => app.start_reorder(),
        KeyCode::Down | KeyCode::Char('j') => {
            if app.list_is_focused() {
                app.select_next();
            } else {
                app.scroll_detail_down(1);
            }
        }
        KeyCode::Up | KeyCode::Char('k') => {
            if app.list_is_focused() {
                app.select_previous();
            } else {
                app.scroll_detail_up(1);
            }
        }
        KeyCode::PageDown => {
            if app.list_is_focused() {
                app.select_next_page(app.list_page_step());
            } else {
                app.scroll_detail_down(app.detail_page_step());
            }
        }
        KeyCode::PageUp => {
            if app.list_is_focused() {
                app.select_previous_page(app.list_page_step());
            } else {
                app.scroll_detail_up(app.detail_page_step());
            }
        }
        KeyCode::Home | KeyCode::Char('g') => {
            if app.list_is_focused() {
                app.select_first();
            } else {
                app.scroll_detail_home();
            }
        }
        KeyCode::End | KeyCode::Char('G') => {
            if app.list_is_focused() {
                app.select_last();
            } else {
                app.scroll_detail_end();
            }
        }
        _ => {}
    }

    Ok(false)
}

fn handle_filter_mode(app: &mut TuiState, key: KeyEvent) -> Result<bool> {
    match key.code {
        KeyCode::Esc => app.cancel_filter_edit(),
        KeyCode::Enter => app.save_filter_edit(),
        KeyCode::Tab | KeyCode::Down => app.filter_next_field(),
        KeyCode::BackTab | KeyCode::Up => app.filter_previous_field(),
        KeyCode::Left => {
            app.toggle_filter_has_note();
            app.cycle_filter_template_previous();
        }
        KeyCode::Right => {
            app.toggle_filter_has_note();
            app.cycle_filter_template_next();
        }
        KeyCode::Backspace => app.pop_filter_char(),
        KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            app.clear_filter_field()
        }
        KeyCode::Char(' ') => app.handle_filter_space(),
        KeyCode::Char(ch)
            if !key
                .modifiers
                .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
        {
            app.push_filter_char(ch)
        }
        _ => {}
    }

    Ok(false)
}

fn handle_inspect_mode(app: &mut TuiState, key: KeyEvent) -> Result<bool> {
    match key.code {
        KeyCode::Esc | KeyCode::Char('q') => app.close_inspection_report(),
        KeyCode::Up | KeyCode::Char('k') => app.scroll_inspection_up(1),
        KeyCode::Down | KeyCode::Char('j') => app.scroll_inspection_down(1),
        KeyCode::PageUp => app.scroll_inspection_up(app.inspection_page_step()),
        KeyCode::PageDown => app.scroll_inspection_down(app.inspection_page_step()),
        KeyCode::Home | KeyCode::Char('g') => app.scroll_inspection_home(),
        KeyCode::End | KeyCode::Char('G') => app.scroll_inspection_end(),
        _ => {}
    }

    Ok(false)
}

fn handle_backup_catalog_mode(app: &mut TuiState, key: KeyEvent) -> Result<bool> {
    match key.code {
        KeyCode::Esc | KeyCode::Char('q') => app.close_backup_catalog(),
        KeyCode::Enter | KeyCode::Char('r') => app.start_restore_confirmation(),
        KeyCode::Up | KeyCode::Char('k') => app.backup_select_previous(),
        KeyCode::Down | KeyCode::Char('j') => app.backup_select_next(),
        KeyCode::PageUp => app.backup_select_previous_page(),
        KeyCode::PageDown => app.backup_select_next_page(),
        KeyCode::Home | KeyCode::Char('g') => app.backup_select_first(),
        KeyCode::End | KeyCode::Char('G') => app.backup_select_last(),
        _ => {}
    }

    Ok(false)
}

fn handle_reorder_mode(app: &mut TuiState, key: KeyEvent) -> Result<bool> {
    match key.code {
        KeyCode::Esc => app.cancel_reorder(),
        KeyCode::Enter => {
            if let Err(err) = app.save_reorder() {
                app.set_status(format!("Reorder failed: {err:#}"));
            }
        }
        KeyCode::Up | KeyCode::Char('k') => app.reorder_up(),
        KeyCode::Down | KeyCode::Char('j') => app.reorder_down(),
        _ => {}
    }

    Ok(false)
}

fn handle_edit_mode(app: &mut TuiState, key: KeyEvent) -> Result<bool> {
    match key.code {
        KeyCode::Esc => app.cancel_form(),
        KeyCode::Enter => {
            if let Err(err) = app.save_form() {
                app.set_status(format!("Save failed: {err:#}"));
            }
        }
        KeyCode::Tab | KeyCode::Down => app.form_next_field(),
        KeyCode::BackTab | KeyCode::Up => app.form_previous_field(),
        KeyCode::Left => app.cycle_form_template_previous(),
        KeyCode::Right => app.cycle_form_template_next(),
        KeyCode::Backspace => app.pop_form_char(),
        KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            app.clear_form_field()
        }
        KeyCode::Char(' ') => app.handle_form_space(),
        KeyCode::Char(ch)
            if !key
                .modifiers
                .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
        {
            app.push_form_char(ch)
        }
        _ => {}
    }

    Ok(false)
}

fn handle_search_mode(app: &mut TuiState, key: KeyEvent) -> Result<bool> {
    match key.code {
        KeyCode::Enter => app.finish_search(),
        KeyCode::Esc => app.cancel_search(),
        KeyCode::Backspace => app.pop_search(),
        KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => app.clear_search(),
        KeyCode::Char(ch)
            if !key
                .modifiers
                .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
        {
            app.push_search(ch)
        }
        _ => {}
    }

    Ok(false)
}

fn handle_confirm_delete_mode(app: &mut TuiState, key: KeyEvent) -> Result<bool> {
    match key.code {
        KeyCode::Char('y') | KeyCode::Enter => {
            if let Err(err) = app.confirm_delete() {
                app.set_status(format!("Delete failed: {err:#}"));
                app.cancel_delete_confirmation();
            }
        }
        KeyCode::Char('n') | KeyCode::Esc => app.cancel_delete_confirmation(),
        _ => {}
    }

    Ok(false)
}

fn handle_confirm_restore_mode(app: &mut TuiState, key: KeyEvent) -> Result<bool> {
    match key.code {
        KeyCode::Char('y') | KeyCode::Enter => {
            if let Err(err) = app.confirm_restore() {
                app.set_status(format!("Restore failed: {err:#}"));
                app.cancel_restore_confirmation();
            }
        }
        KeyCode::Char('n') | KeyCode::Esc => app.cancel_restore_confirmation(),
        _ => {}
    }

    Ok(false)
}
