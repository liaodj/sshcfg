pub mod detail;
pub mod host_list;

use ratatui::prelude::*;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap};

use crate::tui::state::{InputMode, TuiState};

pub const BORDER_SOFT: Color = Color::Rgb(92, 118, 132);
pub const BORDER_ACTIVE: Color = Color::Rgb(214, 162, 84);
pub const MUTED_TEXT: Color = Color::Rgb(146, 159, 168);
pub const SURFACE_BG: Color = Color::Rgb(16, 23, 28);
pub const SURFACE_ACCENT: Color = Color::Rgb(64, 98, 112);
pub const KEY_BG: Color = Color::Rgb(36, 52, 61);

pub fn render(frame: &mut Frame, state: &mut TuiState) {
    let root = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2),
            Constraint::Min(0),
            Constraint::Length(1),
            Constraint::Length(2),
        ])
        .split(frame.area());

    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(36), Constraint::Percentage(64)])
        .split(root[1]);

    render_header(frame, root[0], state);
    host_list::render(frame, body[0], state);
    detail::render(frame, body[1], state);
    render_status(frame, root[2], state);
    render_footer(frame, root[3], state);

    if matches!(state.input_mode(), InputMode::ConfirmDelete) {
        render_delete_confirmation(frame, state);
    } else if matches!(state.input_mode(), InputMode::ConfirmRestore) {
        render_restore_confirmation(frame, state);
    } else if matches!(state.input_mode(), InputMode::BackupCatalog) {
        render_backup_catalog_modal(frame, state);
    } else if matches!(state.input_mode(), InputMode::Filter) {
        render_filter_modal(frame, state);
    } else if matches!(state.input_mode(), InputMode::Inspect) {
        render_inspection_modal(frame, state);
    } else if matches!(state.input_mode(), InputMode::Edit) {
        render_edit_modal(frame, state);
    }
}

fn render_header(frame: &mut Frame, area: Rect, state: &TuiState) {
    let selected_host = state
        .selected_entry()
        .map(|entry| truncate_text(entry.entry.primary_pattern(), 20))
        .unwrap_or_else(|| "none".to_string());
    let filters = state
        .active_filter_summary()
        .map(|summary| truncate_text(&summary, 24))
        .unwrap_or_else(|| "none".to_string());

    let mut spans = vec![Span::styled(
        " sshcfg tui ",
        Style::default()
            .fg(Color::White)
            .bg(SURFACE_ACCENT)
            .add_modifier(Modifier::BOLD),
    )];
    append_header_pair(&mut spans, "mode", state.input_mode().label());
    append_header_pair(&mut spans, "focus", state.pane_focus().label());
    append_header_pair(&mut spans, "view", state.detail_mode().short_label());
    append_header_pair(
        &mut spans,
        "visible",
        format!("{}/{}", state.filtered_count(), state.entry_count()),
    );
    append_header_pair(&mut spans, "host", selected_host);
    append_header_pair(&mut spans, "filters", filters);
    append_header_pair(&mut spans, "help", "?");

    let header = Paragraph::new(Line::from(spans)).block(
        Block::default()
            .borders(Borders::BOTTOM)
            .border_style(Style::default().fg(BORDER_SOFT))
            .style(Style::default().bg(SURFACE_BG)),
    );
    frame.render_widget(header, area);
}

fn render_status(frame: &mut Frame, area: Rect, state: &TuiState) {
    let message = match state.input_mode() {
        InputMode::Inspect => state
            .inspection_report()
            .map(|report| report.summary().to_string())
            .unwrap_or_else(|| "No diagnostics loaded".to_string()),
        InputMode::BackupCatalog => state
            .backup_catalog()
            .map(|catalog| catalog.summary())
            .unwrap_or_else(|| "No backup catalog loaded".to_string()),
        InputMode::ConfirmDelete => format!(
            "Delete `{}`? This removes the managed file and updates metadata.",
            state.pending_delete_host().unwrap_or("?")
        ),
        InputMode::ConfirmRestore => {
            let snapshot = state
                .pending_restore_snapshot()
                .map(|snapshot| snapshot.label.as_str())
                .unwrap_or("?");
            format!(
                "Restore `{snapshot}`? Current config will be backed up first, then replaced."
            )
        }
        InputMode::Reorder => format!(
            "Reordering `{}`{}",
            state.reorder_host().unwrap_or("?"),
            if state.reorder_dirty() {
                " | draft order changed"
            } else {
                " | no saved changes yet"
            }
        ),
        InputMode::Search => {
            "Search mode | type to narrow the host list live, Enter keeps it, Esc clears it."
                .to_string()
        }
        InputMode::Filter => {
            "Filter mode | set query, tags, note, and template filters here, then press Enter."
                .to_string()
        }
        InputMode::Edit => {
            "Form mode | edit fields directly here, Enter saves, Esc cancels, Left/Right cycles Template."
                .to_string()
        }
        InputMode::Normal => state
            .status_message()
            .map(ToString::to_string)
            .unwrap_or_else(|| default_status_message(state)),
    };

    let status = Paragraph::new(message).style(Style::default().fg(MUTED_TEXT));
    frame.render_widget(status, area);
}

fn render_footer(frame: &mut Frame, area: Rect, state: &TuiState) {
    let lines = match state.input_mode() {
        InputMode::Normal => normal_footer_lines(state),
        InputMode::Search => vec![
            legend_line(
                "SEARCH",
                vec![
                    ("type".to_string(), "filter live".to_string()),
                    ("Enter".to_string(), "keep query".to_string()),
                    ("Esc".to_string(), "clear + exit".to_string()),
                    ("Ctrl+U".to_string(), "clear input".to_string()),
                ],
            ),
            legend_line(
                "NEXT",
                vec![
                    ("Tab".to_string(), "return after exit".to_string()),
                    ("?".to_string(), "full help later".to_string()),
                ],
            ),
        ],
        InputMode::Filter => vec![
            legend_line(
                "FILTER",
                vec![
                    ("Tab/Shift+Tab".to_string(), "move fields".to_string()),
                    ("type".to_string(), "query/tags/template".to_string()),
                    ("Space/←→".to_string(), "toggle or cycle".to_string()),
                    ("Enter".to_string(), "apply".to_string()),
                    ("Esc".to_string(), "cancel".to_string()),
                ],
            ),
            legend_line(
                "EDIT",
                vec![
                    ("Backspace".to_string(), "delete char".to_string()),
                    ("Ctrl+U".to_string(), "clear field".to_string()),
                ],
            ),
        ],
        InputMode::Inspect => vec![
            legend_line(
                "INSPECT",
                vec![
                    ("Esc/q".to_string(), "close".to_string()),
                    ("j/k ↑↓".to_string(), "scroll".to_string()),
                    ("PgUp/PgDn".to_string(), "page".to_string()),
                    ("Home/End".to_string(), "jump".to_string()),
                    ("g/G".to_string(), "top/bottom".to_string()),
                ],
            ),
            legend_line(
                "RETURN",
                vec![("close report".to_string(), "resume normal mode".to_string())],
            ),
        ],
        InputMode::BackupCatalog => vec![
            legend_line(
                "BACKUPS",
                vec![
                    ("j/k ↑↓".to_string(), "select snapshot".to_string()),
                    ("PgUp/PgDn".to_string(), "page".to_string()),
                    ("Home/End g/G".to_string(), "jump".to_string()),
                    ("Enter/r".to_string(), "restore selected".to_string()),
                    ("Esc/q".to_string(), "close".to_string()),
                ],
            ),
            legend_line(
                "SAFE",
                vec![(
                    "restore".to_string(),
                    "creates a fresh backup before apply".to_string(),
                )],
            ),
        ],
        InputMode::ConfirmDelete => vec![
            legend_line(
                "DELETE",
                vec![
                    ("y/Enter".to_string(), "confirm".to_string()),
                    ("n/Esc".to_string(), "cancel".to_string()),
                ],
            ),
            legend_line(
                "SAFE",
                vec![("backup".to_string(), "created before delete".to_string())],
            ),
        ],
        InputMode::ConfirmRestore => vec![
            legend_line(
                "RESTORE",
                vec![
                    ("y/Enter".to_string(), "confirm".to_string()),
                    ("n/Esc".to_string(), "cancel".to_string()),
                ],
            ),
            legend_line(
                "SAFE",
                vec![(
                    "backup".to_string(),
                    "current state saved first".to_string(),
                )],
            ),
        ],
        InputMode::Edit => vec![
            legend_line(
                "FORM",
                vec![
                    ("type".to_string(), "change value".to_string()),
                    ("Tab/Shift+Tab".to_string(), "move fields".to_string()),
                    ("Enter".to_string(), "save".to_string()),
                    ("Esc".to_string(), "cancel".to_string()),
                    ("←→/Space".to_string(), "cycle Template".to_string()),
                ],
            ),
            legend_line(
                "EDIT",
                vec![
                    ("Backspace".to_string(), "delete char".to_string()),
                    ("Ctrl+U".to_string(), "clear field".to_string()),
                ],
            ),
        ],
        InputMode::Reorder => vec![
            legend_line(
                "REORDER",
                vec![
                    ("j/k ↑↓".to_string(), "move item".to_string()),
                    ("Enter".to_string(), "save order".to_string()),
                    ("Esc".to_string(), "cancel".to_string()),
                ],
            ),
            legend_line(
                "NOTE",
                vec![(
                    "clear filters".to_string(),
                    "required before reorder".to_string(),
                )],
            ),
        ],
    };

    let footer = Paragraph::new(lines)
        .style(Style::default().fg(MUTED_TEXT).bg(SURFACE_BG))
        .wrap(ratatui::widgets::Wrap { trim: false });
    frame.render_widget(footer, area);
}

fn render_delete_confirmation(frame: &mut Frame, state: &TuiState) {
    let area = centered_rect(frame.area(), 52, 18);
    let host = state.pending_delete_host().unwrap_or("?");
    let popup = Paragraph::new(format!(
        "Delete managed entry `{host}`?\n\nThis removes the file from config.d and updates state.toml.\nA backup will be created first."
    ))
    .block(
        Block::default()
            .title(" Confirm Delete ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(BORDER_ACTIVE))
            .style(Style::default().bg(Color::Rgb(20, 28, 34))),
    )
    .wrap(ratatui::widgets::Wrap { trim: false });

    frame.render_widget(Clear, area);
    frame.render_widget(popup, area);
}

fn render_restore_confirmation(frame: &mut Frame, state: &TuiState) {
    let area = centered_rect(frame.area(), 60, 22);
    let snapshot = state
        .pending_restore_snapshot()
        .map(|snapshot| snapshot.label.as_str())
        .unwrap_or("?");
    let popup = Paragraph::new(format!(
        "Restore backup snapshot `{snapshot}`?\n\nThis will replace root config and managed config.d with snapshot content.\nA fresh backup of the current state will be created first."
    ))
    .block(
        Block::default()
            .title(" Confirm Restore ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(BORDER_ACTIVE))
            .style(Style::default().bg(Color::Rgb(20, 28, 34))),
    )
    .wrap(ratatui::widgets::Wrap { trim: false });

    frame.render_widget(Clear, area);
    frame.render_widget(popup, area);
}

fn render_backup_catalog_modal(frame: &mut Frame, state: &mut TuiState) {
    let area = centered_rect(frame.area(), 78, 82);
    let layout = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(42), Constraint::Percentage(58)])
        .split(area);

    state.sync_backup_catalog_viewport(layout[0].height);

    let Some(catalog) = state.backup_catalog() else {
        return;
    };

    let list_items = if catalog.snapshots().is_empty() {
        vec![ListItem::new("No backups found")]
    } else {
        catalog
            .snapshots()
            .iter()
            .map(|snapshot| {
                let head = Line::from(vec![Span::styled(
                    snapshot.label.clone(),
                    Style::default()
                        .fg(Color::White)
                        .add_modifier(Modifier::BOLD),
                )]);
                let tail = Line::from(vec![
                    Span::styled(
                        format!(
                            "  root:{} ",
                            if snapshot.has_root_config {
                                "yes"
                            } else {
                                "no"
                            }
                        ),
                        Style::default().fg(MUTED_TEXT),
                    ),
                    Span::styled(
                        format!("managed:{}", snapshot.managed_file_count),
                        Style::default().fg(Color::Rgb(140, 190, 130)),
                    ),
                ]);
                ListItem::new(vec![head, tail])
            })
            .collect::<Vec<_>>()
    };

    let list = List::new(list_items)
        .block(
            Block::default()
                .title(format!(" Backups | {} ", catalog.position_label()))
                .borders(Borders::ALL)
                .border_style(Style::default().fg(BORDER_ACTIVE))
                .style(Style::default().bg(Color::Rgb(20, 28, 34))),
        )
        .highlight_style(
            Style::default()
                .bg(Color::Rgb(28, 49, 58))
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol(">> ");

    let mut list_state = ListState::default().with_offset(catalog.list_offset());
    list_state.select(catalog.selected_visible_index());

    let details = Paragraph::new(catalog.detail_lines().join("\n"))
        .block(
            Block::default()
                .title(" Snapshot Details ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(BORDER_SOFT))
                .style(Style::default().bg(Color::Rgb(20, 28, 34))),
        )
        .wrap(Wrap { trim: false });

    frame.render_widget(Clear, area);
    frame.render_stateful_widget(list, layout[0], &mut list_state);
    frame.render_widget(details, layout[1]);
}

fn render_filter_modal(frame: &mut Frame, state: &TuiState) {
    let Some(form) = state.filter_form() else {
        return;
    };

    let area = centered_rect(frame.area(), 66, 40);
    let lines = crate::tui::state::FilterField::all()
        .into_iter()
        .map(|field| {
            let is_active = field == form.active_field();
            let label_style = if is_active {
                Style::default()
                    .fg(BORDER_ACTIVE)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(MUTED_TEXT)
            };
            let value_style = if is_active {
                Style::default().bg(Color::Rgb(36, 52, 61)).fg(Color::White)
            } else {
                Style::default().fg(Color::White)
            };

            Line::from(vec![
                Span::styled(format!("{:<16}", field.label()), label_style),
                Span::styled(form.display_value(field), value_style),
            ])
        })
        .collect::<Vec<_>>();

    let popup = Paragraph::new(lines)
        .block(
            Block::default()
                .title(" Filters ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(BORDER_ACTIVE))
                .style(Style::default().bg(Color::Rgb(20, 28, 34))),
        )
        .wrap(ratatui::widgets::Wrap { trim: false });

    frame.render_widget(Clear, area);
    frame.render_widget(popup, area);
}

fn render_inspection_modal(frame: &mut Frame, state: &mut TuiState) {
    let area = centered_rect(frame.area(), 76, 78);
    state.sync_inspection_viewport(area.height);

    let Some(report) = state.inspection_report() else {
        return;
    };

    let border_color = if report.is_alert() {
        BORDER_ACTIVE
    } else {
        BORDER_SOFT
    };
    let popup = Paragraph::new(report.body())
        .block(
            Block::default()
                .title(format!(
                    " {} | {} ",
                    report.title(),
                    report.position_label()
                ))
                .borders(Borders::ALL)
                .border_style(Style::default().fg(border_color))
                .style(Style::default().bg(Color::Rgb(20, 28, 34))),
        )
        .scroll((report.scroll(), 0))
        .wrap(ratatui::widgets::Wrap { trim: false });

    frame.render_widget(Clear, area);
    frame.render_widget(popup, area);
}

fn render_edit_modal(frame: &mut Frame, state: &TuiState) {
    let Some(form) = state.entry_form() else {
        return;
    };

    let area = centered_rect(frame.area(), 72, 84);
    let lines = form
        .fields()
        .into_iter()
        .map(|(field, value)| {
            let is_active = field == form.active_field();
            let label_style = if is_active {
                Style::default()
                    .fg(BORDER_ACTIVE)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(MUTED_TEXT)
            };
            let value_style = if is_active {
                Style::default().bg(Color::Rgb(36, 52, 61)).fg(Color::White)
            } else {
                Style::default().fg(Color::White)
            };
            let display_value = if value.is_empty() { "<empty>" } else { value };

            Line::from(vec![
                Span::styled(format!("{:<24}", field.label()), label_style),
                Span::styled(display_value.to_string(), value_style),
            ])
        })
        .collect::<Vec<_>>();

    let title = format!(" {} {} ", form.mode().title(), form.original_host_label());
    let popup = Paragraph::new(lines)
        .block(
            Block::default()
                .title(title)
                .borders(Borders::ALL)
                .border_style(Style::default().fg(BORDER_ACTIVE))
                .style(Style::default().bg(Color::Rgb(20, 28, 34))),
        )
        .wrap(ratatui::widgets::Wrap { trim: false });

    frame.render_widget(Clear, area);
    frame.render_widget(popup, area);
}

fn centered_rect(area: Rect, width_percent: u16, height_percent: u16) -> Rect {
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - height_percent) / 2),
            Constraint::Percentage(height_percent),
            Constraint::Percentage((100 - height_percent) / 2),
        ])
        .split(area);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - width_percent) / 2),
            Constraint::Percentage(width_percent),
            Constraint::Percentage((100 - width_percent) / 2),
        ])
        .split(vertical[1])[1]
}

fn default_status_message(state: &TuiState) -> String {
    if state.entry_count() == 0 {
        return "Quick start | run `sshcfg init`, then press `a` to add an entry. `?` opens the full guide.".to_string();
    }

    if state.filtered_count() == 0 {
        return "No visible entries | press `x` to clear filters, `f` to edit filters, or `/` to refine the search.".to_string();
    }

    let selected = state
        .selected_entry()
        .map(|entry| entry.entry.primary_pattern().to_string())
        .unwrap_or_else(|| "<none>".to_string());

    if state.list_is_focused() {
        format!(
            "Selected `{selected}` | Tab switches to detail, `a/e/d/r` manage entries, `v` toggles raw / merged, `?` opens full help."
        )
    } else {
        format!(
            "Inspecting `{selected}` | use `j/k` or PgUp/PgDn to scroll, Tab returns to the host list, `v` toggles raw / merged."
        )
    }
}

fn normal_footer_lines(state: &TuiState) -> Vec<Line<'static>> {
    let nav_action = if state.list_is_focused() {
        "move list"
    } else {
        "scroll detail"
    };

    vec![
        legend_line(
            "NAV",
            vec![
                ("Tab".to_string(), "switch pane".to_string()),
                ("j/k ↑↓".to_string(), nav_action.to_string()),
                ("PgUp/PgDn".to_string(), "page".to_string()),
                ("Home/End g/G".to_string(), "jump".to_string()),
            ],
        ),
        legend_line(
            "ACT",
            vec![
                ("/".to_string(), "search".to_string()),
                ("f".to_string(), "filters".to_string()),
                ("x".to_string(), "clear".to_string()),
                (
                    "v".to_string(),
                    format!("view:{}", state.detail_mode().short_label()),
                ),
                ("a".to_string(), "add".to_string()),
                ("e".to_string(), "edit".to_string()),
                ("d".to_string(), "delete".to_string()),
                ("r".to_string(), "reorder".to_string()),
                ("V/D".to_string(), "diagnose".to_string()),
                ("t/b".to_string(), "catalogs".to_string()),
                ("Ctrl+R".to_string(), "reload".to_string()),
                ("?".to_string(), "help".to_string()),
                ("q".to_string(), "quit".to_string()),
            ],
        ),
    ]
}

fn legend_line(label: &str, items: Vec<(String, String)>) -> Line<'static> {
    let mut spans = vec![Span::styled(
        format!("{label:<7}"),
        Style::default()
            .fg(BORDER_ACTIVE)
            .add_modifier(Modifier::BOLD),
    )];

    for (key, description) in items {
        spans.push(Span::styled(
            format!(" {key} "),
            Style::default()
                .fg(Color::White)
                .bg(KEY_BG)
                .add_modifier(Modifier::BOLD),
        ));
        spans.push(Span::styled(
            format!(" {description}  "),
            Style::default().fg(MUTED_TEXT),
        ));
    }

    Line::from(spans)
}

fn append_header_pair(spans: &mut Vec<Span<'static>>, label: &str, value: impl Into<String>) {
    spans.push(Span::raw("  "));
    spans.push(Span::styled(
        format!("{} ", label.to_ascii_uppercase()),
        Style::default().fg(MUTED_TEXT).add_modifier(Modifier::BOLD),
    ));
    spans.push(Span::styled(
        truncate_text(&value.into(), 24),
        Style::default().fg(Color::White),
    ));
}

fn truncate_text(value: &str, max_width: usize) -> String {
    let chars = value.chars().collect::<Vec<_>>();
    if chars.len() <= max_width {
        return value.to_string();
    }

    if max_width <= 3 {
        return ".".repeat(max_width);
    }

    chars[..max_width - 3].iter().collect::<String>() + "..."
}
