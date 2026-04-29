use ratatui::prelude::*;
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph};

use crate::tui::state::{InputMode, TuiState};
use crate::tui::views::{BORDER_ACTIVE, BORDER_SOFT, MUTED_TEXT};

pub fn render(frame: &mut Frame, area: Rect, state: &mut TuiState) {
    state.sync_list_viewport(area.height);

    let border_style = match state.input_mode() {
        InputMode::Normal if state.list_is_focused() => Style::default().fg(BORDER_ACTIVE),
        InputMode::Search => Style::default().fg(BORDER_ACTIVE),
        InputMode::Filter => Style::default().fg(BORDER_ACTIVE),
        InputMode::Inspect => Style::default().fg(BORDER_ACTIVE),
        InputMode::BackupCatalog => Style::default().fg(BORDER_ACTIVE),
        InputMode::ConfirmDelete => Style::default().fg(BORDER_ACTIVE),
        InputMode::ConfirmRestore => Style::default().fg(BORDER_ACTIVE),
        InputMode::Edit => Style::default().fg(BORDER_ACTIVE),
        InputMode::Reorder => Style::default().fg(BORDER_ACTIVE),
        InputMode::Normal => Style::default().fg(BORDER_SOFT),
    };

    let mut title = format!(" Hosts {}/{} ", state.filtered_count(), state.entry_count());
    if let Some(summary) = state.active_filter_summary() {
        title.push_str(&format!("| {summary} "));
    }
    if let Some(position) = state.list_position_label() {
        title.push_str(&format!("| {position} "));
    }
    if matches!(state.input_mode(), InputMode::Normal) {
        title.push_str(&format!("[focus:{}] ", state.pane_focus().label()));
    }
    if matches!(state.input_mode(), InputMode::Reorder) {
        title.push_str("[reordering] ");
    }

    if state.entry_count() == 0 {
        let empty = Paragraph::new(
            "No managed entries yet.\n\nQuick start:\n  1. Run `sshcfg init`\n  2. Press `a` to create an entry or use `sshcfg add ...`\n  3. Press `?` for the full TUI guide",
        )
        .block(
            Block::default()
                .title(title)
                .borders(Borders::ALL)
                .border_style(border_style),
        )
        .wrap(ratatui::widgets::Wrap { trim: false });
        frame.render_widget(empty, area);
        return;
    }

    if state.filtered_count() == 0 {
        let empty = Paragraph::new(
            "No entries match the current filters.\n\nPress `x` to clear filters, `f` to edit them, or `/` to change the search query.\nPress `?` for the full key guide.",
        )
        .block(
            Block::default()
                .title(title)
                .borders(Borders::ALL)
                .border_style(border_style),
        )
        .wrap(ratatui::widgets::Wrap { trim: false });
        frame.render_widget(empty, area);
        return;
    }

    let items = state
        .filtered_indices()
        .iter()
        .map(|index| {
            let entry = state.entry(*index);
            let metadata = state.metadata(*index);
            let hostname = entry.entry.hostname.as_deref().unwrap_or("-");
            let tags = metadata
                .filter(|metadata| !metadata.tags.is_empty())
                .map(|metadata| metadata.tags.join(","))
                .unwrap_or_else(|| "-".to_string());

            let head = Line::from(vec![
                Span::styled(
                    format!("{:>3}", entry.order),
                    Style::default().fg(MUTED_TEXT),
                ),
                Span::raw(" "),
                Span::styled(
                    format!("{:<7}", entry.entry.kind().label()),
                    Style::default().fg(Color::Rgb(201, 178, 111)),
                ),
                Span::styled(
                    entry.entry.primary_pattern().to_string(),
                    Style::default().fg(Color::White),
                ),
            ]);

            let tail = Line::from(vec![
                Span::styled("  ", Style::default()),
                Span::styled(
                    hostname.to_string(),
                    Style::default().fg(Color::Rgb(123, 185, 173)),
                ),
                Span::styled("  tags:", Style::default().fg(MUTED_TEXT)),
                Span::styled(tags, Style::default().fg(Color::Rgb(140, 190, 130))),
            ]);

            ListItem::new(vec![head, tail])
        })
        .collect::<Vec<_>>();

    let list = List::new(items)
        .block(
            Block::default()
                .title(title)
                .borders(Borders::ALL)
                .border_style(border_style),
        )
        .highlight_style(
            Style::default()
                .bg(Color::Rgb(28, 49, 58))
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol(">> ");

    let mut list_state = ListState::default().with_offset(state.list_offset());
    list_state.select(state.selected_visible_index());
    frame.render_stateful_widget(list, area, &mut list_state);
}
