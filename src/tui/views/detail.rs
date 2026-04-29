use ratatui::prelude::*;
use ratatui::text::Line;
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};

use crate::tui::state::TuiState;
use crate::tui::views::{BORDER_ACTIVE, BORDER_SOFT, MUTED_TEXT};

pub fn render(frame: &mut Frame, area: Rect, state: &mut TuiState) {
    let sections = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(11), Constraint::Min(0)])
        .split(area);

    render_summary(frame, sections[0], state);
    render_content(frame, sections[1], state);
}

fn render_summary(frame: &mut Frame, area: Rect, state: &TuiState) {
    let Some(entry) = state.selected_entry() else {
        let (title, message) = if state.entry_count() == 0 {
            (
                " Quick Start ",
                "This workspace has no managed entries yet.\n\nRun `sshcfg init`, then press `a` to create one.\nUse `?` any time for the full key guide.",
            )
        } else if state.filtered_count() == 0 {
            (
                " Filters ",
                "No entry is currently visible.\n\nPress `x` to clear filters, `f` to edit filters, or `/` to change the search query.",
            )
        } else {
            (
                " Entry ",
                "Select an entry from the left list.\n\nUse Tab to switch panes and `?` for the full key guide.",
            )
        };
        let summary = Paragraph::new(message)
            .block(Block::default().title(title).borders(Borders::ALL))
            .wrap(Wrap { trim: false });
        frame.render_widget(summary, area);
        return;
    };

    let metadata = state.selected_metadata();
    let hostname = entry.entry.hostname.as_deref().unwrap_or("-");
    let template = metadata
        .and_then(|metadata| metadata.template_source.as_deref())
        .unwrap_or("-");
    let ssh_tag = entry.entry.tag.as_deref().unwrap_or("-");
    let tags = metadata
        .filter(|metadata| !metadata.tags.is_empty())
        .map(|metadata| metadata.tags.join(","))
        .unwrap_or_else(|| "-".to_string());
    let note = metadata
        .and_then(|metadata| metadata.note.as_deref())
        .unwrap_or("-");
    let updated_at = metadata
        .map(|metadata| metadata.updated_at.as_str())
        .unwrap_or("-");

    let lines = vec![
        summary_line("Host", entry.entry.primary_pattern()),
        summary_line("HostName", hostname),
        summary_line(
            "Order",
            format!(
                "{}   kind={}   file={}",
                entry.order,
                entry.entry.kind().label(),
                entry.path.display()
            ),
        ),
        summary_line("Patterns", &entry.entry.host_patterns.join(",")),
        summary_line("Template", template),
        summary_line("SSH Tag", ssh_tag),
        summary_line("Tags", &tags),
        summary_line("Note", note),
        summary_line("Updated", updated_at),
    ];

    let summary = Paragraph::new(lines)
        .block(
            Block::default()
                .title(" Entry ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(BORDER_SOFT)),
        )
        .wrap(Wrap { trim: false });
    frame.render_widget(summary, area);
}

fn render_content(frame: &mut Frame, area: Rect, state: &mut TuiState) {
    let border_style = if state.detail_is_focused() {
        Style::default().fg(BORDER_ACTIVE)
    } else {
        Style::default().fg(BORDER_SOFT)
    };

    let content = state.selected_content();
    state.sync_detail_viewport(area.height, content.lines().count().max(1));

    let title = if matches!(state.input_mode(), crate::tui::state::InputMode::Normal) {
        format!(
            "{} | {} | focus:{}",
            state.selected_content_title(),
            state.detail_position_label(),
            state.pane_focus().label()
        )
    } else {
        format!(
            "{} | {}",
            state.selected_content_title(),
            state.detail_position_label()
        )
    };
    let content = Paragraph::new(content)
        .block(
            Block::default()
                .title(title)
                .borders(Borders::ALL)
                .border_style(border_style),
        )
        .scroll((state.detail_scroll(), 0))
        .wrap(Wrap { trim: false });
    frame.render_widget(content, area);
}

fn summary_line(label: &str, value: impl Into<String>) -> Line<'static> {
    Line::from(vec![
        Span::styled(
            format!("{label:<10}"),
            Style::default().fg(MUTED_TEXT).add_modifier(Modifier::BOLD),
        ),
        Span::raw(" "),
        Span::raw(value.into()),
    ])
}
