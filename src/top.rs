//! `ridgewarden-health top`: the services and open alerts, live in a terminal, for
//! operators on a headless Pi over SSH. It reads the running app's JSON API, so it needs no
//! access to the app's config or database.

use std::collections::BTreeSet;
use std::io;
use std::time::Duration;

use serde::Deserialize;

use ridgewarden_client::tui::ratatui::Frame;
use ridgewarden_client::tui::ratatui::crossterm::event::{KeyCode, KeyEvent};
use ridgewarden_client::tui::ratatui::layout::{Constraint, Layout, Rect};
use ridgewarden_client::tui::ratatui::style::Style;
use ridgewarden_client::tui::ratatui::text::{Line, Span};
use ridgewarden_client::tui::ratatui::widgets::{Cell, Paragraph, Row, Table, TableState, Wrap};
use ridgewarden_client::tui::{
    self, Chrome, Fetch, Notice, Pill, Refresh, Theme, View, move_key, pill_table, tab_key,
};
use ridgewarden_client::ui::Color;
use ridgewarden_client::util::{human_duration, now_ms};

use crate::health::{Class, NodeCheck, Uptime, pct_text};
use crate::web::{check_words, class_color, plural};

const SERVICES: usize = 0;
const ALERTS: usize = 1;

/// Run `top` until the user quits, reading the app at `url` every `every`.
pub fn run(url: &str, every: Duration) -> anyhow::Result<()> {
    let base = url.trim_end_matches('/').to_string();
    // each read has the app work the whole services list out afresh, so give it time
    let fetch = Fetch::new(Duration::from_secs(10))?;
    let refresh = Refresh::spawn(every, async move || read(&fetch, &base).await)?;
    tui::run(
        &mut Top::new(refresh, Theme::from_env()),
        Duration::from_millis(250),
    )?;
    Ok(())
}

#[derive(Deserialize)]
struct Services {
    generated: i64,
    site: Option<String>,
    services: Vec<Svc>,
}

/// A service or heartbeat, as `/api/services` has it.
#[derive(Deserialize, Clone)]
struct Svc {
    name: String,
    /// the host's name from [site_names], or its node name
    host_label: String,
    link: String,
    heartbeat: bool,
    /// the state's label, e.g. "PARTIAL"
    class: String,
    since: Option<i64>,
    /// the state began before the history the app looks at, so `since` is a lower bound
    since_open: bool,
    reason: String,
    /// what AREDN's own check makes of it, when that's worth saying
    aredn: Option<String>,
    /// why its alerts are held back, if they are
    held: Option<String>,
    uptime: Uptime,
    vantages: Vec<Site>,
}

/// One site's verdict on a service, and its latest check.
#[derive(Deserialize, Clone)]
struct Site {
    /// the site's name from [site_names], or its node name
    label: String,
    ok: bool,
    ms: Option<f64>,
    detail: String,
    ts: i64,
    check: String,
    aredn: Option<NodeCheck>,
}

/// `/api/alerts`: what the services page shows above its list.
#[derive(Deserialize)]
struct Notes {
    cut_off: Vec<CutOff>,
    lapsed: Vec<Lapsed>,
    alerts: Vec<Open>,
}

/// A site whose latest round failed everywhere.
#[derive(Deserialize)]
struct CutOff {
    label: String,
}

/// A silence past its review date.
#[derive(Deserialize)]
struct Lapsed {
    matches: String,
    reason: String,
    review: String,
}

#[derive(Deserialize)]
struct Open {
    key: String,
    severity: String,
    title: String,
    text: String,
    opened: i64,
    acked: bool,
}

/// What one read of the app found.
struct Snap {
    /// when it was read, on this box's clock
    at: i64,
    /// when the app answered, on its clock, which the times in the data are on
    generated: i64,
    /// this site's node; None until the app has heard it from its core
    site: Option<String>,
    services: Vec<Svc>,
    /// the open alerts, or why they couldn't be read
    notes: Result<Notes, Failed>,
}

/// A read that failed: the URL and what went wrong in a few words, and what to try when
/// the way it failed makes that clear.
#[derive(Debug)]
struct Failed {
    what: String,
    hint: Option<&'static str>,
}

impl Failed {
    fn new(e: &anyhow::Error) -> Self {
        let hint = match e.downcast_ref::<reqwest::Error>() {
            Some(r) if r.is_connect() || r.is_timeout() => Some(
                "Is it running? Start it with: sudo systemctl start ridgewarden-health, or give \
                 its address with --url.",
            ),
            Some(r) if r.is_decode() || r.status().is_some_and(|s| s.as_u16() == 404) => Some(
                "Something answered, but not with what this view reads: it may be an older \
                 version of ridgewarden-health, or another program. Update it, or give the right \
                 address with --url.",
            ),
            _ => None,
        };
        Self {
            what: e.to_string(),
            hint,
        }
    }

    /// "Can't read the app: <url>: timed out. Is it running? ...", for `about` "the app".
    fn text(&self, about: &str) -> String {
        match self.hint {
            Some(h) => format!("Can't read {about}: {}. {h}", self.what),
            None => format!("Can't read {about}: {}.", self.what),
        }
    }
}

async fn read(fetch: &Fetch, base: &str) -> Result<Snap, Failed> {
    let s: Services = fetch
        .json(&format!("{base}/api/services"))
        .await
        .map_err(|e| Failed::new(&e))?;
    let notes = fetch
        .json(&format!("{base}/api/alerts"))
        .await
        .map_err(|e| Failed::new(&e));
    Ok(Snap {
        at: now_ms(),
        generated: s.generated,
        site: s.site,
        services: s.services,
        notes,
    })
}

/// A picked row that stays on the same service or alert while the rows move around, as
/// services change state and the worst come first.
#[derive(Default)]
struct Pick {
    rows: TableState,
    /// a service's link or an alert's key
    id: Option<String>,
}

impl Pick {
    /// Find the picked item among new rows. With nothing picked yet the first row is; when
    /// the item has gone, the row now in its place.
    fn keep(&mut self, ids: &[&str]) {
        let at = (!ids.is_empty()).then(|| {
            let id = self.id.as_deref();
            ids.iter()
                .position(|x| Some(*x) == id)
                .unwrap_or_else(|| self.rows.selected().map_or(0, |i| i.min(ids.len() - 1)))
        });
        self.set(at, ids);
    }

    fn key(&mut self, k: &KeyEvent, ids: &[&str], page: usize) {
        if move_key(&mut self.rows, k, ids.len(), page) {
            self.set(self.rows.selected(), ids);
        }
    }

    fn set(&mut self, at: Option<usize>, ids: &[&str]) {
        self.rows.select(at);
        self.id = at.map(|i| ids[i].to_string());
    }
}

/// The ids of a page's rows: the services' links, or the alerts' keys.
fn ids(s: &Snap, tab: usize) -> Vec<&str> {
    match (tab, &s.notes) {
        (SERVICES, _) => s.services.iter().map(|x| x.link.as_str()).collect(),
        (_, Ok(n)) => n.alerts.iter().map(|a| a.key.as_str()).collect(),
        (_, Err(_)) => vec![],
    }
}

/// How far the details are scrolled, kept as a row picked among the scroll positions so the
/// same keys move it as move the lists.
#[derive(Default)]
struct Scroll {
    at: TableState,
    /// the furthest it could go at the last draw
    max: usize,
}

struct Top {
    theme: Theme,
    refresh: Refresh<Result<Snap, Failed>>,
    snap: Option<Snap>,
    /// why the latest read failed, if it did; the last good one stays on screen
    err: Option<Failed>,
    tab: usize,
    picks: [Pick; 2],
    /// the picked service's details are open
    detail: bool,
    scroll: Scroll,
    /// rows a page had room for at the last draw, for PgUp and PgDn
    page: usize,
}

impl Top {
    fn new(refresh: Refresh<Result<Snap, Failed>>, theme: Theme) -> Self {
        Self {
            theme,
            refresh,
            snap: None,
            err: None,
            tab: SERVICES,
            picks: Default::default(),
            detail: false,
            scroll: Scroll::default(),
            page: 0,
        }
    }

    fn take(&mut self, read: Result<Snap, Failed>) {
        match read {
            Ok(s) => {
                for tab in [SERVICES, ALERTS] {
                    self.picks[tab].keep(&ids(&s, tab));
                }
                self.snap = Some(s);
                self.err = None;
                self.detail &= self.picked().is_some();
            }
            Err(e) => self.err = Some(e),
        }
    }

    fn picked(&self) -> Option<&Svc> {
        let i = self.picks[SERVICES].rows.selected()?;
        self.snap.as_ref()?.services.get(i)
    }

    fn status(&self, now: i64) -> Span<'static> {
        let Some(s) = &self.snap else {
            return match self.err {
                Some(_) => Span::styled("can't read the app", self.theme.bad()),
                None => Span::styled("loading", self.theme.mute()),
            };
        };
        let age = format!("updated {} ago", human_duration(now - s.at));
        match s.site {
            Some(_) => Span::styled(age, self.theme.mute()),
            None => Span::styled(format!("core not reached yet, {age}"), self.theme.bad()),
        }
    }

    fn help(&self) -> &'static str {
        if self.detail {
            "q quit  Esc back  Up Down PgUp PgDn scroll  1-2 Tab pages  r reload"
        } else if self.tab == SERVICES {
            "q quit  1-2 Tab pages  Up Down PgUp PgDn move  Enter details  r reload"
        } else {
            "q quit  1-2 Tab pages  Up Down PgUp PgDn move  r reload"
        }
    }

    fn render(&mut self, f: &mut Frame, now: i64) {
        let title = match self.snap.as_ref().and_then(|s| s.site.as_deref()) {
            Some(site) if !site.is_empty() => format!("ridgewarden-health top  {site}"),
            _ => "ridgewarden-health top".to_string(),
        };
        let open = match self.snap.as_ref().map(|s| &s.notes) {
            Some(Ok(n)) if !n.alerts.is_empty() => format!("Alerts ({})", n.alerts.len()),
            Some(Err(_)) => "Alerts (failed)".to_string(),
            _ => "Alerts".to_string(),
        };
        let tabs = ["Services", open.as_str()];
        let chrome = Chrome {
            title: &title,
            status: self.status(now),
            tabs: &tabs,
            tab: self.tab,
            help: self.help(),
        };
        let Some(mut area) = chrome.draw(f, &self.theme) else {
            return;
        };
        if let (Some(e), Some(_)) = (&self.err, &self.snap) {
            let msg = format!("Reading failed, so this is from earlier: {}", e.what);
            let lines: Vec<Line> = wrap(&msg, area.width.into())
                .into_iter()
                .take(2)
                .map(|l| Line::styled(l, self.theme.bad()))
                .collect();
            let [banner, rest] =
                Layout::vertical([Constraint::Length(lines.len() as u16), Constraint::Fill(1)])
                    .areas(area);
            f.render_widget(Paragraph::new(lines), banner);
            area = rest;
        }
        let Some(s) = &self.snap else {
            let msg;
            let n = match &self.err {
                Some(e) => {
                    msg = e.text("the app");
                    Notice::Error(&msg)
                }
                None => Notice::Loading,
            };
            f.render_widget(n.paragraph(&self.theme), area);
            return;
        };
        // the data's times are on the app's clock, which may not agree with this box's: count
        // from when the app answered, plus however long ago that was here
        let c = Ctx {
            theme: &self.theme,
            s,
            now: s.generated + (now - s.at),
        };
        let picked = self.picks[SERVICES]
            .rows
            .selected()
            .and_then(|i| s.services.get(i));
        self.page = match (self.tab, picked) {
            (SERVICES, Some(x)) if self.detail => details(&c, f, area, x, &mut self.scroll),
            (SERVICES, _) => services(&c, f, area, &mut self.picks[SERVICES].rows),
            _ => alerts(&c, f, area, &mut self.picks[ALERTS].rows),
        };
    }
}

impl View for Top {
    fn tick(&mut self) -> io::Result<()> {
        if let Some(read) = self.refresh.latest()? {
            self.take(read);
        }
        Ok(())
    }

    fn key(&mut self, k: KeyEvent) -> bool {
        if let Some(t) = tab_key(&k, self.tab, 2) {
            self.tab = t;
            self.detail = false;
        } else if k.code == KeyCode::Char('r') {
            self.refresh.again();
        } else if self.detail {
            if matches!(k.code, KeyCode::Esc | KeyCode::Enter | KeyCode::Backspace) {
                self.detail = false;
            } else {
                move_key(&mut self.scroll.at, &k, self.scroll.max + 1, self.page);
            }
        } else if k.code == KeyCode::Enter && self.tab == SERVICES && self.picked().is_some() {
            self.detail = true;
            self.scroll.at.select(Some(0));
        } else if let Some(s) = &self.snap {
            self.picks[self.tab].key(&k, &ids(s, self.tab), self.page);
        }
        true
    }

    fn draw(&mut self, f: &mut Frame) {
        self.render(f, now_ms());
    }
}

/// What the pages draw from.
struct Ctx<'a> {
    theme: &'a Theme,
    s: &'a Snap,
    /// now, on the app's clock
    now: i64,
}

/// A colored word like the page's pills, for this app's states and alert severities, which
/// aren't among the shared `Pill`s.
fn tag(theme: &Theme, c: Color, word: &str) -> Span<'static> {
    Span::styled(format!(" {word} "), theme.pill(c))
}

/// A state's color on the page; gray for one this build doesn't know.
fn state_color(label: &str) -> Color {
    Class::from_label(label).map_or(Color::Unknown, class_color)
}

fn severity_color(severity: &str) -> Color {
    if severity == "critical" {
        Color::Red
    } else {
        Color::Yellow
    }
}

/// A table with a header and the picked row in reverse video, as `pill_table` draws them.
fn table<'a>(
    theme: &Theme,
    header: &[&'a str],
    widths: &[Constraint],
    rows: Vec<Row<'a>>,
) -> Table<'a> {
    Table::new(rows, widths.to_vec())
        .header(Row::new(header.to_vec()).style(theme.heading()))
        .row_highlight_style(theme.selected())
}

/// `text` broken at spaces into lines at most `width` columns wide; a longer word gets a
/// line of its own.
fn wrap(text: &str, width: usize) -> Vec<String> {
    let mut out = vec![];
    let (mut line, mut used) = (String::new(), 0);
    for word in text.split_whitespace() {
        let w = Span::raw(word).width();
        if used > 0 && used + 1 + w > width {
            out.push(std::mem::take(&mut line));
            used = 0;
        }
        if used > 0 {
            line.push(' ');
            used += 1;
        }
        line.push_str(word);
        used += w;
    }
    if used > 0 {
        out.push(line);
    }
    out
}

/// "8 services, 1 heartbeat: 1 DOWN, 1 PARTIAL, 7 UP", worst first as the app sorts them.
fn summary(list: &[Svc]) -> String {
    let beats = list.iter().filter(|x| x.heartbeat).count();
    let mut what = plural(list.len() - beats, "service", "services");
    if beats > 0 {
        what = format!("{what}, {}", plural(beats, "heartbeat", "heartbeats"));
    }
    let mut counts: Vec<(&str, usize)> = vec![];
    for x in list {
        match counts.iter_mut().find(|(c, _)| *c == x.class) {
            Some((_, n)) => *n += 1,
            None => counts.push((&x.class, 1)),
        }
    }
    let counts: Vec<String> = counts.iter().map(|(c, n)| format!("{n} {c}")).collect();
    format!("{what}: {}", counts.join(", "))
}

/// "2/3": how many of the sites with recent results find it working. A heartbeat says
/// "push": only the site it checks in at judges it.
fn answering(x: &Svc) -> String {
    match x.vantages.len() {
        _ if x.heartbeat => "push".into(),
        0 => "-".into(),
        n => format!("{}/{n}", x.vantages.iter().filter(|v| v.ok).count()),
    }
}

/// How long it has been in its state: "12 min", or "over 3 d" when that began before the
/// history the app looks at.
fn lasted(x: &Svc, now: i64) -> String {
    let Some(t) = x.since else {
        return String::new();
    };
    let more = if x.since_open { "over " } else { "" };
    format!("{more}{}", human_duration(now - t))
}

/// The services, worst first, and the picked one's reason under them. Returns the rows the
/// list has room for.
fn services(c: &Ctx, f: &mut Frame, area: Rect, rows: &mut TableState) -> usize {
    let list = &c.s.services;
    if list.is_empty() {
        let why = "No services seen yet. The core needs to poll its node at least once.";
        f.render_widget(Notice::Empty(why).paragraph(c.theme), area);
        return 0;
    }
    let width = area.width.into();
    let mut head: Vec<Line> = wrap(&summary(list), width)
        .into_iter()
        .map(Line::raw)
        .collect();
    if let Ok(n) = &c.s.notes {
        for site in &n.cut_off {
            let msg = format!(
                "Every check from {} failed, so it looks cut off and its results are left out.",
                site.label
            );
            head.extend(
                wrap(&msg, width)
                    .into_iter()
                    .map(|l| Line::styled(l, c.theme.bad())),
            );
        }
    }
    let [top, _, list_area, _, pane] = Layout::vertical([
        Constraint::Length(head.len() as u16),
        Constraint::Length(1),
        Constraint::Fill(1),
        Constraint::Length(1),
        Constraint::Length(4),
    ])
    .areas(area);
    f.render_widget(Paragraph::new(head), top);
    // as wide as the longest state shown, so the names get the room when that's short
    let state = list.iter().map(|x| x.class.len() + 2).max().unwrap_or(0);
    let widths = [
        Constraint::Length(state.max(5) as u16),
        Constraint::Fill(3),
        Constraint::Fill(2),
        Constraint::Length(5),
        Constraint::Length(6),
        Constraint::Length(8),
    ];
    let items = list.iter().map(|x| service_row(c, x)).collect();
    let header = ["State", "Service", "Host", "Sites", "30 d", "For"];
    f.render_stateful_widget(table(c.theme, &header, &widths, items), list_area, rows);
    if let Some(x) = rows.selected().and_then(|i| list.get(i)) {
        f.render_widget(why(c, x), pane);
    }
    list_area.height.saturating_sub(1).into()
}

fn service_row<'a>(c: &Ctx, x: &'a Svc) -> Row<'a> {
    Row::new([
        Cell::from(tag(c.theme, state_color(&x.class), &x.class)),
        Cell::from(x.name.as_str()),
        Cell::from(x.host_label.as_str()),
        Cell::from(answering(x)),
        Cell::from(pct_text(x.uptime.month)),
        Cell::from(lasted(x, c.now)),
    ])
}

/// The picked service's reason, as the page's Why column has it.
fn why<'a>(c: &Ctx, x: &'a Svc) -> Paragraph<'a> {
    let mut lines = vec![Line::from(vec![
        Span::styled(format!("{}: ", x.name), c.theme.heading()),
        Span::raw(x.reason.as_str()),
    ])];
    if let Some(h) = &x.held {
        lines.push(Line::styled(h.as_str(), c.theme.mute()));
    }
    if x.aredn.is_some() && x.class != Class::UnpublishedAlive.label() {
        lines.push(Line::raw(
            "AREDN's check would fail on it, so the node stops listing it once it has failed \
             for 2.5 hours; Enter for details.",
        ));
    }
    Paragraph::new(lines).wrap(Wrap { trim: true })
}

/// One service: each site's verdict and latest check, then the reason, what AREDN's own
/// check makes of it, its uptime and how it's checked, scrolling when that doesn't fit.
/// Returns the text's height.
fn details(c: &Ctx, f: &mut Frame, area: Rect, x: &Svc, scroll: &mut Scroll) -> usize {
    // the sites get about half the height at most, so the reason below keeps some room
    let room = usize::from(area.height / 2).saturating_sub(1).max(2);
    let rows = x.vantages.len().clamp(1, room);
    let [head, _, sites_area, _, text] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(rows as u16 + 1),
        Constraint::Length(1),
        Constraint::Fill(1),
    ])
    .areas(area);
    let lines = detail_lines(c, x, text.width.into());
    let shown = usize::from(text.height);
    scroll.max = lines.len().saturating_sub(shown);
    let at = scroll.at.selected().unwrap_or(0).min(scroll.max);
    scroll.at.select(Some(at));
    let mut first = vec![
        tag(c.theme, state_color(&x.class), &x.class),
        Span::raw(" "),
        Span::styled(x.name.as_str(), c.theme.heading()),
        Span::raw(format!(" on {}", x.host_label)),
    ];
    let lasted = lasted(x, c.now);
    if !lasted.is_empty() {
        first.push(Span::styled(format!(", for {lasted}"), c.theme.mute()));
    }
    let place = if scroll.max > 0 {
        let last = (at + shown).min(lines.len());
        Span::styled(
            format!("lines {}-{last} of {}", at + 1, lines.len()),
            c.theme.mute(),
        )
    } else {
        Span::raw("")
    };
    let [left, right] = Layout::horizontal([
        Constraint::Fill(1),
        Constraint::Length(place.width() as u16),
    ])
    .spacing(1)
    .areas(head);
    f.render_widget(Line::from(first), left);
    f.render_widget(place, right);
    site_table(c, f, sites_area, x, rows);
    f.render_widget(Paragraph::new(lines).scroll((at as u16, 0)), text);
    shown
}

/// Each site's verdict and latest check, in at most `rows` rows: when there are more sites
/// than that, the last row says how many more there are.
fn site_table(c: &Ctx, f: &mut Frame, area: Rect, x: &Svc, rows: usize) {
    if x.vantages.is_empty() {
        let none = Notice::Empty("No recent results from any site.");
        f.render_widget(none.paragraph(c.theme), area);
        return;
    }
    let shown = if x.vantages.len() > rows {
        rows - 1
    } else {
        rows
    };
    let mut items: Vec<(Option<Pill>, Vec<Cell>)> = x.vantages[..shown]
        .iter()
        .map(|v| {
            let ms = v.ms.map(|m| format!(", {m:.0} ms")).unwrap_or_default();
            let mut cells = vec![
                Cell::from(v.label.as_str()),
                Cell::from(format!("{}{ms}", v.detail)),
                Cell::from(format!("{} ago", human_duration(c.now - v.ts))),
            ];
            if !x.heartbeat {
                cells.push(Cell::from(node_word(c.theme, v.aredn.as_ref())));
            }
            (Some(if v.ok { Pill::Ok } else { Pill::Down }), cells)
        })
        .collect();
    let more = x.vantages.len() - shown;
    if more > 0 {
        let text = Span::styled(format!("+{more} more"), c.theme.mute());
        items.push((None, vec![Cell::from(text)]));
    }
    let mut header = vec!["Site", "Last check", "Checked"];
    let mut widths = vec![
        Constraint::Length(14),
        Constraint::Fill(1),
        Constraint::Length(10),
    ];
    if !x.heartbeat {
        header.push("AREDN's check");
        widths.push(Constraint::Length(13));
    }
    f.render_widget(pill_table(c.theme, &header, &widths, items), area);
}

/// What the node's own check makes of it from one site, in two words.
fn node_word(theme: &Theme, a: Option<&NodeCheck>) -> Span<'static> {
    match a {
        None => Span::styled("-", theme.mute()),
        Some(a) if a.pass => Span::raw("keeps it"),
        Some(_) => Span::styled("drops it", theme.bad()),
    }
}

/// The details' text, wrapped to `width`.
fn detail_lines(c: &Ctx, x: &Svc, width: usize) -> Vec<Line<'static>> {
    let mut paras = vec![(x.reason.clone(), Style::new())];
    if let Some(h) = &x.held {
        paras.push((h.clone(), c.theme.mute()));
    }
    if let Some(a) = &x.aredn {
        paras.push((format!("AREDN's own check: {a}"), Style::new()));
    }
    let u = &x.uptime;
    let uptime = format!(
        "Uptime from every site's checks: 24 hours {}, 30 days {}, 1 year {}.",
        pct_text(u.day),
        pct_text(u.month),
        pct_text(u.year)
    );
    paras.push((uptime, c.theme.mute()));
    paras.push((how(x), c.theme.mute()));
    let mut lines = vec![];
    for (i, (text, style)) in paras.into_iter().enumerate() {
        if i > 0 {
            lines.push(Line::default());
        }
        lines.extend(
            wrap(&text, width)
                .into_iter()
                .map(|l| Line::styled(l, style)),
        );
    }
    lines
}

/// What is checked and how, in the service page's words.
fn how(x: &Svc) -> String {
    if x.heartbeat {
        return format!(
            "A push heartbeat received at {}. That site judges whether it is on time and \
             shares its verdict with every other site.",
            x.host_label
        );
    }
    let kinds: BTreeSet<&str> = x.vantages.iter().map(|v| v.check.as_str()).collect();
    let how: Vec<&str> = kinds.into_iter().map(check_words).collect();
    let on = format!("{} on {}.", x.link, x.host_label);
    if how.is_empty() {
        on
    } else {
        format!("{on} Checked with {}.", how.join(", "))
    }
}

/// The open alerts, worst first, the picked one's text under them, and above them any site
/// that looks cut off and any silence past its review date. Returns the rows the list has
/// room for.
fn alerts(c: &Ctx, f: &mut Frame, area: Rect, rows: &mut TableState) -> usize {
    let n = match &c.s.notes {
        Ok(n) => n,
        Err(e) => {
            let msg = e.text("the open alerts");
            f.render_widget(Notice::Error(&msg).paragraph(c.theme), area);
            return 0;
        }
    };
    let banners = n.cut_off.iter().map(|site| {
        format!(
            "Every check from {} failed in its last round, so that site is probably cut off \
             from the mesh. Its results are left out until it can reach things again.",
            site.label
        )
    });
    let banners = banners.chain(n.lapsed.iter().map(|x| {
        format!(
            "The silence on \"{}\" passed its review date ({}). Alerts for it are back on; \
             remove it from the config or set a new date. Reason given: {}",
            x.matches, x.review, x.reason
        )
    }));
    let head: Vec<Line> = banners
        .flat_map(|b| wrap(&b, area.width.into()))
        .map(|l| Line::styled(l, c.theme.bad()))
        .collect();
    let gap = u16::from(!head.is_empty());
    let [top, _, rest] = Layout::vertical([
        Constraint::Length(head.len() as u16),
        Constraint::Length(gap),
        Constraint::Fill(1),
    ])
    .areas(area);
    f.render_widget(Paragraph::new(head), top);
    if n.alerts.is_empty() {
        f.render_widget(Notice::Empty("No open alerts.").paragraph(c.theme), rest);
        return 0;
    }
    let tall = (n.alerts.len() as u16 + 1).min(rest.height / 2).max(2);
    let [list, _, text] = Layout::vertical([
        Constraint::Length(tall),
        Constraint::Length(1),
        Constraint::Fill(1),
    ])
    .areas(rest);
    let items = n
        .alerts
        .iter()
        .map(|a| {
            Row::new([
                Cell::from(tag(c.theme, severity_color(&a.severity), &a.severity)),
                Cell::from(a.title.as_str()),
                Cell::from(human_duration(c.now - a.opened)),
                Cell::from(if a.acked { "yes" } else { "" }),
            ])
        })
        .collect();
    let widths = [
        Constraint::Length(10),
        Constraint::Fill(1),
        Constraint::Length(8),
        Constraint::Length(5),
    ];
    let header = ["Severity", "Alert", "Open for", "Acked"];
    f.render_stateful_widget(table(c.theme, &header, &widths, items), list, rows);
    if let Some(a) = rows.selected().and_then(|i| n.alerts.get(i)) {
        let p = Paragraph::new(vec![
            Line::styled(a.title.as_str(), c.theme.heading()),
            Line::raw(a.text.as_str()),
        ]);
        f.render_widget(p.wrap(Wrap { trim: true }), text);
    }
    list.height.saturating_sub(1).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use std::sync::Arc;

    use ridgewarden_client::Event;
    use ridgewarden_client::alerts::{self, Alert, Severity};
    use ridgewarden_client::mesh::testing::Fake;
    use ridgewarden_client::tui::MIN_SIZE;
    use ridgewarden_client::tui::ratatui::Terminal;
    use ridgewarden_client::tui::ratatui::backend::TestBackend;
    use ridgewarden_client::tui::ratatui::buffer::Buffer;
    use ridgewarden_client::tui::ratatui::crossterm::event::KeyModifiers;
    use ridgewarden_client::tui::ratatui::style::Color as Ansi;
    use serde_json::{Value, json};

    use crate::app::App;
    use crate::config::{Config, EXAMPLE};

    const MIN: i64 = 60_000;
    const NOW: i64 = 1_800_000_000_000;

    fn top() -> Top {
        let refresh = Refresh::spawn(Duration::from_secs(3600), async || {
            Err(failed("not read in this test"))
        })
        .unwrap();
        Top::new(refresh, Theme { color: false })
    }

    fn failed(what: &str) -> Failed {
        Failed {
            what: what.into(),
            hint: None,
        }
    }

    fn press(top: &mut Top, code: KeyCode) {
        assert!(top.key(KeyEvent::new(code, KeyModifiers::NONE)));
    }

    fn draw(top: &mut Top, w: u16, h: u16, now: i64) -> Buffer {
        let mut t = Terminal::new(TestBackend::new(w, h)).unwrap();
        t.draw(|f| top.render(f, now)).unwrap();
        t.backend().buffer().clone()
    }

    fn text(b: &Buffer) -> String {
        let rows = (0..b.area.height).map(|y| {
            let row: String = (0..b.area.width).map(|x| b[(x, y)].symbol()).collect();
            row.trim_end().to_string()
        });
        rows.collect::<Vec<_>>().join("\n")
    }

    /// The text on a `w` by `h` terminal after one draw.
    fn screen(top: &mut Top, w: u16, h: u16) -> String {
        text(&draw(top, w, h, NOW))
    }

    /// Text with its line breaks and runs of spaces as single spaces, for wrapped sentences.
    fn flat(s: &str) -> String {
        s.split_whitespace().collect::<Vec<_>>().join(" ")
    }

    /// A service as `/api/services` has it, checked from `sites` (name, working), with no
    /// [site_names] set.
    fn svc(name: &str, class: &str, sites: &[(&str, bool)]) -> Value {
        let vantages: Vec<Value> = sites
            .iter()
            .map(|(v, ok)| {
                json!({"vantage": v, "label": v, "ok": ok, "ms": 12.0, "ts": NOW - MIN,
                       "pending": 0, "detail": if *ok { "HTTP 200" } else { "timed out" },
                       "check": "http", "aredn": {"pass": true, "code": "http-ok", "status": 200}})
            })
            .collect();
        json!({
            "name": name, "host": "tst-tower", "host_label": "tst-tower",
            "link": format!("http://tst-tower.local.mesh/{name}"),
            "heartbeat": false, "class": class, "since": NOW - 12 * MIN, "since_open": false,
            "reason": format!("Why {name} is {class}."), "aredn": null, "held": null,
            "uptime": {"day": 100.0, "month": 99.5, "year": null}, "vantages": vantages,
        })
    }

    /// A read 2 s before NOW, with the app's clock agreeing with ours.
    fn snap(services: Vec<Value>) -> Snap {
        Snap {
            at: NOW - 2000,
            generated: NOW - 2000,
            site: Some("tst-shack".into()),
            services: serde_json::from_value(Value::Array(services)).unwrap(),
            notes: Ok(Notes {
                cut_off: vec![],
                lapsed: vec![],
                alerts: vec![],
            }),
        }
    }

    #[test]
    fn rows_read_like_the_page() {
        let s = snap(vec![
            svc(
                "Cam",
                "DOWN",
                &[("tst-shack", false), ("tst-harbor", false)],
            ),
            svc(
                "Map",
                "PARTIAL",
                &[("tst-shack", true), ("tst-harbor", false)],
            ),
            svc("Wiki", "UP", &[("tst-shack", true)]),
            svc("Chat", "UP", &[]),
        ]);
        assert_eq!(summary(&s.services), "4 services: 1 DOWN, 1 PARTIAL, 2 UP");
        let sites: Vec<String> = s.services.iter().map(answering).collect();
        assert_eq!(sites, ["0/2", "1/2", "1/1", "-"]);
        let mut x = s.services[0].clone();
        assert_eq!(lasted(&x, NOW), "12 min");
        x.since = Some(NOW - 3 * 86_400_000);
        x.since_open = true;
        assert_eq!(
            lasted(&x, NOW),
            "over 3 d",
            "it began before the history kept"
        );
        x.since = None;
        assert_eq!(lasted(&x, NOW), "");
        let mut beat = s.services[2].clone();
        beat.heartbeat = true;
        assert_eq!(answering(&beat), "push");
        assert_eq!(
            summary(&[s.services[2].clone(), beat]),
            "1 service, 1 heartbeat: 2 UP"
        );
    }

    #[test]
    fn states_and_severities_get_the_pages_colors() {
        assert_eq!(state_color("UP"), Color::Green);
        assert_eq!(
            state_color("UNPUBLISHED-BUT-ALIVE"),
            Color::Green,
            "dropped from the list, but working"
        );
        assert_eq!(state_color("PARTIAL"), Color::Yellow);
        assert_eq!(state_color("STALE"), Color::Yellow);
        assert_eq!(state_color("DOWN"), Color::Red);
        assert_eq!(state_color("GONE"), Color::Unknown);
        assert_eq!(state_color("UNKNOWN"), Color::Unknown);
        assert_eq!(
            state_color("NEWER-STATE"),
            Color::Unknown,
            "from a newer app"
        );
        assert_eq!(severity_color("critical"), Color::Red);
        assert_eq!(severity_color("warning"), Color::Yellow);
        assert_eq!(severity_color("info"), Color::Yellow);
        let mut t = top();
        t.theme = Theme { color: true };
        t.take(Ok(snap(vec![
            svc("Cam", "DOWN", &[]),
            svc("Wiki", "UP", &[]),
        ])));
        let b = draw(&mut t, 80, 24, NOW);
        let rows: Vec<String> = text(&b).lines().map(str::to_string).collect();
        let bg = |name: &str| {
            let y = rows.iter().position(|r| r.contains(name)).unwrap() as u16;
            b[(1, y)].bg
        };
        assert_eq!((bg("Cam"), bg("Wiki")), (Ansi::Red, Ansi::Green));
    }

    #[test]
    fn the_pick_stays_on_a_service_as_rows_move() {
        let mut t = top();
        let names = |list: &[&str]| -> Vec<Value> {
            list.iter()
                .map(|n| svc(n, if *n == list[0] { "DOWN" } else { "UP" }, &[]))
                .collect()
        };
        t.take(Ok(snap(names(&["Cam", "Map", "Wiki"]))));
        assert_eq!(
            t.picked().unwrap().name,
            "Cam",
            "the worst is first and picked"
        );
        press(&mut t, KeyCode::Down);
        assert_eq!(t.picked().unwrap().name, "Map");
        t.take(Ok(snap(names(&["Map", "Cam", "Wiki"]))));
        assert_eq!(
            (
                t.picks[SERVICES].rows.selected(),
                t.picked().unwrap().name.as_str()
            ),
            (Some(0), "Map"),
            "Map went down and moved to the top, and the pick went with it"
        );
        t.take(Ok(snap(names(&["Cam", "Wiki"]))));
        assert_eq!(
            t.picked().unwrap().name,
            "Cam",
            "Map is gone: the row in its place"
        );
        assert!(
            screen(&mut t, 80, 24).contains("Cam: Why Cam is DOWN."),
            "its reason shows under the list"
        );
        t.take(Ok(snap(vec![])));
        assert!(t.picked().is_none());
    }

    #[test]
    fn enter_opens_a_services_details_and_esc_or_another_page_closes_them() {
        let mut t = top();
        t.take(Ok(snap(vec![svc("Cam", "DOWN", &[("tst-shack", false)])])));
        press(&mut t, KeyCode::Enter);
        assert!(t.detail);
        let s = screen(&mut t, 80, 24);
        assert!(s.contains(" DOWN  Cam on tst-tower, for 12 min"), "{s}");
        assert!(
            s.contains("tst-shack") && s.contains("timed out, 12 ms"),
            "{s}"
        );
        press(&mut t, KeyCode::Esc);
        assert!(!t.detail);
        press(&mut t, KeyCode::Enter);
        press(&mut t, KeyCode::Char('2'));
        assert_eq!((t.tab, t.detail), (ALERTS, false));
        press(&mut t, KeyCode::Enter);
        assert!(!t.detail, "an alert's text is under the list already");
        press(&mut t, KeyCode::Tab);
        press(&mut t, KeyCode::Enter);
        t.take(Ok(snap(vec![])));
        assert!(!t.detail, "the service went away");
        press(&mut t, KeyCode::Enter);
        assert!(!t.detail, "nothing to open");
    }

    #[test]
    fn text_wraps_at_spaces_within_the_width() {
        assert_eq!(wrap("one two three four", 9), ["one two", "three", "four"]);
        assert_eq!(
            wrap("at http://tst-tower.local.mesh:8080/ now", 12),
            ["at", "http://tst-tower.local.mesh:8080/", "now"]
        );
        assert_eq!(wrap("  spaced   out ", 80), ["spaced out"]);
        assert!(wrap("", 10).is_empty());
    }

    #[test]
    fn holds_lapsed_silences_and_cut_off_sites_show_where_the_page_has_them() {
        let mut x = svc("Cam", "DOWN", &[("tst-shack", false)]);
        x["held"] = json!("Maintenance until 2026-11-23 19:00 UTC: tower work");
        let mut s = snap(vec![x]);
        if let Ok(n) = &mut s.notes {
            n.cut_off = vec![CutOff {
                label: "tst-creek".into(),
            }];
            n.lapsed = vec![Lapsed {
                matches: "camera".into(),
                reason: "owner is replacing it".into(),
                review: "2026-11-01".into(),
            }];
        }
        let mut t = top();
        t.take(Ok(s));
        let list = flat(&screen(&mut t, 80, 24));
        assert!(
            list.contains("Every check from tst-creek failed, so it looks cut off"),
            "{list}"
        );
        assert!(
            list.contains(
                "Cam: Why Cam is DOWN. Maintenance until 2026-11-23 19:00 UTC: tower work"
            ),
            "{list}"
        );
        press(&mut t, KeyCode::Enter);
        let d = flat(&screen(&mut t, 80, 24));
        assert!(
            d.contains("Why Cam is DOWN. Maintenance until 2026-11-23 19:00 UTC: tower work"),
            "{d}"
        );
        press(&mut t, KeyCode::Char('2'));
        let a = flat(&screen(&mut t, 80, 24));
        for want in [
            "Every check from tst-creek failed in its last round, so that site is probably cut \
             off from the mesh.",
            "The silence on \"camera\" passed its review date (2026-11-01). Alerts for it are \
             back on; remove it from the config or set a new date. Reason given: owner is \
             replacing it",
            "No open alerts.",
        ] {
            assert!(a.contains(want), "{want:?} missing from {a}");
        }
    }

    #[test]
    fn a_heartbeats_details_have_no_aredn_column() {
        let mut x = svc("Nightly backup", "UP", &[("tst-shack", true)]);
        x["heartbeat"] = json!(true);
        x["host_label"] = json!("tst-shack");
        let beat = &mut x["vantages"][0];
        beat["check"] = json!("push");
        beat["detail"] = json!("last beat 5 min ago: copied 42 files");
        beat["ms"] = json!(null);
        beat["aredn"] = json!(null);
        let mut t = top();
        t.take(Ok(snap(vec![x])));
        let list = screen(&mut t, 80, 24);
        let row = list.lines().find(|l| l.contains("Nightly backup")).unwrap();
        assert!(row.contains(" push "), "{list}");
        press(&mut t, KeyCode::Enter);
        let d = screen(&mut t, 80, 24);
        let header = d.lines().find(|l| l.starts_with("State")).unwrap();
        assert!(
            header.contains("Checked") && !header.contains("AREDN"),
            "{d}"
        );
        let site = d.lines().find(|l| l.contains("copied 42 files")).unwrap();
        assert!(site.starts_with(" OK ") && site.ends_with("ago"), "{d}");
        assert!(
            flat(&d).contains("A push heartbeat received at tst-shack."),
            "{d}"
        );
    }

    #[test]
    fn page_keys_move_a_screenful_through_a_long_list() {
        let list: Vec<Value> = (1..=30)
            .map(|i| svc(&format!("Service {i:02}"), "UP", &[("tst-shack", true)]))
            .collect();
        let mut t = top();
        t.take(Ok(snap(list)));
        let first = screen(&mut t, 80, 24);
        assert!(
            first.contains("Service 01") && !first.contains("Service 30"),
            "{first}"
        );
        let page = t.page;
        assert!(page >= 10, "most of the 24 rows hold the list: {page}");
        let picked = |t: &Top| t.picked().unwrap().name.clone();
        press(&mut t, KeyCode::PageDown);
        assert_eq!(picked(&t), format!("Service {:02}", 1 + page));
        let s = screen(&mut t, 80, 24);
        assert!(
            s.contains(&format!("Service {:02}", 1 + page)),
            "the list scrolls to the pick: {s}"
        );
        press(&mut t, KeyCode::PageDown);
        press(&mut t, KeyCode::PageDown);
        assert_eq!(picked(&t), "Service 30", "it stops at the end");
        assert!(screen(&mut t, 80, 24).contains("Service 30"));
        press(&mut t, KeyCode::PageUp);
        assert_eq!(picked(&t), format!("Service {:02}", 30 - page));
        press(&mut t, KeyCode::Home);
        assert_eq!(picked(&t), "Service 01");
    }

    /// Tick `t` until its latest read is from `site`.
    fn read_until(t: &mut Top, site: &str) {
        let until = std::time::Instant::now() + Duration::from_secs(10);
        while t.snap.as_ref().and_then(|s| s.site.as_deref()) != Some(site) {
            assert!(std::time::Instant::now() < until, "{site} was never read");
            t.tick().unwrap();
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    #[test]
    fn r_reads_again_and_backspace_closes_the_details() {
        use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
        let reads = Arc::new(AtomicUsize::new(0));
        let count = reads.clone();
        let refresh = Refresh::spawn(Duration::from_secs(3600), async move || {
            let n = count.fetch_add(1, SeqCst) + 1;
            let mut s = snap(vec![svc("Cam", "DOWN", &[("tst-shack", false)])]);
            s.site = Some(format!("read-{n}"));
            Ok(s)
        })
        .unwrap();
        let mut t = Top::new(refresh, Theme { color: false });
        read_until(&mut t, "read-1");
        press(&mut t, KeyCode::Enter);
        press(&mut t, KeyCode::Char('r'));
        read_until(&mut t, "read-2");
        assert!(t.detail, "reading again leaves the details open");
        press(&mut t, KeyCode::Backspace);
        assert!(!t.detail);
        assert_eq!(
            reads.load(SeqCst),
            2,
            "read at the start and on r, not in between"
        );
    }

    #[test]
    fn times_count_on_the_apps_clock_and_updated_on_this_ones() {
        // the app's clock is an hour ahead of this box's
        let ahead = 3_600_000;
        let mut s = snap(vec![svc("Cam", "DOWN", &[("tst-shack", false)])]);
        s.generated += ahead;
        for x in &mut s.services {
            x.since = x.since.map(|t| t + ahead);
            for v in &mut x.vantages {
                v.ts += ahead;
            }
        }
        let mut t = top();
        t.take(Ok(s));
        let list = screen(&mut t, 80, 24);
        assert!(
            list.lines().next().unwrap().ends_with("updated 2 s ago"),
            "{list}"
        );
        let row = list.lines().find(|l| l.contains("Cam")).unwrap();
        assert!(row.ends_with("12 min"), "{list}");
        press(&mut t, KeyCode::Enter);
        let d = screen(&mut t, 80, 24);
        let site = d.lines().find(|l| l.contains("timed out")).unwrap();
        assert!(site.contains("60 s ago"), "{d}");
    }

    #[test]
    fn many_sites_take_at_most_half_the_details() {
        let names: Vec<String> = (1..=12).map(|i| format!("tst-site-{i:02}")).collect();
        let sites: Vec<(&str, bool)> = names.iter().map(|n| (n.as_str(), true)).collect();
        let mut t = top();
        t.take(Ok(snap(vec![svc("Wiki", "UP", &sites)])));
        press(&mut t, KeyCode::Enter);
        let d = screen(&mut t, 80, 24);
        let shown = d.lines().filter(|l| l.starts_with(" OK ")).count();
        assert!((1..=10).contains(&shown), "{d}");
        assert!(d.contains(&format!("+{} more", 12 - shown)), "{d}");
        assert!(
            d.contains("Why Wiki is UP."),
            "the reason still has room: {d}"
        );
    }

    #[test]
    fn says_when_it_is_loading_empty_or_cannot_reach_the_app() {
        let mut t = top();
        assert!(screen(&mut t, 80, 24).contains("Loading..."));
        let gone = "http://127.0.0.1:8791/api/services: could not connect";
        let hint = "Is it running? Start it with: sudo systemctl start ridgewarden-health.";
        t.take(Err(Failed {
            what: gone.into(),
            hint: Some(hint),
        }));
        let s = screen(&mut t, 80, 24);
        assert!(
            flat(&s).contains(&format!("ERROR Can't read the app: {gone}. {hint}")),
            "{s}"
        );
        assert!(
            s.lines().next().unwrap().ends_with("can't read the app"),
            "{s}"
        );
        t.take(Ok(snap(vec![])));
        assert!(screen(&mut t, 80, 24).contains("No services seen yet."));
        t.take(Err(Failed {
            what: gone.into(),
            hint: Some(hint),
        }));
        let s = screen(&mut t, 80, 24);
        assert!(
            flat(&s).contains(&format!("Reading failed, so this is from earlier: {gone}")),
            "the whole reason fits, over two lines: {s}"
        );
        assert!(
            !s.contains("Is it running"),
            "the hint is for a blank screen: {s}"
        );
        let mut lost = snap(vec![svc("Cam", "UP", &[])]);
        lost.site = None;
        t.take(Ok(lost));
        let s = screen(&mut t, 80, 24);
        assert!(s.contains("core not reached yet, updated 2 s ago"), "{s}");
        let mut cut = snap(vec![svc("Cam", "UP", &[])]);
        if let Ok(n) = &mut cut.notes {
            n.cut_off = vec![CutOff {
                label: "tst-upper-meadow-relay".into(),
            }];
        }
        t.take(Ok(cut));
        let s = screen(&mut t, 80, 24);
        assert!(
            flat(&s).contains(
                "Every check from tst-upper-meadow-relay failed, so it looks cut off and its \
                 results are left out."
            ),
            "a long site name wraps instead of cutting the sentence short: {s}"
        );
        t.tab = ALERTS;
        assert!(screen(&mut t, 80, 24).contains("No open alerts."));
        let mut broken = snap(vec![]);
        broken.notes = Err(failed("http://127.0.0.1:8791/api/alerts: HTTP 500"));
        t.take(Ok(broken));
        let s = screen(&mut t, 80, 24);
        assert!(
            flat(&s).contains(
                "Can't read the open alerts: http://127.0.0.1:8791/api/alerts: HTTP 500."
            ),
            "{s}"
        );
        t.tab = SERVICES;
        let s = screen(&mut t, 80, 24);
        assert!(
            s.contains(" 2 Alerts (failed)"),
            "the other page says its alerts didn't load: {s}"
        );
        for tab in [SERVICES, ALERTS] {
            t.tab = tab;
            assert!(!screen(&mut t, MIN_SIZE.0, MIN_SIZE.1).contains("Make the terminal"));
        }
    }

    /// An address nothing listens on.
    fn closed() -> SocketAddr {
        std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
    }

    /// Feed `events` (event, wall time) to the app's projections, as following its core would.
    fn feed(app: &App, events: &[(Event, i64)]) {
        let mut db = app.db();
        let tx = db.transaction().unwrap();
        for (e, ts) in events {
            for p in crate::app::PROJECTIONS {
                p.apply(&tx, e, *ts).unwrap();
            }
        }
        tx.commit().unwrap();
    }

    #[tokio::test]
    async fn read_takes_what_the_app_serves_and_says_when_it_cannot() {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg: Config = toml::from_str(EXAMPLE).unwrap();
        cfg.data_dir = dir.path().into();
        cfg.core.token_file = dir.path().join("no-token");
        cfg.core.url = format!("http://{}", closed());
        cfg.site_names = [("tst-harbor", "Harbor hut"), ("tst-creek", "Creek camp")]
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .into();
        let app = Arc::new(App::new(cfg).unwrap());
        // tst-harbor lists a camera on its own node and finds it working; tst-creek's last
        // round failed everywhere
        let now = now_ms();
        let cam = "http://tst-harbor.local.mesh:8080/cam";
        let list = json!([{"name": "Cam", "host": "tst-harbor", "link": cam, "protocol": "tcp"}]);
        let hash = ridgewarden_client::event::list_hash(&list);
        let result =
            |ok: bool| json!([{"name": "Cam", "link": cam, "host": "tst-harbor", "ok": ok}]);
        let mut sign = Fake::new(vec![]);
        let mut at = |kind: &str, payload: Value| (sign.add(kind, payload, now - MIN), now - MIN);
        let events = [
            at("mesh.list", json!({"hash": hash, "list": list})),
            at(
                "node.poll",
                json!({"node": "tst-harbor", "ok": true, "via": "lan", "ads_hash": hash}),
            ),
            at(
                "svc.probe",
                json!({"vantage": "tst-harbor", "results": result(true)}),
            ),
            at(
                "node.poll",
                json!({"node": "tst-creek", "ok": true, "via": "lan"}),
            ),
            at(
                "svc.probe",
                json!({"vantage": "tst-creek", "cut_off": true, "results": result(false)}),
            ),
        ];
        feed(&app, &events);
        let open = Alert {
            key: format!("svc {cam} DOWN"),
            severity: Severity::Critical,
            title: "Cam on tst-harbor is down".into(),
            text: "Not answering from any site (timed out).".into(),
        };
        alerts::update(&app.db(), &[open], &|_| false, NOW).unwrap();
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", l.local_addr().unwrap());
        let router = crate::web::router(app).into_make_service_with_connect_info::<SocketAddr>();
        tokio::spawn(async move { axum::serve(l, router).await });
        let fetch = Fetch::new(Duration::from_secs(20)).unwrap();
        let s = read(&fetch, &url).await.unwrap();
        assert_eq!(s.site, None, "the app's core isn't answering");
        let x = &s.services[0];
        assert_eq!(
            (x.class.as_str(), x.host_label.as_str()),
            ("UP", "Harbor hut")
        );
        let sites: Vec<&str> = x.vantages.iter().map(|v| v.label.as_str()).collect();
        assert_eq!(sites, ["Harbor hut"], "the cut-off round is left out");
        let notes = s.notes.unwrap();
        assert_eq!(notes.alerts[0].title, "Cam on tst-harbor is down");
        let cut: Vec<&str> = notes.cut_off.iter().map(|c| c.label.as_str()).collect();
        assert_eq!(cut, ["Creek camp"]);

        let gone = format!("http://{}", closed());
        let e = read(&fetch, &gone).await.err().unwrap();
        assert_eq!(e.what, format!("{gone}/api/services: could not connect"));
        assert!(
            e.hint.is_some_and(|h| h.contains("systemctl start")),
            "nothing answered, so maybe it isn't running: {e:?}"
        );
        // something that answers, but not with this view's API
        let e = read(&fetch, &format!("{url}/not-the-app"))
            .await
            .err()
            .unwrap();
        assert_eq!(e.what, format!("{url}/not-the-app/api/services: HTTP 404"));
        assert!(
            e.hint
                .is_some_and(|h| h.contains("older version") && !h.contains("systemctl")),
            "{e:?}"
        );
    }

    #[test]
    fn hosts_and_sites_go_by_their_site_names() {
        let mut x = svc("Cam", "DOWN", &[("tst-shack", false)]);
        x["host_label"] = json!("Tower hut");
        x["vantages"][0]["label"] = json!("Shack");
        let mut s = snap(vec![x]);
        if let Ok(n) = &mut s.notes {
            n.cut_off = vec![CutOff {
                label: "Creek camp".into(),
            }];
        }
        let mut t = top();
        t.take(Ok(s));
        let list = screen(&mut t, 80, 24);
        let row = list.lines().find(|l| l.contains("Cam")).unwrap();
        assert!(
            row.contains("Tower hut") && !row.contains("tst-tower"),
            "{list}"
        );
        assert!(
            flat(&list).contains("Every check from Creek camp failed"),
            "{list}"
        );
        press(&mut t, KeyCode::Enter);
        let d = screen(&mut t, 80, 24);
        assert!(d.contains(" DOWN  Cam on Tower hut, for 12 min"), "{d}");
        let site = d.lines().find(|l| l.contains("timed out, 12 ms")).unwrap();
        assert!(site.contains("Shack") && !site.contains("tst-shack"), "{d}");
        assert!(
            flat(&d).contains("/Cam on Tower hut. Checked with an HTTP request."),
            "{d}"
        );
    }

    /// What the running app said on the simulator, from tests/fixtures: two services down
    /// (one with a first good check since), one only partly reachable, one dropped from the
    /// mesh list while working, and a heartbeat. Also returns a moment 2 s after the read.
    fn simulated() -> (Top, i64) {
        let s: Services =
            serde_json::from_str(include_str!("../tests/fixtures/services.json")).unwrap();
        let notes = serde_json::from_str(include_str!("../tests/fixtures/alerts.json")).unwrap();
        let mut t = top();
        t.take(Ok(Snap {
            at: s.generated,
            generated: s.generated,
            site: s.site,
            services: s.services,
            notes: Ok(notes),
        }));
        (t, s.generated + 2000)
    }

    /// The README's picture of `top`: with README_SHOTS set, the services page is also
    /// written to ridgewarden-health-top.html in the temp folder, to be screenshotted.
    #[test]
    fn the_simulated_mesh_reads_well_at_80x24() {
        let (mut t, now) = simulated();
        t.theme = Theme { color: true };
        let b = draw(&mut t, 80, 24, now);
        if std::env::var_os("README_SHOTS").is_some() {
            let page = std::env::temp_dir().join("ridgewarden-health-top.html");
            std::fs::write(page, html(&b)).unwrap();
        }
        let list = text(&b);
        for want in [
            "ridgewarden-health top  tst-shack",
            "updated 2 s ago",
            "2 Alerts (4)",
            "8 services, 1 heartbeat: 2 DOWN, 1 PARTIAL, 1 UNPUBLISHED-BUT-ALIVE, 5 UP",
        ] {
            assert!(list.contains(want), "{want:?} missing from\n{list}");
        }
        let row = |name: &str| list.lines().find(|l| l.contains(name)).unwrap();
        assert!(row("Harbor Camera").starts_with(" DOWN "), "{list}");
        assert!(row("Creek Camera").starts_with(" PARTIAL "), "{list}");
        assert!(row("Creek Camera").contains(" 1/3 "), "{list}");
        assert!(
            row("net_logger").starts_with(" UNPUBLISHED-BUT-ALIVE "),
            "{list}"
        );
        assert!(row("Nightly backup").contains(" push "), "{list}");
        assert!(
            flat(&list).contains(
                "Harbor Camera: Not answering from any site (HTTP 503). tst-harbor: 1 good check \
                 in a row, 2 needed to change."
            ),
            "the worst is picked, and why it's down is the failure, not the good check since: {list}"
        );

        while t.picked().unwrap().name != "net_logger" {
            press(&mut t, KeyCode::Down);
        }
        press(&mut t, KeyCode::Enter);
        let d = text(&draw(&mut t, 80, 24, now));
        assert!(
            d.contains(" UNPUBLISHED-BUT-ALIVE  net_logger on tst-valley, for 4 min"),
            "{d}"
        );
        for s in ["tst-harbor", "tst-shack"] {
            let row = d
                .lines()
                .find(|l| l.contains(s) && l.contains("HTTP 404, 1 ms"))
                .unwrap();
            assert!(row.starts_with(" OK "), "{d}");
            assert!(row.ends_with("drops it"), "{d}");
        }
        assert!(
            flat(&d).contains(
                "AREDN's own check: It answers HTTP 404, but AREDN's check only accepts 200 or 401"
            ),
            "{d}"
        );
        assert!(
            !d.contains("lines 1-"),
            "it all fits, so nothing scrolls: {d}"
        );
        let short = text(&draw(&mut t, 80, 16, now));
        assert!(short.contains("lines 1-7 of 12"), "{short}");
        assert!(
            !flat(&short).contains("Checked with an HTTP request."),
            "{short}"
        );
        press(&mut t, KeyCode::End);
        let end = text(&draw(&mut t, 80, 16, now));
        assert!(end.contains("lines 6-12 of 12"), "{end}");
        assert!(
            flat(&end).contains("Checked with an HTTP request."),
            "{end}"
        );
        assert!(!end.contains("Missing from the mesh service list"), "{end}");

        press(&mut t, KeyCode::Char('2'));
        let a = text(&draw(&mut t, 80, 24, now));
        let alert = |title: &str| a.lines().find(|l| l.contains(title)).unwrap();
        assert!(
            alert("Harbor Camera on tst-harbor is down").starts_with(" critical "),
            "{a}"
        );
        assert!(
            alert("Creek Camera on tst-creek").starts_with(" warning "),
            "{a}"
        );
        assert!(
            alert("net_logger on tst-valley").starts_with(" info "),
            "{a}"
        );
        assert!(
            flat(&a).contains(
                "Harbor Camera on tst-harbor is down Not answering from any site (HTTP 503)."
            ),
            "the first alert's text shows under the list: {a}"
        );
    }

    /// A frame as a page of colored monospace cells, light or dark with the system, the way
    /// the core draws its own for its README.
    fn html(b: &Buffer) -> String {
        let mut page = String::from(
            "<!doctype html><meta charset=utf-8><title>ridgewarden-health top</title><style>\
             :root{--fg:#1f2328;--bg:#fff;--edge:#d0d7de}\
             @media (prefers-color-scheme:dark){:root{--fg:#d1d7e0;--bg:#0d1117;--edge:#30363d}}\
             body{margin:0;background:var(--bg)}\
             pre{display:inline-block;margin:0;padding:10px 14px;border:1px solid var(--edge);\
             font:16px/1.3 Consolas,monospace;color:var(--fg);background:var(--bg)}\
             </style><pre>",
        );
        for y in 0..b.area.height {
            let mut run = (String::new(), String::new());
            for x in 0..b.area.width {
                let c = &b[(x, y)];
                let style = css(c);
                if style != run.0 {
                    span(&mut page, &run);
                    run = (style, String::new());
                }
                run.1.push_str(c.symbol());
            }
            span(&mut page, &run);
            page.push('\n');
        }
        page + "</pre>"
    }

    fn span(page: &mut String, (style, text): &(String, String)) {
        if !text.is_empty() {
            let text = ridgewarden_client::util::esc(text);
            page.push_str(&format!("<span style=\"{style}\">{text}</span>"));
        }
    }

    /// A cell as CSS: Tango's palette for the pills, and the page's own colors for the
    /// terminal's default ones.
    fn css(c: &ridgewarden_client::tui::ratatui::buffer::Cell) -> String {
        use ridgewarden_client::tui::ratatui::style::Modifier;
        let color = |c: Ansi, default: &'static str| match c {
            Ansi::Reset => default,
            Ansi::Black => "#2e3436",
            Ansi::Red => "#cc0000",
            Ansi::Green => "#4e9a06",
            Ansi::Yellow => "#c4a000",
            Ansi::Gray => "#d3d7cf",
            Ansi::White => "#eeeeec",
            other => panic!("no CSS for {other:?}"),
        };
        let (mut fg, mut bg) = (color(c.fg, "var(--fg)"), color(c.bg, "var(--bg)"));
        if c.modifier.contains(Modifier::REVERSED) {
            std::mem::swap(&mut fg, &mut bg);
        }
        let mut s = format!("color:{fg};background:{bg}");
        if c.modifier.contains(Modifier::BOLD) {
            s.push_str(";font-weight:bold");
        }
        if c.modifier.contains(Modifier::DIM) {
            s.push_str(";opacity:.6");
        }
        s
    }
}
