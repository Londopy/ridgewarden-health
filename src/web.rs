//! The services page, a page per service, alert acknowledgements, push heartbeats, and the
//! same data as JSON.

use std::collections::{BTreeSet, HashMap};
use std::fmt::Write as _;
use std::sync::Arc;

use std::net::SocketAddr;

use axum::extract::{ConnectInfo, Path, Query, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use ridgewarden_client::alerts;
use ridgewarden_client::svg::{Chart, Line, strip};
use ridgewarden_client::ui::{Color, Page, pill};
use ridgewarden_client::util::{esc, human_duration, now_ms, short_time};
use serde_json::{Value, json};

use crate::app::App;
use crate::findings::{self, Finding};
use crate::health::{
    Class, NodeCheck, Rules, ServiceView, aredn_text, aredn_view, classify, cut_off_sites, latency,
    pct_text, recent, uptime,
};
use crate::heartbeat;
use crate::probe::probing_sites;
use crate::probes::DAY;

pub fn router(app: Arc<App>) -> Router {
    Router::new()
        .route("/", get(services_page))
        .route("/service", get(service_page))
        .route("/ack/{token}", get(ack_page).post(ack_post))
        .route("/push/{token}", post(push))
        .route("/api/services", get(services_json))
        .route("/healthz", get(|| async { "ok" }))
        .with_state(app)
}

struct Fail(anyhow::Error);

impl IntoResponse for Fail {
    fn into_response(self) -> Response {
        tracing::error!("request failed: {:#}", self.0);
        (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response()
    }
}

impl<E: Into<anyhow::Error>> From<E> for Fail {
    fn from(e: E) -> Self {
        Fail(e.into())
    }
}

pub fn class_color(c: Class) -> Color {
    match c {
        Class::Up | Class::UnpublishedAlive => Color::Green,
        Class::Partial | Class::Stale => Color::Yellow,
        Class::Down => Color::Red,
        Class::Unknown | Class::Unpublished => Color::Unknown,
    }
}

/// Percent-encode a query value.
fn enc(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
            o.push(b as char);
        } else {
            let _ = write!(o, "%{b:02X}");
        }
    }
    o
}

fn plural(n: usize, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

async fn page(app: &App, active: &str, title: &str, body: &str, refresh: bool) -> Html<String> {
    let who = app
        .vantage()
        .await
        .unwrap_or_else(|_| "core unreachable".into());
    let page = Page {
        app: "ridgewarden-health",
        nav: &[("/", "Services")],
        active,
        who: &who,
        refresh,
    };
    Html(page.render(title, body))
}

fn held(app: &App, v: &ServiceView, now: i64) -> Option<String> {
    let text = format!("{} {} {}", v.svc.link, v.svc.name, v.svc.host);
    app.cfg.alerts.hold(&text, now)
}

/// Who besides the main channels hears about this service.
fn owners_of(app: &App, v: &ServiceView) -> Vec<String> {
    let text = format!("{} {} {}", v.svc.link, v.svc.name, v.svc.host);
    app.owners
        .iter()
        .filter(|o| o.cfg.covers(&text))
        .map(|o| o.cfg.name.clone())
        .collect()
}

fn notes(app: &App, now: i64) -> Result<String, Fail> {
    let mut b = String::new();
    let cut = cut_off_sites(&app.db(), now, app.fresh_ms())?;
    for site in cut {
        let _ = write!(
            b,
            "<div class=banner>Every check from {} failed in its last round, so that site is \
             probably cut off from the mesh. Its results are left out until it can reach things again.</div>",
            esc(&app.cfg.label(&site))
        );
    }
    for x in app.cfg.alerts.lapsed(now) {
        let _ = write!(
            b,
            "<div class=banner>The silence on \"{}\" passed its review date ({}). Alerts for it are back on; \
             remove it from the config or set a new date. Reason given: {}</div>",
            esc(&x.matches),
            esc(&x.review),
            esc(&x.reason)
        );
    }
    let open = alerts::open_alerts(&app.db())?;
    if !open.is_empty() {
        b.push_str("<h2>Open alerts</h2><ul class=plain>");
        for a in open {
            let _ = write!(
                b,
                "<li>{} {} <span class=\"mute small\">since {}{}</span></li>",
                pill(
                    if a.severity == "critical" {
                        Color::Red
                    } else {
                        Color::Yellow
                    },
                    &a.severity
                ),
                esc(&a.title),
                esc(&short_time(a.opened_ms)),
                if a.acked { ", acknowledged" } else { "" }
            );
        }
        b.push_str("</ul>");
    }
    Ok(b)
}

fn check_strip(app: &App, link: &str, n: usize) -> Result<String, Fail> {
    let cells: Vec<(Color, String)> = recent(&app.db(), link, n)?
        .into_iter()
        .map(|c| {
            let color = if c.ok { Color::Green } else { Color::Red };
            let tip = format!(
                "{}, from {}: {}",
                short_time(c.ts),
                app.cfg.label(&c.vantage),
                c.detail
            );
            (color, tip)
        })
        .collect();
    Ok(strip(&cells))
}

fn finding_list(app: &App, title: &str, list: &[Finding], now: i64) -> String {
    if list.is_empty() {
        return String::new();
    }
    let mut b = format!("<details><summary>{}</summary><ul class=plain>", esc(title));
    for f in list {
        let seen = if now - f.last_ms < 10 * 60_000 {
            "still so".to_string()
        } else {
            format!("last seen so {}", short_time(f.last_ms))
        };
        let _ = write!(
            b,
            "<li><a href=\"/service?link={}\">{}</a> on {} <span class=\"mute small\">found {}, {}</span></li>",
            enc(&f.link),
            esc(&f.name),
            esc(&app.cfg.label(&f.host)),
            esc(&short_time(f.first_ms)),
            esc(&seen)
        );
    }
    b.push_str("</ul></details>");
    b
}

/// The spec's success measures, as far as this app can count them.
fn findings_section(app: &App, now: i64) -> Result<String, Fail> {
    let Some(s) = findings::summary(&app.db())? else {
        return Ok(String::new());
    };
    let (ws, wu) = s.first_week();
    let week_end = s.since + 7 * DAY;
    let mut b = format!(
        "<h2>What it has found</h2><p>Since {}: {} and {}. In its first week{}: {} stale and {} \
         wrongly unpublished.</p>",
        esc(&short_time(s.since)),
        plural(
            s.stale.len(),
            "listed service never seen working",
            "listed services never seen working"
        ),
        plural(
            s.unpublished.len(),
            "working service AREDN dropped from the mesh list",
            "working services AREDN dropped from the mesh list"
        ),
        if now < week_end {
            format!(", which ends {}", esc(&short_time(week_end)))
        } else {
            String::new()
        },
        ws,
        wu,
    );
    b.push_str(&finding_list(app, "Never seen working", &s.stale, now));
    b.push_str(&finding_list(
        app,
        "Working, but dropped from the list",
        &s.unpublished,
        now,
    ));
    b.push_str(
        "<p class=\"mute small\">Whether an owner heard about an outage from an alert before a \
         user reported it can't be counted here: this app doesn't know when people noticed.</p>",
    );
    Ok(b)
}

async fn services_page(State(app): State<Arc<App>>) -> Result<Html<String>, Fail> {
    let now = now_ms();
    let views = classify(&app.db(), now, &Rules::from_cfg(&app.cfg))?;
    let mut b = String::from(
        "<h1>Services</h1><p class=\"mute small\">Every service advertised on the mesh in the last week, \
         probed from each site running ridgewarden-health, and the push heartbeats those sites \
         receive. Uptime counts checks from every site.</p>",
    );
    b.push_str(&notes(&app, now)?);
    if views.is_empty() {
        b.push_str("<p class=mute>No services seen yet. The core needs to poll its node at least once.</p>");
    } else {
        b.push_str(
            "<div class=wrap><table><tr><th>State</th><th>Service</th><th>Host</th><th>30 d</th>\
             <th>Recent checks</th><th>Since</th><th>Why</th></tr>",
        );
        for s in &views {
            let mut why = esc(&s.reason);
            if let Some(h) = held(&app, s, now) {
                let _ = write!(why, "<br><span class=\"mute small\">{}</span>", esc(&h));
            }
            if aredn_view(s).is_some_and(|_| s.class != Class::UnpublishedAlive) {
                why.push_str(
                    "<br><span class=small>AREDN may drop it from the mesh list; see details.</span>",
                );
            }
            let up = uptime(&app.db(), &s.svc.link, now)?;
            let name = if s.is_heartbeat() {
                format!(
                    "{} <span class=\"mute small\">heartbeat</span>",
                    esc(&s.svc.name)
                )
            } else {
                esc(&s.svc.name)
            };
            let _ = write!(
                b,
                "<tr><td>{}</td><td><a href=\"/service?link={}\">{name}</a></td><td>{}</td><td>{}</td>\
                 <td style=\"min-width:120px\">{}</td><td>{}</td><td>{why}</td></tr>",
                pill(class_color(s.class), s.class.label()),
                enc(&s.svc.link),
                esc(&app.cfg.label(&s.svc.host)),
                pct_text(up.month),
                check_strip(&app, &s.svc.link, 24)?,
                esc(&s.since_text(now))
            );
        }
        b.push_str("</table></div>");
    }
    b.push_str(&findings_section(&app, now)?);
    Ok(page(&app, "/", "Services", &b, true).await)
}

fn check_words(kind: &str) -> &'static str {
    match kind {
        "http" => "an HTTP request",
        "tcp" => "a TCP connection",
        "winlink" => "waiting for the Winlink login prompt (it never logs in)",
        "meshchat" => "MeshChat's own API",
        "push" => "push heartbeats",
        _ => "an unknown kind of check",
    }
}

fn node_cell(a: Option<&NodeCheck>) -> String {
    match a {
        None => "<span class=mute>-</span>".into(),
        Some(a) => format!(
            "{} <span class=\"mute small\">{}</span>",
            pill(
                if a.pass { Color::Green } else { Color::Red },
                if a.pass { "keeps it" } else { "drops it" }
            ),
            esc(&aredn_text(a))
        ),
    }
}

fn not_found_body() -> &'static str {
    "<h1>Not found</h1><p>No service with that link has been advertised in the last week, and no \
     site has reported a heartbeat by that name. <a href=\"/\">All services</a></p>"
}

async fn service_page(
    State(app): State<Arc<App>>,
    Query(q): Query<HashMap<String, String>>,
) -> Result<Response, Fail> {
    let now = now_ms();
    let link = q.get("link").cloned().unwrap_or_default();
    let views = classify(&app.db(), now, &Rules::from_cfg(&app.cfg))?;
    let Some(s) = views.into_iter().find(|v| v.svc.link == link) else {
        return Ok((
            StatusCode::NOT_FOUND,
            page(&app, "", "Not found", not_found_body(), false).await,
        )
            .into_response());
    };
    let mut b = String::new();
    let _ = write!(
        b,
        "<h1>{}</h1><p>{} <span class=mute>{}</span></p><p>{}</p>",
        esc(&s.svc.name),
        pill(class_color(s.class), s.class.label()),
        esc(&s.since_text(now)),
        esc(&s.reason),
    );
    if s.is_heartbeat() {
        let _ = write!(
            b,
            "<p class=\"mute small\">A push heartbeat received at {}. That site judges whether it \
             is on time and shares its verdict with every other site.</p>",
            esc(&app.cfg.label(&s.svc.host))
        );
    } else {
        let kinds: BTreeSet<&str> = s.vantages.iter().map(|v| v.check.as_str()).collect();
        let how = kinds
            .iter()
            .map(|k| check_words(k))
            .collect::<Vec<_>>()
            .join(", ");
        let _ = write!(
            b,
            "<p class=\"mute small\">{} on {}{}</p>",
            esc(&s.svc.link),
            esc(&app.cfg.label(&s.svc.host)),
            if how.is_empty() {
                String::new()
            } else {
                format!(". Checked with {}.", esc(&how))
            }
        );
    }
    if let Some(h) = held(&app, &s, now) {
        let _ = write!(b, "<p class=banner>{}</p>", esc(&h));
    }
    let owners = owners_of(&app, &s);
    if !owners.is_empty() {
        let _ = write!(
            b,
            "<p class=\"mute small\">Alerts also go to {}.</p>",
            esc(&owners.join(", "))
        );
    }
    if let Some(why) = aredn_view(&s) {
        let _ = write!(b, "<h2>AREDN's own check</h2><p>{}</p>", esc(&why));
    }
    let up = uptime(&app.db(), &link, now)?;
    let _ = write!(
        b,
        "<h2>Uptime</h2><div class=cards><div class=card><div class=n>{}</div>24 hours</div>\
         <div class=card><div class=n>{}</div>30 days</div><div class=card><div class=n>{}</div>1 year</div></div>",
        pct_text(up.day),
        pct_text(up.month),
        pct_text(up.year)
    );
    if !s.is_heartbeat() {
        let from = now - 7 * DAY;
        let lines = latency(&app.db(), &link, from)?
            .into_iter()
            .map(|(v, points)| Line {
                label: app.cfg.label(&v),
                points,
            })
            .collect();
        let chart = Chart {
            from,
            to: now,
            unit: "ms".into(),
            lines,
            gap_ms: 3 * 3_600_000,
            ..Default::default()
        };
        b.push_str(
            "<h2>Response time, last 7 days</h2><p class=\"mute small\">Hourly average from each site.</p>",
        );
        b.push_str(&chart.render("Response time by site, last 7 days"));
    }
    let _ = write!(
        b,
        "<h2>Recent checks</h2><p class=\"mute small\">The last 48 checks from every site, oldest first. \
         Hover for details.</p>{}",
        check_strip(&app, &link, 48)?
    );
    b.push_str(&site_table(&app, &s, now)?);
    b.push_str("<p><a href=\"/\">All services</a></p>");
    Ok(page(&app, "", &s.svc.name, &b, true).await.into_response())
}

fn site_table(app: &App, s: &ServiceView, now: i64) -> Result<String, Fail> {
    let mut b = String::from("<h2>Each site</h2>");
    let cap = app.cfg.probe.sites_per_service;
    let probing = probing_sites(&app.db(), now, app.fresh_ms())?.len();
    if !s.is_heartbeat() && cap > 0 && probing > cap {
        let _ = write!(
            b,
            "<p class=\"mute small\">{probing} sites are probing; each service is probed from at \
             most {cap} of them (probe.sites_per_service), shared out so every service is \
             covered, plus the site on its own node.</p>"
        );
    }
    b.push_str("<div class=wrap><table><tr><th>Site</th><th>Verdict</th><th>Last check</th>");
    if !s.is_heartbeat() {
        b.push_str("<th>AREDN's check, from here</th>");
    }
    b.push_str("</tr>");
    let (yes, no) = if s.is_heartbeat() {
        ("on time", "missed")
    } else {
        ("answering", "not answering")
    };
    for v in &s.vantages {
        let _ = write!(
            b,
            "<tr><td>{}</td><td>{}</td><td>{}{} <span class=\"mute small\">{}</span></td>",
            esc(&app.cfg.label(&v.vantage)),
            pill(
                if v.ok { Color::Green } else { Color::Red },
                if v.ok { yes } else { no }
            ),
            esc(&v.detail),
            v.ms.map(|m| format!(", {m:.0} ms")).unwrap_or_default(),
            esc(&short_time(v.ts))
        );
        if !s.is_heartbeat() {
            let _ = write!(b, "<td>{}</td>", node_cell(v.aredn.as_ref()));
        }
        b.push_str("</tr>");
    }
    if s.vantages.is_empty() {
        b.push_str("<tr><td colspan=4 class=mute>No recent results from any site.</td></tr>");
    }
    b.push_str("</table></div>");
    Ok(b)
}

async fn ack_page(State(app): State<Arc<App>>, Path(token): Path<String>) -> Html<String> {
    // a GET only shows the button, so link previews in chat apps can't acknowledge anything
    let b = format!(
        "<h1>Acknowledge alert</h1><p>Acknowledging stops repeats of this alert. You'll still hear \
         when it's resolved.</p><form method=post action=\"/ack/{}\"><button type=submit>Acknowledge</button></form>",
        enc(&token)
    );
    page(&app, "", "Acknowledge", &b, false).await
}

fn ack_any(app: &App, token: &str, now: i64) -> anyhow::Result<Option<String>> {
    if let Some(t) = alerts::ack(&app.db(), token, now)? {
        return Ok(Some(t));
    }
    for o in &app.owners {
        let db = o.db.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(t) = alerts::ack(&db, token, now)? {
            return Ok(Some(t));
        }
    }
    Ok(None)
}

async fn ack_post(
    State(app): State<Arc<App>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path(token): Path<String>,
) -> Result<Response, Fail> {
    let now = now_ms();
    let who = peer.ip();
    let done = if app.guessing(who, now) {
        None
    } else {
        ack_any(&app, &token, now)?
    };
    let (code, b) = match done {
        Some(title) => (
            StatusCode::OK,
            format!(
                "<h1>Acknowledged</h1><p>{}</p><p><a href=\"/\">All services</a></p>",
                esc(&title)
            ),
        ),
        None if app.guessing(who, now) => (
            StatusCode::TOO_MANY_REQUESTS,
            "<h1>Try again in a minute</h1><p>Too many wrong acknowledge links came from this \
             address just now.</p>"
                .to_string(),
        ),
        None => {
            app.wrong_token(who, now);
            (
                StatusCode::NOT_FOUND,
                "<h1>Nothing to acknowledge</h1><p>That alert is already resolved, or the link is wrong.</p>"
                    .to_string(),
            )
        }
    };
    Ok((code, page(&app, "", "Acknowledge", &b, false).await).into_response())
}

/// `POST /push/<token>`, optionally with `?status=down&msg=...`.
async fn push(
    State(app): State<Arc<App>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path(token): Path<String>,
    Query(q): Query<HashMap<String, String>>,
) -> Result<Response, Fail> {
    let now = now_ms();
    if app.guessing(peer.ip(), now) {
        return Ok((
            StatusCode::TOO_MANY_REQUESTS,
            "too many wrong push tokens from this address; try again in a minute\n",
        )
            .into_response());
    }
    let ok = match q.get("status").map(|s| s.to_ascii_lowercase()).as_deref() {
        None | Some("" | "up" | "ok") => true,
        Some("down" | "fail" | "error") => false,
        Some(_) => {
            return Ok((StatusCode::BAD_REQUEST, "status must be up or down\n").into_response());
        }
    };
    let db = app.db();
    let Some(h) = heartbeat::find(&db, &app.cfg.heartbeats, &token)? else {
        app.wrong_token(peer.ip(), now);
        return Ok((StatusCode::NOT_FOUND, "no heartbeat has that push token\n").into_response());
    };
    let msg = heartbeat::clean_msg(q.get("msg").map_or("", String::as_str));
    if !heartbeat::record(&db, &h.name, ok, &msg, now)? {
        return Ok((
            StatusCode::TOO_MANY_REQUESTS,
            "a beat came in seconds ago; one every 5 s at most\n",
        )
            .into_response());
    }
    Ok(format!(
        "ok: {} {} (expected every {})\n",
        h.name.trim(),
        if ok { "up" } else { "down" },
        human_duration(h.every_s as i64 * 1000)
    )
    .into_response())
}

async fn services_json(State(app): State<Arc<App>>) -> Result<Json<Value>, Fail> {
    let now = now_ms();
    let views = classify(&app.db(), now, &Rules::from_cfg(&app.cfg))?;
    let mut out = vec![];
    for s in &views {
        let up = uptime(&app.db(), &s.svc.link, now)?;
        out.push(json!({
            "name": s.svc.name, "host": s.svc.host, "link": s.svc.link,
            "heartbeat": s.is_heartbeat(),
            "class": s.class.label(), "since": s.since, "reason": s.reason,
            "aredn": aredn_view(s), "held": held(&app, s, now),
            "uptime": {"day": up.day, "month": up.month, "year": up.year},
            "vantages": s.vantages.iter().map(|v| json!({
                "vantage": v.vantage, "ok": v.ok, "ms": v.ms, "detail": v.detail, "ts": v.ts,
                "pending": v.pending, "check": v.check,
                "aredn": v.aredn.as_ref().map(|a| json!({"pass": a.pass, "code": a.code, "status": a.status})),
            })).collect::<Vec<_>>(),
        }));
    }
    Ok(Json(json!({"generated": now, "services": out})))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, EXAMPLE, HeartbeatCfg, OwnerCfg};

    fn app(dir: &std::path::Path) -> Arc<App> {
        let mut cfg: Config = toml::from_str(EXAMPLE).unwrap();
        cfg.data_dir = dir.into();
        cfg.core.token_file = dir.join("no-token");
        cfg.heartbeats = vec![HeartbeatCfg {
            name: "Backup".into(),
            every_s: 3600,
            grace_s: 60,
        }];
        cfg.owners = vec![OwnerCfg {
            name: "Cams".into(),
            matches: vec!["camera".into()],
            ntfy: Some("http://10.1.1.1/c".into()),
            ..Default::default()
        }];
        cfg.validate().unwrap();
        Arc::new(App::new(cfg).unwrap())
    }

    fn q(pairs: &[(&str, &str)]) -> Query<HashMap<String, String>> {
        Query(
            pairs
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        )
    }

    const JOB: &str = "10.1.2.3:40000";
    const JUNK: &str = "10.9.9.9:40000";

    async fn push_as(
        app: &Arc<App>,
        from: &str,
        token: &str,
        pairs: &[(&str, &str)],
    ) -> StatusCode {
        let peer = ConnectInfo(from.parse::<SocketAddr>().unwrap());
        match push(State(app.clone()), peer, Path(token.into()), q(pairs)).await {
            Ok(r) => r.status(),
            Err(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    #[tokio::test]
    async fn push_records_beats_and_slows_guessers() {
        let dir = tempfile::tempdir().unwrap();
        let app = app(dir.path());
        let tok = heartbeat::token(&app.db(), "Backup").unwrap();
        let down = [("status", "down"), ("msg", "disk full")];
        assert_eq!(push_as(&app, JOB, &tok, &down).await, StatusCode::OK);
        let r = heartbeat::results(&app.db(), &app.cfg.heartbeats, "n", 0, now_ms()).unwrap();
        assert!(
            !r[0].ok && r[0].detail.contains("disk full"),
            "{}",
            r[0].detail
        );
        assert_eq!(
            push_as(&app, JOB, &tok, &[]).await,
            StatusCode::TOO_MANY_REQUESTS,
            "seconds after the last one"
        );
        assert_eq!(
            push_as(&app, JOB, &tok, &[("status", "maybe")]).await,
            StatusCode::BAD_REQUEST
        );
        let wrong = "0".repeat(24);
        for _ in 0..30 {
            assert_eq!(
                push_as(&app, JUNK, &wrong, &[]).await,
                StatusCode::NOT_FOUND
            );
        }
        assert_eq!(
            push_as(&app, JUNK, &tok, &[]).await,
            StatusCode::TOO_MANY_REQUESTS,
            "after 30 wrong tokens in a minute that address waits, right token or not"
        );
        app.db().execute("DELETE FROM beats", []).unwrap();
        assert_eq!(
            push_as(&app, JOB, &tok, &[]).await,
            StatusCode::OK,
            "junk from one address doesn't lock out a job on another"
        );
    }

    #[tokio::test]
    async fn an_owners_acknowledge_link_works_and_acks_only_their_copy() {
        use ridgewarden_client::alerts::{Alert, Severity, ack_token, open_alerts, update};
        let dir = tempfile::tempdir().unwrap();
        let app = app(dir.path());
        let a = Alert {
            key: "svc http://cam/ DOWN".into(),
            severity: Severity::Critical,
            title: "Camera on tst-paso is down".into(),
            text: String::new(),
        };
        let theirs = crate::owned(&app.owners[0].cfg, std::slice::from_ref(&a));
        assert_eq!(theirs.len(), 1);
        update(&app.db(), std::slice::from_ref(&a), &|_| false, 1000).unwrap();
        let tok = {
            let owner_db = app.owners[0].db.lock().unwrap();
            update(&owner_db, &theirs, &|_| false, 1000).unwrap();
            ack_token(&owner_db, &a.key, 1000).unwrap()
        };
        let peer = ConnectInfo(JOB.parse::<SocketAddr>().unwrap());
        let r = ack_post(State(app.clone()), peer, Path(tok))
            .await
            .ok()
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK);
        assert!(open_alerts(&app.owners[0].db.lock().unwrap()).unwrap()[0].acked);
        assert!(!open_alerts(&app.db()).unwrap()[0].acked);
    }

    #[test]
    fn query_values_are_encoded() {
        assert_eq!(
            enc("http://a:80/x?y=1&z"),
            "http%3A%2F%2Fa%3A80%2Fx%3Fy%3D1%26z"
        );
    }
}
