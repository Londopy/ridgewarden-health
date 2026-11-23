//! Service health classifier (spec 06).
//!
//! The point of probing from several sites: a service that answers from one site and not
//! another is a *link* problem, not a service problem, and the report says so.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::Result;
use rusqlite::{Connection, params};

use ridgewarden_client::alerts::{Alert, Severity};
use ridgewarden_client::aredn::Service;
use ridgewarden_client::util::{human_duration, short_time};

use crate::config::Config;
use crate::probe::{AREDN_CODES, REMEMBER_MS, targets};
use crate::probes::{DAY, rolled_to};

/// (ts, ok, latency ms, detail, HTTP status)
type ProbeRow = (i64, bool, Option<f64>, String, Option<u16>);

/// how far back the "since" timelines look
const TIMELINE_MS: i64 = 3 * 86_400_000;

/// How results turn into verdicts.
#[derive(Clone, Copy, Debug)]
pub struct Rules {
    /// a site's results older than this say nothing about now
    pub fresh_ms: i64,
    /// failed checks in a row before a site calls a service down
    pub fail_after: u32,
    /// good checks in a row before it counts as back up
    pub ok_after: u32,
}

impl Rules {
    pub fn from_cfg(c: &Config) -> Self {
        Rules {
            fresh_ms: c.fresh_s as i64 * 1000,
            fail_after: c.probe.fail_after,
            ok_after: c.probe.ok_after,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Class {
    Down,
    Partial,
    Stale,
    UnpublishedAlive,
    Unknown,
    Unpublished,
    Up,
}

impl Class {
    pub fn label(self) -> &'static str {
        match self {
            Class::Up => "UP",
            Class::Partial => "PARTIAL",
            Class::Down => "DOWN",
            Class::Stale => "STALE",
            Class::UnpublishedAlive => "UNPUBLISHED-BUT-ALIVE",
            Class::Unpublished => "GONE",
            Class::Unknown => "UNKNOWN",
        }
    }

    /// Words for people who've never heard of Babel (the status page).
    pub fn plain(self) -> &'static str {
        match self {
            Class::Up => "Working",
            Class::Partial => "Partly reachable",
            Class::Down => "Not working",
            Class::Stale => "Listed but never seen working",
            Class::UnpublishedAlive => "Working (missing from the mesh list)",
            Class::Unpublished => "Removed",
            Class::Unknown => "Unknown",
        }
    }
}

/// What the AREDN node's own check would make of a service, from one site's probe.
#[derive(Clone, Debug, PartialEq)]
pub struct NodeCheck {
    pub pass: bool,
    pub code: String,
    pub status: Option<u16>,
}

#[derive(Clone, Debug)]
pub struct VantageResult {
    pub vantage: String,
    pub ok: bool,
    pub ms: Option<f64>,
    pub detail: String,
    pub status: Option<u16>,
    pub ts: i64,
    /// when the streak that set this site's current verdict began
    pub run_start: i64,
    /// latest results that disagree with the verdict but haven't reached the threshold
    pub pending: u32,
    /// the kind of check: http, tcp, winlink, meshchat or push
    pub check: String,
    pub aredn: Option<NodeCheck>,
}

#[derive(Clone, Debug)]
pub struct ServiceView {
    pub svc: Service,
    pub class: Class,
    pub vantages: Vec<VantageResult>,
    pub since: Option<i64>,
    /// true when the run started before the timeline window, so "since" is a lower bound
    pub since_open: bool,
    pub reason: String,
}

impl ServiceView {
    pub fn since_text(&self, now: i64) -> String {
        let Some(t) = self.since else {
            return String::new();
        };
        let more = if self.since_open { "over " } else { "" };
        match self.class {
            Class::Up | Class::UnpublishedAlive => {
                format!("up for {more}{}", human_duration(now - t))
            }
            Class::Down => format!("down since {}", short_time(t)),
            Class::Partial => format!("partial since {}", short_time(t)),
            _ => String::new(),
        }
    }

    /// A push heartbeat rather than an advertised service.
    pub fn is_heartbeat(&self) -> bool {
        is_push(&self.svc.link)
    }
}

pub fn is_push(link: &str) -> bool {
    link.starts_with("push://")
}

/// Links in the *latest* service list of every node polled recently. Using each node's
/// latest list (not "seen in the window") means an unpublished service is noticed on the
/// next poll, not after the window runs out.
/// None when no node has sent a fresh service list: then we can't tell "unpublished"
/// from "we just haven't heard", and say unknown.
fn advertised_now(conn: &Connection, now: i64, fresh_ms: i64) -> Result<Option<BTreeSet<String>>> {
    let mut st = conn.prepare(
        "SELECT l.json FROM polls p JOIN lists l ON l.hash = p.ads_hash
         WHERE p.ok = 1 AND p.ts >= ?1
           AND p.ts = (SELECT max(q.ts) FROM polls q WHERE q.node = p.node AND q.ok = 1 AND q.ads_hash IS NOT NULL)",
    )?;
    let mut out = BTreeSet::new();
    let mut any = false;
    for j in st.query_map(params![now - fresh_ms], |r| r.get::<_, String>(0))? {
        any = true;
        for s in serde_json::from_str::<Vec<Service>>(&j?).unwrap_or_default() {
            out.insert(s.link);
        }
    }
    Ok(any.then_some(out))
}

/// Heartbeats any site reported on in the last week, as services hosted by that site.
fn heartbeats(conn: &Connection, now: i64) -> Result<Vec<Service>> {
    let mut st = conn.prepare(
        "SELECT link, name, vantage, max(ts) FROM probes
         WHERE link LIKE 'push://%' AND ts > ?1 GROUP BY link",
    )?;
    let v = st
        .query_map(params![now - REMEMBER_MS], |r| {
            Ok(Service {
                link: r.get(0)?,
                name: r.get(1)?,
                host: r.get(2)?,
                protocol: "push".into(),
            })
        })?
        .collect::<Result<_, _>>()?;
    Ok(v)
}

/// (link, vantage) -> (kind of check, node-check verdict)
type Latest = BTreeMap<(String, String), (String, Option<NodeCheck>)>;

/// Each site's latest kind of check and node-check verdict, per link.
fn latest_checks(conn: &Connection) -> Result<Latest> {
    let mut st = conn
        .prepare("SELECT link, vantage, check_kind, aredn_code, aredn_status FROM probe_latest")?;
    let mut out = BTreeMap::new();
    for r in st.query_map([], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, Option<String>>(3)?,
            r.get::<_, Option<u16>>(4)?,
        ))
    })? {
        let (link, v, check, code, status) = r?;
        let node = code.and_then(|c| {
            AREDN_CODES
                .iter()
                .find(|(k, _)| *k == c)
                .map(|(k, pass)| NodeCheck {
                    pass: *pass,
                    code: k.to_string(),
                    status,
                })
        });
        out.insert((link, v), (check, node));
    }
    Ok(out)
}

/// A site's verdict on one service with the thresholds applied: it flips only after
/// `fail_after` failures, or `ok_after` successes, in a row. Returns the verdict, when the
/// streak that set it began, and how many of the latest results disagree with it so far.
fn settle(rows: &[ProbeRow], fail_after: u32, ok_after: u32) -> (bool, i64, u32) {
    let mut state = rows[0].1;
    let mut since = rows[0].0;
    let mut streak = 0;
    let mut streak_start = since;
    for r in rows {
        if r.1 == state {
            streak = 0;
            continue;
        }
        if streak == 0 {
            streak_start = r.0;
        }
        streak += 1;
        if streak >= if state { fail_after } else { ok_after } {
            state = r.1;
            since = streak_start;
            streak = 0;
        }
    }
    (state, since, streak)
}

/// A heartbeat's verdict: the site that receives it already allowed for lateness, so
/// there are no thresholds on top, and only that site can say anything about it.
fn beat_class(
    conn: &Connection,
    svc: &Service,
    vantages: &[VantageResult],
) -> Result<(Class, Option<i64>, String)> {
    Ok(match vantages.first() {
        None => (
            Class::Unknown,
            None,
            format!(
                "No recent word from {}, which receives this heartbeat. That site may be cut \
                 off, or its ridgewarden-health stopped.",
                svc.host
            ),
        ),
        Some(v) if v.ok => (
            Class::Up,
            Some(v.run_start),
            format!("Checking in at {}: {}.", svc.host, v.detail),
        ),
        Some(v) if ever_answered(conn, &svc.link)? => (
            Class::Down,
            Some(v.run_start),
            format!("At {}: {}.", svc.host, v.detail),
        ),
        Some(_) => (
            Class::Stale,
            None,
            format!("Has never checked in at {}.", svc.host),
        ),
    })
}

/// An advertised service's verdict from every site's results and the mesh's latest lists.
fn judge(
    conn: &Connection,
    svc: &Service,
    vantages: &[VantageResult],
    live: &BTreeSet<String>,
) -> Result<(Class, Option<i64>, String)> {
    let advertised_now = live.contains(&svc.link);
    let up: Vec<&VantageResult> = vantages.iter().filter(|v| v.ok).collect();
    let down: Vec<&VantageResult> = vantages.iter().filter(|v| !v.ok).collect();
    let names = |vs: &[&VantageResult]| {
        vs.iter()
            .map(|v| v.vantage.clone())
            .collect::<Vec<_>>()
            .join(", ")
    };
    Ok(if vantages.is_empty() {
        (Class::Unknown, None, "No recent probe results.".to_string())
    } else if !advertised_now && !up.is_empty() {
        (
            Class::UnpublishedAlive,
            up.iter().map(|v| v.run_start).min(),
            "Missing from the mesh service list, but still answering. AREDN's own \
             reachability check may have unpublished it by mistake."
                .into(),
        )
    } else if !advertised_now {
        (
            Class::Unpublished,
            None,
            "No longer advertised and not answering.".into(),
        )
    } else if down.is_empty() {
        (
            Class::Up,
            // up everywhere since the last site to see it come back did
            up.iter().map(|v| v.run_start).max(),
            format!("Answering from {}.", names(&up)),
        )
    } else if !up.is_empty() {
        (
            Class::Partial,
            down.iter().map(|v| v.run_start).min(),
            format!(
                "Answering from {}, but not from {} ({}). The service is up; a link between \
                 those sites is the likely problem.",
                names(&up),
                names(&down),
                down[0].detail
            ),
        )
    } else if !ever_answered(conn, &svc.link)? {
        (
            Class::Stale,
            None,
            format!(
                "Advertised but has never passed a check ({}). Probably a leftover advert, or \
                 a service that needs a different kind of check (probe.override).",
                down[0].detail
            ),
        )
    } else {
        (
            Class::Down,
            down.iter().map(|v| v.run_start).max(),
            format!("Not answering from any site ({}).", down[0].detail),
        )
    })
}

pub fn classify(conn: &Connection, now: i64, rules: &Rules) -> Result<Vec<ServiceView>> {
    let fresh_ms = rules.fresh_ms;
    let live_ads = advertised_now(conn, now, fresh_ms)?;
    let checks = latest_checks(conn)?;

    // every probe row in the timeline window, per link and vantage, oldest first
    let mut rows: BTreeMap<(String, String), Vec<ProbeRow>> = BTreeMap::new();
    let mut st = conn.prepare(
        "SELECT link, vantage, ts, ok, latency_ms, coalesce(detail, ''), status FROM probes
         WHERE ts > ?1 AND cut_off = 0 ORDER BY ts",
    )?;
    let window_start = now - TIMELINE_MS;
    for r in st.query_map(params![window_start], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get(2)?,
            r.get(3)?,
            r.get(4)?,
            r.get(5)?,
            r.get(6)?,
        ))
    })? {
        let (link, v, ts, ok, ms, d, status) = r?;
        rows.entry((link, v))
            .or_default()
            .push((ts, ok, ms, d, status));
    }

    let mut out = vec![];
    for svc in targets(conn, now)?
        .into_iter()
        .chain(heartbeats(conn, now)?)
    {
        let push = is_push(&svc.link);
        let (fail_after, ok_after) = if push {
            (1, 1)
        } else {
            (rules.fail_after, rules.ok_after)
        };
        let mut vantages = vec![];
        let mut oldest = i64::MAX;
        for ((link, v), rs) in rows.range((svc.link.clone(), String::new())..) {
            if link != &svc.link {
                break;
            }
            let Some(last) = rs.last() else { continue };
            oldest = oldest.min(rs[0].0);
            if last.0 < now - fresh_ms {
                continue; // this vantage stopped probing; its old answer says nothing now
            }
            let (ok, run_start, pending) = settle(rs, fail_after, ok_after);
            let (check, aredn) = checks
                .get(&(link.clone(), v.clone()))
                .cloned()
                .unwrap_or_else(|| ("http".into(), None));
            vantages.push(VantageResult {
                vantage: v.clone(),
                ok,
                ms: last.2,
                detail: last.3.clone(),
                status: last.4,
                ts: last.0,
                run_start,
                pending,
                check,
                aredn,
            });
        }
        let (class, since, reason) = match &live_ads {
            _ if push => beat_class(conn, &svc, &vantages)?,
            Some(live) => judge(conn, &svc, &vantages, live)?,
            None => (
                Class::Unknown,
                None,
                "No fresh service list from the mesh, so its state is unknown.".into(),
            ),
        };
        let since_open = since.is_some_and(|s| s <= oldest && oldest <= window_start + fresh_ms);
        let mut reason = reason;
        for v in vantages.iter().filter(|v| v.pending > 0) {
            let (what, need) = if v.ok {
                ("failed", fail_after)
            } else {
                ("good", ok_after)
            };
            reason.push_str(&format!(
                " {}: {} {what} check{} in a row, {need} needed to change.",
                v.vantage,
                v.pending,
                if v.pending == 1 { "" } else { "s" }
            ));
        }
        out.push(ServiceView {
            svc,
            class,
            vantages,
            since,
            since_open,
            reason,
        });
    }
    out.sort_by(|a, b| {
        a.class
            .cmp(&b.class)
            .then_with(|| a.svc.name.cmp(&b.svc.name))
    });
    Ok(out)
}

/// What's worth telling someone about. Keys hold the link and the state, so a service
/// going from partial to down closes one alert and opens another.
pub fn alerts_for(views: &[ServiceView], cut_off_here: Option<&str>, now: i64) -> Vec<Alert> {
    let mut out = vec![];
    if let Some(site) = cut_off_here {
        out.push(Alert {
            key: format!("site {site} cut off"),
            severity: Severity::Warning,
            title: format!("{site} can't reach any service"),
            text: "Every check from this site failed, so it is probably cut off from the mesh. \
                   Its results are left out until it can reach things again."
                .into(),
        });
    }
    for v in views {
        let (severity, what) = match v.class {
            Class::Down if v.is_heartbeat() => (Severity::Critical, "stopped checking in"),
            Class::Down => (Severity::Critical, "is down"),
            Class::Partial => (Severity::Warning, "is only partly reachable"),
            Class::UnpublishedAlive => (
                Severity::Info,
                "was dropped from the mesh list but still works",
            ),
            _ => continue,
        };
        let mut text = v.reason.clone();
        let since = v.since_text(now);
        if !since.is_empty() {
            text = format!("{text} ({since})");
        }
        if let Some(why) = aredn_view(v) {
            text = format!("{text} {why}");
        }
        out.push(Alert {
            key: format!("svc {} {}", v.svc.link, v.class.label()),
            severity,
            title: format!("{} on {} {what}", v.svc.name, v.svc.host),
            text,
        });
    }
    out
}

fn ever_answered(conn: &Connection, link: &str) -> Result<bool> {
    let n: i64 = conn.query_row(
        "SELECT count(*) FROM (SELECT 1 FROM probes WHERE link = ?1 AND ok = 1 LIMIT 1)",
        params![link],
        |r| r.get(0),
    )?;
    Ok(n > 0)
}

/// Alerts about these services stay open even though they aren't active: with no fresh
/// data we can't say they're fixed.
pub fn unjudged(views: &[ServiceView]) -> Vec<String> {
    views
        .iter()
        .filter(|v| v.class == Class::Unknown)
        .map(|v| format!("svc {} ", v.svc.link))
        .collect()
}

/// Sites whose latest probe round was marked cut off: every check failed, so their
/// results are left out of the verdicts.
pub fn cut_off_sites(conn: &Connection, now: i64, fresh_ms: i64) -> Result<Vec<String>> {
    let mut st = conn.prepare(
        "SELECT p.vantage FROM probes p
         WHERE p.ts >= ?1 AND p.cut_off = 1
           AND p.ts = (SELECT max(q.ts) FROM probes q
                       WHERE q.vantage = p.vantage AND q.link NOT LIKE 'push://%')
         GROUP BY p.vantage",
    )?;
    let v = st
        .query_map(params![now - fresh_ms], |r| r.get(0))?
        .collect::<Result<_, _>>()?;
    Ok(v)
}

/// Share of checks that worked, from every site, as percentages.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Uptime {
    pub day: Option<f64>,
    pub month: Option<f64>,
    pub year: Option<f64>,
}

pub fn uptime(conn: &Connection, link: &str, now: i64) -> Result<Uptime> {
    let raw = |from: i64| -> Result<(i64, i64)> {
        Ok(conn.query_row(
            "SELECT count(*), coalesce(sum(ok), 0) FROM probes WHERE link = ?1 AND cut_off = 0 AND ts >= ?2",
            params![link, from],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?)
    };
    let pct = |(n, ok): (i64, i64)| (n > 0).then(|| ok as f64 * 100.0 / n as f64);
    let edge = rolled_to(conn)?;
    let (rn, rok): (i64, i64) = conn.query_row(
        "SELECT coalesce(sum(checks), 0), coalesce(sum(oks), 0) FROM probe_days
         WHERE link = ?1 AND day >= ?2 AND day < ?3",
        params![link, now - 365 * DAY, edge],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    let (n, ok) = raw(edge)?;
    Ok(Uptime {
        day: pct(raw(now - DAY)?),
        month: pct(raw(now - 30 * DAY)?),
        year: pct((rn + n, rok + ok)),
    })
}

/// "99.95%", or a dash when there's nothing to go on.
pub fn pct_text(p: Option<f64>) -> String {
    match p {
        None => "-".into(),
        Some(p) if p >= 99.995 => "100%".into(),
        Some(p) => format!("{:.2}%", (p * 100.0).floor() / 100.0),
    }
}

#[derive(Clone, Debug)]
pub struct Check {
    pub ts: i64,
    pub vantage: String,
    pub ok: bool,
    pub detail: String,
}

/// The latest checks of a service from every site, oldest first.
pub fn recent(conn: &Connection, link: &str, limit: usize) -> Result<Vec<Check>> {
    let mut st = conn.prepare(
        "SELECT ts, vantage, ok, coalesce(detail, '') FROM probes
         WHERE link = ?1 AND cut_off = 0 ORDER BY ts DESC LIMIT ?2",
    )?;
    let mut v: Vec<Check> = st
        .query_map(params![link, limit as i64], |r| {
            Ok(Check {
                ts: r.get(0)?,
                vantage: r.get(1)?,
                ok: r.get(2)?,
                detail: r.get(3)?,
            })
        })?
        .collect::<Result<_, _>>()?;
    v.reverse();
    Ok(v)
}

/// Hourly average response time per site since `from`.
pub fn latency(
    conn: &Connection,
    link: &str,
    from: i64,
) -> Result<BTreeMap<String, Vec<(i64, f64)>>> {
    let mut st = conn.prepare(
        "SELECT vantage, ts - (ts % 3600000), avg(latency_ms) FROM probes
         WHERE link = ?1 AND ts >= ?2 AND ok = 1 AND cut_off = 0 AND latency_ms IS NOT NULL
         GROUP BY 1, 2 ORDER BY 1, 2",
    )?;
    let mut out: BTreeMap<String, Vec<(i64, f64)>> = BTreeMap::new();
    for r in st.query_map(params![link, from], |r| {
        Ok((r.get::<_, String>(0)?, r.get(1)?, r.get(2)?))
    })? {
        let (v, t, ms) = r?;
        out.entry(v).or_default().push((t, ms));
    }
    Ok(out)
}

/// What one node-check verdict means, and what to change, in plain words.
pub fn aredn_text(c: &NodeCheck) -> String {
    let code = c.status.unwrap_or_default();
    match c.code.as_str() {
        "http-ok" => format!("It answers HTTP {code}, which AREDN's check accepts."),
        "https-redirect" => {
            "It redirects to an https address, which AREDN's check takes on trust.".into()
        }
        "http-status" if (300..400).contains(&code) => format!(
            "It ends on a redirect (HTTP {code}) that doesn't lead to a page, or redirects more \
             than 50 times. AREDN follows redirects and keeps the service only if they end on a \
             page that returns 200 or 401, or on an https address, so the node stops listing it \
             once it has failed for 2.5 hours."
        ),
        "http-status" => format!(
            "It answers HTTP {code}, but AREDN's check only accepts 200 or 401, so the node \
             stops listing it once it has failed for 2.5 hours, even though a server is there. \
             Point the advertised link at a page that returns 200, such as the app's front page."
        ),
        "http-slow" => "It takes longer than the 10 s AREDN's check waits for an answer, so the \
                        node stops listing it once it has failed for 2.5 hours."
            .into(),
        "http-unreachable" => "It doesn't take a connection within the 2 s AREDN's check allows. \
                               If the node can't connect either, it stops listing the service \
                               once it has failed for 2.5 hours."
            .into(),
        "https-untrusted" => "It leads to an https address whose certificate can't be verified \
                              (a self-signed one, most likely). AREDN's check fetches a Redirect \
                              service's address itself with curl, which refuses that certificate, \
                              so the node stops listing it once it has failed for 2.5 hours. \
                              Advertise the service as https on its own port instead: the node \
                              only checks that the port takes a connection."
            .into(),
        "not-http" => "Its link is http, so AREDN's check sends it an HTTP request, but the port \
                       doesn't speak HTTP (a Winlink port sends a login prompt instead), so the \
                       node stops listing it once it has failed for 2.5 hours. In the node's \
                       service settings, turn the link off for it or give it a protocol other \
                       than http."
            .into(),
        "tcp" => "It takes a TCP connection within 2 s, which AREDN's check accepts.".into(),
        "udp" => "It takes no TCP connection, but its UDP port doesn't refuse, which AREDN's \
                  check accepts."
            .into(),
        "refused" => "Its port takes no TCP connection and refuses UDP, so AREDN's check fails \
                      and the node stops listing it once it has failed for 2.5 hours. Check the \
                      port in the advert, and any firewall on the host."
            .into(),
        _ => String::new(),
    }
}

/// What AREDN's own check on the node makes of this service, from our sites' results.
/// The node checks every 5 minutes (hourly before firmware 4.26.10.0) and stops listing a
/// service that has failed for 2.5 hours. HTTP links pass on a 200 or 401 within 10 s,
/// redirects followed, and 2 s to connect; other links (https included) pass on a TCP
/// connection within 2 s, or a UDP send that isn't refused. Behind a NAT port forward the
/// node checks the forward's target; on any other LAN type it skips the services of a host
/// in its host list whose last good ping or arping reply is over 2.5 hours old. From
/// files/usr/share/ucode/aredn/services.uc and files/usr/local/mgr/lan_monitor.uc in the
/// AREDN firmware.
pub fn aredn_view(v: &ServiceView) -> Option<String> {
    if v.is_heartbeat() {
        return None;
    }
    // the node's verdict on a service that answers nowhere says nothing new
    let working = v.vantages.iter().filter(|x| x.ok);
    let failing = working
        .clone()
        .find_map(|x| x.aredn.as_ref().filter(|a| !a.pass).map(|a| (x, a)));
    if let Some((x, a)) = failing {
        return Some(format!("{} (seen from {})", aredn_text(a), x.vantage));
    }
    let passed = working.clone().find_map(|x| x.aredn.as_ref());
    if v.class != Class::UnpublishedAlive {
        return None;
    }
    let first = match passed {
        Some(a) => format!("{} ", aredn_text(a)),
        None => "It answers from here. ".into(),
    };
    // services.uc reads `dpor` while mapping forwards; the manager imports it statically, and
    // ucode compiles static imports with strict declarations, so that most likely throws
    Some(format!(
        "{first}So the node probably couldn't reach it when it last checked. It checks every 5 \
         minutes (hourly before firmware 4.26.10.0) and lists the service again once it passes. \
         Behind a NAT port forward, check that the forward points at the right address. On a \
         NAT LAN with an enabled port forward, AREDN 4.26's check hits an undeclared variable \
         (dpor, a typo for dport) and most likely errors out, so that node neither refreshes \
         nor drops services. On the other LAN types (the default) the node skips the services \
         of a host in its host list whose last good reply to ping or arping is over 2.5 hours \
         old, so check that the host still answers on the node's LAN at the address the node \
         has for it."
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::probes::Probes;
    use ridgewarden_client::core::Projection;
    use ridgewarden_client::mesh::Mesh;
    use ridgewarden_client::mesh::testing::Fake;
    use serde_json::{Value, json};

    /// An event from a site, after the poll of its own node that lets it speak for it.
    fn report(l: &mut Fake, kind: &str, payload: Value, ts: i64) {
        let site = payload["vantage"].as_str().unwrap_or_default().to_string();
        l.add(
            "node.poll",
            json!({"node": site, "ok": true, "via": "lan"}),
            ts,
        );
        l.add(kind, payload, ts);
    }

    const MIN: i64 = 60_000;
    const NOW: i64 = 1_800_000_000_000;
    const FRESH: i64 = 20 * MIN;
    /// no thresholds, for the tests about classes
    const NOW_RULES: Rules = Rules {
        fresh_ms: FRESH,
        fail_after: 1,
        ok_after: 1,
    };
    const RULES: Rules = Rules {
        fresh_ms: FRESH,
        fail_after: 3,
        ok_after: 2,
    };

    fn log() -> Fake {
        Fake::new(vec![Box::new(Mesh), Box::new(Probes)])
    }

    fn ads(services: &[(&str, &str)]) -> Value {
        json!(
            services
                .iter()
                .map(|(n, l)| json!({"host": "h", "name": n, "link": l, "protocol": "tcp"}))
                .collect::<Vec<_>>()
        )
    }

    fn advertise(l: &mut Fake, ts: i64, list: &[(&str, &str)]) {
        let a = ads(list);
        let hash = ridgewarden_client::event::list_hash(&a);
        l.add("mesh.list", json!({"hash": hash, "list": a}), ts);
        l.add(
            "node.poll",
            json!({"node": "n", "ok": true, "ads_hash": hash}),
            ts,
        );
    }

    fn probe(l: &mut Fake, ts: i64, vantage: &str, results: &[(&str, bool)]) {
        let r: Vec<_> = results
            .iter()
            .map(|(link, ok)| json!({"name": "x", "link": link, "host": "h", "ok": ok, "detail": if *ok {"HTTP 200"} else {"timed out"}}))
            .collect();
        report(
            l,
            "svc.probe",
            json!({"vantage": vantage, "results": r}),
            ts,
        );
    }

    fn class_of(views: &[ServiceView], link: &str) -> Class {
        views.iter().find(|v| v.svc.link == link).unwrap().class
    }

    #[test]
    fn classifies_every_case() {
        let mut l = log();
        let list = [
            ("Up", "http://up/"),
            ("Partial", "http://partial/"),
            ("Down", "http://down/"),
            ("Stale", "http://stale/"),
        ];
        advertise(
            &mut l,
            NOW - 60 * MIN,
            &[list.as_slice(), &[("Dropped", "http://dropped/")]].concat(),
        );
        advertise(&mut l, NOW - 5 * MIN, &list);
        probe(&mut l, NOW - 50 * MIN, "a", &[("http://down/", true)]);
        for v in ["a", "b"] {
            probe(
                &mut l,
                NOW - 4 * MIN,
                v,
                &[
                    ("http://up/", true),
                    ("http://partial/", v == "a"),
                    ("http://down/", false),
                    ("http://stale/", false),
                    ("http://dropped/", true),
                ],
            );
        }
        let views = classify(&l.conn, NOW, &NOW_RULES).unwrap();
        assert_eq!(class_of(&views, "http://up/"), Class::Up);
        assert_eq!(class_of(&views, "http://partial/"), Class::Partial);
        assert_eq!(class_of(&views, "http://down/"), Class::Down);
        assert_eq!(class_of(&views, "http://stale/"), Class::Stale);
        assert_eq!(class_of(&views, "http://dropped/"), Class::UnpublishedAlive);
        let p = views.iter().find(|v| v.class == Class::Partial).unwrap();
        assert!(p.reason.contains("not from b"), "{}", p.reason);
        assert_eq!(views[0].class, Class::Down, "worst first");
    }

    #[test]
    fn unpublishing_is_noticed_on_the_next_poll() {
        let mut l = log();
        advertise(
            &mut l,
            NOW - 3 * MIN,
            &[("S", "http://s/"), ("T", "http://t/")],
        );
        advertise(&mut l, NOW - MIN, &[("T", "http://t/")]);
        probe(
            &mut l,
            NOW - MIN,
            "a",
            &[("http://s/", true), ("http://t/", true)],
        );
        let views = classify(&l.conn, NOW, &NOW_RULES).unwrap();
        assert_eq!(class_of(&views, "http://s/"), Class::UnpublishedAlive);
        assert_eq!(class_of(&views, "http://t/"), Class::Up);
    }

    #[test]
    fn no_fresh_service_list_means_unknown_not_removed() {
        let mut l = log();
        advertise(&mut l, NOW - 3 * 60 * MIN, &[("S", "http://s/")]);
        probe(&mut l, NOW - MIN, "a", &[("http://s/", false)]);
        let views = classify(&l.conn, NOW, &NOW_RULES).unwrap();
        assert_eq!(views[0].class, Class::Unknown, "{}", views[0].reason);
    }

    #[test]
    fn old_results_mean_unknown() {
        let mut l = log();
        advertise(&mut l, NOW - 5 * MIN, &[("S", "http://s/")]);
        probe(&mut l, NOW - 3 * 60 * MIN, "a", &[("http://s/", true)]);
        let views = classify(&l.conn, NOW, &NOW_RULES).unwrap();
        assert_eq!(views[0].class, Class::Unknown);
    }

    fn probe_cut(l: &mut Fake, ts: i64, vantage: &str, results: &[(&str, bool)]) {
        let r: Vec<_> = results
            .iter()
            .map(|(link, ok)| json!({"name": "x", "link": link, "host": "h", "ok": ok, "detail": "timed out"}))
            .collect();
        report(
            l,
            "svc.probe",
            json!({"vantage": vantage, "cut_off": true, "results": r}),
            ts,
        );
    }

    #[test]
    fn one_failed_check_is_not_down() {
        let mut l = log();
        advertise(&mut l, NOW - 2 * MIN, &[("S", "http://s/")]);
        for i in 0..5 {
            probe(
                &mut l,
                NOW - (50 - i * 10) * MIN,
                "a",
                &[("http://s/", i != 4)],
            );
        }
        let views = classify(&l.conn, NOW, &RULES).unwrap();
        assert_eq!(views[0].class, Class::Up);
        assert_eq!(views[0].vantages[0].pending, 1);
        assert!(
            views[0].reason.contains("1 failed check in a row"),
            "{}",
            views[0].reason
        );
        // two more and it's down, since the first of the three
        probe(&mut l, NOW - 5 * MIN, "a", &[("http://s/", false)]);
        probe(&mut l, NOW - 2 * MIN, "a", &[("http://s/", false)]);
        let views = classify(&l.conn, NOW, &RULES).unwrap();
        assert_eq!(views[0].class, Class::Down);
        assert_eq!(views[0].since, Some(NOW - 10 * MIN));
        // and one good check doesn't bring it back
        probe(&mut l, NOW - MIN, "a", &[("http://s/", true)]);
        assert_eq!(
            classify(&l.conn, NOW, &RULES).unwrap()[0].class,
            Class::Down
        );
    }

    #[test]
    fn a_cut_off_site_gives_no_verdict() {
        let mut l = log();
        advertise(
            &mut l,
            NOW - 2 * MIN,
            &[("S", "http://s/"), ("T", "http://t/")],
        );
        probe(
            &mut l,
            NOW - 30 * MIN,
            "a",
            &[("http://s/", true), ("http://t/", true)],
        );
        probe(
            &mut l,
            NOW - 3 * MIN,
            "b",
            &[("http://s/", true), ("http://t/", true)],
        );
        probe_cut(
            &mut l,
            NOW - 2 * MIN,
            "a",
            &[("http://s/", false), ("http://t/", false)],
        );
        // a heartbeat logged by the cut-off site afterwards doesn't hide the cut
        beat(&mut l, NOW - MIN, "a", "Backup", true);
        let views = classify(&l.conn, NOW, &NOW_RULES).unwrap();
        assert!(views.iter().all(|v| v.class == Class::Up), "{views:?}");
        assert_eq!(
            cut_off_sites(&l.conn, NOW, FRESH).unwrap(),
            vec!["a".to_string()]
        );
    }

    #[test]
    fn uptime_counts_rollups_and_raw_results() {
        let mut l = log();
        let day = |d: i64| NOW - d * DAY;
        // 40 days ago: rolled up, then the raw rows are dropped
        probe(&mut l, day(40), "a", &[("http://s/", true)]);
        probe(&mut l, day(40) + MIN, "a", &[("http://s/", false)]);
        // 10 days ago, and today
        probe(&mut l, day(10), "a", &[("http://s/", true)]);
        probe(&mut l, NOW - MIN, "a", &[("http://s/", true)]);
        probe_cut(&mut l, NOW - 2 * MIN, "a", &[("http://s/", false)]);
        crate::probes::rollup(&l.conn, NOW).unwrap();
        let raw: i64 = l
            .conn
            .query_row(
                "SELECT count(*) FROM probes WHERE ts < ?1",
                [day(35)],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(raw, 0, "raw results past their keep time are gone");
        let u = uptime(&l.conn, "http://s/", NOW).unwrap();
        assert_eq!(u.day, Some(100.0), "cut-off rounds don't count");
        assert_eq!(u.month, Some(100.0));
        assert_eq!(u.year, Some(75.0));
        // rolling up again doesn't count anything twice
        crate::probes::rollup(&l.conn, NOW + 3_600_000).unwrap();
        assert_eq!(uptime(&l.conn, "http://s/", NOW).unwrap().year, Some(75.0));
        assert_eq!(pct_text(Some(99.999)), "100%");
        assert_eq!(pct_text(Some(99.957)), "99.95%");
    }

    #[test]
    fn late_results_still_count() {
        let mut l = log();
        let day = |d: i64| NOW - d * DAY;
        probe(&mut l, day(10), "a", &[("http://s/", true)]);
        crate::probes::rollup(&l.conn, NOW).unwrap();
        // a site that was cut off syncs four-day-old failures after the day was rolled up
        for i in 0..3 {
            probe(&mut l, day(4) + i * MIN, "b", &[("http://s/", false)]);
        }
        crate::probes::rollup(&l.conn, NOW + 3_600_000).unwrap();
        assert_eq!(uptime(&l.conn, "http://s/", NOW).unwrap().year, Some(25.0));
        // a day that just finished counts even before the next rollup
        probe(&mut l, NOW - MIN, "a", &[("http://s/", true)]);
        let tomorrow = NOW + 3 * DAY;
        assert_eq!(
            uptime(&l.conn, "http://s/", tomorrow).unwrap().year,
            Some(40.0)
        );
    }

    fn checked(link: &str, ok: bool, aredn: Value) -> Value {
        json!({"name": "x", "link": link, "host": "h", "ok": ok, "detail": "", "check": "http", "aredn": aredn})
    }

    #[test]
    fn explains_why_aredn_would_drop_a_service() {
        let mut l = log();
        advertise(
            &mut l,
            NOW - 2 * MIN,
            &[
                ("Wiki", "http://wiki/"),
                ("Ok", "http://ok/"),
                ("Gw", "http://gw:8772/"),
                ("Nas", "http://node/a/redirect?https://nas/"),
            ],
        );
        report(
            &mut l,
            "svc.probe",
            json!({"vantage": "a", "results": [
                checked("http://wiki/", true, json!({"pass": false, "code": "http-status", "status": 404})),
                checked("http://ok/", true, json!({"pass": true, "code": "http-ok", "status": 200})),
                checked("http://gw:8772/", true, json!({"pass": true, "code": "not-http"})),
                checked("http://node/a/redirect?https://nas/", true, json!({"pass": true, "code": "https-untrusted"})),
            ]}),
            NOW - MIN,
        );
        let views = classify(&l.conn, NOW, &NOW_RULES).unwrap();
        let get = |n: &str| views.iter().find(|v| v.svc.name == n).unwrap();
        let why = aredn_view(get("Wiki")).unwrap();
        assert!(why.contains("404") && why.contains("200 or 401"), "{why}");
        assert!(why.contains("seen from a"), "{why}");
        assert!(aredn_view(get("Ok")).is_none());
        // the pass flag comes from our own table of codes, not from whoever sent it
        let why = aredn_view(get("Gw")).unwrap();
        assert!(why.contains("doesn't speak HTTP"), "{why}");
        let why = aredn_view(get("Nas")).unwrap();
        assert!(why.contains("certificate"), "{why}");
        assert_eq!(get("Wiki").vantages[0].check, "http");
    }

    #[test]
    fn a_dropped_service_that_passes_the_check_points_at_what_the_node_sees() {
        let mut l = log();
        advertise(&mut l, NOW - 3 * MIN, &[("Cam", "http://cam/")]);
        advertise(&mut l, NOW - MIN, &[]);
        report(
            &mut l,
            "svc.probe",
            json!({"vantage": "a", "results": [
                checked("http://cam/", true, json!({"pass": true, "code": "http-ok", "status": 200})),
            ]}),
            NOW - MIN,
        );
        let views = classify(&l.conn, NOW, &NOW_RULES).unwrap();
        assert_eq!(views[0].class, Class::UnpublishedAlive);
        let why = aredn_view(&views[0]).unwrap();
        // only a listed host that has stopped answering for 2.5 hours gets its services skipped
        assert!(
            why.contains("ping or arping is over 2.5 hours old"),
            "{why}"
        );
        // 4.26's undeclared dpor most likely stops the check rather than dropping anything
        assert!(
            why.contains("dpor") && why.contains("neither refreshes nor drops"),
            "{why}"
        );
        assert!(!why.contains("fail behind a forward"), "{why}");
        assert!(why.contains("every 5 minutes"), "{why}");
    }

    #[test]
    fn every_failing_verdict_says_when_the_node_drops_it() {
        for status in [302, 404] {
            for (code, _) in AREDN_CODES.iter().filter(|(_, pass)| !pass) {
                let c = NodeCheck {
                    pass: false,
                    code: code.to_string(),
                    status: Some(status),
                };
                let text = aredn_text(&c);
                assert!(
                    text.contains("once it has failed for 2.5 hours"),
                    "{code} {status}: {text}"
                );
            }
        }
    }

    #[test]
    fn down_since_is_when_it_stopped_answering() {
        let mut l = log();
        advertise(&mut l, NOW - 2 * MIN, &[("S", "http://s/")]);
        for i in 0..6 {
            let ts = NOW - (60 - i * 10) * MIN;
            probe(&mut l, ts, "a", &[("http://s/", i < 3)]);
        }
        let views = classify(&l.conn, NOW, &RULES).unwrap();
        assert_eq!(views[0].class, Class::Down);
        assert_eq!(views[0].since, Some(NOW - 30 * MIN));
    }

    fn beat(l: &mut Fake, ts: i64, site: &str, name: &str, ok: bool) {
        let link = format!("push://{site}/{}", name.to_ascii_lowercase());
        report(
            l,
            "svc.beat",
            json!({"vantage": site, "results": [{"name": name, "link": link, "host": site, "ok": ok,
                "detail": if ok {"last beat 1 min ago"} else {"late: last beat 2 h ago"}, "check": "push"}]}),
            ts,
        );
    }

    #[test]
    fn heartbeats_are_judged_by_the_site_that_receives_them() {
        let mut l = log();
        advertise(&mut l, NOW - 2 * MIN, &[]);
        beat(&mut l, NOW - 10 * MIN, "a", "Backup", true);
        beat(&mut l, NOW - 5 * MIN, "a", "Backup", false);
        let views = classify(&l.conn, NOW, &RULES).unwrap();
        let v = views.iter().find(|v| v.is_heartbeat()).unwrap();
        // one late result is enough: the receiving site already allowed for lateness
        assert_eq!(v.class, Class::Down, "{}", v.reason);
        assert_eq!(v.svc.host, "a");
        let alerts = alerts_for(&views, None, NOW);
        assert!(
            alerts[0].title.contains("stopped checking in"),
            "{:?}",
            alerts
        );
        // the site went quiet: no word either way
        let later = NOW + 2 * FRESH;
        let views = classify(&l.conn, later, &RULES).unwrap();
        assert_eq!(views[0].class, Class::Unknown);
        // and it never needed a fresh service list from the mesh
        let mut l = log();
        beat(&mut l, NOW - MIN, "a", "Backup", true);
        assert_eq!(classify(&l.conn, NOW, &RULES).unwrap()[0].class, Class::Up);
    }

    #[test]
    fn a_site_cannot_file_heartbeats_under_another_or_probe_results_as_beats() {
        let mut l = log();
        report(
            &mut l,
            "svc.beat",
            json!({"vantage": "a", "results": [{"name": "x", "link": "push://b/x", "host": "b", "ok": false}]}),
            NOW - MIN,
        );
        report(
            &mut l,
            "svc.probe",
            json!({"vantage": "a", "results": [{"name": "x", "link": "push://a/x", "host": "a", "ok": true}]}),
            NOW - MIN,
        );
        report(
            &mut l,
            "svc.probe",
            json!({"vantage": "a", "results": [{"name": "x", "link": "PUSH://a/x", "host": "a", "ok": true}]}),
            NOW - MIN,
        );
        report(
            &mut l,
            "svc.probe",
            json!({"vantage": "bad name!", "results": [{"name": "x", "link": "http://s/", "host": "a", "ok": true}]}),
            NOW - MIN,
        );
        let n: i64 = l
            .conn
            .query_row("SELECT count(*) FROM probes", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 0);
    }

    /// An event from another station, which `Fake` can't sign for; projections don't
    /// check signatures (the core does).
    fn from_other(l: &mut Fake, kind: &str, payload: Value) {
        let e = ridgewarden_client::Event {
            id: "f".repeat(64),
            author: ridgewarden_client::Author {
                call: "N0OTHER".into(),
                key: "other-key".into(),
            },
            seq: 0,
            prev: None,
            lamport: 0,
            wall_time: ridgewarden_client::util::ms_to_rfc3339(NOW - MIN),
            mono_time: 0,
            kind: kind.into(),
            payload,
            sig: String::new(),
            log: None,
        };
        let tx = l.conn.transaction().unwrap();
        Mesh.apply(&tx, &e, NOW - MIN).unwrap();
        Probes.apply(&tx, &e, NOW - MIN).unwrap();
        tx.commit().unwrap();
    }

    #[test]
    fn a_station_reports_only_from_the_node_it_polls() {
        let mut l = log();
        advertise(&mut l, NOW - 2 * MIN, &[("S", "http://s/")]);
        probe(&mut l, NOW - 3 * MIN, "a", &[("http://s/", true)]);
        // another station claims to be site a, then invents a site of its own
        for v in ["a", "made-up"] {
            from_other(
                &mut l,
                "svc.probe",
                json!({"vantage": v, "cut_off": true, "results": [{"name": "S", "link": "http://s/", "host": "h", "ok": false}]}),
            );
        }
        let views = classify(&l.conn, NOW, &NOW_RULES).unwrap();
        assert_eq!(views[0].class, Class::Up, "{}", views[0].reason);
        assert!(cut_off_sites(&l.conn, NOW, FRESH).unwrap().is_empty());
        let sites = crate::probe::probing_sites(&l.conn, NOW, FRESH).unwrap();
        assert_eq!(sites.into_iter().collect::<Vec<_>>(), ["a"]);
        // once it polls its own node on its LAN, it reports under that name
        from_other(
            &mut l,
            "node.poll",
            json!({"node": "b", "ok": true, "via": "lan"}),
        );
        from_other(
            &mut l,
            "svc.probe",
            json!({"vantage": "b", "results": [{"name": "S", "link": "http://s/", "host": "h", "ok": false}]}),
        );
        let views = classify(&l.conn, NOW, &NOW_RULES).unwrap();
        assert_eq!(views[0].class, Class::Partial);
    }
}
