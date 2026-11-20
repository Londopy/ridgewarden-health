//! Push heartbeats, for things that can't be probed: a backup job, a battery monitor, a
//! station on a timer. Each POSTs to its own secret URL on this site. Once a minute this
//! site turns what it heard into results (on time, late, or reporting a problem) and logs
//! them through its core as a signed `svc.beat` event, so every site sees them.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::json;

use ridgewarden_client::util::{human_duration, now_ms};

use crate::app::App;
use crate::config::{HeartbeatCfg, slug};
use crate::probe::ProbeResult;

pub const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS beats (
    name TEXT PRIMARY KEY,
    ts   INTEGER NOT NULL,
    ok   INTEGER NOT NULL,
    msg  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS push_secret (
    id     INTEGER PRIMARY KEY CHECK (id = 1),
    secret TEXT NOT NULL
);";

/// Beats closer together than this are refused: something is looping.
const MIN_GAP_MS: i64 = 5_000;

fn secret(conn: &Connection) -> Result<String> {
    if let Some(s) = conn
        .query_row("SELECT secret FROM push_secret WHERE id = 1", [], |r| {
            r.get(0)
        })
        .optional()?
    {
        return Ok(s);
    }
    let mut b = [0u8; 16];
    getrandom::fill(&mut b).map_err(|e| anyhow::anyhow!("no OS randomness: {e}"))?;
    conn.execute(
        "INSERT OR IGNORE INTO push_secret (id, secret) VALUES (1, ?1)",
        params![hex::encode(b)],
    )?;
    secret(conn)
}

/// The secret part of a heartbeat's push URL. It comes from this app's own random secret,
/// so it never needs to be written in the config.
pub fn token(conn: &Connection, name: &str) -> Result<String> {
    let s = secret(conn)?;
    let h = blake3::hash(format!("{s}:push:{}", slug(name)).as_bytes());
    Ok(h.to_hex()[..24].to_string())
}

/// The heartbeat a push token belongs to.
pub fn find<'a>(
    conn: &Connection,
    beats: &'a [HeartbeatCfg],
    tok: &str,
) -> Result<Option<&'a HeartbeatCfg>> {
    for h in beats {
        if token(conn, &h.name)? == tok {
            return Ok(Some(h));
        }
    }
    Ok(None)
}

/// Record a beat. False when the last one came only moments ago.
pub fn record(conn: &Connection, name: &str, ok: bool, msg: &str, now: i64) -> Result<bool> {
    let last: Option<i64> = conn
        .query_row(
            "SELECT ts FROM beats WHERE name = ?1",
            params![slug(name)],
            |r| r.get(0),
        )
        .optional()?;
    if last.is_some_and(|t| now - t < MIN_GAP_MS) {
        return Ok(false);
    }
    conn.execute(
        "INSERT INTO beats (name, ts, ok, msg) VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(name) DO UPDATE SET ts = excluded.ts, ok = excluded.ok, msg = excluded.msg",
        params![slug(name), now, ok, msg],
    )?;
    Ok(true)
}

/// A message from a pushing script, made safe to show: one line, at most 200 characters.
pub fn clean_msg(m: &str) -> String {
    m.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .take(200)
        .collect::<String>()
        .trim()
        .to_string()
}

/// The link a heartbeat goes by in the results: it lives on the site that receives it.
pub fn link(node: &str, name: &str) -> String {
    format!("push://{node}/{}", slug(name))
}

/// Each heartbeat's state right now, as results from this site. Lateness counts from
/// `started` at the earliest: while this app was down, nobody could have checked in.
pub fn results(
    conn: &Connection,
    beats: &[HeartbeatCfg],
    node: &str,
    started: i64,
    now: i64,
) -> Result<Vec<ProbeResult>> {
    let mut out = vec![];
    for h in beats {
        let last: Option<(i64, bool, String)> = conn
            .query_row(
                "SELECT ts, ok, msg FROM beats WHERE name = ?1",
                params![slug(&h.name)],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        let every = human_duration(h.every_s as i64 * 1000);
        let due = (h.every_s + h.grace_s) as i64 * 1000;
        let (ok, detail) = match last {
            None => (false, format!("no beat yet; expected every {every}")),
            Some((ts, _, _)) if now - ts.max(started) > due => (
                false,
                format!(
                    "late: last beat {} ago, expected every {every}",
                    human_duration(now - ts)
                ),
            ),
            Some((ts, false, msg)) => (
                false,
                format!(
                    "reported a problem {} ago{}",
                    human_duration(now - ts),
                    if msg.is_empty() {
                        String::new()
                    } else {
                        format!(": {msg}")
                    }
                ),
            ),
            Some((ts, true, msg)) => (
                true,
                format!(
                    "last beat {} ago{}",
                    human_duration(now - ts),
                    if msg.is_empty() {
                        String::new()
                    } else {
                        format!(": {msg}")
                    }
                ),
            ),
        };
        out.push(ProbeResult {
            name: h.name.trim().to_string(),
            host: node.to_string(),
            link: link(node, &h.name),
            ok,
            ms: None,
            status: None,
            detail,
            check: "push",
            aredn: None,
        });
    }
    Ok(out)
}

/// Turn heartbeats into results once a minute. They're logged when one changes, and
/// otherwise once a probe interval, so the uptime figures have something to count.
pub fn spawn(app: Arc<App>) {
    tokio::spawn(async move {
        let started = now_ms();
        let mut last: Option<(Vec<bool>, i64)> = None;
        loop {
            tokio::time::sleep(Duration::from_secs(60)).await;
            let now = now_ms();
            let node = match app.vantage().await {
                Ok(n) if !n.is_empty() => n,
                _ => continue,
            };
            let results = match results(&app.db(), &app.cfg.heartbeats, &node, started, now) {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!("reading heartbeats: {e:#}");
                    continue;
                }
            };
            let states: Vec<bool> = results.iter().map(|r| r.ok).collect();
            let every = app.cfg.probe.interval_s as i64 * 1000;
            if last
                .as_ref()
                .is_some_and(|(s, t)| *s == states && now - t < every)
            {
                continue;
            }
            let ev = app
                .core
                .append_telemetry("svc.beat", json!({"vantage": node, "results": results}))
                .await;
            match ev {
                Ok(_) => last = Some((states, now)),
                Err(e) => tracing::warn!("logging heartbeats: {e:#}"),
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_800_000_000_000;
    const MIN: i64 = 60_000;

    fn db() -> Connection {
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch(SCHEMA).unwrap();
        c
    }

    fn hb(name: &str, every_s: u64) -> HeartbeatCfg {
        HeartbeatCfg {
            name: name.into(),
            every_s,
            grace_s: 60,
        }
    }

    #[test]
    fn tokens_are_secret_stable_and_per_heartbeat() {
        let c = db();
        let beats = [hb("Backup", 3600), hb("Battery", 600)];
        let t = token(&c, "Backup").unwrap();
        assert_eq!(t, token(&c, "Backup").unwrap());
        assert_ne!(t, token(&c, "Battery").unwrap());
        assert_eq!(find(&c, &beats, &t).unwrap().unwrap().name, "Backup");
        assert!(
            find(&c, &beats, "0123456789abcdef01234567")
                .unwrap()
                .is_none()
        );
        // another install has its own secret, so its tokens differ
        assert_ne!(t, token(&db(), "Backup").unwrap());
    }

    #[test]
    fn beats_on_time_late_and_reporting_trouble() {
        let c = db();
        let beats = [hb("Backup", 3600)];
        let r = results(&c, &beats, "tst-shack", 0, NOW).unwrap();
        assert!(
            !r[0].ok && r[0].detail.contains("no beat yet"),
            "{}",
            r[0].detail
        );
        assert_eq!(r[0].link, "push://tst-shack/backup");
        record(&c, "Backup", true, "42 files", NOW - 30 * MIN).unwrap();
        let r = results(&c, &beats, "tst-shack", 0, NOW).unwrap();
        assert!(r[0].ok, "{}", r[0].detail);
        assert!(r[0].detail.contains("42 files"));
        // on time up to an hour and the minute's grace after the last beat, late after
        let due = NOW - 30 * MIN + 61 * MIN;
        assert!(results(&c, &beats, "tst-shack", 0, due).unwrap()[0].ok);
        let r = results(&c, &beats, "tst-shack", 0, due + 1).unwrap();
        assert!(
            !r[0].ok && r[0].detail.starts_with("late"),
            "{}",
            r[0].detail
        );
        // but not when this app only started a moment ago: nobody could have checked in
        assert!(results(&c, &beats, "tst-shack", due - MIN, due + 1).unwrap()[0].ok);
        record(&c, "Backup", false, "disk full", NOW).unwrap();
        let r = results(&c, &beats, "tst-shack", 0, NOW).unwrap();
        assert!(
            !r[0].ok && r[0].detail.contains("disk full"),
            "{}",
            r[0].detail
        );
    }

    #[test]
    fn a_looping_script_is_slowed_down() {
        let c = db();
        assert!(record(&c, "Backup", true, "", NOW).unwrap());
        assert!(!record(&c, "Backup", true, "", NOW + 1000).unwrap());
        assert!(record(&c, "Backup", true, "", NOW + MIN_GAP_MS).unwrap());
        assert_eq!(clean_msg("two\nlines\u{7}"), "two lines");
    }
}
