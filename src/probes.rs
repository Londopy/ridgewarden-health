//! The `probes` view, built from `svc.probe` and `svc.beat` events (this site's and every
//! other site's). The status page app reuses it.
//!
//! Raw results are kept for 35 days. Before that, each finished day is rolled up per
//! service and site into `probe_days`, which keeps 400 days for the yearly uptime figure.
//! The rollups sit outside the projection, so a rebuild (after a trust change) doesn't
//! lose history the core has already pruned.

use anyhow::Result;
use ridgewarden_client::Event;
use ridgewarden_client::core::Projection;
use ridgewarden_client::mesh::{f, s};
use ridgewarden_client::util::{norm_node, valid_node};
use rusqlite::{Connection, Transaction, params};
use serde_json::Value;

use crate::probe::AREDN_CODES;

pub struct Probes;

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS probes (
    event_id   TEXT NOT NULL,
    ts         INTEGER NOT NULL,
    author_key TEXT NOT NULL,
    vantage    TEXT NOT NULL,
    link       TEXT NOT NULL,
    name       TEXT NOT NULL,
    host       TEXT,
    ok         INTEGER NOT NULL,
    latency_ms REAL,
    status     INTEGER,
    detail     TEXT,
    cut_off    INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS probes_link_ts ON probes(link, ts);
CREATE INDEX IF NOT EXISTS probes_ts ON probes(ts);
-- covers uptime and "ever answered" without touching the table
CREATE INDEX IF NOT EXISTS probes_link_cut_ts_ok ON probes(link, cut_off, ts, ok);

CREATE TABLE IF NOT EXISTS probe_days (
    link    TEXT NOT NULL,
    vantage TEXT NOT NULL,
    day     INTEGER NOT NULL,
    checks  INTEGER NOT NULL,
    oks     INTEGER NOT NULL,
    PRIMARY KEY (link, vantage, day)
);

-- the latest kind of check from each site, and what the node's own check would make of it
CREATE TABLE IF NOT EXISTS probe_latest (
    link        TEXT NOT NULL,
    vantage     TEXT NOT NULL,
    ts          INTEGER NOT NULL,
    check_kind  TEXT NOT NULL,
    aredn_code  TEXT,
    aredn_status INTEGER,
    PRIMARY KEY (link, vantage)
);
"#;

/// Whether this key's core polls `node` on its own LAN: a site's results only count under
/// the name of the node it sits next to, so one station can't speak for another.
fn polled_by(tx: &Transaction, key: &str, node: &str) -> Result<bool> {
    Ok(tx.query_row(
        "SELECT EXISTS (SELECT 1 FROM polls WHERE author_key = ?1 AND node = ?2
                        AND coalesce(via, 'lan') = 'lan')",
        params![key, node],
        |r| r.get(0),
    )?)
}

fn is_push(link: &str) -> bool {
    link.get(..7)
        .is_some_and(|p| p.eq_ignore_ascii_case("push://"))
}

fn text(v: &Value, k: &str, max: usize) -> Option<String> {
    s(v, k).map(|t| t.chars().take(max).collect())
}

/// Codes this version knows; anything else from another site is dropped.
fn known<'a>(code: Option<&str>, set: &[&'a str]) -> Option<&'a str> {
    code.and_then(|c| set.iter().find(|k| **k == c).copied())
}

impl Projection for Probes {
    fn schema(&self) -> &'static str {
        SCHEMA
    }

    fn reset(&self, tx: &Transaction) -> Result<()> {
        tx.execute("DELETE FROM probes", [])?;
        tx.execute("DELETE FROM probe_latest", [])?;
        Ok(())
    }

    /// `svc.probe` is a probe round; `svc.beat` carries the same kind of results for the
    /// push heartbeats a site receives, which may only be filed under that site's name.
    fn apply(&self, tx: &Transaction, e: &Event, ts: i64) -> Result<()> {
        let beats = match e.kind.as_str() {
            "svc.probe" => false,
            "svc.beat" => true,
            _ => return Ok(()),
        };
        let p = &e.payload;
        let vantage = norm_node(s(p, "vantage").unwrap_or(""));
        if !valid_node(&vantage) || !polled_by(tx, &e.author.key, &vantage)? {
            return Ok(());
        }
        let push = format!("push://{vantage}/");
        let cut_off = !beats && p.get("cut_off").and_then(Value::as_bool).unwrap_or(false);
        let checks: Vec<&str> = ["http", "tcp", "winlink", "meshchat", "push"].into();
        let codes: Vec<&str> = AREDN_CODES.iter().map(|(c, _)| *c).collect();
        for r in p
            .get("results")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            // a real round is a few dozen results
            .take(1000)
        {
            let Some(link) = s(r, "link").filter(|l| l.len() <= 512) else {
                continue;
            };
            if beats != link.starts_with(&push) || (!beats && is_push(link)) {
                continue;
            }
            tx.execute(
                "INSERT INTO probes (event_id, ts, author_key, vantage, link, name, host, ok, latency_ms,
                     status, detail, cut_off)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
                params![
                    e.id,
                    ts,
                    e.author.key,
                    vantage,
                    link,
                    text(r, "name", 100).unwrap_or_default(),
                    s(r, "host").map(norm_node).filter(|h| h.len() <= 253),
                    r.get("ok").and_then(Value::as_bool).unwrap_or(false),
                    f(r, "ms").filter(|m| m.is_finite() && *m >= 0.0),
                    r.get("status").and_then(Value::as_u64).filter(|c| *c < 1000).map(|c| c as i64),
                    text(r, "detail", 300),
                    cut_off,
                ],
            )?;
            let check =
                known(s(r, "check"), &checks).unwrap_or(if beats { "push" } else { "http" });
            let a = r.get("aredn");
            let code = known(a.and_then(|a| s(a, "code")), &codes);
            let status = a
                .and_then(|a| a.get("status"))
                .and_then(Value::as_u64)
                .filter(|c| *c < 1000)
                .map(|c| c as i64);
            tx.execute(
                "INSERT INTO probe_latest (link, vantage, ts, check_kind, aredn_code, aredn_status)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                 ON CONFLICT(link, vantage) DO UPDATE SET ts = excluded.ts,
                     check_kind = excluded.check_kind, aredn_code = excluded.aredn_code,
                     aredn_status = excluded.aredn_status
                 WHERE excluded.ts >= probe_latest.ts",
                params![link, vantage, ts, check, code, status],
            )?;
        }
        Ok(())
    }
}

pub const DAY: i64 = 86_400_000;
pub const RAW_KEEP: i64 = 35 * DAY;
const ROLLUP_KEEP: i64 = 400 * DAY;
/// Days are rolled up this long after they end, so results from a site that was cut off
/// for a day still make it in.
pub const ROLLUP_LAG: i64 = 2 * DAY;

/// Start of the first day that isn't rolled up yet: the yearly figure counts rollups
/// before it and raw results from it on.
pub fn rolled_to(conn: &Connection) -> Result<i64> {
    Ok(conn.query_row(
        "SELECT coalesce(max(day) + 86400000, 0) FROM probe_days",
        [],
        |r| r.get(0),
    )?)
}

/// Roll finished days up and drop raw results past their keep time. A day is rolled
/// again when its raw results outnumber its rollup, which is how results from a site
/// that was cut off for a while still make it in. It never shrinks: after a rebuild the
/// core may hold less of an old day than the rollup already counted.
pub fn rollup(conn: &Connection, now: i64) -> Result<()> {
    let edge = now - now.rem_euclid(DAY) - ROLLUP_LAG;
    // never rolled up: roll it, at any age. Rolled before: roll again only if it has gained
    // results, and not the oldest raw day, which may be partly pruned already
    let from = now - now.rem_euclid(DAY) - RAW_KEEP + DAY;
    let stale: Vec<i64> = conn
        .prepare(
            "SELECT r.day FROM
               (SELECT ts - (ts % 86400000) AS day, count(*) AS n FROM probes
                WHERE cut_off = 0 AND ts < ?2 GROUP BY 1) r
             LEFT JOIN (SELECT day, sum(checks) AS n FROM probe_days GROUP BY day) d
               ON d.day = r.day
             WHERE d.n IS NULL OR (r.n > d.n AND r.day >= ?1)",
        )?
        .query_map(params![from, edge], |r| r.get(0))?
        .collect::<Result<_, _>>()?;
    let tx = conn.unchecked_transaction()?;
    for day in stale {
        tx.execute("DELETE FROM probe_days WHERE day = ?1", params![day])?;
        tx.execute(
            "INSERT INTO probe_days (link, vantage, day, checks, oks)
             SELECT link, vantage, ?1, count(*), sum(ok) FROM probes
             WHERE cut_off = 0 AND ts >= ?1 AND ts < ?2 GROUP BY link, vantage",
            params![day, day + DAY],
        )?;
    }
    tx.commit()?;
    conn.execute("DELETE FROM probes WHERE ts < ?1", params![now - RAW_KEEP])?;
    conn.execute(
        "DELETE FROM probe_days WHERE day < ?1",
        params![now - ROLLUP_KEEP],
    )?;
    Ok(())
}
