//! What this app has caught AREDN's own list getting wrong: services listed but never
//! seen working (stale), and working services the node dropped from the list. The spec
//! counts finding some of each in the first week as success, so the page counts them.

use anyhow::Result;
use rusqlite::{Connection, params};

use crate::health::{Class, ServiceView};

pub const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS findings (
    link     TEXT NOT NULL,
    class    TEXT NOT NULL,
    name     TEXT NOT NULL,
    host     TEXT NOT NULL,
    first_ms INTEGER NOT NULL,
    last_ms  INTEGER NOT NULL,
    PRIMARY KEY (link, class)
);
CREATE TABLE IF NOT EXISTS started (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    ms INTEGER NOT NULL
);";

fn tag(c: Class) -> Option<&'static str> {
    match c {
        Class::Stale => Some("stale"),
        Class::UnpublishedAlive => Some("unpublished"),
        _ => None,
    }
}

/// Note the stale and wrongly unpublished services in this classification.
pub fn note(conn: &Connection, views: &[ServiceView], now: i64) -> Result<()> {
    conn.execute(
        "INSERT OR IGNORE INTO started (id, ms) VALUES (1, ?1)",
        params![now],
    )?;
    for v in views {
        let Some(class) = tag(v.class) else { continue };
        if v.svc.link.starts_with("push://") {
            continue;
        }
        conn.execute(
            "INSERT INTO findings (link, class, name, host, first_ms, last_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?5)
             ON CONFLICT(link, class) DO UPDATE SET name = excluded.name, host = excluded.host,
                 last_ms = excluded.last_ms",
            params![v.svc.link, class, v.svc.name, v.svc.host, now],
        )?;
    }
    conn.execute(
        "DELETE FROM findings WHERE last_ms < ?1",
        params![now - 400 * 86_400_000],
    )?;
    Ok(())
}

#[derive(Clone, Debug)]
pub struct Finding {
    pub link: String,
    pub name: String,
    pub host: String,
    pub first_ms: i64,
    pub last_ms: i64,
}

pub struct Summary {
    /// when this app first classified anything
    pub since: i64,
    pub stale: Vec<Finding>,
    pub unpublished: Vec<Finding>,
}

impl Summary {
    /// How many of each were first found within a week of starting.
    pub fn first_week(&self) -> (usize, usize) {
        let early = |f: &&Finding| f.first_ms < self.since + 7 * 86_400_000;
        (
            self.stale.iter().filter(early).count(),
            self.unpublished.iter().filter(early).count(),
        )
    }
}

pub fn summary(conn: &Connection) -> Result<Option<Summary>> {
    let since: Option<i64> = conn
        .query_row("SELECT ms FROM started WHERE id = 1", [], |r| r.get(0))
        .ok();
    let Some(since) = since else { return Ok(None) };
    let list = |class: &str| -> Result<Vec<Finding>> {
        let mut st = conn.prepare(
            "SELECT link, name, host, first_ms, last_ms FROM findings WHERE class = ?1
             ORDER BY first_ms",
        )?;
        let v = st
            .query_map(params![class], |r| {
                Ok(Finding {
                    link: r.get(0)?,
                    name: r.get(1)?,
                    host: r.get(2)?,
                    first_ms: r.get(3)?,
                    last_ms: r.get(4)?,
                })
            })?
            .collect::<Result<_, _>>()?;
        Ok(v)
    };
    Ok(Some(Summary {
        since,
        stale: list("stale")?,
        unpublished: list("unpublished")?,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ridgewarden_client::aredn::Service;

    fn view(link: &str, class: Class) -> ServiceView {
        ServiceView {
            svc: Service {
                host: "h".into(),
                name: "n".into(),
                link: link.into(),
                protocol: "tcp".into(),
            },
            class,
            vantages: vec![],
            since: None,
            since_open: false,
            reason: String::new(),
        }
    }

    #[test]
    fn counts_each_finding_once_and_the_first_week_apart() {
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch(SCHEMA).unwrap();
        let day = 86_400_000;
        let t0 = 1_800_000_000_000;
        let views = [
            view("http://a/", Class::Stale),
            view("http://b/", Class::UnpublishedAlive),
            view("http://c/", Class::Up),
            view("push://x/backup", Class::Stale),
        ];
        note(&c, &views, t0).unwrap();
        note(&c, &views, t0 + 60_000).unwrap();
        note(&c, &[view("http://d/", Class::Stale)], t0 + 9 * day).unwrap();
        let s = summary(&c).unwrap().unwrap();
        assert_eq!(s.since, t0);
        assert_eq!(
            s.stale.len(),
            2,
            "heartbeats aren't adverts, so they don't count"
        );
        assert_eq!(s.unpublished.len(), 1);
        assert_eq!(s.stale[0].last_ms, t0 + 60_000);
        assert_eq!(s.first_week(), (1, 1));
    }
}
