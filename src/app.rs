//! The running app: its config, its database, and its line to the core.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;

use anyhow::{Context, Result};
use ridgewarden_client::alerts::AlertCfg;
use ridgewarden_client::core::Projection;
use ridgewarden_client::core::Whoami;
use ridgewarden_client::mesh::Mesh;
use ridgewarden_client::{CoreClient, open_db};
use rusqlite::Connection;

use crate::config::{Config, OwnerCfg};
use crate::probe::Prober;
use crate::probes::Probes;

pub const PROJECTIONS: &[&dyn Projection] = &[&Mesh, &Probes];

/// Wrong tokens one address may send per minute to the push and acknowledge endpoints.
const GUESSES_PER_MIN: u32 = 30;

/// A service owner and their own alert history, kept apart from the main one so their
/// alerts open, repeat and get acknowledged on their own.
pub struct Owner {
    pub cfg: OwnerCfg,
    pub alerts: AlertCfg,
    pub db: Mutex<Connection>,
}

pub struct App {
    pub cfg: Config,
    pub core: CoreClient,
    pub db: Mutex<Connection>,
    pub prober: Prober,
    /// for alert delivery, which may go out to the internet over TLS
    pub alert_http: reqwest::Client,
    pub owners: Vec<Owner>,
    /// the core's identity, cached after the first successful lookup
    who: Mutex<Option<Whoami>>,
    /// (minute, wrong tokens from each address in it)
    guesses: Mutex<(i64, HashMap<IpAddr, u32>)>,
}

impl App {
    pub fn new(cfg: Config) -> Result<Self> {
        let token = cfg
            .core
            .token_file
            .exists()
            .then_some(cfg.core.token_file.as_path());
        if token.is_none() && (cfg.probe.enabled || !cfg.heartbeats.is_empty()) {
            tracing::warn!(
                "core token {} not found; probe and heartbeat results can't be logged",
                cfg.core.token_file.display()
            );
        }
        let core = CoreClient::new(&cfg.core.url, token)?;
        let db = open_db(&cfg.db_path(), PROJECTIONS)?;
        db.execute_batch(ridgewarden_client::alerts::SCHEMA)?;
        db.execute_batch(crate::heartbeat::SCHEMA)?;
        db.execute_batch(crate::findings::SCHEMA)?;
        let owners = cfg
            .owners
            .iter()
            .map(|o| {
                let path = cfg.data_dir.join(format!("owner-{}.db", o.slug()));
                let c = Connection::open(&path)
                    .with_context(|| format!("opening {}", path.display()))?;
                c.busy_timeout(Duration::from_secs(5))?;
                c.execute_batch(ridgewarden_client::alerts::SCHEMA)?;
                Ok(Owner {
                    cfg: o.clone(),
                    alerts: o.alert_cfg(&cfg.alerts),
                    db: Mutex::new(c),
                })
            })
            .collect::<Result<_>>()?;
        Ok(Self {
            prober: Prober::new(&cfg.probe)?,
            cfg,
            core,
            db: Mutex::new(db),
            alert_http: reqwest::Client::builder()
                .timeout(Duration::from_secs(20))
                .user_agent(concat!("ridgewarden-health/", env!("CARGO_PKG_VERSION")))
                .build()?,
            owners,
            who: Mutex::new(None),
            guesses: Mutex::new((0, HashMap::new())),
        })
    }

    pub fn db(&self) -> MutexGuard<'_, Connection> {
        self.db.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The core's key and node (the site this app probes from), cached once known.
    pub async fn whoami(&self) -> Result<Whoami> {
        if let Some(w) = self.who.lock().unwrap().clone()
            && !w.node.is_empty()
        {
            return Ok(w);
        }
        let w = self.core.whoami().await?;
        *self.who.lock().unwrap() = Some(w.clone());
        Ok(w)
    }

    pub async fn vantage(&self) -> Result<String> {
        Ok(self.whoami().await?.node)
    }

    pub fn fresh_ms(&self) -> i64 {
        self.cfg.fresh_s as i64 * 1000
    }

    /// Whether `who` sent too many wrong tokens this minute to look at another of theirs.
    pub fn guessing(&self, who: IpAddr, now: i64) -> bool {
        let g = self.guesses.lock().unwrap_or_else(|e| e.into_inner());
        g.0 == now / 60_000 && g.1.get(&who).is_some_and(|n| *n >= GUESSES_PER_MIN)
    }

    pub fn wrong_token(&self, who: IpAddr, now: i64) {
        let mut g = self.guesses.lock().unwrap_or_else(|e| e.into_inner());
        let minute = now / 60_000;
        if g.0 != minute {
            *g = (minute, HashMap::new());
        }
        *g.1.entry(who).or_default() += 1;
    }
}

pub fn short_err(e: &anyhow::Error) -> String {
    if let Some(r) = e.downcast_ref::<reqwest::Error>() {
        if r.is_timeout() {
            return "timed out".into();
        }
        if r.is_connect() {
            return "could not connect".into();
        }
        if let Some(s) = r.status() {
            return format!("HTTP {}", s.as_u16());
        }
    }
    format!("{e:#}").chars().take(160).collect()
}
