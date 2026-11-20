//! ridgewarden-health: what's really up on an AREDN mesh, why, and since when.
//!
//! Runs next to a ridgewarden core. It follows the core's event feed for the mesh's service
//! lists, probes every advertised service from this site, and logs the results through
//! the core, so every site's results end up everywhere. A service that answers from one
//! site and not another is a link problem, not a service problem, and the page says so.

pub mod app;
pub mod config;
pub mod findings;
pub mod health;
pub mod heartbeat;
pub mod probe;
pub mod probes;
pub mod web;

use std::sync::Arc;

use ridgewarden_client::alerts::Alert;
use std::time::Duration;

/// `base` seconds, give or take `pct` percent.
pub fn jittered(base: u64, pct: u64) -> Duration {
    let spread = base * 1000 * pct / 100;
    let r = getrandom::u64().unwrap_or(0) % (2 * spread + 1);
    Duration::from_millis(base * 1000 - spread + r)
}

async fn alert_round(app: &app::App) -> anyhow::Result<usize> {
    let now = ridgewarden_client::util::now_ms();
    let me = app.vantage().await.ok();
    let (active, unjudged) = {
        let db = app.db();
        let views = health::classify(&db, now, &health::Rules::from_cfg(&app.cfg))?;
        findings::note(&db, &views, now)?;
        let cut = health::cut_off_sites(&db, now, app.fresh_ms())?;
        let here = me.as_deref().filter(|m| cut.iter().any(|c| c == m));
        (
            health::alerts_for(&views, here, now),
            health::unjudged(&views),
        )
    };
    let keep = |k: &str| unjudged.iter().any(|p| k.starts_with(p.as_str()));
    let mut sent = ridgewarden_client::alerts::run(
        &app.alert_http,
        &app.db,
        &app.cfg.alerts,
        "ridgewarden-health",
        active.clone(),
        &keep,
    )
    .await?;
    for o in &app.owners {
        let theirs = owned(&o.cfg, &active);
        let r = ridgewarden_client::alerts::run(
            &app.alert_http,
            &o.db,
            &o.alerts,
            "ridgewarden-health",
            theirs,
            &keep,
        )
        .await;
        match r {
            Ok(n) => sent += n,
            Err(e) => tracing::warn!("alerts for owner {:?}: {e:#}", o.cfg.name),
        }
    }
    Ok(sent)
}

/// The alerts an owner looks after: ones whose key (which holds the link) or title (which
/// holds the service and host names) matches what they listed.
pub fn owned(owner: &config::OwnerCfg, active: &[Alert]) -> Vec<Alert> {
    active
        .iter()
        .filter(|a| owner.covers(&format!("{} {}", a.key, a.title)))
        .cloned()
        .collect()
}

/// Follow the core's feed, probe, judge heartbeats, roll up history and send alerts on
/// schedule, forever.
pub fn spawn_loops(app: Arc<app::App>) {
    let a = app.clone();
    tokio::spawn(async move {
        loop {
            if let Err(e) = ridgewarden_client::follow(&a.core, &a.db, app::PROJECTIONS).await {
                tracing::warn!("following the core: {e:#}");
            }
            tokio::time::sleep(Duration::from_secs(10)).await;
        }
    });
    let a = app.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(120)).await;
        loop {
            let r = probes::rollup(&a.db(), ridgewarden_client::util::now_ms());
            if let Err(e) = r {
                tracing::warn!("rolling up probe history: {e:#}");
            }
            tokio::time::sleep(Duration::from_secs(3600)).await;
        }
    });
    let a = app.clone();
    tokio::spawn(async move {
        // give the feed and a probe round time to land first
        tokio::time::sleep(Duration::from_secs(90)).await;
        loop {
            match alert_round(&a).await {
                Ok(0) => {}
                Ok(n) => tracing::info!("{n} alert notices sent"),
                Err(e) => tracing::warn!("alerts: {e:#}"),
            }
            tokio::time::sleep(Duration::from_secs(60)).await;
        }
    });
    if !app.cfg.heartbeats.is_empty() {
        heartbeat::spawn(app.clone());
    }
    if app.cfg.probe.enabled {
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(15)).await;
            loop {
                match probe::round(app.clone()).await {
                    Ok(Some(ev)) => tracing::debug!("probe round logged as {}", &ev.id[..12]),
                    Ok(None) => tracing::debug!("nothing to probe yet"),
                    Err(e) => tracing::warn!("probe round failed: {e:#}"),
                }
                tokio::time::sleep(jittered(app.cfg.probe.interval_s, 20)).await;
            }
        });
    }
}
