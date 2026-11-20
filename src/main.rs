use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};

use ridgewarden_client::aredn::Service;
use ridgewarden_health::app::App;
use ridgewarden_health::config::{Config, EXAMPLE};
use ridgewarden_health::health::{NodeCheck, aredn_text};
use ridgewarden_health::probe::{Mode, Prober, allowed_host, host_port, mode_for};
use ridgewarden_health::{heartbeat, spawn_loops, web};

#[derive(Parser)]
#[command(
    version,
    about = "Service health checker for AREDN meshes (a ridgewarden app)"
)]
struct Cli {
    #[arg(
        long,
        short,
        global = true,
        default_value = "/etc/ridgewarden/health.toml"
    )]
    config: PathBuf,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Write a starter config
    Init,
    /// Follow the core, probe services, serve the services page
    Run,
    /// Probe one link now, from this box, and say what AREDN's own check would make of it
    Check {
        /// the service's link, e.g. http://tst-shack.local.mesh:8080/meshchat
        link: String,
        /// the service's name, which probe overrides match on
        #[arg(long, default_value = "")]
        name: String,
    },
    /// Print each heartbeat's push URL
    Heartbeats,
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "ridgewarden_health=info,ridgewarden_client=info".into()),
        )
        .init();
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Init => {
            if cli.config.exists() {
                bail!(
                    "{} already exists; not overwriting it",
                    cli.config.display()
                );
            }
            if let Some(d) = cli.config.parent() {
                std::fs::create_dir_all(d)?;
            }
            std::fs::write(&cli.config, EXAMPLE)?;
            println!("Wrote {}", cli.config.display());
            Ok(())
        }
        Cmd::Run => {
            let cfg = Config::load(&cli.config)?;
            tokio::runtime::Runtime::new()?.block_on(run(cfg))
        }
        Cmd::Check { link, name } => {
            let cfg = Config::load(&cli.config)?;
            tokio::runtime::Runtime::new()?.block_on(check(cfg, link, name))
        }
        Cmd::Heartbeats => heartbeats(&Config::load(&cli.config)?),
    }
}

async fn run(cfg: Config) -> Result<()> {
    let listen = cfg.listen;
    let app = Arc::new(App::new(cfg)?);
    tracing::info!(
        "ridgewarden-health {} following {}, page on http://{listen}",
        env!("CARGO_PKG_VERSION"),
        app.core.base()
    );
    spawn_loops(app.clone());
    let listener = tokio::net::TcpListener::bind(listen)
        .await
        .with_context(|| format!("binding {listen}"))?;
    // the caller's address, for limiting wrong push and acknowledge tokens per address
    let service = web::router(app).into_make_service_with_connect_info::<std::net::SocketAddr>();
    axum::serve(listener, service)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}

async fn check(cfg: Config, link: String, name: String) -> Result<()> {
    let Some((_, host, _)) = host_port(&link) else {
        bail!("{link:?} doesn't look like a link (scheme://host:port/path)");
    };
    let svc = Service {
        host: host.clone(),
        name,
        link,
        protocol: "tcp".into(),
    };
    let mode = mode_for(&svc, &cfg.probe);
    if mode == Mode::Skip {
        if !allowed_host(&host, &cfg.probe.allow_hosts) {
            bail!(
                "{host} isn't a mesh host (a node name, *.local.mesh, 10.x or 44.x); add it to \
                 probe.allow_hosts to check it"
            );
        }
        bail!("this link isn't probed: it has no port to connect to, or a probe.override skips it");
    }
    let r = Prober::new(&cfg.probe)?.probe(&svc, mode).await;
    println!("check:  {}", r.check);
    println!(
        "result: {}, {}{}",
        if r.ok { "working" } else { "not working" },
        r.detail,
        r.ms.map(|m| format!(", {m:.0} ms")).unwrap_or_default()
    );
    match r.aredn {
        Some(a) => {
            let c = NodeCheck {
                pass: a.pass,
                code: a.code.to_string(),
                status: a.status,
            };
            println!(
                "AREDN:  {}. {}",
                if a.pass {
                    "the node's check would keep it"
                } else {
                    "the node's check would drop it"
                },
                aredn_text(&c)
            );
        }
        None => println!("AREDN:  can't tell what the node's check would make of it from here"),
    }
    Ok(())
}

fn heartbeats(cfg: &Config) -> Result<()> {
    if cfg.heartbeats.is_empty() {
        println!("No [[heartbeat]] entries in the config.");
        return Ok(());
    }
    // the secret lives in the app's database, which may not exist before the first run
    let conn = ridgewarden_client::open_db(&cfg.db_path(), ridgewarden_health::app::PROJECTIONS)?;
    conn.execute_batch(heartbeat::SCHEMA)?;
    let base = match &cfg.alerts.public_url {
        Some(u) => u.trim_end_matches('/').to_string(),
        None => {
            println!(
                "alerts.public_url isn't set, so put this box's mesh name in place of <this-box>.\n"
            );
            format!("http://<this-box>:{}", cfg.listen.port())
        }
    };
    for h in &cfg.heartbeats {
        println!(
            "{} (every {} s, {} s grace)\n  curl -fsS -m 10 -X POST {base}/push/{}\n",
            h.name.trim(),
            h.every_s,
            h.grace_s,
            heartbeat::token(&conn, &h.name)?
        );
    }
    println!(
        "Add ?status=down&msg=... to report a problem. Keep these URLs private: anyone with one \
         can check in for that heartbeat."
    );
    Ok(())
}
