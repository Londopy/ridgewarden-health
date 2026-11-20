//! Service probing: every site probes the services the mesh advertises, from where it
//! sits, and logs the results through its core as one signed `svc.probe` event per round.
//! Each result also says whether the AREDN node's own hourly check would pass, worked out
//! the way the node does it.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Result, bail};
use rusqlite::{Connection, params};
use serde::Serialize;
use serde_json::{Value, json};
use tokio::io::AsyncReadExt;
use tokio::net::{TcpSocket, TcpStream, UdpSocket};
use tokio::sync::Semaphore;

use ridgewarden_client::Event;
use ridgewarden_client::aredn::Service;
use ridgewarden_client::util::{human_duration, norm_node, now_ms};

use crate::app::{App, short_err};
use crate::config::{ProbeCfg, ProbeOverride};

/// Services advertised at any point in this window keep being probed, which is how
/// "unpublished but still alive" gets noticed after AREDN's hourly check drops one.
pub const REMEMBER_MS: i64 = 7 * 86_400_000;

const CONCURRENCY: usize = 8;

/// Most of a page we'll read looking for a keyword.
const KEYWORD_BYTES: usize = 256 * 1024;

/// How long a Winlink server gets to send its login prompt once connected.
const PROMPT_WAIT: Duration = Duration::from_secs(5);

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Mode {
    Http,
    Tcp(String, u16),
    /// connect and wait for the "Callsign :" prompt, never sending anything
    Winlink(String, u16),
    /// ask MeshChat's API at this base URL
    MeshChat(String),
    Skip,
}

impl Mode {
    pub fn check(&self) -> &'static str {
        match self {
            Mode::Http => "http",
            Mode::Tcp(..) => "tcp",
            Mode::Winlink(..) => "winlink",
            Mode::MeshChat(_) => "meshchat",
            Mode::Skip => "skip",
        }
    }
}

/// What the node's own check would make of a service, seen from here. The codes are a
/// fixed set so pages explain them in their own words, whichever site sent them.
#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct Aredn {
    pub pass: bool,
    pub code: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
}

/// Every code an `Aredn` can carry, and whether the node keeps the service for it.
pub const AREDN_CODES: &[(&str, bool)] = &[
    ("http-ok", true),
    ("https-redirect", true),
    ("http-status", false),
    ("http-slow", false),
    ("http-unreachable", false),
    ("not-http", false),
    ("tcp", true),
    ("udp", true),
    ("refused", false),
];

fn aredn(code: &'static str, status: Option<u16>) -> Aredn {
    let pass = AREDN_CODES.iter().any(|(c, p)| *c == code && *p);
    Aredn { pass, code, status }
}

#[derive(Serialize, Clone, Debug)]
pub struct ProbeResult {
    pub name: String,
    pub host: String,
    pub link: String,
    pub ok: bool,
    pub ms: Option<f64>,
    /// HTTP status, for working out whether AREDN's own check would keep the service listed
    pub status: Option<u16>,
    pub detail: String,
    /// which kind of check this was: http, tcp, winlink, meshchat or push
    pub check: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aredn: Option<Aredn>,
}

/// AREDN lists a service with no link as proto://host:0/, and keeps it without checking:
/// there is nothing to connect to, so it is left out here too.
pub fn linkless(link: &str) -> bool {
    host_port(link).is_some_and(|h| h.2 == Some(0))
}

fn services_in(conn: &Connection, sql: &str, args: impl rusqlite::Params) -> Result<Vec<Service>> {
    let mut st = conn.prepare(sql)?;
    let lists = st.query_map(args, |r| r.get::<_, String>(0))?;
    let mut by_link: BTreeMap<String, Service> = BTreeMap::new();
    for l in lists {
        for s in serde_json::from_str::<Vec<Service>>(&l?).unwrap_or_default() {
            if !s.link.is_empty() && !linkless(&s.link) {
                by_link.entry(s.link.clone()).or_insert(s);
            }
        }
    }
    Ok(by_link.into_values().collect())
}

/// Every service any node advertised in the last week, one entry per link.
pub fn targets(conn: &Connection, now: i64) -> Result<Vec<Service>> {
    services_in(
        conn,
        "SELECT DISTINCT a.json FROM polls p JOIN lists a ON a.hash = p.ads_hash WHERE p.ts > ?1",
        params![now - REMEMBER_MS],
    )
}

/// What this site probes: the services in the mesh-wide list *its own node* reported in
/// the last week. Other sites' copies of the list are only used for reading results, never
/// to choose what we connect to; the list itself still comes from the mesh, so every
/// host in it goes through `allowed_host` and `resolve` first.
pub fn own_targets(conn: &Connection, now: i64, core_key: &str) -> Result<Vec<Service>> {
    services_in(
        conn,
        "SELECT DISTINCT a.json FROM polls p JOIN lists a ON a.hash = p.ads_hash
         WHERE p.ts > ?1 AND p.author_key = ?2 AND coalesce(p.via, 'lan') = 'lan'",
        params![now - REMEMBER_MS, core_key],
    )
}

/// Sites that sent probe results lately: the ones sharing the probing out.
pub fn probing_sites(conn: &Connection, now: i64, fresh_ms: i64) -> Result<BTreeSet<String>> {
    let v = conn
        .prepare(
            "SELECT DISTINCT vantage FROM probes
             WHERE ts >= ?1 AND cut_off = 0 AND link NOT LIKE 'push://%'",
        )?
        .query_map(params![now - fresh_ms], |r| r.get(0))?
        .collect::<Result<_, _>>()?;
    Ok(v)
}

fn rank(link: &str, site: &str) -> [u8; 32] {
    *blake3::hash(format!("{link}\n{site}").as_bytes()).as_bytes()
}

/// Whether this site is one of the `k` that probe `link` (0: every site is). Every site
/// ranks the probing sites the same way for each link (rendezvous hashing), so they agree
/// on who probes what without talking about it, and when one goes quiet the next in line
/// takes over.
pub fn assigned(link: &str, me: &str, sites: &BTreeSet<String>, k: usize) -> bool {
    let mine = rank(link, me);
    k == 0
        || sites
            .iter()
            .filter(|s| s.as_str() != me && rank(link, s) > mine)
            .count()
            < k
}

/// Hosts we'll open connections to: mesh names, the mesh's address ranges, and anything
/// listed in `probe.allow_hosts`. Never loopback or the wider internet by default.
pub fn allowed_host(host: &str, extra: &[String]) -> bool {
    let h = host.trim_matches(['[', ']']).to_ascii_lowercase();
    if extra.iter().any(|e| e.eq_ignore_ascii_case(&h)) {
        return true;
    }
    // a bare node name resolves through the node's DNS, unless the OS reads it as an
    // address (2130706433, 0x7f000001) or maps it locally
    let numeric = h.bytes().all(|b| b.is_ascii_digit()) || h.starts_with("0x");
    if h.ends_with(".local.mesh")
        || (h != "localhost" && !numeric && ridgewarden_client::util::valid_node(&h))
    {
        return true;
    }
    h.parse().is_ok_and(mesh_ip)
}

/// AREDN hands out 10.0.0.0/8; 44.0.0.0/8 is AMPRNet.
fn mesh_ip(ip: IpAddr) -> bool {
    matches!(ip, IpAddr::V4(v) if matches!(v.octets()[0], 10 | 44))
}

/// The addresses we'll connect to for `host`: every one for a host in `probe.allow_hosts`,
/// otherwise only mesh addresses, so a name the OS answers itself (this box's own
/// hostname, ip6-localhost) can't aim a probe back at this box.
async fn resolve(host: &str, port: u16, allow: &[String]) -> Result<Vec<SocketAddr>> {
    let bare = host.trim_matches(['[', ']']);
    let trusted = allow.iter().any(|a| a.eq_ignore_ascii_case(bare));
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((bare, port))
        .await?
        .filter(|a| trusted || mesh_ip(a.ip()))
        .collect();
    if addrs.is_empty() {
        bail!("{host} doesn't resolve to a mesh address");
    }
    Ok(addrs)
}

/// Name lookups for the HTTP clients, held to the same rule as everything else.
struct MeshDns(Vec<String>);

impl reqwest::dns::Resolve for MeshDns {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let allow = self.0.clone();
        let host = name.as_str().to_string();
        Box::pin(async move {
            let addrs = resolve(&host, 0, &allow).await?;
            Ok(Box::new(addrs.into_iter()) as reqwest::dns::Addrs)
        })
    }
}

/// Split "scheme://host:port/path" without pulling in a URL crate.
pub fn host_port(link: &str) -> Option<(String, String, Option<u16>)> {
    let (scheme, rest) = link.split_once("://")?;
    let authority = rest.split(['/', '\\', '?', '#']).next()?;
    let authority = authority.rsplit('@').next()?;
    if authority.is_empty() {
        return None;
    }
    // [v6]:port is not something AREDN hands out; keep it simple
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse().ok()),
        None => (authority.to_string(), None),
    };
    Some((scheme.to_ascii_lowercase(), host, port))
}

fn path_of(link: &str) -> &str {
    let rest = link.split_once("://").map_or("", |(_, r)| r);
    let path = rest.find('/').map_or("", |i| &rest[i..]);
    path.split(['?', '#']).next().unwrap_or("")
}

fn scheme(link: &str) -> String {
    link.split_once("://")
        .map_or(String::new(), |(s, _)| s.to_ascii_lowercase())
}

pub fn override_for<'a>(s: &Service, cfg: &'a ProbeCfg) -> Option<&'a ProbeOverride> {
    let name = s.name.to_ascii_lowercase();
    cfg.overrides
        .iter()
        .find(|o| name.contains(&o.name_contains.to_ascii_lowercase()))
}

/// RMS Relay and Winlink's own telnet listen on 8772, Pat's telnet on 8774.
fn winlink_port(p: u16) -> bool {
    p == 8772 || p == 8774
}

pub fn mode_for(s: &Service, cfg: &ProbeCfg) -> Mode {
    let forced = override_for(s, cfg).and_then(|o| o.mode.as_deref());
    let Some((scheme, host, port)) = host_port(&s.link) else {
        return Mode::Skip;
    };
    if !allowed_host(&host, &cfg.allow_hosts) || port == Some(0) {
        return Mode::Skip;
    }
    let web = scheme == "http" || scheme == "https";
    let default_port = match scheme.as_str() {
        "http" => Some(80),
        "https" => Some(443),
        _ => None,
    };
    let port_or_default = port.or(default_port);
    let base = || match port {
        Some(p) => format!("{scheme}://{host}:{p}"),
        None => format!("{scheme}://{host}"),
    };
    let meshchat = web
        && path_of(&s.link)
            .trim_end_matches('/')
            .ends_with("/meshchat");
    match forced {
        Some("skip") => Mode::Skip,
        Some("tcp") => port_or_default.map_or(Mode::Skip, |p| Mode::Tcp(host, p)),
        Some("winlink") => port_or_default.map_or(Mode::Skip, |p| Mode::Winlink(host, p)),
        Some("meshchat") if web => Mode::MeshChat(base()),
        Some("meshchat") => Mode::Skip,
        Some("http") => Mode::Http,
        // an HTTP request to a Winlink port would be read as a callsign: a login attempt
        _ if port.is_some_and(winlink_port) => Mode::Winlink(host, port.unwrap_or_default()),
        _ if meshchat => Mode::MeshChat(base()),
        _ if web => Mode::Http,
        _ => port.map_or(Mode::Skip, |p| Mode::Tcp(host, p)),
    }
}

/// Whether an HTTP answer counts as working: by default any status below 500 (a 401 or
/// 404 still proves a server is there); per-service checks can ask for more.
fn http_verdict(status: u16, body: Option<&str>, check: Option<&ProbeOverride>) -> (bool, String) {
    let detail = format!("HTTP {status}");
    let wanted = check
        .map(|c| c.expect_status.as_slice())
        .unwrap_or_default();
    if !wanted.is_empty() && !wanted.contains(&status) {
        return (false, format!("{detail}, expected {wanted:?}"));
    }
    if wanted.is_empty() && status >= 500 {
        return (false, detail);
    }
    match (check.and_then(|c| c.keyword.as_deref()), body) {
        (Some(k), Some(b)) if !b.contains(k) => (false, format!("{detail}, page lacks {k:?}")),
        _ => (true, detail),
    }
}

async fn read_some(mut r: reqwest::Response) -> String {
    let mut buf = Vec::new();
    while buf.len() < KEYWORD_BYTES {
        match r.chunk().await {
            Ok(Some(c)) => buf.extend_from_slice(&c),
            _ => break,
        }
    }
    buf.truncate(KEYWORD_BYTES);
    String::from_utf8_lossy(&buf).into_owned()
}

/// Printable text from whatever a server sent, short enough for a detail line.
fn snippet(b: &[u8]) -> String {
    let text = String::from_utf8_lossy(b).replace(|c: char| c.is_control(), " ");
    text.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .take(40)
        .collect()
}

fn ms_since(t: Instant) -> f64 {
    (t.elapsed().as_secs_f64() * 10_000.0).round() / 10.0
}

async fn tcp_connect(host: &str, port: u16, cfg: &ProbeCfg) -> Result<TcpStream> {
    let src = cfg.source_ip;
    let mut last = anyhow::anyhow!("no address for {host}");
    for addr in resolve(host, port, &cfg.allow_hosts).await? {
        let sock = if addr.is_ipv4() {
            TcpSocket::new_v4()?
        } else {
            TcpSocket::new_v6()?
        };
        if let Some(ip) = src
            && ip.is_ipv4() == addr.is_ipv4()
        {
            sock.bind(SocketAddr::new(ip, 0))?;
        }
        match sock.connect(addr).await {
            Ok(s) => return Ok(s),
            Err(e) => last = e.into(),
        }
    }
    Err(last)
}

/// AREDN's fallback for ports that took no TCP connection: send an empty datagram and see
/// whether the host refuses it. True when it did.
async fn udp_refused(host: &str, port: u16, cfg: &ProbeCfg) -> Result<bool> {
    use std::io::ErrorKind::{ConnectionRefused, ConnectionReset};
    let addr = resolve(host, port, &cfg.allow_hosts).await?[0];
    let local = match cfg.source_ip {
        Some(ip) if ip.is_ipv4() == addr.is_ipv4() => SocketAddr::new(ip, 0),
        _ if addr.is_ipv4() => "0.0.0.0:0".parse()?,
        _ => "[::]:0".parse()?,
    };
    let sock = UdpSocket::bind(local).await?;
    sock.connect(addr).await?;
    let refused = |e: &std::io::Error| matches!(e.kind(), ConnectionRefused | ConnectionReset);
    if let Err(e) = sock.send(&[]).await {
        return if refused(&e) { Ok(true) } else { Err(e.into()) };
    }
    // the node waits a moment on its own LAN; across the mesh a refusal takes longer
    let mut buf = [0u8; 64];
    match tokio::time::timeout(Duration::from_secs(1), sock.recv(&mut buf)).await {
        Ok(Err(e)) if refused(&e) => Ok(true),
        Ok(Err(e)) => Err(e.into()),
        _ => Ok(false),
    }
}

/// How a connection-style check went.
struct Connected {
    ok: bool,
    detail: String,
    /// time to connect, when it connected
    connect_ms: Option<f64>,
}

type Outcome = (bool, Option<f64>, Option<u16>, String, Option<Aredn>);

/// Makes the probes. Two HTTP clients: one for our own verdict (no redirects followed, so
/// a redirect can't aim our probes somewhere else), and one that behaves like the node's
/// curl (2 s to connect, 10 s in all, redirects followed while they stay on the mesh).
pub struct Prober {
    pub cfg: ProbeCfg,
    http: reqwest::Client,
    like_node: reqwest::Client,
}

impl Prober {
    pub fn new(cfg: &ProbeCfg) -> Result<Self> {
        let agent = concat!("ridgewarden-health/", env!("CARGO_PKG_VERSION"));
        let allow = cfg.allow_hosts.clone();
        let follow = reqwest::redirect::Policy::custom(move |a| {
            let on_mesh = a.url().host_str().is_some_and(|h| allowed_host(h, &allow));
            if a.previous().len() >= 10 || a.url().scheme() != "http" || !on_mesh {
                a.stop()
            } else {
                a.follow()
            }
        });
        let dns = Arc::new(MeshDns(cfg.allow_hosts.clone()));
        // mesh https services mostly have self-signed certificates; a probe asks whether
        // the service answers, not who it is
        let mut pb = reqwest::Client::builder()
            .no_proxy()
            .dns_resolver(dns.clone())
            .danger_accept_invalid_certs(true)
            .timeout(Duration::from_secs(cfg.timeout_s))
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(agent);
        let mut nb = reqwest::Client::builder()
            .no_proxy()
            .dns_resolver(dns)
            .connect_timeout(Duration::from_secs(2))
            .timeout(Duration::from_secs(10))
            .redirect(follow)
            .user_agent(agent);
        if let Some(ip) = cfg.source_ip {
            pb = pb.local_address(ip);
            nb = nb.local_address(ip);
        }
        Ok(Self {
            cfg: cfg.clone(),
            http: pb.build()?,
            like_node: nb.build()?,
        })
    }

    pub async fn probe(&self, s: &Service, mode: Mode) -> ProbeResult {
        let check = mode.check();
        let (ok, ms, status, detail, aredn) = match mode {
            Mode::Http => self.http_check(s).await,
            Mode::MeshChat(base) => self.meshchat(s, &base).await,
            Mode::Tcp(host, port) => {
                let c = self.connect(&host, port, self.cfg.timeout_s).await;
                let a = self.node_view(s, &host, port, &c).await;
                (c.ok, c.connect_ms, None, c.detail, a)
            }
            Mode::Winlink(host, port) => {
                let c = self.winlink(&host, port).await;
                // the node would send an HTTP request, which a Winlink port can't answer
                let a = match scheme(&s.link).as_str() {
                    "http" if c.ok => Some(aredn("not-http", None)),
                    "http" => None,
                    _ => self.node_view(s, &host, port, &c).await,
                };
                (c.ok, c.connect_ms, None, c.detail, a)
            }
            Mode::Skip => unreachable!("skipped before probing"),
        };
        ProbeResult {
            name: s.name.clone(),
            host: s.host.clone(),
            link: s.link.clone(),
            ok,
            ms: if ok { ms } else { None },
            status,
            detail,
            check,
            aredn,
        }
    }

    async fn http_check(&self, s: &Service) -> Outcome {
        let start = Instant::now();
        let check = override_for(s, &self.cfg);
        let r = match self.http.get(&s.link).send().await {
            Ok(r) => r,
            Err(e) => {
                let a = self.node_any(s).await;
                return (false, None, None, short_err(&e.into()), a);
            }
        };
        let ms = ms_since(start);
        let code = r.status().as_u16();
        let redirect = r.status().is_redirection();
        let body = match check.and_then(|c| c.keyword.as_ref()) {
            Some(_) => Some(read_some(r).await),
            None => None,
        };
        let (ok, detail) = http_verdict(code, body.as_deref(), check);
        let a = match scheme(&s.link).as_str() {
            // the node follows redirects; we only ask again when there is one to follow
            "http" if redirect => self.node_http(&s.link).await,
            "http" => Some(node_status(code, ms)),
            // https links get the node's TCP check, which a quick answer has already passed
            _ if ms <= 2000.0 => Some(aredn("tcp", None)),
            _ => self.node_any(s).await,
        };
        (ok, Some(ms), Some(code), detail, a)
    }

    /// MeshChat's `config` action answers with its version, node and zone; `sync_status`
    /// says when it last pulled messages from each other MeshChat node.
    async fn meshchat(&self, s: &Service, base: &str) -> Outcome {
        let start = Instant::now();
        let api = format!("{base}/cgi-bin/meshchat");
        let r = match self.http.get(format!("{api}?action=config")).send().await {
            Ok(r) => r,
            Err(e) => {
                let a = self.node_http(&s.link).await;
                return (false, None, None, short_err(&e.into()), a);
            }
        };
        let ms = ms_since(start);
        let code = r.status().as_u16();
        let cfg: Option<Value> = serde_json::from_str(&read_some(r).await).ok();
        let field = |k: &str| {
            cfg.as_ref()
                .and_then(|c| c.get(k))
                .and_then(Value::as_str)
                .map(|v| snippet(v.as_bytes()))
        };
        let (ok, detail) = match field("version") {
            Some(v) if code == 200 => {
                let mut d = format!("MeshChat {v}");
                if let Some(z) = field("zone") {
                    d.push_str(&format!(", zone {z}"));
                }
                if let Some(sync) = self.meshchat_sync(&api).await {
                    d.push_str(&format!("; {sync}"));
                }
                (true, d)
            }
            _ => (
                false,
                format!("HTTP {code}, but no MeshChat API at /cgi-bin/meshchat"),
            ),
        };
        let a = self.node_http(&s.link).await;
        (ok, Some(ms), Some(code), detail, a)
    }

    async fn meshchat_sync(&self, api: &str) -> Option<String> {
        let r = self
            .http
            .get(format!("{api}?action=sync_status"))
            .send()
            .await
            .ok()?;
        let v: Value = serde_json::from_str(&read_some(r).await).ok()?;
        let newest = v
            .as_array()?
            .iter()
            .filter_map(|e| e.get("epoch").and_then(Value::as_i64))
            .max();
        Some(match newest {
            Some(t) => format!(
                "last synced with another node {} ago",
                human_duration(now_ms().saturating_sub(t.saturating_mul(1000)))
            ),
            None => "not synced with any other MeshChat node".into(),
        })
    }

    async fn connect_stream(
        &self,
        host: &str,
        port: u16,
        limit_s: u64,
    ) -> (Result<TcpStream, String>, f64) {
        let start = Instant::now();
        let r = tokio::time::timeout(
            Duration::from_secs(limit_s),
            tcp_connect(host, port, &self.cfg),
        )
        .await;
        let r = match r {
            Ok(Ok(s)) => Ok(s),
            Ok(Err(e)) => Err(format!("TCP {port}: {e}")),
            Err(_) => Err("timed out".into()),
        };
        (r, ms_since(start))
    }

    async fn connect(&self, host: &str, port: u16, limit_s: u64) -> Connected {
        let (r, ms) = self.connect_stream(host, port, limit_s).await;
        match r {
            Ok(_) => Connected {
                ok: true,
                detail: format!("TCP {port} open"),
                connect_ms: Some(ms),
            },
            Err(detail) => Connected {
                ok: false,
                detail,
                connect_ms: None,
            },
        }
    }

    /// Connect and wait for the login prompt that RMS Relay, Winlink's own telnet and Pat
    /// all send first ("Callsign :"). Nothing is ever sent, so this never logs in.
    async fn winlink(&self, host: &str, port: u16) -> Connected {
        let (r, connect_ms) = self.connect_stream(host, port, self.cfg.timeout_s).await;
        let mut stream = match r {
            Ok(s) => s,
            Err(detail) => {
                return Connected {
                    ok: false,
                    detail,
                    connect_ms: None,
                };
            }
        };
        let mut got = Vec::new();
        let read = tokio::time::timeout(PROMPT_WAIT, async {
            let mut buf = [0u8; 256];
            loop {
                match stream.read(&mut buf).await {
                    Ok(0) | Err(_) => return false,
                    Ok(n) => got.extend_from_slice(&buf[..n]),
                }
                let text = String::from_utf8_lossy(&got).to_ascii_lowercase();
                if text.contains("callsign") {
                    return true;
                }
                if got.len() > 512 {
                    return false;
                }
            }
        })
        .await;
        let (ok, detail) = match read {
            Ok(true) => (true, "Winlink login prompt".to_string()),
            _ if !got.is_empty() => (
                false,
                format!(
                    "connected, but it sent \"{}\" instead of a Winlink login prompt",
                    snippet(&got)
                ),
            ),
            Ok(false) => (
                false,
                "connected, but it closed without a Winlink login prompt".into(),
            ),
            Err(_) => (
                false,
                format!(
                    "connected, but no Winlink login prompt within {} s",
                    PROMPT_WAIT.as_secs()
                ),
            ),
        };
        Connected {
            ok,
            detail,
            connect_ms: Some(connect_ms),
        }
    }

    /// The node's check for a non-HTTP link: a TCP connection within 2 s, else a UDP send
    /// that isn't refused. Our own connection attempt settles the TCP half.
    async fn node_view(&self, s: &Service, host: &str, port: u16, c: &Connected) -> Option<Aredn> {
        match scheme(&s.link).as_str() {
            // the request a Winlink server would read as a callsign is never sent
            "http" if winlink_port(port) => return None,
            "http" => return self.node_http(&s.link).await,
            _ => {}
        }
        if c.connect_ms.is_some_and(|ms| ms <= 2000.0) {
            return Some(aredn("tcp", None));
        }
        match udp_refused(host, port, &self.cfg).await {
            Ok(true) => Some(aredn("refused", None)),
            Ok(false) => Some(aredn("udp", None)),
            Err(_) => None,
        }
    }

    /// The node's check when our own probe said nothing about it: it failed, or it was an
    /// https link that answered slowly.
    async fn node_any(&self, s: &Service) -> Option<Aredn> {
        if scheme(&s.link) == "http" {
            return self.node_http(&s.link).await;
        }
        let (_, host, port) = host_port(&s.link)?;
        let port = port.unwrap_or(443);
        let c = self.connect(&host, port, 2).await;
        self.node_view(s, &host, port, &c).await
    }

    /// The node's HTTP check: like its `curl --location --connect-timeout 2 --max-time 10`.
    async fn node_http(&self, link: &str) -> Option<Aredn> {
        let start = Instant::now();
        match self.like_node.get(link).send().await {
            Ok(r) => {
                let code = r.status().as_u16();
                let to_https = r
                    .headers()
                    .get(reqwest::header::LOCATION)
                    .and_then(|l| l.to_str().ok())
                    .is_some_and(|l| l.to_ascii_lowercase().starts_with("https:"));
                if r.status().is_redirection() && to_https {
                    return Some(aredn("https-redirect", Some(code)));
                }
                Some(node_status(code, ms_since(start)))
            }
            Err(e) if e.is_connect() => Some(aredn("http-unreachable", None)),
            Err(e) if e.is_timeout() => Some(aredn("http-slow", None)),
            Err(_) => Some(aredn("not-http", None)),
        }
    }
}

/// The node keeps an HTTP service whose answer, after redirects, is 200 or 401 within 10 s.
fn node_status(code: u16, ms: f64) -> Aredn {
    if ms > 10_000.0 {
        aredn("http-slow", Some(code))
    } else if code == 200 || code == 401 {
        aredn("http-ok", Some(code))
    } else {
        aredn("http-status", Some(code))
    }
}

/// A round where everything failed, across more than one host or while our own node
/// wasn't answering, says more about this site than about the services. It is still
/// logged, marked, and gives no verdict.
pub fn cut_off(results: &[ProbeResult], node_down: bool) -> bool {
    let hosts: BTreeSet<&str> = results.iter().map(|r| r.host.as_str()).collect();
    !results.is_empty() && results.iter().all(|r| !r.ok) && (hosts.len() >= 2 || node_down)
}

/// Whether the core's last poll of our own node failed.
fn node_down(conn: &Connection, core_key: &str) -> bool {
    let ok: Option<bool> = conn
        .query_row(
            "SELECT ok FROM polls WHERE author_key = ?1 AND coalesce(via, 'lan') = 'lan'
             ORDER BY ts DESC LIMIT 1",
            params![core_key],
            |r| r.get(0),
        )
        .ok();
    ok == Some(false)
}

/// What this site probes this round, and how: its own node's adverts minus skips, and
/// minus the services other sites have in hand when `sites_per_service` caps the sites.
/// Services on our own node are always ours: from here they're one LAN hop away.
pub fn plan(
    conn: &Connection,
    cfg: &ProbeCfg,
    now: i64,
    fresh_ms: i64,
    key: &str,
    node: &str,
) -> Result<Vec<(Service, Mode)>> {
    let sites = probing_sites(conn, now, fresh_ms)?;
    let me = norm_node(node);
    let mut list: Vec<(Service, Mode)> = own_targets(conn, now, key)?
        .into_iter()
        .filter(|s| {
            norm_node(&s.host) == me || assigned(&s.link, &me, &sites, cfg.sites_per_service)
        })
        .map(|s| {
            let m = mode_for(&s, cfg);
            (s, m)
        })
        .filter(|(_, m)| *m != Mode::Skip)
        .collect();
    list.truncate(cfg.max_targets);
    Ok(list)
}

/// Probe every target once and log the round. Returns None when there was nothing to probe.
pub async fn round(app: Arc<App>) -> Result<Option<Event>> {
    let now = now_ms();
    let me = app.whoami().await?;
    if me.node.is_empty() {
        // the core hasn't polled its node yet, so we don't know which site we are
        return Ok(None);
    }
    let list = plan(
        &app.db(),
        &app.cfg.probe,
        now,
        app.fresh_ms(),
        &me.key,
        &me.node,
    )?;
    let sem = Arc::new(Semaphore::new(CONCURRENCY));
    let mut tasks = tokio::task::JoinSet::new();
    for (s, mode) in list {
        let app = app.clone();
        let sem = sem.clone();
        tasks.spawn(async move {
            let _permit = sem.acquire_owned().await;
            app.prober.probe(&s, mode).await
        });
    }
    let mut results = vec![];
    while let Some(r) = tasks.join_next().await {
        if let Ok(r) = r {
            results.push(r);
        }
    }
    if results.is_empty() {
        return Ok(None);
    }
    results.sort_by(|a, b| a.link.cmp(&b.link));
    let cut = cut_off(&results, node_down(&app.db(), &me.key));
    if cut {
        tracing::warn!("every check failed this round; treating this site as cut off");
    }
    let ev = app
        .core
        .append_telemetry(
            "svc.probe",
            json!({"vantage": me.node, "cut_off": cut, "results": results}),
        )
        .await?;
    Ok(Some(ev))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ProbeOverride;
    use std::io::{Read, Write};

    fn svc(name: &str, link: &str) -> Service {
        Service {
            host: "h".into(),
            name: name.into(),
            link: link.into(),
            protocol: "tcp".into(),
        }
    }

    fn local() -> Prober {
        Prober::new(&ProbeCfg {
            allow_hosts: vec!["127.0.0.1".into()],
            timeout_s: 3,
            ..Default::default()
        })
        .unwrap()
    }

    /// A TCP server on loopback that writes `greeting` to each connection and reports
    /// what the client sent.
    fn server(greeting: &'static [u8]) -> (u16, std::sync::mpsc::Receiver<Vec<u8>>) {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            for mut s in l.incoming().flatten() {
                let _ = s.write_all(greeting);
                s.set_read_timeout(Some(Duration::from_millis(500)))
                    .unwrap();
                let mut got = vec![];
                let _ = s.read_to_end(&mut got);
                let _ = tx.send(got);
            }
        });
        (port, rx)
    }

    /// An HTTP server on loopback answering each request with `respond(path)`.
    fn http_server(respond: fn(&str) -> String) -> u16 {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for mut s in l.incoming().flatten() {
                let mut buf = [0u8; 4096];
                let n = s.read(&mut buf).unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                let path = req.split_whitespace().nth(1).unwrap_or("/").to_string();
                let _ = s.write_all(respond(&path).as_bytes());
            }
        });
        port
    }

    fn reply(status: &str, extra: &str, body: &str) -> String {
        format!(
            "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n{extra}\r\n{body}",
            body.len()
        )
    }

    #[test]
    fn only_mesh_hosts_are_probed() {
        assert!(allowed_host("n0call-cuesta.local.mesh", &[]));
        assert!(allowed_host("n0call-cuesta", &[]));
        assert!(allowed_host("10.12.34.56", &[]));
        assert!(allowed_host("44.4.1.1", &[]));
        assert!(!allowed_host("127.0.0.1", &[]));
        assert!(!allowed_host("192.168.1.1", &[]));
        assert!(!allowed_host("example.com", &[]));
        assert!(allowed_host("127.0.0.1", &["127.0.0.1".into()]));
        for sneaky in ["localhost", "2130706433", "0x7f000001", "0x7f.1"] {
            assert!(!allowed_host(sneaky, &[]), "{sneaky}");
        }
        assert_eq!(
            mode_for(
                &svc("x", "http://127.0.0.1:9100\\@10.1.1.1/"),
                &ProbeCfg::default()
            ),
            Mode::Skip,
            "a backslash ends the host for the HTTP client"
        );
        assert_eq!(
            mode_for(&svc("x", "tcp://localhost:22"), &ProbeCfg::default()),
            Mode::Skip
        );
        let cfg = ProbeCfg::default();
        assert_eq!(
            mode_for(&svc("x", "http://127.0.0.1:9100/admin"), &cfg),
            Mode::Skip
        );
    }

    #[test]
    fn targets_come_only_from_this_sites_own_node() {
        use ridgewarden_client::mesh::Mesh;
        use ridgewarden_client::mesh::testing::Fake;
        let mut f = Fake::new(vec![Box::new(Mesh)]);
        let list = serde_json::json!([{"host": "h", "name": "S", "link": "http://h.local.mesh/", "protocol": "tcp"}]);
        let hash = ridgewarden_client::event::list_hash(&list);
        f.add(
            "mesh.list",
            serde_json::json!({"hash": hash, "list": list}),
            now_ms(),
        );
        let e = f.add(
            "node.poll",
            serde_json::json!({"node": "n", "ok": true, "via": "lan", "ads_hash": hash}),
            now_ms(),
        );
        assert_eq!(
            own_targets(&f.conn, now_ms(), &e.author.key).unwrap().len(),
            1
        );
        assert!(
            own_targets(&f.conn, now_ms(), "someone-else")
                .unwrap()
                .is_empty()
        );
    }

    fn result(host: &str, ok: bool) -> ProbeResult {
        ProbeResult {
            name: "s".into(),
            host: host.into(),
            link: format!("http://{host}/"),
            ok,
            ms: None,
            status: None,
            detail: String::new(),
            check: "http",
            aredn: None,
        }
    }

    #[test]
    fn a_round_where_everything_failed_is_a_cut_off_site() {
        assert!(cut_off(&[result("a", false), result("b", false)], false));
        assert!(!cut_off(&[result("a", false), result("b", true)], false));
        // one host down is just that host, unless our own node isn't answering either
        assert!(!cut_off(&[result("a", false), result("a", false)], false));
        assert!(cut_off(&[result("a", false)], true));
        assert!(!cut_off(&[], true));
    }

    #[test]
    fn status_and_keyword_checks() {
        assert!(
            http_verdict(404, None, None).0,
            "a 404 still means a server answered"
        );
        assert!(!http_verdict(502, None, None).0);
        let c = ProbeOverride {
            name_contains: "chat".into(),
            expect_status: vec![200],
            keyword: Some("MeshChat".into()),
            ..Default::default()
        };
        assert!(http_verdict(200, Some("<title>MeshChat</title>"), Some(&c)).0);
        let (ok, why) = http_verdict(200, Some("It works!"), Some(&c));
        assert!(!ok && why.contains("lacks"), "{why}");
        let (ok, why) = http_verdict(404, Some("MeshChat"), Some(&c));
        assert!(!ok && why.contains("expected"), "{why}");
    }

    #[test]
    fn parses_links() {
        assert_eq!(
            host_port("http://node.local.mesh:8080/path?q"),
            Some(("http".into(), "node.local.mesh".into(), Some(8080)))
        );
        assert_eq!(
            host_port("tcp://10.0.0.1:8772"),
            Some(("tcp".into(), "10.0.0.1".into(), Some(8772)))
        );
        assert_eq!(host_port("nonsense"), None);
        assert_eq!(path_of("http://a:8080/meshchat?x=1"), "/meshchat");
        assert_eq!(path_of("tcp://a:1"), "");
    }

    #[test]
    fn modes_follow_link_and_overrides() {
        let mut cfg = ProbeCfg::default();
        assert_eq!(mode_for(&svc("Chat", "http://a:80/"), &cfg), Mode::Http);
        assert_eq!(
            mode_for(&svc("Gateway", "tcp://a:8772"), &cfg),
            Mode::Winlink("a".into(), 8772)
        );
        assert_eq!(
            mode_for(&svc("Pat", "http://a:8774/"), &cfg),
            Mode::Winlink("a".into(), 8774),
            "an HTTP request to a Winlink port would look like a login"
        );
        assert_eq!(
            mode_for(&svc("Chat", "http://a.local.mesh:8080/meshchat"), &cfg),
            Mode::MeshChat("http://a.local.mesh:8080".into())
        );
        assert_eq!(
            mode_for(&svc("Shell", "tcp://a:22"), &cfg),
            Mode::Tcp("a".into(), 22)
        );
        assert_eq!(mode_for(&svc("Phone", "sip://a"), &cfg), Mode::Skip);
        assert_eq!(
            mode_for(&svc("Link-less", "http://a:0/"), &cfg),
            Mode::Skip,
            "AREDN lists services without a link on port 0"
        );
        assert!(linkless("tcp://a:0/") && !linkless("tcp://a:22/"));
        assert_eq!(mode_for(&svc("x", ""), &cfg), Mode::Skip);
        for (name, mode) in [("winlink", "winlink"), ("camera", "skip"), ("relay", "tcp")] {
            cfg.overrides.push(ProbeOverride {
                name_contains: name.into(),
                mode: Some(mode.into()),
                ..Default::default()
            });
        }
        assert_eq!(
            mode_for(&svc("My WINLINK gw", "tcp://a:9000/"), &cfg),
            Mode::Winlink("a".into(), 9000)
        );
        assert_eq!(
            mode_for(&svc("Relay", "tcp://a:8772/"), &cfg),
            Mode::Tcp("a".into(), 8772)
        );
        assert_eq!(mode_for(&svc("Camera", "http://a/"), &cfg), Mode::Skip);
    }

    #[test]
    fn the_cap_shares_services_out_and_covers_each_one() {
        let sites: BTreeSet<String> = (0..9).map(|i| format!("site{i}")).collect();
        for n in 0..50 {
            let link = format!("http://svc{n}/");
            let who = sites
                .iter()
                .filter(|s| assigned(&link, s, &sites, 3))
                .count();
            assert_eq!(who, 3, "{link}");
        }
        // with the cap off, or no more sites than the cap, every site probes everything
        assert!(sites.iter().all(|s| assigned("http://x/", s, &sites, 0)));
        let few: BTreeSet<String> = sites.iter().take(3).cloned().collect();
        assert!(few.iter().all(|s| assigned("http://x/", s, &few, 3)));
        // a site others haven't heard from yet still counts itself
        let me = "site4".to_string();
        let mut without_me = sites.clone();
        without_me.remove(&me);
        for n in 0..50 {
            let link = format!("http://svc{n}/");
            assert_eq!(
                assigned(&link, &me, &sites, 3),
                assigned(&link, &me, &without_me, 3)
            );
        }
    }

    #[tokio::test]
    async fn winlink_check_waits_for_the_prompt_and_never_logs_in() {
        let p = local();
        let (port, sent) = server(b"\r\rCallsign :\r");
        let s = svc("Gateway", &format!("tcp://127.0.0.1:{port}"));
        let r = p.probe(&s, Mode::Winlink("127.0.0.1".into(), port)).await;
        assert!(r.ok, "{}", r.detail);
        assert_eq!(r.check, "winlink");
        assert_eq!(r.aredn, Some(aredn("tcp", None)));
        assert!(
            sent.recv_timeout(Duration::from_secs(5))
                .unwrap()
                .is_empty(),
            "nothing may be sent to a Winlink server"
        );
        let (port, _) = server(b"SSH-2.0-OpenSSH_9.6\r\n");
        let s = svc("Gateway", &format!("tcp://127.0.0.1:{port}"));
        let r = p.probe(&s, Mode::Winlink("127.0.0.1".into(), port)).await;
        assert!(!r.ok);
        assert!(r.detail.contains("SSH-2.0"), "{}", r.detail);
    }

    #[tokio::test]
    async fn a_winlink_port_advertised_as_http_fails_the_nodes_check() {
        let p = local();
        let (port, _) = server(b"Callsign :\r");
        let s = svc("Gateway", &format!("http://127.0.0.1:{port}/"));
        let r = p.probe(&s, Mode::Winlink("127.0.0.1".into(), port)).await;
        assert!(r.ok);
        assert_eq!(r.aredn, Some(aredn("not-http", None)));
    }

    #[tokio::test]
    async fn meshchat_check_asks_its_api() {
        let p = local();
        let port = http_server(|path| {
            if path.contains("action=config") {
                reply(
                    "200 OK",
                    "",
                    r#"{"version":"2.12.0","node":"tst-shack","zone":"MeshChat"}"#,
                )
            } else if path.contains("action=sync_status") {
                let epoch = now_ms() / 1000 - 120;
                let body =
                    format!(r#"[{{"node":"tst-lopez","epoch":{epoch}}},{{"node":"x","epoch":5}}]"#);
                reply("200 OK", "", &body)
            } else {
                reply("200 OK", "", "<html>MeshChat</html>")
            }
        });
        let s = svc("Chat", &format!("http://127.0.0.1:{port}/meshchat"));
        let r = p.probe(&s, mode_for(&s, &p.cfg)).await;
        assert!(r.ok, "{}", r.detail);
        assert!(r.detail.contains("MeshChat 2.12.0"), "{}", r.detail);
        assert!(
            r.detail.contains("last synced with another node 2 min ago"),
            "{}",
            r.detail
        );
        assert_eq!(r.aredn, Some(aredn("http-ok", Some(200))));
        // a web server that isn't MeshChat
        let port = http_server(|_| reply("200 OK", "", "It works!"));
        let s = svc("Chat", &format!("http://127.0.0.1:{port}/meshchat"));
        let r = p.probe(&s, mode_for(&s, &p.cfg)).await;
        assert!(!r.ok);
        assert!(r.detail.contains("no MeshChat API"), "{}", r.detail);
    }

    #[tokio::test]
    async fn the_node_view_follows_redirects_like_the_node() {
        let p = local();
        let port = http_server(|path| match path {
            "/" => reply("302 Found", "Location: /wiki/\r\n", ""),
            "/wiki/" => reply("404 Not Found", "", "nope"),
            "/secure" => reply("301 Moved", "Location: https://10.9.9.9/\r\n", ""),
            "/moved" => reply("302 Found", "Location: /broken\r\n", ""),
            "/broken" => reply("500 Oops", "", ""),
            "/away" => reply("302 Found", "Location: http://192.168.1.1/\r\n", ""),
            _ => reply("401 Unauthorized", "", ""),
        });
        let base = format!("http://127.0.0.1:{port}");
        let r = p.probe(&svc("Wiki", &format!("{base}/")), Mode::Http).await;
        assert!(r.ok, "a redirect still shows a server is there");
        assert_eq!(r.aredn, Some(aredn("http-status", Some(404))));
        // our own verdict doesn't follow redirects; the node's view does
        let r = p
            .probe(&svc("Moved", &format!("{base}/moved")), Mode::Http)
            .await;
        assert!(r.ok && r.status == Some(302), "{:?}", r.status);
        assert_eq!(r.aredn, Some(aredn("http-status", Some(500))));
        // and the node's view stops at a redirect off the mesh rather than follow it
        let r = p
            .probe(&svc("Away", &format!("{base}/away")), Mode::Http)
            .await;
        assert_eq!(r.aredn, Some(aredn("http-status", Some(302))));
        let r = p
            .probe(&svc("Secure", &format!("{base}/secure")), Mode::Http)
            .await;
        assert_eq!(r.aredn, Some(aredn("https-redirect", Some(301))));
        let r = p
            .probe(&svc("Admin", &format!("{base}/admin")), Mode::Http)
            .await;
        assert_eq!(r.aredn, Some(aredn("http-ok", Some(401))));
    }

    #[tokio::test]
    async fn a_closed_port_fails_tcp_and_the_nodes_udp_fallback() {
        let p = local();
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let s = svc("Thing", &format!("tcp://127.0.0.1:{port}"));
        let r = p.probe(&s, Mode::Tcp("127.0.0.1".into(), port)).await;
        assert!(!r.ok);
        assert_eq!(r.aredn, Some(aredn("refused", None)));
        // a UDP-only service: no TCP, but UDP isn't refused, which the node accepts
        let u = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = u.local_addr().unwrap().port();
        let s = svc("Phone", &format!("tcp://127.0.0.1:{port}"));
        let r = p.probe(&s, Mode::Tcp("127.0.0.1".into(), port)).await;
        assert!(!r.ok);
        assert_eq!(r.aredn, Some(aredn("udp", None)));
    }

    #[tokio::test]
    async fn names_must_resolve_to_mesh_addresses() {
        // single-label names pass the name check, and some of them are the box itself
        assert!(allowed_host("ip6-localhost", &[]));
        assert!(resolve("localhost", 80, &[]).await.is_err());
        assert!(
            resolve("localhost", 80, &["localhost".into()])
                .await
                .is_ok()
        );
        // every way of connecting goes through the same rule
        let port = http_server(|_| reply("200 OK", "", "hello"));
        let p = Prober::new(&ProbeCfg::default()).unwrap();
        let s = svc("Sneaky", &format!("http://localhost:{port}/"));
        let r = p.probe(&s, Mode::Http).await;
        assert!(!r.ok && r.status.is_none(), "{}", r.detail);
        let r = p.probe(&s, Mode::Tcp("localhost".into(), port)).await;
        assert!(!r.ok && r.detail.contains("mesh address"), "{}", r.detail);
    }

    #[test]
    fn the_plan_takes_a_share_and_everything_on_our_own_node() {
        use ridgewarden_client::mesh::Mesh;
        use ridgewarden_client::mesh::testing::Fake;
        let mut f = Fake::new(vec![Box::new(Mesh), Box::new(crate::probes::Probes)]);
        let now = now_ms();
        let mut list: Vec<Value> = (0..20)
            .map(|i| json!({"host": "far", "name": format!("S{i}"), "link": format!("http://far/{i}"), "protocol": "tcp"}))
            .collect();
        list.push(json!({"host": "me", "name": "Mine", "link": "http://me/", "protocol": "tcp"}));
        let list = json!(list);
        let hash = ridgewarden_client::event::list_hash(&list);
        f.add("mesh.list", json!({"hash": hash, "list": list}), now);
        let e = f.add(
            "node.poll",
            json!({"node": "me", "ok": true, "via": "lan", "ads_hash": hash}),
            now,
        );
        for site in ["s1", "s2", "s3"] {
            f.add(
                "node.poll",
                json!({"node": site, "ok": true, "via": "lan"}),
                now,
            );
            let r = json!([{"name": "S0", "link": "http://far/0", "host": "far", "ok": true}]);
            f.add("svc.probe", json!({"vantage": site, "results": r}), now);
        }
        let mut cfg = ProbeCfg::default();
        let plan_with = |cfg: &ProbeCfg| {
            plan(&f.conn, cfg, now, 600_000, &e.author.key, "me")
                .unwrap()
                .into_iter()
                .map(|(s, _)| s.name)
                .collect::<Vec<_>>()
        };
        assert_eq!(
            plan_with(&cfg).len(),
            21,
            "four sites, a cap of five: all of it"
        );
        cfg.sites_per_service = 1;
        let mine = plan_with(&cfg);
        assert!(mine.contains(&"Mine".to_string()), "{mine:?}");
        assert!(mine.len() < 21, "about a quarter of the rest: {mine:?}");
        let sites: BTreeSet<String> = ["s1", "s2", "s3"].map(String::from).into();
        let expected = (0..20)
            .filter(|i| assigned(&format!("http://far/{i}"), "me", &sites, 1))
            .count();
        assert_eq!(mine.len(), expected + 1);
    }
}
