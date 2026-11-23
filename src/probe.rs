//! Service probing: every site probes the services the mesh advertises, from where it
//! sits, and logs the results through its core as one signed `svc.probe` event per round.
//! Each result also says whether the AREDN node's own reachability check would pass,
//! worked out the way the node does it.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Result, bail};
use reqwest::Url;
use reqwest::header::{COOKIE, HeaderMap, LOCATION, SET_COOKIE};
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
/// "unpublished but still alive" gets noticed after AREDN's own check drops one.
pub const REMEMBER_MS: i64 = 7 * 86_400_000;

const CONCURRENCY: usize = 8;

/// Most of a page we'll read looking for a keyword.
const KEYWORD_BYTES: usize = 256 * 1024;

/// How long a Winlink server gets to send its login prompt once connected.
const PROMPT_WAIT: Duration = Duration::from_secs(5);

/// The redirects the node's check accepts when they end on an https address
/// (files/usr/share/ucode/aredn/services.uc in the AREDN firmware). Its curl follows any
/// 3xx with a Location.
const HTTPS_REDIRECTS: [u16; 5] = [301, 302, 303, 307, 308];

/// curl's default --max-redirs, which the node's check doesn't change.
const MAX_REDIRECTS: usize = 50;

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
    ("https-untrusted", false),
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

/// The node keeps a service whose link is turned off as proto://host:0/ and never checks
/// it (services.uc); sysinfo shows it with an empty link. Nothing to connect to either way.
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

/// The address a Redirect service (the node's /a/redirect?<address>) sends people to.
fn redirect_target(link: &str) -> Option<&str> {
    let rest = link.split_once("://")?.1;
    rest[rest.find('/')?..].strip_prefix("/a/redirect?")
}

/// What the node's check hands curl for an http(s) link (services.uc): a Redirect service's
/// target, else the link. It goes into a shell command unquoted, so sh ends it at the first
/// & or ;. Other shell characters ($, |, quotes, spaces) mangle it too; those aren't copied.
fn node_target(link: &str) -> &str {
    let t = redirect_target(link).unwrap_or(link);
    t.split(['&', ';']).next().unwrap_or(t)
}

/// The address the node's check fetches: `node_target`, with .local.mesh added to a bare
/// host unless it's a Redirect service's target, which is fetched as it stands.
pub fn node_url(link: &str) -> Option<Url> {
    let mut url = Url::parse(node_target(link))
        .ok()
        .filter(|u| matches!(u.scheme(), "http" | "https"))?;
    let bare = url
        .host_str()
        .filter(|h| redirect_target(link).is_none() && !h.contains('.'))
        .map(|h| format!("{h}.local.mesh"));
    if let Some(h) = bare {
        url.set_host(Some(&h)).ok()?;
    }
    Some(url)
}

/// curl's cookie jar, cut down: name=value pairs, sent back only to the host that set them.
/// Unlike curl it ignores Path, Domain, Secure and expiry, so Max-Age=0 doesn't delete one.
type Jar = BTreeMap<(String, String), String>;

fn keep_cookies(jar: &mut Jar, host: &str, headers: &HeaderMap) {
    for c in headers
        .get_all(SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
    {
        if let Some((name, value)) = c.split(';').next().and_then(|p| p.split_once('=')) {
            jar.insert((host.into(), name.trim().into()), value.trim().into());
        }
    }
}

fn cookies_for(jar: &Jar, host: &str) -> String {
    jar.iter()
        .filter(|((h, _), _)| h == host)
        .map(|((_, n), v)| format!("{n}={v}"))
        .collect::<Vec<_>>()
        .join("; ")
}

pub fn override_for<'a>(s: &Service, cfg: &'a ProbeCfg) -> Option<&'a ProbeOverride> {
    let name = s.name.to_ascii_lowercase();
    cfg.overrides
        .iter()
        .find(|o| name.contains(&o.name_contains.to_ascii_lowercase()))
}

/// 8772 is Winlink's telnet port (wl2k-go transport/telnet/dial.go), 8774 Pat's telnet
/// listener (pat cfg/config.go).
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
    // the node waits 1 ms for a refusal on its own LAN (services.uc); across the mesh one
    // takes longer
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

/// Makes the probes. Two HTTP clients, neither following redirects by itself: one for our
/// own verdict (so a redirect can't aim our probes somewhere else), and one that behaves
/// like the node's curl (2 s to connect, certificates checked), which `node_http` walks
/// through redirects the way curl does.
pub struct Prober {
    pub cfg: ProbeCfg,
    http: reqwest::Client,
    like_node: reqwest::Client,
}

impl Prober {
    pub fn new(cfg: &ProbeCfg) -> Result<Self> {
        let agent = concat!("ridgewarden-health/", env!("CARGO_PKG_VERSION"));
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
            .redirect(reqwest::redirect::Policy::none())
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

    /// Where our own HTTP check goes: the link, or for a Redirect service the address it
    /// leads to while that's on the mesh, so it's judged by the page people reach.
    fn own_url<'a>(&self, link: &'a str) -> &'a str {
        redirect_target(link)
            .filter(|t| {
                host_port(t).is_some_and(|(s, h, _)| {
                    (s == "http" || s == "https") && allowed_host(&h, &self.cfg.allow_hosts)
                })
            })
            .unwrap_or(link)
    }

    async fn http_check(&self, s: &Service) -> Outcome {
        let start = Instant::now();
        let check = override_for(s, &self.cfg);
        let url = self.own_url(&s.link);
        let r = match self.http.get(url).send().await {
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
        // the node's curl starts where we did, give or take .local.mesh on a bare host
        let same = scheme(url) == "http" && node_target(&s.link) == url;
        let a = match scheme(&s.link).as_str() {
            // our answer is the node's too, unless its curl would go elsewhere or further
            "http" if same && !redirect => Some(node_status(code, ms)),
            "http" => self.node_http(&s.link).await,
            // https links get the node's TCP check, which a quick answer has already passed
            _ if ms <= 2000.0 => Some(aredn("tcp", None)),
            _ => self.node_any(s).await,
        };
        (ok, Some(ms), Some(code), detail, a)
    }

    /// MeshChat's `config` action answers with its version, node and zone; `sync_status`
    /// says when it last pulled messages from each other MeshChat node (the `meshchat` CGI
    /// script in hickey/meshchat).
    async fn meshchat(&self, s: &Service, base: &str) -> Outcome {
        let start = Instant::now();
        let api = format!("{base}/cgi-bin/meshchat");
        let r = match self.http.get(format!("{api}?action=config")).send().await {
            Ok(r) => r,
            Err(e) => {
                let a = self.node_any(s).await;
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
        let a = self.node_any(s).await;
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

    /// The node's check for a non-HTTP link (services.uc): a TCP connection within 2 s,
    /// else an empty UDP send that isn't refused. Our own connection attempt settles the
    /// TCP half.
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

    /// The node's HTTP check, as services.uc runs it: `curl --location --cookie-jar
    /// --connect-timeout 2 --max-time 10`, which passes on a 200 or 401.
    async fn node_http(&self, link: &str) -> Option<Aredn> {
        let url = node_url(link)?;
        tokio::time::timeout(Duration::from_secs(10), self.follow(url))
            .await
            .unwrap_or(Some(aredn("http-slow", None)))
    }

    async fn follow(&self, mut url: Url) -> Option<Aredn> {
        let start = Instant::now();
        let mut jar = Jar::new();
        let mut hops = 0;
        loop {
            // the node would follow a redirect anywhere; this box stays on the mesh
            let host = url
                .host_str()
                .filter(|h| allowed_host(h, &self.cfg.allow_hosts))?
                .to_string();
            let mut req = self.like_node.get(url.clone());
            let sent = cookies_for(&jar, &host);
            if !sent.is_empty() {
                req = req.header(COOKIE, sent);
            }
            let r = match req.send().await {
                Ok(r) => r,
                Err(e) if e.is_connect() => return Some(self.no_connection(&url, &host).await),
                Err(e) if e.is_timeout() => return Some(aredn("http-slow", None)),
                Err(_) => return Some(aredn("not-http", None)),
            };
            let code = r.status().as_u16();
            keep_cookies(&mut jar, &host, r.headers());
            let next = r
                .headers()
                .get(LOCATION)
                .and_then(|l| l.to_str().ok())
                .and_then(|l| url.join(l).ok())
                .filter(|_| r.status().is_redirection());
            match next {
                // services.uc takes a redirect to https on trust: its curl can't check a
                // self-signed certificate
                Some(n)
                    if n.scheme() == "https"
                        && HTTPS_REDIRECTS.contains(&code)
                        && hops < MAX_REDIRECTS =>
                {
                    return Some(aredn("https-redirect", Some(code)));
                }
                Some(n) if n.scheme() == "http" && hops < MAX_REDIRECTS => {
                    url = n;
                    hops += 1;
                }
                _ => return Some(node_status(code, ms_since(start))),
            }
        }
    }

    /// Why the node's kind of request got no answer: nothing took the connection, or it
    /// was https and the TLS handshake failed. `https-untrusted` stands for any TLS failure
    /// (an unverifiable certificate, a protocol curl won't speak, a port that isn't TLS),
    /// since each one stops curl the same way.
    async fn no_connection(&self, url: &Url, host: &str) -> Aredn {
        let port = url.port_or_known_default().unwrap_or(443);
        if url.scheme() == "https" && self.connect(host, port, 2).await.ok {
            aredn("https-untrusted", None)
        } else {
            aredn("http-unreachable", None)
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

    /// An HTTP server on loopback answering each request with `respond(path, request)`.
    fn http_server(respond: fn(&str, &str) -> String) -> u16 {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for mut s in l.incoming().flatten() {
                let mut buf = [0u8; 4096];
                let n = s.read(&mut buf).unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                let path = req.split_whitespace().nth(1).unwrap_or("/").to_string();
                let _ = s.write_all(respond(&path, &req).as_bytes());
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
        let port = http_server(|path, _| {
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
        let port = http_server(|_, _| reply("200 OK", "", "It works!"));
        let s = svc("Chat", &format!("http://127.0.0.1:{port}/meshchat"));
        let r = p.probe(&s, mode_for(&s, &p.cfg)).await;
        assert!(!r.ok);
        assert!(r.detail.contains("no MeshChat API"), "{}", r.detail);
    }

    #[tokio::test]
    async fn an_https_meshchat_gets_the_nodes_tcp_check() {
        let p = local();
        // not TLS, so our MeshChat check fails, but the port takes a connection
        let (port, _) = server(b"not a TLS server\r\n");
        let s = svc("Chat", &format!("https://127.0.0.1:{port}/meshchat"));
        assert!(matches!(mode_for(&s, &p.cfg), Mode::MeshChat(_)));
        let r = p.probe(&s, mode_for(&s, &p.cfg)).await;
        assert!(!r.ok, "{}", r.detail);
        assert_eq!(
            r.aredn,
            Some(aredn("tcp", None)),
            "the node checks every https link with a TCP connection"
        );
    }

    #[tokio::test]
    async fn the_node_view_follows_redirects_like_the_nodes_curl() {
        let p = local();
        let port = http_server(|path, req| match path {
            "/" => reply("302 Found", "Location: /wiki/\r\n", ""),
            "/wiki/" => reply("404 Not Found", "", "nope"),
            "/secure" => reply("301 Moved", "Location: https://10.9.9.9/\r\n", ""),
            "/choices" => reply("300 Choices", "Location: https://10.9.9.9/\r\n", ""),
            "/moved" => reply("302 Found", "Location: /broken\r\n", ""),
            "/broken" => reply("500 Oops", "", ""),
            "/away" => reply("302 Found", "Location: http://192.168.1.1/\r\n", ""),
            "/login" => reply(
                "302 Found",
                "Set-Cookie: session=abc; Path=/; HttpOnly\r\nLocation: /home\r\n",
                "",
            ),
            "/home" if req.contains("session=abc") => reply("200 OK", "", "home"),
            "/home" => reply("302 Found", "Location: /login\r\n", ""),
            _ => reply("401 Unauthorized", "", ""),
        });
        let base = format!("http://127.0.0.1:{port}");
        let view = async |path: &str| {
            p.probe(&svc("S", &format!("{base}{path}")), Mode::Http)
                .await
        };
        let r = view("/").await;
        assert!(r.ok, "a redirect still shows a server is there");
        assert_eq!(r.aredn, Some(aredn("http-status", Some(404))));
        // our own verdict doesn't follow redirects; the node's view does
        let r = view("/moved").await;
        assert!(r.ok && r.status == Some(302), "{:?}", r.status);
        assert_eq!(r.aredn, Some(aredn("http-status", Some(500))));
        assert_eq!(
            view("/login").await.aredn,
            Some(aredn("http-ok", Some(200))),
            "curl keeps cookies across redirects; without them this one loops"
        );
        assert_eq!(
            view("/secure").await.aredn,
            Some(aredn("https-redirect", Some(301)))
        );
        assert_eq!(
            view("/choices").await.aredn,
            Some(aredn("http-status", Some(300))),
            "only 301, 302, 303, 307 and 308 count when they end on https"
        );
        assert_eq!(
            view("/admin").await.aredn,
            Some(aredn("http-ok", Some(401)))
        );
        // the node would follow a redirect off the mesh; this box doesn't, so it can't say
        assert_eq!(view("/away").await.aredn, None);
    }

    #[tokio::test]
    async fn the_node_view_stops_where_curl_stops() {
        let p = local();
        let port = http_server(|path, _| {
            let hop = |to: &str| reply("302 Found", &format!("Location: {to}\r\n"), "");
            match path {
                "/ping" => hop("/pong"),
                "/pong" => hop("/ping"),
                p if p.starts_with("/https/") => reply(
                    &format!("{} Moved", &p[7..]),
                    "Location: https://10.9.9.9/\r\n",
                    "",
                ),
                // /chain/<end>/<redirects>/<i>: that many redirects, then a page or https
                p if p.starts_with("/chain/") => {
                    let v: Vec<&str> = p.split('/').collect();
                    let (len, i): (u32, u32) = (v[3].parse().unwrap(), v[4].parse().unwrap());
                    match v[2] {
                        _ if i < len => hop(&format!("/chain/{}/{len}/{}", v[2], i + 1)),
                        "tls" => hop("https://10.9.9.9/"),
                        _ => reply("200 OK", "", ""),
                    }
                }
                _ => reply("404 Not Found", "", ""),
            }
        });
        let base = format!("http://127.0.0.1:{port}");
        let view = async |path: &str| {
            p.probe(&svc("S", &format!("{base}{path}")), Mode::Http)
                .await
                .aredn
        };
        assert_eq!(
            view("/ping").await,
            Some(aredn("http-status", Some(302))),
            "a loop ends on a redirect once curl gives up"
        );
        for code in [302, 303, 307, 308] {
            assert_eq!(
                view(&format!("/https/{code}")).await,
                Some(aredn("https-redirect", Some(code)))
            );
        }
        // curl's default --max-redirs is 50
        assert_eq!(
            view("/chain/ok/50/0").await,
            Some(aredn("http-ok", Some(200)))
        );
        assert_eq!(
            view("/chain/ok/51/0").await,
            Some(aredn("http-status", Some(302)))
        );
        assert_eq!(
            view("/chain/tls/49/0").await,
            Some(aredn("https-redirect", Some(302)))
        );
        assert_eq!(
            view("/chain/tls/50/0").await,
            Some(aredn("http-status", Some(302))),
            "past the cap curl doesn't follow it to https, so it ends on the redirect"
        );
    }

    #[tokio::test]
    async fn the_node_view_keeps_cookies_to_the_host_that_set_them() {
        let p = Prober::new(&ProbeCfg {
            allow_hosts: vec!["127.0.0.1".into(), "localhost".into()],
            timeout_s: 3,
            ..Default::default()
        })
        .unwrap();
        let port = http_server(|path, req| match path {
            "/set" => {
                let port = req
                    .lines()
                    .find(|l| l.to_ascii_lowercase().starts_with("host:"))
                    .and_then(|l| l.rsplit(':').next())
                    .unwrap_or_default()
                    .trim()
                    .to_string();
                let to = format!("http://localhost:{port}/check");
                reply(
                    "302 Found",
                    &format!("Set-Cookie: session=abc; Path=/\r\nLocation: {to}\r\n"),
                    "",
                )
            }
            "/check" if req.contains("session=abc") => reply("500 Leaked", "", ""),
            "/check" => reply("200 OK", "", ""),
            _ => reply("404 Not Found", "", ""),
        });
        let s = svc("S", &format!("http://127.0.0.1:{port}/set"));
        assert_eq!(
            p.probe(&s, Mode::Http).await.aredn,
            Some(aredn("http-ok", Some(200))),
            "a cookie from 127.0.0.1 isn't sent to localhost"
        );
    }

    #[tokio::test]
    async fn the_node_asks_for_what_its_shell_leaves_of_the_link() {
        let p = local();
        let port = http_server(|path, _| match path {
            "/cam?cmd=Snap&channel=0" => reply("200 OK", "", "jpeg"),
            _ => reply("400 Bad Request", "", ""),
        });
        let s = svc(
            "Cam",
            &format!("http://127.0.0.1:{port}/cam?cmd=Snap&channel=0"),
        );
        let r = p.probe(&s, Mode::Http).await;
        assert!(r.ok && r.status == Some(200), "{}", r.detail);
        // sh -c ends the unquoted address at the &, so curl asks for /cam?cmd=Snap
        assert_eq!(r.aredn, Some(aredn("http-status", Some(400))));
    }

    #[tokio::test]
    async fn a_redirect_service_is_checked_at_the_address_it_leads_to() {
        let p = local();
        let port = http_server(|path, _| match path {
            "/locked" => reply("401 Unauthorized", "", ""),
            "/gone" => reply("404 Not Found", "", ""),
            // the node's /a/redirect page itself, which neither check may stop at
            _ => reply("502 Bad Gateway", "", ""),
        });
        let base = format!("http://127.0.0.1:{port}");
        let probe = async |target: String| {
            let link = format!("{base}/a/redirect?{target}");
            p.probe(&svc("Cam", &link), Mode::Http).await
        };
        let r = probe(format!("{base}/locked")).await;
        assert!(r.ok && r.status == Some(401), "{}", r.detail);
        assert_eq!(r.aredn, Some(aredn("http-ok", Some(401))));
        let r = probe(format!("{base}/gone")).await;
        assert_eq!(r.aredn, Some(aredn("http-status", Some(404))));
        // the node's curl checks certificates, so an https target it can't verify fails
        let (tls, _) = server(b"not a TLS server\r\n");
        let r = probe(format!("https://127.0.0.1:{tls}/")).await;
        assert_eq!(r.aredn, Some(aredn("https-untrusted", None)));
        let closed = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let r = probe(format!("https://127.0.0.1:{closed}/")).await;
        assert_eq!(r.aredn, Some(aredn("http-unreachable", None)));
        // off the mesh this box only reaches the node's page, which says nothing of the target
        let r = probe("http://192.168.1.1/".into()).await;
        assert_eq!(r.aredn, None, "{}", r.detail);
    }

    #[test]
    fn our_own_check_goes_where_people_go() {
        let p = local();
        assert_eq!(
            p.own_url("http://tst-cam:8080/x"),
            "http://tst-cam:8080/x",
            "the link as advertised, so a bare name listed in allow_hosts still matches"
        );
        assert_eq!(
            p.own_url("http://tst-node/a/redirect?http://127.0.0.1:81/cam"),
            "http://127.0.0.1:81/cam"
        );
        let away = "http://tst-node/a/redirect?http://example.com/";
        assert_eq!(
            p.own_url(away),
            away,
            "off the mesh only the node's page is ours"
        );
    }

    #[test]
    fn the_node_fetches_bare_names_under_local_mesh_and_redirects_at_their_target() {
        let u = |l: &str| node_url(l).map(String::from);
        assert_eq!(
            u("http://tst-cam:8080/snap?x=1").as_deref(),
            Some("http://tst-cam.local.mesh:8080/snap?x=1")
        );
        assert_eq!(u("http://10.1.2.3/").as_deref(), Some("http://10.1.2.3/"));
        assert_eq!(
            u("http://tst-node:80/a/redirect?http://user:pw@tst-cam/snap.jpg").as_deref(),
            Some("http://user:pw@tst-cam/snap.jpg"),
            "a Redirect service's target is fetched as it stands"
        );
        assert_eq!(
            u("http://tst-cam:8080/api.cgi?cmd=Snap&channel=0").as_deref(),
            Some("http://tst-cam.local.mesh:8080/api.cgi?cmd=Snap"),
            "the node's shell ends the unquoted address at the first &"
        );
        assert_eq!(
            u("http://tst-node:80/a/redirect?http://10.1.2.3/x?a=1;b=2").as_deref(),
            Some("http://10.1.2.3/x?a=1"),
            "or ;"
        );
        assert_eq!(u("tcp://tst-cam:22/"), None);
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
        let port = http_server(|_, _| reply("200 OK", "", "hello"));
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
