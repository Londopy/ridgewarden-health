//! `ridgewarden-health.toml`.

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use ridgewarden_client::alerts::{AlertCfg, EmailCfg};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub core: CoreCfg,
    #[serde(default = "d_data_dir")]
    pub data_dir: PathBuf,
    #[serde(default = "d_listen")]
    pub listen: SocketAddr,
    /// results older than this count as stale ("unknown"); make it a few probe rounds
    #[serde(default = "d_fresh")]
    pub fresh_s: u64,
    #[serde(default)]
    pub probe: ProbeCfg,
    /// friendly site names: node name -> label, e.g. "n0call-cuesta" = "Cuesta Peak"
    #[serde(default)]
    pub site_names: BTreeMap<String, String>,
    /// Configure this on one site only, or every site sends the same alert.
    #[serde(default)]
    pub alerts: AlertCfg,
    /// service owners who hear about their own services on their own channels
    #[serde(default, rename = "owner")]
    pub owners: Vec<OwnerCfg>,
    /// things that can't be probed, which check in by POSTing to this app instead
    #[serde(default, rename = "heartbeat")]
    pub heartbeats: Vec<HeartbeatCfg>,
}

/// Someone who looks after some services. Alerts about services whose name, host or link
/// contains one of `matches` go to these channels too, on top of the main `[alerts]` ones.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(deny_unknown_fields)]
pub struct OwnerCfg {
    pub name: String,
    pub matches: Vec<String>,
    #[serde(default)]
    pub ntfy: Option<String>,
    #[serde(default)]
    pub discord: Option<String>,
    #[serde(default)]
    pub webhooks: Vec<String>,
    #[serde(default)]
    pub email: Option<EmailCfg>,
    /// by default the main `[alerts]` settings
    #[serde(default)]
    pub quiet_hours: Option<String>,
    #[serde(default)]
    pub repeat_hours: Option<u64>,
}

/// A name made safe for file names and links: "Winlink team" -> "winlink-team".
pub fn slug(name: &str) -> String {
    let s: String = name
        .to_ascii_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect();
    s.trim_matches('-').to_string()
}

impl OwnerCfg {
    pub fn slug(&self) -> String {
        slug(&self.name)
    }

    pub fn covers(&self, text: &str) -> bool {
        let t = text.to_ascii_lowercase();
        self.matches
            .iter()
            .map(|m| m.trim().to_ascii_lowercase())
            .any(|m| !m.is_empty() && t.contains(&m))
    }

    /// The owner's channels, with the main config's quiet hours and repeats unless the
    /// owner sets their own, and always its maintenance windows and silences.
    pub fn alert_cfg(&self, main: &AlertCfg) -> AlertCfg {
        AlertCfg {
            ntfy: self.ntfy.clone(),
            discord: self.discord.clone(),
            webhooks: self.webhooks.clone(),
            email: self.email.clone(),
            quiet_hours: self
                .quiet_hours
                .clone()
                .unwrap_or_else(|| main.quiet_hours.clone()),
            repeat_hours: self.repeat_hours.unwrap_or(main.repeat_hours),
            public_url: main.public_url.clone(),
            maintenance: main.maintenance.clone(),
            silence: main.silence.clone(),
        }
    }
}

/// A push heartbeat: something that POSTs to `/push/<token>` at least every `every_s`.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct HeartbeatCfg {
    pub name: String,
    pub every_s: u64,
    /// how late a beat may be before it counts as missed
    #[serde(default = "d_grace")]
    pub grace_s: u64,
}

/// Where the ridgewarden core runs on this box.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct CoreCfg {
    #[serde(default = "d_core_url")]
    pub url: String,
    /// the core's `local.token`; needed to log probe results
    #[serde(default = "d_token")]
    pub token_file: PathBuf,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct ProbeCfg {
    #[serde(default = "d_true")]
    pub enabled: bool,
    #[serde(default = "d_300")]
    pub interval_s: u64,
    #[serde(default = "d_10")]
    pub timeout_s: u64,
    /// cap on services probed per round, so a big mesh can't turn probing into load
    #[serde(default = "d_200")]
    pub max_targets: usize,
    /// at most this many sites probe each service (0: every site); the sites share the
    /// work out among themselves, and each still probes the services on its own node
    #[serde(default = "d_5")]
    pub sites_per_service: usize,
    /// failed checks in a row before a site calls a service down
    #[serde(default = "d_3")]
    pub fail_after: u32,
    /// good checks in a row before it counts as back up
    #[serde(default = "d_2")]
    pub ok_after: u32,
    /// probe from this local address (multi-homed hosts, and the simulator)
    #[serde(default)]
    pub source_ip: Option<IpAddr>,
    #[serde(default, rename = "override")]
    pub overrides: Vec<ProbeOverride>,
    /// hosts to allow besides mesh names and 10.x / 44.x addresses (e.g. a simulator)
    #[serde(default)]
    pub allow_hosts: Vec<String>,
}

/// Per-service checks: services advertised as http that aren't, ones not to probe at all,
/// and pages that must return a given status or contain a given word.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(deny_unknown_fields)]
pub struct ProbeOverride {
    /// case-insensitive substring of the service name
    pub name_contains: String,
    /// "http", "tcp", "winlink", "meshchat" or "skip"; by default meshchat for links ending
    /// in /meshchat, http for other http(s) links, winlink on ports 8772 and 8774, else tcp
    #[serde(default)]
    pub mode: Option<String>,
    /// HTTP status codes that count as working; by default anything below 500
    #[serde(default)]
    pub expect_status: Vec<u16>,
    /// text the page must contain, e.g. "Main Page" (status and keyword checks apply to http checks)
    #[serde(default)]
    pub keyword: Option<String>,
}

fn d_data_dir() -> PathBuf {
    PathBuf::from("/var/lib/ridgewarden-health")
}
fn d_listen() -> SocketAddr {
    "0.0.0.0:8791".parse().unwrap()
}
fn d_core_url() -> String {
    "http://127.0.0.1:8790".into()
}
fn d_token() -> PathBuf {
    PathBuf::from("/var/lib/ridgewarden/local.token")
}
fn d_fresh() -> u64 {
    960
}
fn d_true() -> bool {
    true
}
fn d_300() -> u64 {
    300
}
fn d_10() -> u64 {
    10
}
fn d_200() -> usize {
    200
}
fn d_5() -> usize {
    5
}
fn d_grace() -> u64 {
    60
}
fn d_3() -> u32 {
    3
}
fn d_2() -> u32 {
    2
}

impl Default for CoreCfg {
    fn default() -> Self {
        Self {
            url: d_core_url(),
            token_file: d_token(),
        }
    }
}

impl Default for ProbeCfg {
    fn default() -> Self {
        Self {
            enabled: true,
            interval_s: 300,
            timeout_s: 10,
            max_targets: 200,
            sites_per_service: 5,
            fail_after: 3,
            ok_after: 2,
            source_ip: None,
            overrides: vec![],
            allow_hosts: vec![],
        }
    }
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let cfg: Config =
            toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> Result<()> {
        if self.probe.interval_s < 60 {
            bail!("probe.interval_s must be at least 60");
        }
        if self.fresh_s < 2 * self.probe.interval_s {
            bail!("fresh_s must be at least two probe intervals, since rounds are jittered");
        }
        if self.probe.timeout_s == 0 {
            bail!("probe.timeout_s must be at least 1");
        }
        if self.probe.fail_after == 0 || self.probe.ok_after == 0 {
            bail!("probe.fail_after and probe.ok_after must be at least 1");
        }
        for o in &self.probe.overrides {
            if let Some(m) = &o.mode
                && !matches!(m.as_str(), "http" | "tcp" | "winlink" | "meshchat" | "skip")
            {
                bail!(
                    "probe override mode must be http, tcp, winlink, meshchat or skip, not {m:?}"
                );
            }
        }
        self.alerts.validate()?;
        self.validate_owners()?;
        self.validate_heartbeats()
    }

    fn validate_owners(&self) -> Result<()> {
        let mut seen = std::collections::BTreeSet::new();
        for o in &self.owners {
            if o.slug().is_empty() {
                bail!("every [[owner]] needs a name with letters or digits in it");
            }
            if !seen.insert(o.slug()) {
                bail!("two owners have the same name, {:?}", o.name);
            }
            if o.matches.iter().all(|m| m.trim().is_empty()) {
                bail!("owner {:?} needs at least one entry in `matches`", o.name);
            }
            if o.ntfy.is_none() && o.discord.is_none() && o.webhooks.is_empty() && o.email.is_none()
            {
                bail!(
                    "owner {:?} has no ntfy, discord, webhooks or email to send to",
                    o.name
                );
            }
            o.alert_cfg(&self.alerts)
                .validate()
                .with_context(|| format!("owner {:?}", o.name))?;
        }
        Ok(())
    }

    fn validate_heartbeats(&self) -> Result<()> {
        let mut seen = std::collections::BTreeSet::new();
        for h in &self.heartbeats {
            let name = h.name.trim();
            if slug(name).is_empty()
                || name.chars().count() > 64
                || name.chars().any(char::is_control)
            {
                bail!(
                    "heartbeat names must be 1 to 64 characters with a letter or digit, not {:?}",
                    h.name
                );
            }
            if !seen.insert(slug(name)) {
                bail!("two heartbeats have names that differ only in punctuation: {name:?}");
            }
            if h.every_s < 60 {
                bail!("heartbeat {name:?}: every_s must be at least 60");
            }
        }
        Ok(())
    }

    pub fn db_path(&self) -> PathBuf {
        self.data_dir.join("health.db")
    }

    pub fn label(&self, node: &str) -> String {
        label(&self.site_names, node)
    }
}

pub fn label(names: &BTreeMap<String, String>, node: &str) -> String {
    names
        .iter()
        .find(|(k, _)| ridgewarden_client::util::norm_node(k) == node)
        .map(|(_, v)| v.clone())
        .unwrap_or_else(|| node.to_string())
}

pub const EXAMPLE: &str = r#"# ridgewarden-health configuration
data_dir = "/var/lib/ridgewarden-health"
listen = "0.0.0.0:8791"
fresh_s = 960

[core]
url = "http://127.0.0.1:8790"
token_file = "/var/lib/ridgewarden/local.token"

[probe]
enabled = true
interval_s = 300
timeout_s = 10
# a site calls a service down after this many failed checks in a row, up after ok_after good ones
fail_after = 3
ok_after = 2
# at most this many sites probe each service (0: every site does)
sites_per_service = 5
# The check is picked from the link: links ending in /meshchat ask MeshChat's API, other
# http(s) links get an HTTP request, ports 8772 and 8774 wait for a Winlink login prompt
# (without logging in), and anything else gets a TCP connection. Overrides go by name:
# [[probe.override]]
# name_contains = "winlink"
# mode = "winlink"            # http, tcp, winlink, meshchat or skip
# [[probe.override]]
# name_contains = "wiki"
# expect_status = [200]
# keyword = "Main Page"

[site_names]
# "n0call-cuesta" = "Cuesta Peak"

# Alerts: set these up on one site only, or every site sends the same alert.
[alerts]
# ntfy = "http://10.1.2.3/mesh-alerts"
# discord = "https://discord.com/api/webhooks/..."
# webhooks = []
# public_url = "http://n0call-pi.local.mesh:8791"
# quiet_hours = "22-6"
# repeat_hours = 4

# [[alerts.maintenance]]
# matches = "cuesta"
# from = "2026-11-22T15:00:00Z"
# to = "2026-11-22T19:00:00Z"
# note = "tower work"

# [[alerts.silence]]
# matches = "camera"
# reason = "owner is replacing it"
# review = "2027-01-31"

# Mail goes through this box's sendmail program (msmtp or Postfix; see the README).
# [alerts.email]
# to = ["ops@example.org"]
# from = "mesh-health@example.org"
# sendmail = "/usr/sbin/sendmail"

# Owners hear about their own services, on top of the channels above.
# [[owner]]
# name = "Winlink team"
# matches = ["winlink", "tst-gateway"]   # any service whose name, host or link contains one
# ntfy = "http://10.1.2.3/winlink-team"
# quiet_hours = "21-7"
# [owner.email]
# to = ["winlink@example.org"]
# from = "mesh-health@example.org"

# Push heartbeats, for things that can't be probed. Each gets a secret URL to POST to;
# `ridgewarden-health heartbeats` prints them.
# [[heartbeat]]
# name = "Backup link to the EOC"
# every_s = 3600
# grace_s = 300
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn example_parses() {
        let c: Config = toml::from_str(EXAMPLE).unwrap();
        c.validate().unwrap();
    }

    /// The example with every commented-out setting turned on.
    fn example_in_full() -> String {
        EXAMPLE
            .lines()
            .map(|l| match l.strip_prefix("# ") {
                Some(rest)
                    if rest.starts_with('[')
                        || rest.starts_with('"')
                        || rest.split_once(" = ").is_some_and(|(k, _)| {
                            k.bytes().all(|b| b.is_ascii_lowercase() || b == b'_')
                        }) =>
                {
                    rest
                }
                _ => l,
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn every_example_setting_is_valid() {
        let c: Config = toml::from_str(&example_in_full()).unwrap();
        c.validate().unwrap();
        assert_eq!(c.owners.len(), 1);
        assert_eq!(c.heartbeats.len(), 1);
        assert!(c.alerts.email.is_some());
        let o = c.owners[0].alert_cfg(&c.alerts);
        assert_eq!(o.quiet_hours, "21-7", "the owner's own quiet hours");
        assert_eq!(o.repeat_hours, 4, "the main repeat setting");
        assert_eq!(
            o.maintenance.len(),
            1,
            "maintenance windows hold owners' alerts too"
        );
        assert!(o.discord.is_none(), "only the owner's own channels");
    }

    fn with(extra: &str) -> Result<Config> {
        let c: Config = toml::from_str(&format!("{EXAMPLE}\n{extra}"))?;
        c.validate()?;
        Ok(c)
    }

    #[test]
    fn owners_and_heartbeats_are_checked() {
        let owner =
            "[[owner]]\nname = \"Cams\"\nmatches = [\"camera\"]\nntfy = \"http://10.1.1.1/c\"";
        let c = with(owner).unwrap();
        assert!(c.owners[0].covers("svc http://cam/ DOWN Camera 3 on tst-paso"));
        assert!(!c.owners[0].covers("Winlink on tst-cuesta"));
        assert!(
            with("[[owner]]\nname = \"Cams\"\nmatches = [\"camera\"]").is_err(),
            "no channels"
        );
        assert!(
            with("[[owner]]\nname = \"Cams\"\nmatches = [\" \"]\nntfy = \"http://a/\"").is_err()
        );
        assert!(
            with(&format!("{owner}\n{owner}")).is_err(),
            "same name twice"
        );
        assert!(
            with("[[owner]]\nname = \"Cams\"\nmatches = [\"c\"]\nntfy = \"ftp://a/\"").is_err()
        );
        let beat = |name: &str, every: u64| {
            format!("[[heartbeat]]\nname = \"{name}\"\nevery_s = {every}\n")
        };
        assert!(with(&beat("Backup", 3600)).is_ok());
        assert!(with(&beat("Backup", 30)).is_err());
        assert!(with(&beat("!!", 3600)).is_err());
        assert!(with(&format!("{}{}", beat("Backup", 3600), beat("backup!", 600))).is_err());
    }
}
