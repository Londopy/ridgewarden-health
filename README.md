# ridgewarden-health

[![CI](https://github.com/Londopy/ridgewarden-health/actions/workflows/ci.yml/badge.svg)](https://github.com/Londopy/ridgewarden-health/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/Londopy/ridgewarden-health)](https://github.com/Londopy/ridgewarden-health/releases/latest)
[![changelog](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/Londopy/ridgewarden-health/gh-pages/changelog-badge.json)](CHANGELOG.md)
[![License](https://img.shields.io/github/license/Londopy/ridgewarden-health)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-stable-orange)](https://www.rust-lang.org)
[![Linux](https://img.shields.io/badge/platform-Linux%20(Pi%20%7C%20x86__64)-555)](#building-from-source)

**Know which mesh services are really up, from every site, and why.**

A ridgewarden app for AREDN meshes. It probes every service the mesh advertises from each site that runs it, and logs the results through the site's ridgewarden core, so every site sees every site's results. A service that answers from one site and not another is a link problem, not a service problem, and the page says so.

It needs a [ridgewarden](https://github.com/Londopy/ridgewarden) core running on the same box. The core is the only part that polls the AREDN node and syncs with other sites; this app reads the core's event feed. Spec sheet 06 of the AREDN app suite.

## Features

- States: **UP**, **PARTIAL** (reachable from some sites: a link problem), **DOWN**, **STALE** (advertised but never seen working), **UNPUBLISHED-BUT-ALIVE** (dropped by AREDN's hourly check but still working), and **UNKNOWN** when the data is too old to say.
- Says why AREDN's own check would drop a service, worked out the way the node does it. The node keeps an `http` link only if it ends on a 200 or 401 within 10 seconds (redirects followed, 2 seconds to connect); any other link, `https` included, needs a TCP connection within 2 seconds or a UDP port that doesn't refuse. Each probe does the same from where it sits, so the service page can say "it answers HTTP 404, point the link at a page that returns 200", or that a Winlink port advertised as `http` can never pass, or that a host answers but probably drops ping.
- Checks that know the protocol. Links ending in `/meshchat` are asked through MeshChat's own API (`/cgi-bin/meshchat?action=config`, which answers with its version and zone, and `action=sync_status` for when it last synced with another MeshChat node). Ports 8772 (RMS Relay, Winlink telnet) and 8774 (Pat's telnet) get a Winlink check: connect and wait for the `Callsign :` prompt those servers send first. It never sends anything, so it never logs in.
- Push heartbeats for things that can't be probed: a backup job, a battery monitor, a station on a timer. Each one POSTs to its own secret URL on one site; that site decides whether it's on time and logs the verdict as a signed event, so every site sees it.
- Thresholds: a site calls a service down after 3 failed checks in a row and up again after 2 good ones, so one dropped packet doesn't page anyone.
- If every check from a site fails, that site is probably cut off. Its results are left out and the page says so, instead of calling the whole mesh down.
- Uptime for 24 hours, 30 days and a year, counted over checks from every site. Raw results are kept 35 days and rolled up by day for 400 days.
- A page per service with a response-time chart from each site, a strip of recent checks, and each site's view of what AREDN's check would do.
- Per-service checks: expected status codes and a keyword the page must contain.
- Alerts to email, ntfy, Discord or any webhook, one per problem, with an acknowledge link, repeats until acknowledged, quiet hours for anything not critical, maintenance windows and silences that expire on a review date.
- Owner routing: an owner's services (matched by name, host or link) also alert to that owner's own channels, with their own quiet hours and their own acknowledgements.
- Counts what it has found: how many listed services were never seen working and how many working services AREDN dropped, overall and in the first week.
- Picks what to probe only from the service list your own node reports, never from another site's copy, and connects only to mesh addresses: every name must resolve to 10.x or 44.x (unless listed in `probe.allow_hosts`), so neither an advert nor a redirect can aim a probe at this box or off the mesh. Services AREDN lists without a link (port 0) have nothing to probe and are left out. Self-signed https certificates are accepted, since a probe asks whether a service answers, not who it is.
- A site's results count only under the name of the node its core polls on its own LAN, so one station can't report for another or invent sites.
- Polite: one round every 5 minutes by default, jittered, at most 200 targets and 8 at a time, and each service probed from at most 5 sites. The sites share services out among themselves without talking about it, and when one goes quiet the next takes over.
- `/api/services` returns the same data as JSON.

## Install

On a Raspberry Pi or Linux box that already runs the [ridgewarden core](https://github.com/Londopy/ridgewarden):

```sh
curl -fsSL https://github.com/Londopy/ridgewarden-health/releases/latest/download/install.sh | sudo sh
```

Or take the `.deb` from the [releases page](https://github.com/Londopy/ridgewarden-health/releases/latest): `sudo apt install ./ridgewarden-health_<version>_arm64.deb` (`_amd64` on a PC). Either way the download is checked against the release key your core already trusts, `/etc/ridgewarden/health.toml` is written if missing, and the service starts once the core is set up. The page is on port 8791.

Every release also has each download as a `.torrent`, with its GitHub download as the web seed, and signed `SHA256SUMS.txt` checksums.

The service runs as its own user, `ridgewarden-health`, in the core's `ridgewarden` group, so it can sign events through the core but can't read the station's key. Run commands that touch the app's data as that user, so files keep the right owner: `sudo -u ridgewarden-health ridgewarden-health --config /etc/ridgewarden/health.toml <command>`.

## Usage

```sh
ridgewarden-health init --config /etc/ridgewarden/health.toml
ridgewarden-health run  --config /etc/ridgewarden/health.toml
```

The page is on `http://<pi>:8791/`. Add it to the core's dashboard with an `[[app]]` entry in `ridgewarden.toml`.

To try a link by hand, say after changing an advert, probe it once from this box:

```sh
ridgewarden-health check http://tst-shack.local.mesh:8080/meshchat
```

It prints the kind of check, the result, and what AREDN's check on the node would make of it.

## Configuration

`/etc/ridgewarden/health.toml` (`init` writes a commented one):

```toml
[core]
url = "http://127.0.0.1:8790"
token_file = "/var/lib/ridgewarden/local.token"   # lets this app log results via the core

[probe]
interval_s = 300
fail_after = 3              # failed checks in a row before a site calls it down
ok_after = 2                # good checks in a row before it's back up
sites_per_service = 5       # at most this many sites probe each service; 0 for every site

[[probe.override]]          # pick the check by service name
name_contains = "gateway"
mode = "winlink"            # http, tcp, winlink, meshchat or skip

[[probe.override]]          # a page that must really be the wiki, not an error page
name_contains = "wiki"
expect_status = [200]
keyword = "Main Page"
```

Without an override the check comes from the link: `/meshchat` links get the MeshChat check, ports 8772 and 8774 the Winlink check, other `http` and `https` links an HTTP request, and anything else with a port a TCP connection.

With `sites_per_service`, each site still probes the services on its own node, since it's one LAN hop from them. A service probed from fewer sites can still show PARTIAL, but only among the sites probing it.

### Alerts

Set alerts up on one site only, or every site sends the same one.

```toml
[alerts]
ntfy = "https://ntfy.sh/your-mesh-topic"      # or a self-hosted ntfy on the mesh
discord = "https://discord.com/api/webhooks/..."
webhooks = ["http://10.1.2.3:9000/hook"]       # JSON: app, key, state, severity, title, text, ack_url
public_url = "http://n0call-pi.local.mesh:8791" # for acknowledge links and push URLs
quiet_hours = "22-6"                            # UTC; only critical alerts go out
repeat_hours = 4                                # until someone acknowledges

[alerts.email]
to = ["ops@example.org"]
from = "mesh-health@example.org"
sendmail = "/usr/sbin/sendmail"                 # the default

[[alerts.maintenance]]
matches = "cuesta"                              # any service whose name, host or link contains this
from = "2026-11-22T15:00:00Z"
to = "2026-11-22T19:00:00Z"
note = "tower work"

[[alerts.silence]]
matches = "camera"
reason = "owner is replacing it"
review = "2027-01-31"                           # alerts come back after this day
```

Down services and missed heartbeats are critical, partly reachable ones are warnings, and a working service that AREDN dropped from the list is informational. Each alert goes out when it starts, again every `repeat_hours` until someone acknowledges it, and once when it clears. The acknowledge link opens a page with a button, so a chat app's link preview can't acknowledge it for you.

### Email

Mail is handed to the box's `sendmail` program, so no mail password lives in this config. Two ways to set that up:

- **msmtp** (simplest): `sudo apt install msmtp-mta`, then put your mail server in `/etc/msmtprc` (not `~/.msmtprc`: the service can't see home directories), readable only by a group for the apps that send mail: `sudo groupadd -f mailers && sudo chgrp mailers /etc/msmtprc && sudo chmod 640 /etc/msmtprc && sudo usermod -a -G mailers ridgewarden-health`, then restart the service. Leave `logfile` unset or use `syslog on`, since the service can't write log files outside its data directory. Nothing else changes.
- **Postfix**: its `sendmail` drops mail into `/var/spool/postfix/maildrop` through the setgid `postdrop` helper. The service runs with `NoNewPrivileges=yes` and `ProtectSystem=strict`, which stop both, so give it the group and that one directory with a drop-in:

  ```sh
  sudo mkdir -p /etc/systemd/system/ridgewarden-health.service.d
  printf '[Service]\nSupplementaryGroups=postdrop\nReadWritePaths=/var/spool/postfix/maildrop\n' |
      sudo tee /etc/systemd/system/ridgewarden-health.service.d/postfix.conf
  sudo systemctl daemon-reload && sudo systemctl restart ridgewarden-health
  ```

  This isn't in the shipped unit because systemd refuses to start a unit whose `SupplementaryGroups` names a group that doesn't exist, which it won't on a box without Postfix.

Either way, a failed send is logged with the program's own error, and the alert is tried again next round if no other channel took it.

### Owners

```toml
[[owner]]
name = "Winlink team"
matches = ["winlink", "tst-gateway"]   # any service whose name, host or link contains one
ntfy = "http://10.1.2.3/winlink-team"  # and/or discord, webhooks, [owner.email]
quiet_hours = "21-7"                   # optional; the [alerts] settings otherwise
```

Owners hear about their services on top of the `[alerts]` channels, not instead of them. Maintenance windows and silences apply to owners too. Each owner's alerts are kept in their own small database next to the main one, so an owner acknowledging an alert stops their repeats without stopping anyone else's.

### Push heartbeats

```toml
[[heartbeat]]
name = "Backup link to the EOC"
every_s = 3600            # how often it should check in
grace_s = 300             # how late it may be; 60 by default
```

Each heartbeat gets its own secret URL. The secret comes from this app's database, not the config, so print the URLs as the service's user:

```sh
sudo -u ridgewarden ridgewarden-health --config /etc/ridgewarden/health.toml heartbeats
```

Then have the job POST to it when it runs, adding `?status=down&msg=...` to report a problem:

```sh
curl -fsS -m 10 -X POST http://n0call-pi.local.mesh:8791/push/<token>
curl -fsS -m 10 -X POST "http://n0call-pi.local.mesh:8791/push/<token>?status=down&msg=disk%20full"
```

The site that receives a heartbeat judges it once a minute and logs the verdict through its core. Other sites show what that site said; if they stop hearing from it, the heartbeat shows UNKNOWN rather than DOWN. After the app has been stopped, a heartbeat gets one full period (plus grace) before it counts as late, since nothing could check in meanwhile. A beat sooner than 5 seconds after the last one is refused, and an address that sends 30 wrong push or acknowledge tokens in a minute is refused until the minute is up; other addresses aren't affected.

The app believes only events from stations the core trusts: its own key, plus the keys listed under `[trust]` in `ridgewarden.toml`.

## Limits

- The AREDN node's verdict is worked out from where this box sits, not from the node: the node checks from its own LAN, through its own port forwards in NAT mode, and in DMZ mode only after pinging and arping the host, none of which this app can see. When a working service gets dropped and our check passes, the page says which of those to look at.
- AREDN 4.26's on-node service watch would let the node report changes as they happen, but it needs a package installed on each node. This app polls through the core instead.
- Whether an owner heard about an outage from an alert before a user reported it can't be measured here: the app doesn't know when people noticed.
- The Winlink check proves a Winlink server is listening, not that it can reach a CMS or pass mail; that would mean logging in.
- The Postfix drop-in was checked with systemd on a test box (the shipped unit blocks the spool, the drop-in allows it), not with Postfix itself installed.

## Building from source

This repo builds against the core's shared client crate, so check the core out next to it:

```sh
git clone https://github.com/Londopy/ridgewarden
git clone https://github.com/Londopy/ridgewarden-health
cd ridgewarden-health
cargo build --release
cargo test
```

## Contributing

Issues and pull requests are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md), and add a line under `Unreleased` in [CHANGELOG.md](CHANGELOG.md) for anything a user would notice.

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).
