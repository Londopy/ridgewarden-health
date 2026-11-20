# Changelog

All notable changes to ridgewarden-health are listed here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html). The section for a version is what appears on its GitHub release page. Validated in CI by [patchnotes](https://github.com/Londopy/patchnotes).

## [Unreleased]

## [0.1.0] - 2026-11-20

### Added

- Runs as its own system user, `ridgewarden-health`, in the core's `ridgewarden` group: it can sign events through the core but not read the station key.
- States: UP, PARTIAL (reachable from some sites: a link problem), DOWN, STALE (advertised but never answered), UNPUBLISHED-BUT-ALIVE (dropped by AREDN's hourly check but still working), and UNKNOWN when the data is too old to say.
- "Up for 12 d" and "down since 03:14" timelines, with each site's own result and latency.
- Picks what to probe only from the service list your own node reports, and connects only to names that resolve to mesh addresses (10.x, 44.x) unless `probe.allow_hosts` lists them, so no advert or redirect can aim a probe at this box or off the mesh.
- A site's results count only under the node its core polls on its own LAN.
- Services listed without a link (port 0) are left out; self-signed https certificates are accepted.
- The service page explains why AREDN's own check would drop a service (it accepts only HTTP 200 or 401 within 10 seconds) and what to change.
- Failure and recovery thresholds, 3 and 2 checks by default.
- A site where every check failed is treated as cut off and left out of the verdicts.
- Uptime for 24 hours, 30 days and a year; daily rollups kept 400 days.
- A page per service with a response-time chart and a strip of recent checks.
- Expected status codes and keyword checks per service.
- Alerts to ntfy, Discord and webhooks with acknowledge links, repeats, quiet hours, maintenance windows and silences with a review date.
- Email alerts through the box's sendmail (msmtp or Postfix), with a systemd drop-in for Postfix in the README.
- Every probe also works out what AREDN's own check would do, the way the node does it: HTTP 200 or 401 within 10 s with redirects followed, or for other links a TCP connection within 2 s and then a UDP send that isn't refused. Each site's view is on the service page.
- MeshChat check through its API (`action=config` and `action=sync_status`), picked for links ending in `/meshchat`.
- Winlink check that waits for the `Callsign :` prompt on ports 8772 and 8774 and never sends anything, so it never logs in.
- Push heartbeats with a secret URL each, judged by the receiving site and shared with every site as signed events. `ridgewarden-health heartbeats` prints the URLs.
- Per-owner alert routing: owners matched by service name, host or link get their own channels, quiet hours and acknowledgements.
- `probe.sites_per_service` caps how many sites probe each service (5 by default); the sites share the work out by rendezvous hashing.
- The services page counts the stale and wrongly unpublished services found, overall and in the first week.
- `ridgewarden-health check <link>` probes one link from this box and prints what AREDN's check would make of it.
- Wrong push and acknowledge tokens are limited to 30 a minute per address.
- `fresh_s` must be at least two probe intervals, so jittered rounds can't make sites flap to UNKNOWN.
- Probe results from other sites are checked before use: node names, link and text lengths, and a cap on results per event.

[Unreleased]: https://github.com/Londopy/ridgewarden-health/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Londopy/ridgewarden-health/releases/tag/v0.1.0
