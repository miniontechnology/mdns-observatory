# mDNS Observatory

Passive mDNS/DNS-SD observability for multi-VLAN networks: capture sensors per
VLAN ship parsed mDNS traffic to a central collector, which serves a live
dashboard of packet rates, talkers, the service catalog, unanswered queries,
and health alerts (chatty devices, non-255 TTL → reflected/proxied traffic).

Built for UniFi deployments with heavy mDNS device fleets (Sonos, Apple TV,
smart TVs, Josh.ai).

## Architecture

```
┌─────────────┐  HTTP   ┌───────────────┐
│ sensor      │───────→ │ collector     │
│ (per VLAN)  │ JSON    │  SQLite + API │
│ AF_PACKET   │         │  :8053        │
└─────────────┘         └──────┬────────┘
                               └──→ dashboard (browser)
```

- **sensor** — raw-socket capture of UDP/5353, parses with dnslib, batches to
  the collector every 2s. Runs with `network_mode: host` so it sees all
  multicast on the host LAN. Docker on x86 Synology works as-is.
- **collector** — FastAPI + SQLite. Ingest, retention (72h default), service
  catalog state, alerting rules, dashboard UI on port 8053.

## Deploy on Synology (Container Manager / Docker)

**Zero-clone deploy** — grab `deploy/docker-compose.yml`, then:

1. If the GHCR packages are public, skip this. Otherwise, one-time:
   `docker login ghcr.io -u <github-user>` with a PAT (`read:packages` scope)
   so the NAS can pull the private images.
2. Find the interface carrying your primary VLAN: `ip link` on the NAS —
   commonly `eth0`, or `ovs_eth0` when bonded/Open vSwitch. Set it as
   `INTERFACE` in the compose file.
3. `docker compose up -d`
4. Open `http://<synology-ip>:8053`.

Images are built and published to GHCR automatically on every push to `main`
(`.github/workflows/build-images.yml`).

**Dev/local build** — clone the repo, edit `docker-compose.yml` (root), then
`docker compose up -d --build`.

The sensor only sees traffic on the VLAN(s) its interface is on. For the other
VLANs later, either create VLAN subinterfaces on the NAS (`eth0.20` etc.) and
run one sensor per interface, or move sensors to a mirror/monitor port on a
switch configured as a trunk.

### On UniFi itself

UDM Pro/Max runs UniFi OS with Docker available — a sensor can run directly on
the gateway, where every VLAN bridge (`br0`, `br20`, …) is visible:

```
INTERFACE=br20 COLLECTOR_URL=http://<collector>:8053 docker run --net=host ...
```

## What the dashboard shows

- **Rates** — mDNS packets/sec now and trend (queries vs responses/min).
- **Top talkers** — devices generating the most mDNS traffic. Devices sending
  packets with IP TTL ≠ 255 are highlighted — that means the packet was routed
  (e.g. by the UniFi mDNS proxy) rather than native multicast, or the sender
  isn't RFC-compliant.
- **Service catalog** — every advertised instance (`_airplay._tcp`, `_sonos._tcp`,
  …) with its host, port, addresses, VLAN, and last-seen time.
- **Top queried names** — what devices are looking for; "unknown" marks queries
  for names no service advertises (classic discovery-failure symptom).
- **Alerts** — chatty devices (>5 pps sustained), non-255 TTL sources, and
  hot queries with no known advertiser.
- **Activity** — live packet feed.

## Local demo (no real LAN needed)

```
pip install dnslib
python3 collector/app.py &          # collector on :8053, DB in /data or ./data
INTERFACE=eth0 COLLECTOR_URL=http://127.0.0.1:8053 python3 sensor/sensor.py &
python3 tools/simulator.py --rate 3 # synthetic Sonos/ATV/Josh traffic
# open http://localhost:8053
```

Set `DB_PATH=/tmp/mdns.db` to keep the demo DB out of the way.

## Security notes

- **No TLS** — sensor→collector traffic and the dashboard are plain HTTP. This
  is designed for a trusted LAN. If you expose the collector beyond the LAN,
  put it behind a reverse proxy with TLS and auth.
- **Dashboard/API has no auth** — anyone on the network can read the dashboard
  and query the API. The data is mDNS metadata only (device names, service
  types), but treat port 8053 as LAN-only. Firewall it or bind behind a proxy
  if that matters to you.
- **Ingest auth is optional** — set `SENSOR_TOKEN` on both collector and
  sensors to require an `X-Sensor-Token` header on `/api/events`. Unset = open
  ingest (fine on a trusted LAN).
- **Sensor privileges** — needs `network_mode: host` and `NET_RAW` to sniff.
  It only reads packets; it transmits nothing except HTTP to the collector.
- **Collector runs non-root** inside its container (uid 1000).

## Config

| Var | Component | Default | Purpose |
|---|---|---|---|
| `COLLECTOR_URL` | sensor | — | where to POST events |
| `INTERFACE` | sensor | — | interface to sniff |
| `SENSOR_ID` | sensor | hostname | label in dashboard |
| `SENSOR_TOKEN` | both | unset | shared secret for ingest auth (`X-Sensor-Token` header) |
| `BATCH_SECONDS` / `BATCH_MAX` | sensor | 2 / 500 | flush tuning |
| `CHATTY_PPS` | collector | 5 | pps threshold for chatty alert |
| `RETENTION_HOURS` | collector | 72 | packet/question/answer retention |
| `DB_PATH` | collector | /data/mdns.db | SQLite location |

## Roadmap hooks

- Propagation matrix: correlate service announcements across VLAN sensors to
  verify the UniFi mDNS proxy is actually reflecting each service (and detect
  reflector loops — same packet seen on N VLANs).
- SSDP/UPnP capture (UDP 1900 + Sonos broadcast discovery 1900/6969).
- Goodbye-packet tracking (TTL=0 announcements) for device churn visibility.
- IGMP/MLD snooping sanity checks.
