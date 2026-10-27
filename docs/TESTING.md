# Test plan — mDNS Observatory

How to verify each feature, in order. Two tiers: **lab** (no real devices
needed — the simulator + scripted packet injections) and **real network**
(the procedures that prove it catches the problems you actually have).

## Lab tier

Run the unit tests — they inject synthetic frames through the sensor parser:

```
pip install pytest dnslib requests
python -m pytest tests/ -v
```

Covers: mDNS query parse, TTL=0 goodbye answer, SSDP M-SEARCH / NOTIFY
byebye / unicast 200-OK response, IGMPv2 report, and non-matching ports
being ignored.

End-to-end smoke test (sensor → collector → dashboard):

```
docker compose up -d --build          # or the published images
python3 tools/simulator.py --rate 5   # emits mDNS + IGMP traffic; needs sudo
```

Then fire one SSDP datagram by hand (no root needed — it's a normal UDP send):

```
python3 - <<'EOF'
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
s.sendto(b"NOTIFY * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"
         b"NT: urn:schemas-upnp-org:device:ZonePlayer:1\r\nNTS: ssdp:alive\r\n"
         b"USN: uuid:TEST-1::urn:schemas-upnp-org:device:ZonePlayer:1\r\n"
         b"LOCATION: http://10.0.0.99:1400/xml/dd.xml\r\nSERVER: Test UPnP/1.0\r\n\r\n",
         ("239.255.255.250", 1900))
EOF
```

Expected: it appears in **SSDP activity** and the **UPnP devices** card within
~10 s, and `curl localhost:8053/api/ssdp` returns it.

## Real-network tier — what to check on the live deployment

### Baseline
1. Open the dashboard. Within a minute, the service catalog should list your
   real `_sonos._tcp`, `_airplay._tcp`, `_raop._tcp`, `_spotify-connect._tcp`
   instances. If the catalog is empty, the sensor isn't seeing the wire
   (wrong `INTERFACE`, or the Synology NIC isn't in promiscuous mode).
2. Top talkers should be plausible: Apple TVs, Sonos players, the UDM itself
   if it reflects. Any device sustaining >5 pps will be flagged chatty —
   at your scale (>60 IoT devices) one misbehaving unit can dominate airtime.

### mDNS troubleshooting checks
- **"Device can't discover X"**: look up X's instance name in the *Top
  queried names* card — `unknown` means queries are going out but nothing
  is answering on this VLAN (either the device is down, or the reflector
  isn't carrying its announcements across). `yes` means the answer exists
  and the problem is elsewhere (client-side, IGMP snooping, ACL).
- **Reflected vs. native**: the `TTL≠255` column/alert distinguishes packets
  the UniFi mDNS proxy re-injected (TTL 255 → decremented or rewritten)
  from genuine LAN multicast. A healthy reflected service shows the
  original VLAN's announcements plus proxy copies.

### SSDP / UPnP / Sonos checks
- **Sonos discovery**: open the Sonos app on a phone on the same VLAN. You
  should see `M-SEARCH` bursts (ST `urn:schemas-upnp-org:...` or
  `urn:smartspeaker-audio:service:SpeakerGroup:1`) in SSDP activity, and
  each player answering. If searches appear but **no responses** come back,
  the players aren't hearing the multicast — check switch IGMP snooping and
  any "block LAN to WLAN multicast" options.
- **Missing speaker in the app**: find its MAC in the UPnP devices card.
  Present with recent NOTIFYs → the player thinks it's fine; the search
  path is broken (usually wireless client isolation or snooping pruning).
  Absent or `byebye` → the player actually left the network.
- **`X-RINCON` headers**: Sonos household IDs ride along in events; multiple
  households on one VLAN explains "wrong speaker controls the room" issues.

### Departure / churn checks (goodbye tracking)
- **Graceful**: power a Sonos/TV off via its UI or app → expect an
  `ssdp:byebye` and/or mDNS TTL=0 goodbye in the Goodbyes panel, and the
  catalog row flips to **goodbye** dimmed within seconds.
- **Ungraceful**: yank the power cord → *no* goodbye; the row stays normal
  until the record ages past ~75 min, then shows **stale**. That's the
  signature distinguishing "device shut down politely" from "device
  crashed / lost connectivity" — the classic flaky-Sonos question.
- Josh.ai/Control4 controllers issue SSDP M-SEARCHes on a schedule; watch
  whether the target STs get answered — a stream of unanswered searches is
  your "controller can't find device" smoking gun.

### IGMP/membership checks
- The **Multicast groups** card should show `224.0.0.251` (mDNS) and
  `239.255.255.250` (SSDP) with member lists roughly matching your known
  speakers/displays. A Sonos *not* in the member list won't receive
  multicast searches at all — that's a snooping/leave problem upstream.
- Leaves flapping (join/leave alternating within minutes) usually means
  the switch's querier timing fights the device — check the joins/leaves
  feed for repeat offenders.

### UniFi enrichment checks
- Set `UNIFI_HOST` + `UNIFI_API_KEY` in the collector env. Within a minute,
  `/api/unifi` should report `clients: N` and `error: null`.
- Names + AP/switch should appear inline in talkers, group members, SSDP
  and goodbye rows ("Living Room @ Den AP (10.0.5.42)").
- With enrichment on, a chatty alert immediately tells you which physical
  AP/port the offender is on — go unplug that one cable instead of hunting.
