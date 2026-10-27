#!/usr/bin/env python3
"""mDNS Observatory collector + dashboard API.

Receives batched events from sensors, stores them in SQLite, and serves
a dashboard plus JSON API.
"""

import hmac
import json
import os
import sqlite3
import threading
import time
from contextlib import closing

import unifi
from fastapi import FastAPI, Query, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

DB_PATH = os.environ.get("DB_PATH", "/data/mdns.db")
CHATTY_PPS = float(os.environ.get("CHATTY_PPS", "5"))  # src sustaining >this pps over a minute is "chatty"
RETENTION_HOURS = int(os.environ.get("RETENTION_HOURS", "72"))
# Optional shared secret: when set, sensors must send it as X-Sensor-Token.
# Leave unset on a trusted LAN to skip auth entirely.
SENSOR_TOKEN = os.environ.get("SENSOR_TOKEN", "")

app = FastAPI(title="mDNS Observatory")
_local = threading.local()
_write_lock = threading.Lock()


def db() -> sqlite3.Connection:
    if not hasattr(_local, "conn"):
        os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
        _local.conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        _local.conn.row_factory = sqlite3.Row
        _local.conn.execute("PRAGMA journal_mode=WAL")
    return _local.conn


def init_db():
    with closing(sqlite3.connect(DB_PATH)) as c:
        c.executescript(
            """
            CREATE TABLE IF NOT EXISTS packets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts REAL, sensor_id TEXT, interface TEXT, vlan INTEGER,
                src_mac TEXT, src_ip TEXT, dst_ip TEXT, ip_ttl INTEGER,
                is_response INTEGER, unicast INTEGER, parse_error INTEGER, size INTEGER
            );
            CREATE INDEX IF NOT EXISTS idx_packets_ts ON packets(ts);
            CREATE INDEX IF NOT EXISTS idx_packets_src ON packets(src_ip, ts);

            CREATE TABLE IF NOT EXISTS questions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts REAL, sensor_id TEXT, vlan INTEGER,
                src_ip TEXT, src_mac TEXT, name TEXT, qtype TEXT, unicast_wanted INTEGER
            );
            CREATE INDEX IF NOT EXISTS idx_questions_ts ON questions(ts);
            CREATE INDEX IF NOT EXISTS idx_questions_name ON questions(name);

            CREATE TABLE IF NOT EXISTS answers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts REAL, sensor_id TEXT, vlan INTEGER,
                src_ip TEXT, src_mac TEXT, name TEXT, rtype TEXT,
                ttl INTEGER, rdata TEXT, section TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_answers_ts ON answers(ts);
            CREATE INDEX IF NOT EXISTS idx_answers_name ON answers(name);

            CREATE TABLE IF NOT EXISTS igmp_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts REAL, sensor_id TEXT, vlan INTEGER,
                src_ip TEXT, src_mac TEXT, dst_ip TEXT,
                group_addr TEXT, action TEXT, record TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_igmp_ts ON igmp_events(ts);
            CREATE INDEX IF NOT EXISTS idx_igmp_group ON igmp_events(group_addr);

            CREATE TABLE IF NOT EXISTS services (
                instance TEXT PRIMARY KEY,
                type TEXT, host TEXT, port INTEGER,
                addresses TEXT, txt TEXT,
                first_seen REAL, last_seen REAL,
                sensor_id TEXT, vlan INTEGER
            );
            CREATE TABLE IF NOT EXISTS hosts (
                hostname TEXT PRIMARY KEY,
                addresses TEXT, last_seen REAL
            );

            CREATE TABLE IF NOT EXISTS ssdp_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts REAL, sensor_id TEXT, vlan INTEGER,
                src_ip TEXT, src_mac TEXT, dst_ip TEXT, dport INTEGER,
                method TEXT, st TEXT, nts TEXT, usn TEXT,
                location TEXT, server TEXT, mcast INTEGER
            );
            CREATE INDEX IF NOT EXISTS idx_ssdp_ts ON ssdp_events(ts);
            CREATE INDEX IF NOT EXISTS idx_ssdp_usn ON ssdp_events(usn);

            CREATE TABLE IF NOT EXISTS upnp_devices (
                usn TEXT PRIMARY KEY,
                sts TEXT, src_ip TEXT, src_mac TEXT,
                location TEXT, server TEXT,
                first_seen REAL, last_seen REAL,
                vlan INTEGER, last_nts TEXT
            );

            CREATE TABLE IF NOT EXISTS goodbyes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts REAL, sensor_id TEXT, vlan INTEGER,
                src_ip TEXT, src_mac TEXT,
                proto TEXT, what TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_goodbyes_ts ON goodbyes(ts);
            """
        )
        try:
            c.execute("ALTER TABLE services ADD COLUMN gone INTEGER DEFAULT 0")
        except sqlite3.OperationalError:
            pass
        c.commit()


@app.on_event("startup")
def startup():
    init_db()
    unifi.start()


def update_services(c, ts, sensor_id, vlan, answers):
    """Fold answer records into the service + host tables."""
    for a in answers:
        name, rtype, rdata = a["name"], a["rtype"], a["rdata"]
        if rtype == "PTR" and name.rstrip(".").endswith(".local"):
            inst = rdata.split(" (")[0] if " (" in rdata else rdata
            inst = inst.rstrip(".")
            svc_type = name.rstrip(".")
            c.execute(
                """INSERT INTO services (instance, type, first_seen, last_seen, sensor_id, vlan)
                   VALUES (?,?,?,?,?,?)
                   ON CONFLICT(instance) DO UPDATE SET
                     last_seen=excluded.last_seen, type=excluded.type,
                     sensor_id=excluded.sensor_id, vlan=excluded.vlan, gone=0""",
                (inst, svc_type, ts, ts, sensor_id, vlan),
            )
        elif rtype == "SRV":
            inst = name.rstrip(".")
            target, _, port = rdata.partition(":")
            port_num = port.split(" ")[0]
            c.execute(
                """INSERT INTO services (instance, host, port, first_seen, last_seen, sensor_id, vlan)
                   VALUES (?,?,?,?,?,?,?)
                   ON CONFLICT(instance) DO UPDATE SET
                     host=excluded.host, port=excluded.port,
                     last_seen=excluded.last_seen, sensor_id=excluded.sensor_id, vlan=excluded.vlan, gone=0""",
                (inst, target.rstrip("."), port_num, ts, ts, sensor_id, vlan),
            )
        elif rtype == "TXT":
            inst = name.rstrip(".")
            c.execute(
                """INSERT INTO services (instance, txt, first_seen, last_seen, sensor_id, vlan)
                   VALUES (?,?,?,?,?,?)
                   ON CONFLICT(instance) DO UPDATE SET
                     txt=excluded.txt, last_seen=excluded.last_seen""",
                (inst, rdata, ts, ts, sensor_id, vlan),
            )
        elif rtype in ("A", "AAAA"):
            host = name.rstrip(".")
            row = c.execute("SELECT addresses FROM hosts WHERE hostname=?", (host,)).fetchone()
            addrs = set(json.loads(row[0])) if row else set()
            addrs.add(rdata)
            c.execute(
                """INSERT INTO hosts (hostname, addresses, last_seen) VALUES (?,?,?)
                   ON CONFLICT(hostname) DO UPDATE SET
                     addresses=excluded.addresses, last_seen=excluded.last_seen""",
                (host, json.dumps(sorted(addrs)), ts),
            )
            # attach addresses to services pointing at this host
            c.execute(
                """UPDATE services SET addresses=? WHERE host=?""",
                (json.dumps(sorted(addrs)), host),
            )


@app.post("/api/events")
async def ingest(request: Request):
    if SENSOR_TOKEN and not hmac.compare_digest(
        request.headers.get("x-sensor-token", ""), SENSOR_TOKEN
    ):
        return JSONResponse({"ok": False, "error": "unauthorized"}, status_code=401)
    body = await request.json()
    sensor_id = body.get("sensor_id", "unknown")
    interface = body.get("interface", "")
    events = body.get("events", [])
    c = db()
    now = time.time()
    try:
      with _write_lock:  # one writer at a time — SQLite serializes writes anyway
        for ev in events:
            ts = ev.get("ts", now)
            vlan = ev.get("vlan", 0)
            if ev.get("kind") == "igmp":
                for g in ev.get("groups", []):
                    c.execute(
                        "INSERT INTO igmp_events (ts,sensor_id,vlan,src_ip,src_mac,dst_ip,group_addr,action,record) VALUES (?,?,?,?,?,?,?,?,?)",
                        (ts, sensor_id, vlan, ev.get("src_ip"), ev.get("src_mac"), ev.get("dst_ip"), g["group"], g["action"], g["record"]),
                    )
                continue
            if ev.get("kind") == "ssdp":
                c.execute(
                    "INSERT INTO ssdp_events (ts,sensor_id,vlan,src_ip,src_mac,dst_ip,dport,method,st,nts,usn,location,server,mcast) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (ts, sensor_id, vlan, ev.get("src_ip"), ev.get("src_mac"), ev.get("dst_ip"),
                     ev.get("dport"), ev.get("method"), ev.get("st"), ev.get("nts"),
                     ev.get("usn"), ev.get("location"), ev.get("server"),
                     1 if ev.get("mcast") else 0),
                )
                usn = ev.get("usn")
                if usn:
                    base = usn.split("::")[0]  # uuid before the service suffix
                    row = c.execute("SELECT sts FROM upnp_devices WHERE usn=?", (base,)).fetchone()
                    sts = set(json.loads(row[0])) if row else set()
                    if ev.get("st"):
                        sts.add(ev["st"])
                    c.execute(
                        """INSERT INTO upnp_devices (usn,sts,src_ip,src_mac,location,server,first_seen,last_seen,vlan,last_nts)
                           VALUES (?,?,?,?,?,?,?,?,?,?)
                           ON CONFLICT(usn) DO UPDATE SET sts=excluded.sts, src_ip=excluded.src_ip,
                             src_mac=excluded.src_mac, location=COALESCE(excluded.location, upnp_devices.location),
                             server=COALESCE(excluded.server, upnp_devices.server),
                             last_seen=excluded.last_seen, last_nts=excluded.last_nts""",
                        (base, json.dumps(sorted(sts)), ev.get("src_ip"), ev.get("src_mac"),
                         ev.get("location"), ev.get("server"), ts, ts, vlan, ev.get("nts")),
                    )
                if ev.get("nts") == "ssdp:byebye":
                    c.execute(
                        "INSERT INTO goodbyes (ts,sensor_id,vlan,src_ip,src_mac,proto,what) VALUES (?,?,?,?,?,?,?)",
                        (ts, sensor_id, vlan, ev.get("src_ip"), ev.get("src_mac"), "ssdp", ev.get("st") or usn),
                    )
                continue
            is_resp = 1 if ev.get("is_response") else 0
            c.execute(
                """INSERT INTO packets
                   (ts,sensor_id,interface,vlan,src_mac,src_ip,dst_ip,ip_ttl,is_response,unicast,parse_error,size)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    ts, sensor_id, interface, vlan, ev.get("src_mac"), ev.get("src_ip"),
                    ev.get("dst_ip"), ev.get("ip_ttl"), is_resp,
                    1 if ev.get("unicast") else 0, 1 if ev.get("parse_error") else 0,
                    ev.get("size"),
                ),
            )
            for q in ev.get("questions", []):
                c.execute(
                    "INSERT INTO questions (ts,sensor_id,vlan,src_ip,src_mac,name,qtype,unicast_wanted) VALUES (?,?,?,?,?,?,?,?)",
                    (ts, sensor_id, vlan, ev.get("src_ip"), ev.get("src_mac"), q["name"], q["qtype"], 1 if q.get("unicast_wanted") else 0),
                )
            for a in ev.get("answers", []):
                c.execute(
                    "INSERT INTO answers (ts,sensor_id,vlan,src_ip,src_mac,name,rtype,ttl,rdata,section) VALUES (?,?,?,?,?,?,?,?,?,?)",
                    (ts, sensor_id, vlan, ev.get("src_ip"), ev.get("src_mac"), a["name"], a["rtype"], a["ttl"], a["rdata"], a["section"]),
                )
                # RFC 6762 goodbye: records re-announced with TTL 0
                if a["ttl"] == 0 and a["rtype"] in ("PTR", "SRV"):
                    what = a["rdata"] if a["rtype"] == "PTR" else a["name"]
                    c.execute(
                        "INSERT INTO goodbyes (ts,sensor_id,vlan,src_ip,src_mac,proto,what) VALUES (?,?,?,?,?,?,?)",
                        (ts, sensor_id, vlan, ev.get("src_ip"), ev.get("src_mac"), "mdns", what),
                    )
                    inst = what.split(" (")[0].rstrip(".") if a["rtype"] == "PTR" else a["name"].rstrip(".")
                    c.execute("UPDATE services SET gone=1 WHERE instance=?", (inst,))
            update_services(c, ts, sensor_id, vlan, ev.get("answers", []))
        # cheap retention sweep
        cutoff = now - RETENTION_HOURS * 3600
        c.execute("DELETE FROM packets WHERE ts < ?", (cutoff,))
        c.execute("DELETE FROM questions WHERE ts < ?", (cutoff,))
        c.execute("DELETE FROM answers WHERE ts < ?", (cutoff,))
        c.execute("DELETE FROM igmp_events WHERE ts < ?", (cutoff,))
        c.execute("DELETE FROM ssdp_events WHERE ts < ?", (cutoff,))
        c.execute("DELETE FROM goodbyes WHERE ts < ?", (cutoff,))
        c.commit()
    except Exception as e:
        c.rollback()
        return JSONResponse({"ok": False, "error": str(e)}, status_code=500)
    return {"ok": True, "received": len(events)}


# ---------- API ----------

@app.get("/api/summary")
def summary():
    c = db()
    now = time.time()
    row = lambda q, *a: c.execute(q, a).fetchone()

    p1m = row("SELECT COUNT(*) n FROM packets WHERE ts > ?", now - 60)["n"]
    p5m = row("SELECT COUNT(*) n FROM packets WHERE ts > ?", now - 300)["n"]
    talkers = row("SELECT COUNT(DISTINCT src_ip) n FROM packets WHERE ts > ?", now - 300)["n"]
    services = row("SELECT COUNT(*) n FROM services WHERE last_seen > ?", now - 86400)["n"]
    sensors = [dict(r) for r in c.execute(
        "SELECT sensor_id, interface, COUNT(DISTINCT vlan) vlans, MAX(ts) last_seen FROM packets GROUP BY sensor_id"
    )]
    return {
        "pps_1m": round(p1m / 60, 2),
        "pps_5m": round(p5m / 300, 2),
        "packets_1m": p1m,
        "talkers_5m": talkers,
        "services_24h": services,
        "sensors": sensors,
    }


@app.get("/api/timeseries")
def timeseries(minutes: int = Query(60, le=1440)):
    c = db()
    since = time.time() - minutes * 60
    rows = c.execute(
        """SELECT CAST(ts/60 AS INT)*60 AS minute,
                  SUM(CASE WHEN is_response=1 THEN 1 ELSE 0 END) responses,
                  SUM(CASE WHEN is_response=0 THEN 1 ELSE 0 END) queries
           FROM packets WHERE ts > ? GROUP BY minute ORDER BY minute""",
        (since,),
    ).fetchall()
    return {"series": [{"t": r["minute"], "queries": r["queries"], "responses": r["responses"]} for r in rows]}


@app.get("/api/talkers")
def talkers(minutes: int = Query(60, le=1440)):
    c = db()
    since = time.time() - minutes * 60
    rows = c.execute(
        """SELECT src_ip, src_mac, COUNT(*) packets,
                  SUM(is_response) responses,
                  COUNT(*) - SUM(is_response) queries,
                  ROUND(AVG(ip_ttl),1) avg_ttl,
                  SUM(CASE WHEN ip_ttl != 255 THEN 1 ELSE 0 END) ttl_not_255,
                  COUNT(DISTINCT vlan) vlans
           FROM packets WHERE ts > ?
           GROUP BY src_ip ORDER BY packets DESC LIMIT 50""",
        (since,),
    ).fetchall()
    total = sum(r["packets"] for r in rows) or 1
    return {
        "talkers": [
            {**dict(r), "share": round(100 * r["packets"] / total, 1),
             "client": unifi.lookup(mac=r["src_mac"], ip=r["src_ip"])} for r in rows
        ]
    }


@app.get("/api/services")
def services():
    c = db()
    rows = c.execute(
        """SELECT s.instance, s.type, s.host, s.port, s.addresses, s.txt,
                  s.first_seen, s.last_seen, s.vlan, s.gone
           FROM services s ORDER BY s.type, s.instance"""
    ).fetchall()
    now = time.time()
    return {
        "services": [
            {**dict(r), "addresses": json.loads(r["addresses"]) if r["addresses"] else [],
             "stale": r["last_seen"] < now - 4500}  # typical mDNS record TTL is 75min
            for r in rows
        ]
    }


@app.get("/api/questions")
def questions(minutes: int = Query(30, le=1440)):
    """Top queried names and whether a matching service is known."""
    c = db()
    since = time.time() - minutes * 60
    rows = c.execute(
        """SELECT name, qtype, COUNT(*) n, COUNT(DISTINCT src_ip) askers,
                  MAX(ts) last_asked
           FROM questions WHERE ts > ?
           GROUP BY name, qtype ORDER BY n DESC LIMIT 50""",
        (since,),
    ).fetchall()
    known = {r[0] for r in c.execute("SELECT type FROM services UNION SELECT instance FROM services")}
    hosts = {r[0] for r in c.execute("SELECT hostname FROM hosts")}
    out = []
    for r in rows:
        base = r["name"].rstrip(".")
        answered = base in known or base in hosts
        out.append({**dict(r), "known_answer": answered})
    return {"questions": out}


@app.get("/api/activity")
def activity(limit: int = Query(50, le=500)):
    c = db()
    rows = c.execute(
        """SELECT p.ts, p.sensor_id, p.vlan, p.src_ip, p.src_mac, p.is_response, p.ip_ttl,
                  (SELECT GROUP_CONCAT(name || '/' || qtype) FROM questions q
                    WHERE q.src_ip = p.src_ip AND abs(q.ts - p.ts) < 0.01 LIMIT 3) qs,
                  (SELECT GROUP_CONCAT(rtype || ' ' || name) FROM answers a
                    WHERE a.src_ip = p.src_ip AND abs(a.ts - p.ts) < 0.01 LIMIT 3) ans
           FROM packets p ORDER BY p.ts DESC LIMIT ?""",
        (limit,),
    ).fetchall()
    return {"activity": [dict(r) for r in rows]}


@app.get("/api/igmp")
def igmp(minutes: int = Query(60, le=1440)):
    """Recent IGMP/MLD membership events (joins, leaves, queries)."""
    c = db()
    since = time.time() - minutes * 60
    rows = c.execute(
        """SELECT ts, sensor_id, vlan, src_ip, src_mac, group_addr, action, record
           FROM igmp_events WHERE ts > ? ORDER BY ts DESC LIMIT 200""",
        (since,),
    ).fetchall()
    return {"events": [dict(r) for r in rows]}


@app.get("/api/memberships")
def memberships():
    """Current multicast group membership estimate: per (src_ip, group, vlan),
    the latest event wins — join/report = member, leave = gone. SQLite's bare
    columns ride along with the MAX(ts) row, so action/record are the latest."""
    c = db()
    rows = c.execute(
        """SELECT src_ip, src_mac, group_addr, vlan, action, record,
                  MAX(ts) last_event, COUNT(*) events
           FROM igmp_events
           GROUP BY src_ip, group_addr, vlan"""
    ).fetchall()
    groups = {}
    left = []
    for r in rows:
        m = dict(r)
        if m["action"] == "query":
            continue  # queries come from routers, not listeners
        if m["action"] in ("join", "report"):
            groups.setdefault(m["group_addr"], []).append(m["src_ip"])
        else:
            left.append(m)
    summary = [
        {"group": g, "members": len(set(v)), "member_ips": sorted(set(v)),
         "members_named": [unifi.lookup(ip=ip) or ip for ip in sorted(set(v))]}
        for g, v in sorted(groups.items())
    ]
    return {"groups": summary, "left": sorted(left, key=lambda x: -x["last_event"])[:50]}


@app.get("/api/alerts")
def alerts():
    c = db()
    now = time.time()
    out = []
    # chatty: > CHATTY_PPS sustained over the last minute
    for r in c.execute(
        """SELECT src_ip, src_mac, COUNT(*) n FROM packets
           WHERE ts > ? GROUP BY src_ip HAVING n > ? ORDER BY n DESC""",
        (now - 60, CHATTY_PPS * 60),
    ):
        out.append({
            "severity": "high",
            "kind": "chatty_device",
            "detail": f"{r['src_ip']} ({r['src_mac']}) sent {r['n']} mDNS packets in the last minute",
        })
    # reflector detection: a MAC that announced many distinct RR names in the
    # window is almost certainly the gateway's mDNS proxy re-originating
    # traffic, not a real device. Excluded from conflict counting and used to
    # explain TTL anomalies.
    reflectors = {r[0] for r in c.execute(
        "SELECT src_mac FROM answers WHERE ts > ? GROUP BY src_mac HAVING COUNT(DISTINCT name) >= 8",
        (now - 600,),
    )}
    # non-255 IP TTL → routed/reflected (or non-compliant) traffic. L2 switches
    # never touch TTL, so either the stack is non-compliant or the packet was
    # re-originated by a router/proxy.
    for r in c.execute(
        """SELECT src_ip, MAX(src_mac) src_mac, COUNT(*) n,
                  MIN(ip_ttl) lo, MAX(ip_ttl) hi FROM packets
           WHERE ts > ? AND ip_ttl != 255 GROUP BY src_ip ORDER BY n DESC LIMIT 10""",
        (now - 600,),
    ):
        native = c.execute(
            "SELECT 1 FROM packets WHERE src_ip=? AND ip_ttl=255 AND ts > ? LIMIT 1",
            (r["src_ip"], now - 600),
        ).fetchone()
        if r["src_mac"] in reflectors:
            why = ("this source announces many unrelated services — almost certainly "
                   "your UniFi mDNS proxy re-originating other VLANs' traffic, which is expected")
            sev = "info"
        elif native:
            why = ("it also sends TTL=255 packets natively → the device itself has a "
                   "non-RFC-compliant stack (TTL is only decremented by routers)")
            sev = "medium"
        else:
            why = ("no TTL=255 packets seen from this source → the traffic is re-originated "
                   "(reflected/proxied across a router) rather than native multicast")
            sev = "medium"
        out.append({
            "severity": sev,
            "kind": "ttl_not_255",
            "detail": f"{r['src_ip']} ({r['src_mac']}) sent {r['n']} mDNS packets at IP TTL {r['lo']}–{r['hi']}; {why}",
        })
    # unicast-destined mdns to port 5353 is fine; flag storms of queries with no answers
    for r in c.execute(
        """SELECT name, COUNT(*) n, COUNT(DISTINCT src_ip) askers FROM questions
           WHERE ts > ? GROUP BY name HAVING n > 60 ORDER BY n DESC LIMIT 10""",
        (now - 600,),
    ):
        known = c.execute(
            "SELECT 1 FROM services WHERE instance=? OR type=? LIMIT 1", (r["name"].rstrip("."), r["name"].rstrip(".")
        )).fetchone()
        if not known:
            out.append({
                "severity": "medium",
                "kind": "unanswered_queries",
                "detail": f"'{r['name']}' queried {r['n']} times by {r['askers']} device(s) in 10 min with no known service advertising it",
            })
    # name conflicts: the same PTR instance name advertised by >1 distinct
    # source. Sources that look like the reflector don't count — reflected
    # copies always carry the gateway's MAC, which would false-positive on
    # every service it mirrors. Only ≥2 real sources is a genuine conflict
    # (two devices claiming one friendly name, e.g. duplicate AirPlay names).
    for r in c.execute(
        """SELECT rdata, GROUP_CONCAT(DISTINCT src_mac) macs,
                  GROUP_CONCAT(DISTINCT src_ip) ips
           FROM answers WHERE rtype='PTR' AND ts > ?
           GROUP BY rdata HAVING COUNT(DISTINCT src_mac) > 1
           ORDER BY COUNT(DISTINCT src_mac) DESC LIMIT 20""",
        (now - 600,),
    ):
        macs = r["macs"].split(",")
        ips = r["ips"].split(",")
        real = [m for m in macs if m not in reflectors]
        pairs = ", ".join(f"{ip}/{m}" for ip, m in zip(ips, macs))
        if len(real) > 1:
            out.append({
                "severity": "high",
                "kind": "name_conflict",
                "detail": f"instance '{r['rdata']}' claimed by {len(real)} different devices ({pairs}) — two devices share one friendly name; legitimate in stereo pairs/groups, otherwise a real conflict",
            })
        elif len(macs) > 1:
            out.append({
                "severity": "info",
                "kind": "reflector_echo",
                "detail": f"instance '{r['rdata']}' also announced by {pairs} — matches the reflector pattern, so this is your UniFi proxy mirroring the service, not a conflict",
            })
    return {"alerts": out, "generated_at": now}


@app.get("/api/ssdp")
def ssdp(minutes: int = Query(60, le=1440)):
    """Recent SSDP/UPnP events: M-SEARCH, NOTIFY alive/byebye, responses."""
    c = db()
    since = time.time() - minutes * 60
    rows = c.execute(
        """SELECT ts, sensor_id, vlan, src_ip, src_mac, dst_ip, dport,
                  method, st, nts, usn, location, server, mcast
           FROM ssdp_events WHERE ts > ? ORDER BY ts DESC LIMIT 300""",
        (since,),
    ).fetchall()
    return {"events": [{**dict(r), "client": unifi.lookup(mac=r["src_mac"], ip=r["src_ip"])} for r in rows]}


@app.get("/api/upnp")
def upnp():
    """UPnP device catalog keyed by USN uuid: what each device advertises,
    its description URL and server string, and whether it said byebye."""
    c = db()
    rows = c.execute("SELECT * FROM upnp_devices ORDER BY src_ip").fetchall()
    return {
        "devices": [
            {**{k: v for k, v in dict(r).items() if k != "sts"},
             "sts": json.loads(r["sts"]) if r["sts"] else [],
             "bye": r["last_nts"] == "ssdp:byebye",
             "client": unifi.lookup(mac=r["src_mac"], ip=r["src_ip"])}
            for r in rows
        ]
    }


@app.get("/api/goodbyes")
def goodbyes(minutes: int = Query(120, le=1440)):
    """Graceful departures: mDNS TTL=0 records and SSDP ssdp:byebye."""
    c = db()
    since = time.time() - minutes * 60
    rows = c.execute(
        "SELECT * FROM goodbyes WHERE ts > ? ORDER BY ts DESC LIMIT 200", (since,)
    ).fetchall()
    return {"goodbyes": [{**dict(r), "client": unifi.lookup(mac=r["src_mac"], ip=r["src_ip"])} for r in rows]}


@app.get("/api/unifi")
def unifi_status():
    return unifi.status()


# ---------- dashboard ----------

STATIC = os.path.join(os.path.dirname(__file__), "static")


@app.get("/")
def index():
    return FileResponse(os.path.join(STATIC, "index.html"))


app.mount("/static", StaticFiles(directory=STATIC), name="static")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", "8053")))
