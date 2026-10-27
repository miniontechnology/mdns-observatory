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
            """
        )
        c.commit()


@app.on_event("startup")
def startup():
    init_db()


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
                     sensor_id=excluded.sensor_id, vlan=excluded.vlan""",
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
                     last_seen=excluded.last_seen, sensor_id=excluded.sensor_id, vlan=excluded.vlan""",
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
            update_services(c, ts, sensor_id, vlan, ev.get("answers", []))
        # cheap retention sweep
        cutoff = now - RETENTION_HOURS * 3600
        c.execute("DELETE FROM packets WHERE ts < ?", (cutoff,))
        c.execute("DELETE FROM questions WHERE ts < ?", (cutoff,))
        c.execute("DELETE FROM answers WHERE ts < ?", (cutoff,))
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
            {**dict(r), "share": round(100 * r["packets"] / total, 1)} for r in rows
        ]
    }


@app.get("/api/services")
def services():
    c = db()
    rows = c.execute(
        """SELECT s.instance, s.type, s.host, s.port, s.addresses, s.txt,
                  s.first_seen, s.last_seen, s.vlan
           FROM services s ORDER BY s.type, s.instance"""
    ).fetchall()
    return {
        "services": [
            {**dict(r), "addresses": json.loads(r["addresses"]) if r["addresses"] else []}
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
    # non-255 IP TTL → routed/reflected (or non-compliant) traffic
    for r in c.execute(
        """SELECT src_ip, COUNT(*) n, ROUND(AVG(ip_ttl),1) ttl FROM packets
           WHERE ts > ? AND ip_ttl != 255 GROUP BY src_ip ORDER BY n DESC LIMIT 10""",
        (now - 600,),
    ):
        out.append({
            "severity": "medium",
            "kind": "ttl_not_255",
            "detail": f"{r['src_ip']} sent {r['n']} packets with avg IP TTL {r['ttl']} (not 255 → likely reflected/proxied or non-RFC-compliant)",
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
    return {"alerts": out, "generated_at": now}


# ---------- dashboard ----------

STATIC = os.path.join(os.path.dirname(__file__), "static")


@app.get("/")
def index():
    return FileResponse(os.path.join(STATIC, "index.html"))


app.mount("/static", StaticFiles(directory=STATIC), name="static")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", "8053")))
