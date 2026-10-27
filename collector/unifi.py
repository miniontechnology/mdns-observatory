#!/usr/bin/env python3
"""Optional UniFi controller enrichment.

Polls the controller's client list on a timer and keeps a MAC/IP -> client
record cache the API endpoints use to label talkers, group members and UPnP
devices with their UniFi name, AP/switch and network.

Two auth modes, tried in order:

1. UNIFI_API_KEY — keys created on UniFi OS Settings -> Control Plane ->
   Integrations authenticate the official Integration API
   (/proxy/network/integration/v1/...). Requires recent UniFi OS/Network
   app; the same key is also tried against the classic stat/sta endpoint
   as a fallback (accepted on some firmware).
2. UNIFI_USER + UNIFI_PASS — a local UniFi account logs in via
   /api/auth/login and the classic /api/s/<site>/stat/sta endpoint is used
   (works on every firmware, needs a real login account).

Environment:
    UNIFI_HOST          e.g. https://192.168.1.1   (no trailing path)
    UNIFI_API_KEY       integrations-page API key          (optional)
    UNIFI_USER          local account username             (optional)
    UNIFI_PASS          local account password             (optional)
    UNIFI_SITE          site slug or display name          (default: default)
    UNIFI_POLL_SECONDS  poll interval                      (default: 60)

Everything is a no-op when no credentials are configured.
"""

import http.cookiejar
import json
import os
import ssl
import threading
import time
import urllib.parse
import urllib.request

UNIFI_HOST = os.environ.get("UNIFI_HOST", "").rstrip("/")
UNIFI_API_KEY = os.environ.get("UNIFI_API_KEY", "")
UNIFI_USER = os.environ.get("UNIFI_USER", "")
UNIFI_PASS = os.environ.get("UNIFI_PASS", "")
UNIFI_SITE = os.environ.get("UNIFI_SITE", "default")
POLL_SECONDS = float(os.environ.get("UNIFI_POLL_SECONDS", "60"))

_cache = {"by_mac": {}, "by_ip": {}, "updated": 0.0, "count": 0, "error": None,
          "site": None, "opener": None, "mode": None}
_lock = threading.Lock()


def enabled() -> bool:
    return bool(UNIFI_HOST and (UNIFI_API_KEY or (UNIFI_USER and UNIFI_PASS)))


def _ssl_ctx():
    # Controllers ship self-signed certs; this is read-only telemetry.
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _get(url, opener=None):
    headers = {"Accept": "application/json"}
    if UNIFI_API_KEY:
        headers["X-API-KEY"] = UNIFI_API_KEY
    req = urllib.request.Request(url, headers=headers)
    if opener is None:
        with urllib.request.urlopen(req, timeout=8, context=_ssl_ctx()) as r:
            return json.loads(r.read())
    with opener.open(req, timeout=8) as r:
        return json.loads(r.read())


def _resolve_site_key():
    """UNIFI_SITE may be the API slug ('default') or display name
    ('EMF UDM'). Resolve via self/sites to the slug."""
    if _cache["site"]:
        return _cache["site"]
    for base in ("/proxy/network", ""):
        try:
            data = _get(f"{UNIFI_HOST}{base}/api/self/sites")
            for s in data.get("data", []):
                if s.get("name") == UNIFI_SITE or (s.get("desc") or "").lower() == UNIFI_SITE.lower():
                    _cache["site"] = s["name"]
                    return s["name"]
            break
        except Exception:
            continue
    return UNIFI_SITE


def _login_opener():
    """Cookie-jar opener logged in via /api/auth/login (local account)."""
    if _cache["opener"]:
        return _cache["opener"]
    cj = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(cj),
        urllib.request.HTTPSHandler(context=_ssl_ctx()),
    )
    req = urllib.request.Request(
        f"{UNIFI_HOST}/api/auth/login",
        data=json.dumps({"username": UNIFI_USER, "password": UNIFI_PASS}).encode(),
        headers={"Content-Type": "application/json"},
    )
    with opener.open(req, timeout=8) as r:
        r.read()
    _cache["opener"] = opener
    return opener


def _fetch_integration():
    """Official Integration API — the surface integrations-page keys are for."""
    sites = _get(f"{UNIFI_HOST}/proxy/network/integration/v1/sites").get("data", [])
    if not sites:
        raise RuntimeError("no sites returned")
    site = None
    for s in sites:
        if s.get("name") == UNIFI_SITE or (s.get("desc") or "").lower() == UNIFI_SITE.lower() or s.get("meta", {}).get("desc") == UNIFI_SITE:
            site = s
            break
    site = site or sites[0]
    _cache["site"] = site.get("id") or site.get("name")
    data = _get(f"{UNIFI_HOST}/proxy/network/integration/v1/sites/{_cache['site']}/clients")
    out = []
    for cl in data.get("data", []):
        out.append({
            "name": cl.get("name") or cl.get("hostname") or "",
            "ap": cl.get("uplinkDeviceName") or cl.get("uplink_device_name") or cl.get("ap_name"),
            "network": cl.get("networkName") or cl.get("network"),
            "essid": cl.get("essid"),
            "wired": cl.get("isWired") if "isWired" in cl else cl.get("type") == "WIRED",
            "ip": cl.get("ipAddress") or cl.get("ip"),
            "mac": cl.get("macAddress") or cl.get("mac"),
        })
    return out


def _fetch_classic(opener=None):
    """Classic Network API stat/sta."""
    site = urllib.parse.quote(_resolve_site_key(), safe="")
    for base in ("/proxy/network", ""):
        url = f"{UNIFI_HOST}{base}/api/s/{site}/stat/sta"
        try:
            data = _get(url, opener=opener)
            return [{
                "name": cl.get("name") or cl.get("hostname") or "",
                "ap": cl.get("ap_name") or cl.get("last_uplink_name") or cl.get("uplink_name"),
                "network": cl.get("network"),
                "essid": cl.get("essid"),
                "wired": cl.get("is_wired"),
                "ip": cl.get("ip"),
                "mac": (cl.get("mac") or "").lower(),
            } for cl in data.get("data", [])]
        except Exception:
            continue
    raise RuntimeError("stat/sta unreachable")


def _fetch_clients():
    errs = []
    if UNIFI_API_KEY:
        try:
            return _fetch_integration()
        except Exception as e:
            errs.append(f"integration API: {e}")
        try:
            return _fetch_classic()
        except Exception as e:
            errs.append(f"classic API w/ key: {e}")
    if UNIFI_USER and UNIFI_PASS:
        try:
            return _fetch_classic(opener=_login_opener())
        except Exception as e:
            _cache["opener"] = None  # force re-login next poll (expired session)
            errs.append(f"classic API w/ login: {e}")
    raise RuntimeError("; ".join(errs) if errs else "no credentials configured")


def _poll():
    while True:
        try:
            clients = _fetch_clients()
            by_mac, by_ip = {}, {}
            for rec in clients:
                m = (rec.pop("mac", None) or "").lower()
                if m:
                    by_mac[m] = rec
                if rec.get("ip"):
                    by_ip[rec["ip"]] = rec
            with _lock:
                _cache.update(
                    {"by_mac": by_mac, "by_ip": by_ip,
                     "updated": time.time(), "count": len(clients), "error": None}
                )
        except Exception as e:
            with _lock:
                _cache["error"] = str(e)
        time.sleep(POLL_SECONDS)


def start():
    if enabled():
        threading.Thread(target=_poll, daemon=True).start()


def lookup(mac=None, ip=None):
    """Return the UniFi client record for a MAC or IP, else None."""
    with _lock:
        if mac:
            rec = _cache["by_mac"].get(mac.lower())
            if rec:
                return rec
        if ip:
            return _cache["by_ip"].get(ip)
    return None


def status() -> dict:
    with _lock:
        return {
            "enabled": enabled(),
            "host": UNIFI_HOST if enabled() else "",
            "clients": _cache["count"],
            "updated": _cache["updated"] or None,
            "error": _cache["error"],
        }
