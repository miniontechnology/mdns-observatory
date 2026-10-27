#!/usr/bin/env python3
"""Optional UniFi controller enrichment.

Polls the Network controller's client list (stat/sta) on a timer and keeps a
MAC/IP -> client record cache the API endpoints use to label talkers, group
members and UPnP devices with their UniFi name, AP/switch and network.

Environment:
    UNIFI_HOST          e.g. https://192.168.1.1   (no trailing path)
    UNIFI_API_KEY       UniFi OS API key (Settings -> Control Plane -> API keys)
    UNIFI_SITE          site name                   (default: default)
    UNIFI_POLL_SECONDS  poll interval               (default: 60)

Everything is a no-op when UNIFI_HOST/UNIFI_API_KEY are unset.
"""

import json
import os
import ssl
import threading
import time
import urllib.request

UNIFI_HOST = os.environ.get("UNIFI_HOST", "").rstrip("/")
UNIFI_API_KEY = os.environ.get("UNIFI_API_KEY", "")
UNIFI_SITE = os.environ.get("UNIFI_SITE", "default")
POLL_SECONDS = float(os.environ.get("UNIFI_POLL_SECONDS", "60"))

_cache = {"by_mac": {}, "by_ip": {}, "updated": 0.0, "count": 0, "error": None}
_lock = threading.Lock()


def enabled() -> bool:
    return bool(UNIFI_HOST and UNIFI_API_KEY)


def _ssl_ctx():
    # Controllers ship self-signed certs; this is read-only telemetry.
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _fetch_clients():
    # UniFi OS consoles (UDM/UDR/UXG/CK) proxy the Network API at
    # /proxy/network; classic controllers serve it at the root.
    last_err = None
    for base in ("/proxy/network", ""):
        url = f"{UNIFI_HOST}{base}/api/s/{UNIFI_SITE}/stat/sta"
        try:
            req = urllib.request.Request(
                url, headers={"X-API-KEY": UNIFI_API_KEY, "Accept": "application/json"}
            )
            with urllib.request.urlopen(req, timeout=8, context=_ssl_ctx()) as r:
                return json.loads(r.read()).get("data", [])
        except Exception as e:
            last_err = e
    raise last_err


def _record(cl: dict) -> dict:
    return {
        "name": cl.get("name") or cl.get("hostname") or "",
        "ap": cl.get("ap_name") or cl.get("last_uplink_name") or cl.get("uplink_name"),
        "network": cl.get("network"),
        "essid": cl.get("essid"),
        "wired": cl.get("is_wired"),
        "ip": cl.get("ip"),
    }


def _poll():
    while True:
        try:
            clients = _fetch_clients()
            by_mac, by_ip = {}, {}
            for cl in clients:
                rec = _record(cl)
                m = (cl.get("mac") or "").lower()
                if m:
                    by_mac[m] = rec
                if cl.get("ip"):
                    by_ip[cl["ip"]] = rec
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
