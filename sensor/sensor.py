#!/usr/bin/env python3
"""mDNS Observatory sensor.

Captures UDP/5353 traffic off a raw AF_PACKET socket, parses it with dnslib,
and ships events in batches to the collector over HTTP.

Environment:
    COLLECTOR_URL   e.g. http://192.168.1.10:8053   (required)
    INTERFACE       interface to sniff, e.g. eth0    (required)
    SENSOR_ID       label for this sensor            (default: hostname)
    SENSOR_TOKEN    shared secret; sent as X-Sensor-Token when the
                    collector has SENSOR_TOKEN set     (optional)
    BATCH_SECONDS   flush interval                   (default: 2)
    BATCH_MAX       max events per flush             (default: 500)
"""

import json
import os
import signal
import socket
import struct
import sys
import threading
import time

import requests
from dnslib import DNSRecord, QTYPE, RCODE

COLLECTOR_URL = os.environ["COLLECTOR_URL"].rstrip("/")
INTERFACE = os.environ["INTERFACE"]
SENSOR_ID = os.environ.get("SENSOR_ID") or socket.gethostname()
BATCH_SECONDS = float(os.environ.get("BATCH_SECONDS", "2"))
BATCH_MAX = int(os.environ.get("BATCH_MAX", "500"))
SENSOR_TOKEN = os.environ.get("SENSOR_TOKEN", "")
_HEADERS = {"X-Sensor-Token": SENSOR_TOKEN} if SENSOR_TOKEN else {}

ETH_P_ALL = 0x0003
ETH_P_8021Q = 0x8100
ETH_P_IP = 0x0800
ETH_P_IPV6 = 0x86DD
IPPROTO_UDP = 17
IPPROTO_IGMP = 2
IPPROTO_ICMPV6 = 58
MDNS_PORT = 5353
# SSDP runs on UDP 1900 (multicast + unicast responses); Sonos controllers
# additionally use broadcast UDP 6969 for discovery.
SSDP_PORTS = (1900, 6969)
SSDP_MCAST = ("239.255.255.250", "255.255.255.255")

IGMP_TYPES = {0x11: "query", 0x12: "v1_report", 0x16: "v2_report", 0x17: "v2_leave", 0x22: "v3_report"}
MLD_TYPES = {130: "query", 131: "v1_report", 132: "v1_done", 143: "v2_report"}
# group-record types inside v3/v2 reports
RECORD_ACTION = {
    1: ("MODE_IS_INCLUDE", "join"),
    2: ("MODE_IS_EXCLUDE", "join"),
    3: ("CHANGE_TO_INCLUDE_MODE", "join"),
    4: ("CHANGE_TO_EXCLUDE_MODE", "leave"),
    5: ("ALLOW_NEW_SOURCES", "join"),
    6: ("BLOCK_OLD_SOURCES", "leave"),
}

_running = True
_queue = []
_lock = threading.Lock()


def mac(b: bytes) -> str:
    return ":".join(f"{x:02x}" for x in b)


def qtype_name(t: int) -> str:
    try:
        return QTYPE[t]
    except KeyError:
        return str(t)


def label(s: str) -> str:
    """Undo dnslib's \\032 escaping so names display as real text."""
    return s.replace("\\032", " ")


def rdata_summary(rr) -> str:
    """Compact, display-friendly rendering of an RR's rdata."""
    rtype = rr.rtype
    rd = rr.rdata
    try:
        if rtype == 16:  # TXT
            return " ".join(s.decode("utf-8", "replace") for s in rd.strings)
        if rtype == 33:  # SRV
            return f"{label(str(rd.target))}:{rd.port} (pri={rd.priority},w={rd.weight})"
        return label(str(rd))
    except Exception:
        return repr(rd)


def parse_igmp(data: bytes, l4: int, is_v6: bool):
    """Parse an IGMP (IPv4, proto 2) or MLD (ICMPv6) packet into an event."""
    if len(data) < l4 + 8:
        return None
    mtype = data[l4]
    table = MLD_TYPES if is_v6 else IGMP_TYPES
    if mtype not in table:
        return None
    name = table[mtype]
    addr_len = 16 if is_v6 else 4
    inet = socket.inet_ntop if is_v6 else socket.inet_ntoa
    inet_args = (socket.AF_INET6,) if is_v6 else ()

    groups = []
    if mtype in (0x22, 143):  # v3/v2 report: group records follow
        if len(data) < l4 + 8 + 4:
            return None
        nrec = struct.unpack("!H", data[l4 + 8 + 2 : l4 + 8 + 4])[0]
        pos = l4 + 8 + 4
        for _ in range(min(nrec, 50)):
            if len(data) < pos + 4 + addr_len:
                break
            rtype, auxlen, nsrc = data[pos], data[pos + 1], struct.unpack("!H", data[pos + 2 : pos + 4])[0]
            grp = inet(*inet_args, data[pos + 4 : pos + 4 + addr_len])
            rname, action = RECORD_ACTION.get(rtype, (f"type_{rtype}", "report"))
            groups.append({"group": grp, "action": action, "record": rname})
            pos += 4 + addr_len + 4 * (nsrc + auxlen)
    else:
        # v1/v2 style: group address sits in the header
        grp = inet(*inet_args, data[l4 + 4 : l4 + 4 + addr_len])
        action = {"query": "query", "v1_done": "leave", "v2_leave": "leave"}.get(name, "join")
        groups.append({"group": grp, "action": action, "record": name})
    return groups


def parse_ssdp(payload: bytes):
    """Parse an SSDP/UPnP datagram (HTTP/1.1-style headers over UDP).

    Returns the interesting fields or None when it doesn't look like SSDP."""
    try:
        text = payload.decode("utf-8", "replace")
    except Exception:
        return None
    lines = text.split("\r\n")
    first = lines[0].strip() if lines else ""
    if first.startswith("HTTP/"):
        method = "response"
    else:
        m = first.split(" ", 1)[0].upper()
        if m not in ("M-SEARCH", "NOTIFY", "M-POST", "SUBSCRIBE", "UNSUBSCRIBE"):
            return None
        method = m.lower().replace("-", "_")
    headers = {}
    for ln in lines[1:]:
        if ":" in ln:
            k, v = ln.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    return {
        "method": method,
        "st": headers.get("st") or headers.get("nt"),
        "nts": headers.get("nts"),
        "usn": headers.get("usn"),
        "location": headers.get("location"),
        "server": headers.get("server"),
        "man": headers.get("man"),
        "mx": headers.get("mx"),
        # Sonos household id — handy to tell multiple Sonos systems apart
        "rincon": headers.get("x-rincon-household"),
    }


def parse_packet(data: bytes):
    """Extract an mDNS event dict from a raw Ethernet frame, or None."""
    if len(data) < 14:
        return None
    ethertype = struct.unpack("!H", data[12:14])[0]
    offset = 14
    vlan = 0
    if ethertype == ETH_P_8021Q:
        tci = struct.unpack("!H", data[14:16])[0]
        vlan = tci & 0x0FFF
        ethertype = struct.unpack("!H", data[16:18])[0]
        offset = 18

    if ethertype == ETH_P_IP:
        ihl = (data[offset] & 0x0F) * 4
        proto = data[offset + 9]
        if proto not in (IPPROTO_UDP, IPPROTO_IGMP):
            return None
        ip_ttl = data[offset + 8]
        src_ip = socket.inet_ntoa(data[offset + 12 : offset + 16])
        dst_ip = socket.inet_ntoa(data[offset + 16 : offset + 20])
        udp = offset + ihl
    elif ethertype == ETH_P_IPV6:
        proto = data[offset + 6]
        if proto not in (IPPROTO_UDP, IPPROTO_ICMPV6):
            return None
        ip_ttl = data[offset + 7]  # hop limit
        src_ip = socket.inet_ntop(socket.AF_INET6, data[offset + 8 : offset + 24])
        dst_ip = socket.inet_ntop(socket.AF_INET6, data[offset + 24 : offset + 40])
        udp = offset + 40
    else:
        return None

    if proto in (IPPROTO_IGMP, IPPROTO_ICMPV6):
        groups = parse_igmp(data, udp, is_v6=(ethertype == ETH_P_IPV6))
        if not groups:
            return None
        return {
            "kind": "igmp",
            "src_mac": mac(data[6:12]),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "ip_ttl": ip_ttl,
            "vlan": vlan,
            "size": len(data),
            "groups": groups,
        }

    if len(data) < udp + 8:
        return None
    sport, dport, ulen = struct.unpack("!HHH", data[udp : udp + 6])
    payload = data[udp + 8 : udp + ulen]
    if sport != MDNS_PORT and dport != MDNS_PORT:
        if sport in SSDP_PORTS or dport in SSDP_PORTS:
            ev = parse_ssdp(payload)
            if ev is None:
                return None
            ev.update({
                "kind": "ssdp",
                "src_mac": mac(data[6:12]),
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "sport": sport,
                "dport": dport,
                "vlan": vlan,
                "size": len(payload),
                "mcast": dst_ip in SSDP_MCAST or dst_ip.lower().startswith("ff0"),
            })
            return ev
        return None

    try:
        dns = DNSRecord.parse(payload)
    except Exception:
        return {
            "kind": "mdns",
            "parse_error": True,
            "src_mac": mac(data[6:12]),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "ip_ttl": ip_ttl,
            "vlan": vlan,
            "size": len(payload),
            "unicast": dport == MDNS_PORT and dst_ip not in ("224.0.0.251",) and not dst_ip.lower().startswith("ff02"),
            "questions": [],
            "answers": [],
        }

    is_response = bool(dns.header.qr)
    questions = [
        {"name": label(str(q.qname)), "qtype": qtype_name(q.qtype), "unicast_wanted": bool(q.qclass & 0x8000)}
        for q in dns.questions
    ]
    answers = [
        {
            "name": label(str(rr.rname)),
            "rtype": qtype_name(rr.rtype),
            "rclass": rr.rclass,
            "ttl": rr.ttl,
            "rdata": rdata_summary(rr),
            "section": sec,
        }
        for sec, rrs in (("answer", dns.rr), ("authority", dns.auth), ("additional", dns.ar))
        for rr in rrs
    ]

    return {
        "kind": "mdns",
        "parse_error": False,
        "src_mac": mac(data[6:12]),
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "ip_ttl": ip_ttl,
        "vlan": vlan,
        "is_response": is_response,
        "size": len(payload),
        "unicast": not (
            dst_ip == "224.0.0.251"
            or dst_ip.lower().startswith("ff02")
            or (is_response and dport == MDNS_PORT)
        ),
        "questions": questions,
        "answers": answers,
    }


def flush():
    while True:
        time.sleep(BATCH_SECONDS)
        with _lock:
            batch, _queue[:] = _queue[:BATCH_MAX], _queue[BATCH_MAX:]
        if not batch:
            continue
        try:
            requests.post(
                f"{COLLECTOR_URL}/api/events",
                json={"sensor_id": SENSOR_ID, "interface": INTERFACE, "events": batch},
                headers=_HEADERS,
                timeout=10,
            )
        except Exception as e:
            print(f"[sensor] flush failed ({len(batch)} events dropped): {e}", file=sys.stderr)


def main():
    print(f"[sensor] id={SENSOR_ID} iface={INTERFACE} collector={COLLECTOR_URL}")
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        s.bind((INTERFACE, 0))
    except PermissionError:
        sys.exit("[sensor] permission denied opening AF_PACKET socket — need NET_RAW (docker default) or root")
    except OSError as e:
        sys.exit(f"[sensor] cannot open {INTERFACE}: {e}")

    threading.Thread(target=flush, daemon=True).start()

    def stop(*_):
        global _running
        _running = False

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)

    seen = 0
    while _running:
        try:
            data, _ = s.recvfrom(65535)
        except OSError:
            break
        ev = parse_packet(data)
        if ev is None:
            continue
        ev["ts"] = time.time()
        with _lock:
            _queue.append(ev)
        seen += 1
        if seen % 500 == 0:
            print(f"[sensor] captured {seen} mDNS packets")


if __name__ == "__main__":
    main()
