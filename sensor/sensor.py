#!/usr/bin/env python3
"""mDNS Observatory sensor.

Captures UDP/5353 traffic off a raw AF_PACKET socket, parses it with dnslib,
and ships events in batches to the collector over HTTP.

Environment:
    COLLECTOR_URL   e.g. http://192.168.1.10:8053   (required)
    INTERFACE       interface to sniff, e.g. eth0    (required)
    SENSOR_ID       label for this sensor            (default: hostname)
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

ETH_P_ALL = 0x0003
ETH_P_8021Q = 0x8100
ETH_P_IP = 0x0800
ETH_P_IPV6 = 0x86DD
IPPROTO_UDP = 17
MDNS_PORT = 5353

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
        if proto != IPPROTO_UDP:
            return None
        ip_ttl = data[offset + 8]
        src_ip = socket.inet_ntoa(data[offset + 12 : offset + 16])
        dst_ip = socket.inet_ntoa(data[offset + 16 : offset + 20])
        udp = offset + ihl
    elif ethertype == ETH_P_IPV6:
        proto = data[offset + 6]
        if proto != IPPROTO_UDP:
            return None
        ip_ttl = data[offset + 7]  # hop limit
        src_ip = socket.inet_ntop(socket.AF_INET6, data[offset + 8 : offset + 24])
        dst_ip = socket.inet_ntop(socket.AF_INET6, data[offset + 24 : offset + 40])
        udp = offset + 40
    else:
        return None

    if len(data) < udp + 8:
        return None
    sport, dport, ulen = struct.unpack("!HHH", data[udp : udp + 6])
    if sport != MDNS_PORT and dport != MDNS_PORT:
        return None
    payload = data[udp + 8 : udp + ulen]

    try:
        dns = DNSRecord.parse(payload)
    except Exception:
        return {
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
