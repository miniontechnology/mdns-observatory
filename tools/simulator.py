#!/usr/bin/env python3
"""Emit realistic synthetic mDNS traffic on the local network.

Useful to validate the sensor+collector pipeline before deploying on a real
LAN, and to demo the dashboard. Sends a mix of queries and announcements for
fictional Sonos / Apple TV / Josh.ai-style devices.

Usage: python3 simulator.py [--rate 2]   (packets/sec, default 2)
Requires: dnslib (pip install dnslib)
"""

import argparse
import random
import socket
import struct
import time

from dnslib import DNSHeader, DNSQuestion, DNSRecord, QTYPE, RR

MDNS_ADDR = "224.0.0.251"
MDNS_PORT = 5353

DEVICES = [
    {
        "host": "sonos-living-room.local.",
        "ip": "192.168.1.51",
        "services": [("_sonos._tcp.local.", "Sonos-48B8 Living Room._sonos._tcp.local.", 1400)],
    },
    {
        "host": "appletv-den.local.",
        "ip": "192.168.1.62",
        "services": [
            ("_airplay._tcp.local.", "Den TV._airplay._tcp.local.", 7000),
            ("_raop._tcp.local.", "F0D430AA1122@Den TV._raop._tcp.local.", 49152),
        ],
    },
    {
        "host": "josh-core.local.",
        "ip": "192.168.1.70",
        "services": [("_josh._tcp.local.", "Josh Core._josh._tcp.local.", 4444)],
    },
    {
        "host": "samsung-frame.local.",
        "ip": "192.168.1.88",
        "services": [("_airplay._tcp.local.", "Frame TV._airplay._tcp.local.", 7000)],
    },
]

QUERIERS = ["192.168.1.100", "192.168.1.101", "192.168.1.115"]
QUERY_NAMES = [
    "_airplay._tcp.local.",
    "_sonos._tcp.local.",
    "_raop._tcp.local.",
    "_spotify-connect._tcp.local.",
    "_companion-link._tcp.local.",
    "_nonexistent-svc._tcp.local.",  # never answered -> shows in alerts/questions
]


def mdns_socket():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    return s


def send(s, record: DNSRecord):
    s.sendto(record.pack(), (MDNS_ADDR, MDNS_PORT))


def announce(s, dev):
    from dnslib import A, PTR, SRV, TXT

    for stype, inst, port in dev["services"]:
        pkt = DNSRecord(DNSHeader(qr=1, aa=1))
        pkt.add_answer(
            RR(stype, rtype=QTYPE.PTR, rclass=1, ttl=4500, rdata=PTR(inst)),
            RR(inst, rtype=QTYPE.SRV, rclass=1, ttl=4500, rdata=SRV(0, 0, port, dev["host"])),
            RR(inst, rtype=QTYPE.TXT, rclass=1, ttl=4500, rdata=TXT("model=Demo")),
            RR(dev["host"], rtype=QTYPE.A, rclass=1, ttl=120, rdata=A(dev["ip"])),
        )
        send(s, pkt)


def query(s):
    qname = random.choice(QUERY_NAMES)
    pkt = DNSRecord(DNSHeader())
    pkt.add_question(DNSQuestion(qname, QTYPE.PTR))
    send(s, pkt)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rate", type=float, default=2.0)
    args = ap.parse_args()
    s = mdns_socket()
    print(f"[sim] emitting ~{args.rate} pkts/s of mDNS to {MDNS_ADDR}:{MDNS_PORT} — ctrl-c to stop")
    # initial burst of announcements
    for d in DEVICES:
        announce(s, d)
    while True:
        if random.random() < 0.65:
            query(s)
        else:
            announce(s, random.choice(DEVICES))
        time.sleep(1.0 / args.rate)


if __name__ == "__main__":
    main()
