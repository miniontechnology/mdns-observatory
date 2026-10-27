"""Parser unit tests — synthetic frames through sensor.parse_packet."""
import os
import struct
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "sensor"))
os.environ.setdefault("COLLECTOR_URL", "http://localhost:8053")
os.environ.setdefault("INTERFACE", "eth0")
import sensor  # noqa: E402

from dnslib import DNSHeader, DNSQuestion, DNSRecord, PTR, QTYPE, RR  # noqa: E402

SMAC = b"\x02\x00\x00\x00\x00\x11"
DMAC = b"\x01\x00\x5e\x00\x00\xfb"


def frame_v4(proto, payload, src=b"\x0a\x00\x00\x32", dst=b"\xe0\x00\x00\xfb", sport=5353, dport=5353, ttl=255):
    eth = DMAC + SMAC + struct.pack("!H", 0x0800)
    if proto == 17:
        l4 = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    else:
        l4 = payload
    ver_ihl, tos, ident, flags = 0x45, 0, 1, 0
    ip = struct.pack("!BBHHHBBH4s4s", ver_ihl, tos, 20 + len(l4), ident, flags, ttl, proto, 0, src, dst)
    return eth + ip + l4


def test_mdns_query():
    q = DNSRecord(DNSHeader(qr=0), q=DNSQuestion("_airplay._tcp.local", QTYPE.PTR))
    ev = sensor.parse_packet(frame_v4(17, q.pack()))
    assert ev and ev["kind"] == "mdns" and not ev["is_response"]
    assert ev["questions"][0]["name"] == "_airplay._tcp.local."


def test_mdns_goodbye_ttl0_answer():
    rr = DNSRecord(DNSHeader(qr=1))
    rr.add_answer(RR("_sonos._tcp.local", QTYPE.PTR, ttl=0, rdata=PTR("SonosZP._sonos._tcp.local")))
    ev = sensor.parse_packet(frame_v4(17, rr.pack()))
    assert ev and ev["answers"][0]["ttl"] == 0


def test_ssdp_msearch():
    payload = (b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"
               b"MAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n")
    ev = sensor.parse_packet(frame_v4(17, payload, dst=b"\xef\xff\xff\xfa", sport=52344, dport=1900))
    assert ev and ev["kind"] == "ssdp" and ev["method"] == "m_search", ev
    assert ev["st"] == "ssdp:all" and ev["mcast"], ev


def test_ssdp_notify_byebye():
    payload = (b"NOTIFY * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"
               b"NT: urn:schemas-upnp-org:device:ZonePlayer:1\r\nNTS: ssdp:byebye\r\n"
               b"USN: uuid:RINCON_12345678::urn:schemas-upnp-org:device:ZonePlayer:1\r\n\r\n")
    ev = sensor.parse_packet(frame_v4(17, payload, sport=1900, dport=1900))
    assert ev and ev["kind"] == "ssdp" and ev["method"] == "notify"
    assert ev["nts"] == "ssdp:byebye" and "RINCON_12345678" in ev["usn"]


def test_ssdp_response_unicast():
    payload = (b"HTTP/1.1 200 OK\r\nST: urn:schemas-upnp-org:service:RenderingControl:1\r\n"
               b"USN: uuid:abcd::urn:schemas-upnp-org:service:RenderingControl:1\r\n"
               b"LOCATION: http://10.0.0.50:1400/xml/device_description.xml\r\n"
               b"SERVER: Linux UPnP/1.0 Sonos/80.1\r\n\r\n")
    ev = sensor.parse_packet(frame_v4(17, payload, dst=b"\x0a\x00\x00\x64", sport=1900, dport=52344))
    assert ev and ev["method"] == "response" and not ev["mcast"]
    assert "Sonos" in ev["server"]


def test_igmp_v2_report():
    pkt = bytes([0x16, 0, 0, 0]) + bytes([224, 0, 0, 251]) + b"\x00" * 8
    ev = sensor.parse_packet(frame_v4(2, pkt))
    assert ev and ev["kind"] == "igmp"
    assert ev["groups"][0]["group"] == "224.0.0.251" and ev["groups"][0]["action"] == "join"


def test_non_matching_port_ignored():
    assert sensor.parse_packet(frame_v4(17, b"garbage", sport=53, dport=53)) is None
