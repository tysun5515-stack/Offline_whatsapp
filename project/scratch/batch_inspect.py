"""
Batch inspector: runs every PCAP in RAW_PCAP through the parser
and prints a structured summary of WHY each file passes or fails.
Covers: link types, ethertypes, IP extraction, CIDR, SNI, DNS, port signals.
"""

import sys, os, struct
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.pcap_reader import read_packets
from src.packet_parser import parse_packet, get_ip_header_offset
from src.whatsapp_filter import (
    check_cidr_matching, check_domain_matching, check_port_matching,
    META_IP_RANGES
)
from src.flow_builder import rebuild_flows

RAW_PCAP_ROOT = os.path.join(os.path.dirname(__file__), '..', 'RAW_PCAP')

# Files confirmed FAILING from UI screenshot
FAILING_UI = {
    "mi2000018a7f81211d7c176.pcap",
    "mi2007c18a8c0e280c4048f.pcap",
    "mi2000018a7f81225895509.pcap",
    "mi2007418aa1d9554741942.pcap",
    "mi2007518a7dcc99a07aecb.pcap",
    "mi2007718a8b2b30750b46b.pcap",
}

def ethertype_name(et):
    names = {
        0x0800: "IPv4", 0x86DD: "IPv6", 0x0806: "ARP",
        0x8100: "VLAN(802.1Q)", 0x88A8: "QinQ",
        0x8847: "MPLS-Unicast", 0x8848: "MPLS-Multicast",
        0x8863: "PPPoE-Discovery", 0x8864: "PPPoE-Session",
        0x88CC: "LLDP", 0x0842: "WoL",
    }
    return names.get(et, f"UNKNOWN(0x{et:04X})")

def get_raw_ethertypes(pcap_path):
    """Walk frames manually before parser to capture true raw ethertype sequence."""
    et_counts = {}
    for ts, link, data in read_packets(pcap_path):
        if link == 1 and len(data) >= 14:
            et = struct.unpack('!H', data[12:14])[0]
            # Walk VLAN tags
            off = 14
            while et in (0x8100, 0x88A8) and off + 4 <= len(data):
                et = struct.unpack('!H', data[off+2:off+4])[0]
                off += 4
            et_counts[et] = et_counts.get(et, 0) + 1
    return et_counts

def inspect_one(pcap_path, fname):
    result = {
        "file": fname,
        "total_packets": 0,
        "ip_packets": 0,
        "non_ip_packets": 0,
        "unique_ips": set(),
        "cidr_hits": [],
        "sni_hits": [],
        "dns_hits": [],
        "ports": set(),
        "flow_count": 0,
        "whatsapp_signals": [],
        "raw_ethertypes_post_vlan": {},
        "link_types": set(),
        "parse_failures": [],
        "flows_detail": [],
    }

    # Raw ethertype check BEFORE parser
    result["raw_ethertypes_post_vlan"] = get_raw_ethertypes(pcap_path)

    packet_records = []
    for ts, link, data in read_packets(pcap_path):
        result["total_packets"] += 1
        result["link_types"].add(link)
        p = parse_packet(result["total_packets"], ts, link, data)
        packet_records.append(p)

    for p in packet_records:
        if p["src_ip"] is not None and p["dst_ip"] is not None:
            result["ip_packets"] += 1
            result["unique_ips"].add(p["src_ip"])
            result["unique_ips"].add(p["dst_ip"])
            if p.get("src_port"): result["ports"].add(p["src_port"])
            if p.get("dst_port"): result["ports"].add(p["dst_port"])
            if p.get("sni"): result["sni_hits"].append(p["sni"])
            if p.get("dns_query"): result["dns_hits"].append(p["dns_query"])
        else:
            result["non_ip_packets"] += 1

    for ip in result["unique_ips"]:
        conf, sigs = check_cidr_matching(ip)
        if conf == "high":
            result["cidr_hits"].append(ip)

    flows = rebuild_flows(packet_records, pcap_id=fname)
    result["flow_count"] = len(flows)

    for f in flows:
        sni_in_flow = None
        dns_in_flow = None
        for p in f["packets"]:
            if p.get("sni"): sni_in_flow = p["sni"]
            if p.get("dns_query"): dns_in_flow = p["dns_query"]

        conf_d, sig_d, sub_d = check_domain_matching(sni_in_flow, dns_in_flow)
        conf_c, sig_c = check_cidr_matching(f.get("server_ip"))
        conf_p, sig_p, port_act = check_port_matching(f.get("server_port"), f.get("protocol_type"))
        signals = sig_d + sig_c + sig_p

        would_pass = (conf_d == "high" or conf_c == "high" or conf_p == "high" or
                      conf_d == "low" or conf_p == "medium")

        result["flows_detail"].append({
            "server_ip": f.get("server_ip"),
            "server_port": f.get("server_port"),
            "proto": f.get("protocol_type"),
            "conf_d": conf_d, "conf_c": conf_c, "conf_p": conf_p,
            "signals": signals,
            "would_pass": would_pass,
        })
        if signals:
            result["whatsapp_signals"].extend(signals)

    return result


def classify_failure_reason(r):
    """Classify the root cause of why a file fails."""
    reasons = []
    et_counts = r["raw_ethertypes_post_vlan"]
    
    # Check if all packets have unhandled ethertypes
    unhandled = {et: cnt for et, cnt in et_counts.items() 
                 if et not in (0x0800, 0x86DD)}
    handled   = {et: cnt for et, cnt in et_counts.items() 
                 if et in (0x0800, 0x86DD)}

    if r["ip_packets"] == 0:
        if 0x8847 in et_counts or 0x8848 in et_counts:
            reasons.append("MPLS_NOT_DECAPPED")
        elif 0x8863 in et_counts or 0x8864 in et_counts:
            reasons.append("PPPOE_NOT_DECAPPED")
        elif unhandled:
            for et in unhandled:
                reasons.append(f"UNKNOWN_ETHERTYPE_{et:04X}")
        else:
            reasons.append("PARSE_FAILED_UNKNOWN")
    elif r["flow_count"] == 0:
        reasons.append("NO_IP_FLOWS_REBUILT")
    elif not any(f["would_pass"] for f in r["flows_detail"]):
        if not r["cidr_hits"]:
            reasons.append("NO_CIDR_MATCH")
        if not r["sni_hits"] and not r["dns_hits"]:
            reasons.append("NO_DOMAIN_SIGNAL")
        if not any(f["conf_p"] in ("high","medium") for f in r["flows_detail"]):
            reasons.append("NO_PORT_SIGNAL")
        # Check if IPs are Meta but weren't matched as server_ip
        for ip in r["unique_ips"]:
            conf, _ = check_cidr_matching(ip)
            if conf == "high" and ip not in r["cidr_hits"]:
                reasons.append(f"META_IP_{ip}_NOT_AS_SERVER")

    if not reasons:
        reasons.append("PASSES_OR_CAUSE_UNKNOWN")

    return reasons


# Collect all PCAPs
all_pcaps = []
for dirpath, dirnames, filenames in os.walk(RAW_PCAP_ROOT):
    for fn in filenames:
        if fn.endswith(".pcap"):
            all_pcaps.append((fn, os.path.join(dirpath, fn)))
all_pcaps.sort(key=lambda x: x[0])

print(f"Found {len(all_pcaps)} PCAP files\n")
print(f"META_IP_RANGES loaded: {len(META_IP_RANGES)} ranges\n")

failing = []
passing = []

for fname, fpath in all_pcaps:
    r = inspect_one(fpath, fname)
    reasons = classify_failure_reason(r)

    # Determine if it would pass
    would_pass = (r["ip_packets"] > 0 and 
                  r["flow_count"] > 0 and
                  any(f["would_pass"] for f in r["flows_detail"]))

    tag = "PASS" if would_pass else "FAIL"
    ui_tag = "[UI-FAIL]" if fname in FAILING_UI else ""

    print(f"[{tag}] {ui_tag} {fname}")
    print(f"  Packets: total={r['total_packets']} ip={r['ip_packets']} non-ip={r['non_ip_packets']}")
    print(f"  Link types: {r['link_types']}")
    print(f"  Ethertypes (post-VLAN): { {ethertype_name(k): v for k, v in r['raw_ethertypes_post_vlan'].items()} }")
    print(f"  Flows: {r['flow_count']}")
    print(f"  CIDR hits: {r['cidr_hits']}")
    print(f"  SNI hits: {r['sni_hits'][:3]}")
    print(f"  DNS hits: {list(set(r['dns_hits']))[:5]}")
    print(f"  Signals: {list(set(r['whatsapp_signals']))}")
    for fd in r["flows_detail"]:
        print(f"    flow: {fd['server_ip']}:{fd['server_port']} {fd['proto']} | cidr={fd['conf_c']} dom={fd['conf_d']} port={fd['conf_p']} sigs={fd['signals']} PASS={fd['would_pass']}")
    if tag == "FAIL":
        print(f"  >> ROOT CAUSE: {reasons}")
    print()

    if tag == "FAIL":
        failing.append((fname, reasons))
    else:
        passing.append(fname)

print("="*60)
print(f"SUMMARY: {len(passing)} PASS, {len(failing)} FAIL")
print()
print("FAILING FILES + CAUSES:")
from collections import Counter
all_causes = []
for fname, reasons in failing:
    for r in reasons:
        all_causes.append(r)
    print(f"  {fname}: {reasons}")

print()
print("CAUSE FREQUENCY:")
for cause, cnt in Counter(all_causes).most_common():
    print(f"  {cause}: {cnt}")
