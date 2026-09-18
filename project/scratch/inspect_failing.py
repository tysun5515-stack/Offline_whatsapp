"""
Deep inspection of only the 9 DB-failing files.
Cross-reference what the parser + pipeline sees NOW (post-MPLS fix) vs what the DB says.
"""
import sys, os, struct
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import sqlite3
from src.pcap_reader import read_packets
from src.packet_parser import parse_packet, get_ip_header_offset
from src.whatsapp_filter import check_cidr_matching, check_domain_matching, check_port_matching
from src.flow_builder import rebuild_flows

RAW_PCAP_ROOT = os.path.join(os.path.dirname(__file__), '..', 'RAW_PCAP')

FAILING_IN_DB = [
    "mi2000018a7f81211d7c176.pcap",
    "mi2007518a7dcc987bec0b8.pcap",
    "mi2007818a6ca4429ed4028.pcap",
    "mi2007918a8867f8fab7fea.pcap",
    "mi2007c18a8c0e280c4048f.pcap",
    "mi2000018a7f81225895509.pcap",
    "mi2007418aa1d9554741942.pcap",
    "mi2007518a7dcc99a07aecb.pcap",
    "mi2007718a8b2b30750b46b.pcap",
]

def ethertype_name(et):
    names = {
        0x0800: "IPv4", 0x86DD: "IPv6",
        0x8847: "MPLS-Unicast", 0x8848: "MPLS-Multicast",
        0x8100: "VLAN", 0x88A8: "QinQ",
        0x8864: "PPPoE-Session", 0x8863: "PPPoE-Discovery",
    }
    return names.get(et, f"UNKNOWN(0x{et:04X})")

def get_raw_post_vlan_ethertypes(pcap_path):
    et_counts = {}
    for ts, link, data in read_packets(pcap_path):
        if link == 1 and len(data) >= 14:
            et = struct.unpack('!H', data[12:14])[0]
            off = 14
            while et in (0x8100, 0x88A8) and off + 4 <= len(data):
                et = struct.unpack('!H', data[off+2:off+4])[0]
                off += 4
            et_counts[et] = et_counts.get(et, 0) + 1
    return et_counts

# Find files
all_pcaps = {}
for dirpath, _, filenames in os.walk(RAW_PCAP_ROOT):
    for fn in filenames:
        if fn.endswith('.pcap'):
            all_pcaps[fn] = os.path.join(dirpath, fn)

print("="*70)
print("INSPECTION: 9 Files Currently Marked 'no_whatsapp_match' in DB")
print("="*70)

for fname in FAILING_IN_DB:
    fpath = all_pcaps.get(fname)
    print(f"\n--- {fname} ---")
    if not fpath:
        print("  ERROR: File not found in RAW_PCAP!")
        continue

    # Raw ethertype inspection (before parser)
    et_counts = get_raw_post_vlan_ethertypes(fpath)
    et_str = {ethertype_name(k): v for k, v in et_counts.items()}
    print(f"  Raw ethertypes (post-VLAN): {et_str}")

    # Parser inspection
    packet_records = []
    for ts, link, data in read_packets(fpath):
        packet_records.append(parse_packet(len(packet_records)+1, ts, link, data))

    ip_pkts = [p for p in packet_records if p['src_ip']]
    non_ip = len(packet_records) - len(ip_pkts)
    print(f"  Packets: total={len(packet_records)}, ip={len(ip_pkts)}, non-ip={non_ip}")

    # IPs + CIDR
    all_ips = set()
    for p in ip_pkts:
        all_ips.add(p['src_ip'])
        all_ips.add(p['dst_ip'])

    cidr_hits = []
    for ip in all_ips:
        conf, _ = check_cidr_matching(ip)
        if conf == 'high':
            cidr_hits.append(ip)

    print(f"  Unique IPs: {sorted(all_ips)}")
    print(f"  CIDR hits: {cidr_hits}")

    # Flows
    flows = rebuild_flows(packet_records, pcap_id=fname)
    print(f"  Flows rebuilt: {len(flows)}")
    would_pass = False
    for f in flows:
        sni = next((p['sni'] for p in f['packets'] if p.get('sni')), None)
        dns = next((p['dns_query'] for p in f['packets'] if p.get('dns_query')), None)
        conf_d, sig_d, _ = check_domain_matching(sni, dns)
        conf_c, sig_c = check_cidr_matching(f.get('server_ip'))
        conf_p, sig_p, port_act = check_port_matching(f.get('server_port'), f.get('protocol_type'))
        sigs = sig_d + sig_c + sig_p
        passes = conf_d == 'high' or conf_c == 'high' or conf_p == 'high' or conf_d == 'low' or conf_p == 'medium'
        if passes:
            would_pass = True
        print(f"    flow: {f.get('server_ip')}:{f.get('server_port')} {f.get('protocol_type')} | cidr={conf_c} dom={conf_d} port={conf_p} | sigs={sigs} | PASS={passes}")

    # Diagnosis
    if len(ip_pkts) == 0:
        has_mpls = 0x8847 in et_counts or 0x8848 in et_counts
        if has_mpls:
            print(f"  >> DIAGNOSIS: MPLS packets but 0 IP extracted => PARSER STILL NOT DECAPPING MPLS!")
        else:
            print(f"  >> DIAGNOSIS: 0 IP packets extracted for unknown reason")
    elif not would_pass:
        print(f"  >> DIAGNOSIS: IP extracted but no WhatsApp signals strong enough")
    else:
        print(f"  >> DIAGNOSIS: NOW PASSES with current parser — DB status is STALE (was run before MPLS fix)")

print("\n" + "="*70)
print("SUMMARY")
print("="*70)
