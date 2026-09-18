import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.pcap_reader import read_packets
from src.packet_parser import parse_packet, get_ip_header_offset
from src.whatsapp_filter import check_cidr_matching, check_domain_matching, check_port_matching, META_IP_RANGES
from src.flow_builder import rebuild_flows, _resolve_flow_roles

PCAP1 = r'RAW_PCAP\81f9c7d8-da04-4572-810e-0ad7562c3504\mi2007718a8b2b30750b46b.pcap'
PCAP2 = r'RAW_PCAP\302caa2e-68ae-436d-bfb8-65721d39f2a7\mi2007a18a6ca4d55316703.pcap'

def inspect_pcap(pcap_path, label):
    print(f"\n{'='*60}")
    print(f"FILE: {label}")
    print(f"Path: {pcap_path}")
    print('='*60)

    packet_records = []
    link_types = set()
    for ts, link, data in read_packets(pcap_path):
        link_types.add(link)
        pkt = parse_packet(len(packet_records)+1, ts, link, data)
        packet_records.append(pkt)

    print(f"\nTotal packets parsed: {len(packet_records)}")
    print(f"Link types in file: {link_types}")

    # Packet-level IP stats
    ip_packets = [p for p in packet_records if p['src_ip'] is not None]
    non_ip = [p for p in packet_records if p['src_ip'] is None]
    print(f"IP-parsed packets: {len(ip_packets)}")
    print(f"Non-IP / failed parse: {len(non_ip)}")

    # Show first 5 non-IP packets
    if non_ip:
        print("\nFirst 5 non-IP packets (raw link+offset inspection):")
        for p in non_ip[:5]:
            print(f"  pkt#{p['packet_no']}: proto={p['protocol']}, length={p['length']}")

    # Show first 5 raw packets
    print("\nFirst 5 packets raw analysis:")
    for ts, link, data in read_packets(pcap_path):
        count = len([]) 
        break  # just need to re-read
    count = 0
    for ts, link, data in read_packets(pcap_path):
        count += 1
        if count > 5:
            break
        offset, ethertype = get_ip_header_offset(link, data)
        eth_str = f"0x{ethertype:04X}" if ethertype is not None else "None"
        print(f"  pkt#{count}: link={link}, frame_len={len(data)}, ip_offset={offset}, ethertype={eth_str}, first8={data[:8].hex()}")

    # IP stats
    src_ips = set(p['src_ip'] for p in ip_packets)
    dst_ips = set(p['dst_ip'] for p in ip_packets)
    all_ips = src_ips | dst_ips
    print(f"\nUnique IPs: {len(all_ips)}")
    for ip in sorted(all_ips):
        conf, sigs = check_cidr_matching(ip)
        tag = "  << META CIDR MATCH!" if conf == "high" else ""
        print(f"  {ip} -> {conf}{tag}")

    # SNI / DNS
    sni_seen = [(p['sni'], p['src_ip'], p['dst_ip']) for p in ip_packets if p.get('sni')]
    dns_seen = [(p['dns_query'], p['src_ip'], p['dst_ip']) for p in ip_packets if p.get('dns_query')]
    print(f"\nSNI entries: {len(sni_seen)}")
    for sni, src, dst in sni_seen[:10]:
        print(f"  SNI={sni}  ({src} -> {dst})")
    print(f"DNS queries: {len(dns_seen)}")
    for dns, src, dst in dns_seen[:10]:
        print(f"  DNS={dns}  ({src} -> {dst})")

    # Port analysis
    ports = set()
    for p in ip_packets:
        if p.get('src_port'): ports.add(p['src_port'])
        if p.get('dst_port'): ports.add(p['dst_port'])
    print(f"\nPorts seen: {sorted(ports)[:30]}")

    # Flow rebuild + classification
    flows = rebuild_flows(packet_records, pcap_id=os.path.basename(pcap_path))
    print(f"\nFlows rebuilt: {len(flows)}")
    for f in flows:
        conf_d, sig_d, sub_d = check_domain_matching(None, None)
        conf_c, sig_c = check_cidr_matching(f.get('server_ip'))
        conf_p, sig_p, port_act = check_port_matching(f.get('server_port'), f.get('protocol_type'))
        print(f"  flow#{f['flow_id']}: {f.get('client_ip')}:{f.get('client_port')} -> {f.get('server_ip')}:{f.get('server_port')} {f.get('protocol_type')}  | cidr={conf_c} sigs={sig_c} | port={conf_p}/{port_act} | role_src={f.get('endpoint_role_source')}")

inspect_pcap(PCAP1, "FAILING - mi2007718a8b2b30750b46b.pcap")
inspect_pcap(PCAP2, "PASSING - mi2007a18a6ca4d55316703.pcap")
