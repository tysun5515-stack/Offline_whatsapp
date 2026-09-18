import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.pcap_reader import read_packets
from src.packet_parser import parse_packet
from src.flow_builder import rebuild_flows
from src.pipeline import _dns_correlation_index, _flow_dns_correlation

def verify(pcap_path):
    print(f"--- Verifying {os.path.basename(pcap_path)} ---")
    packet_records = []
    packet_no = 0
    for ts, link, data in read_packets(pcap_path):
        packet_no += 1
        record = parse_packet(packet_no, ts, link, data)
        packet_records.append(record)
        
        if packet_no in (1272, 3034, 5059):
            print(f"Packet #{packet_no} DNS answers: {record.get('dns_answers')}")

    dns_index = _dns_correlation_index(packet_records)
    
    target_ip = "213.57.23.97"
    if target_ip in dns_index:
        print(f"SUCCESS: {target_ip} found in _dns_correlation_index:")
        for entry in dns_index[target_ip]:
            print(f"  {entry}")
    else:
        print(f"FAILURE: {target_ip} NOT found in _dns_correlation_index")
        
    flows = rebuild_flows(packet_records, pcap_id=os.path.basename(pcap_path), burst_threshold=1.0)
    
    target_flows = [f for f in flows if (f.get("server_ip") == target_ip or f.get("client_ip") == target_ip) and f.get("protocol_type") == "UDP" and (f.get("server_port") == 443 or f.get("client_port") == 443)]
    
    if not target_flows:
        print(f"Could not find UDP/443 flow to {target_ip}")
    
    for flow in target_flows:
        print(f"Found target flow! First seen: {flow.get('first_seen')}, Last seen: {flow.get('last_seen')}")
        corr = _flow_dns_correlation(flow, dns_index)
        if corr:
            print(f"SUCCESS: _flow_dns_correlation MATCHED the flow: {corr}")
        else:
            print(f"FAILURE: _flow_dns_correlation did NOT match the flow")

if __name__ == "__main__":
    pcap = r"RAW_PCAP\69ac413d-3c6a-4075-b321-17954879e251\2.pcap"
    verify(pcap)
