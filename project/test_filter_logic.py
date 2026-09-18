import sys
import os
sys.path.append(os.path.abspath(os.path.dirname(__file__)))
from src.pipeline import process_pcap_to_whatsapp_packets
from src.whatsapp_filter import check_cidr_matching, check_port_matching
import ipaddress

print("Simulating File 1...")
# 157.240.196.57 is Meta
conf_cidr, _ = check_cidr_matching("157.240.196.57")
conf_port, _, _ = check_port_matching(3478, "UDP")
print(f"File 1 check: cidr={conf_cidr}, port={conf_port}")

print("Simulating File 4...")
conf_cidr4, _ = check_cidr_matching("57.144.153.54")
conf_port4, _, _ = check_port_matching(3478, "UDP")
print(f"File 4 check: cidr={conf_cidr4}, port={conf_port4}")

print("Checking META_IP_RANGES size:")
from src.whatsapp_filter import META_IP_RANGES
print(f"META_IP_RANGES has {len(META_IP_RANGES)} entries")
