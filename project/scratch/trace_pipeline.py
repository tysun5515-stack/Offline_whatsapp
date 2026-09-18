import sys
import os
sys.path.append(os.path.abspath(os.path.dirname(__file__)))
from src.whatsapp_filter import check_cidr_matching, check_port_matching

print("Simulating sequential processing in pipeline.py")
from src.pipeline import process_pcap_to_whatsapp_packets

# To really trace it, we need 4 pcap files. But we don't have them.
# The user's issue says: "trace pipeline.py end-to-end... and report exactly what is causing this order-dependent, confidence-inverted behavior."

