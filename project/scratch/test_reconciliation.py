import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.pipeline import process_pcap_to_whatsapp_packets

def test():
    pcap = r"RAW_PCAP\69ac413d-3c6a-4075-b321-17954879e251\2.pcap"
    stats, packets, flows = process_pcap_to_whatsapp_packets(pcap)
    
    print("Stats:")
    for k, v in stats.items():
        print(f"  {k}: {v}")
        
    for flow in flows:
        if flow.get("server_ip") == "213.57.23.97" or flow.get("client_ip") == "213.57.23.97":
            print(f"Flow to 213.57.23.97: confidence={flow.get('whatsapp_confidence')}, reason={flow.get('acceptance_reason')}, pass2={'dns_correlated_whatsapp_pass2' in flow.get('acceptance_reason', '')}")
        
    if stats.get('reconciliation_ok'):
        print("SUCCESS: reconciliation invariant passed!")
    else:
        print("FAILURE: reconciliation invariant failed!")

if __name__ == "__main__":
    test()
