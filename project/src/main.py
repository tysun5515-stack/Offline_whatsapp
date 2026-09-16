import pyshark
import csv
import os
import whatsapp_analysis  


def convert_pcap_to_csv(pcap_file_path, csv_file_path):
    
    capture = pyshark.FileCapture(pcap_file_path, display_filter='ip')  # Use display_filter if needed

    # Get the sniff time of the first packet
    first_sniff_time = None
    first_packet = None
    for packet in capture:
        first_packet = packet
        first_sniff_time = packet.sniff_time
        break

    if first_packet is None:
        print(f"Warning: PCAP file {pcap_file_path} contains no packets matching the filter.")
        return

    # Create a CSV file and write headers
    with open(csv_file_path, 'w', newline='') as csv_file:
        fieldnames = ['No.', 'Time', 'Source', 'Destination', 'Protocol', 'Length', 'Info']
        csv_writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        csv_writer.writeheader()

        def write_packet_row(packet):
            # Calculate Time by seconds as the time of the current packet - time of the first packet
            delta = packet.sniff_time - first_sniff_time
            delta_seconds = delta.total_seconds()  # Convert timedelta to seconds

            packet_data = {
                'No.': packet.number,
                'Time': delta_seconds,
                'Source': packet.ip.src if 'ip' in packet else '',
                'Destination': packet.ip.dst if 'ip' in packet else '',
                'Protocol': packet.highest_layer,
                'Length': packet.length,
                'Info': packet.info if hasattr(packet, 'info') else ''
            }
            csv_writer.writerow(packet_data)

        # Write the cached first packet
        write_packet_row(first_packet)

        # Iterate through remaining packets and write to CSV
        for packet in capture:
            write_packet_row(packet)

    print(f'PCAP file converted to CSV: {csv_file_path}')


def main():



    
    


    # Modify this list to specify different WhatsApp group types for analysis
    GROUPS = ['Message', 'Photo', 'Audio', 'Video']
    # GROUPS = ['YesFilter', 'NoFilter']
    for group in GROUPS:
        BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

        pcap_file_path = os.path.join(BASE_DIR, "resources", f"{group}s_record.pcap")
        csv_file_path = os.path.join(BASE_DIR, "resources", f"{group}s_record.csv")

    
        
      
        print("Current working directory:", os.getcwd())
        print("Expected path:", os.path.abspath(pcap_file_path))
        print("Exists:", os.path.exists(pcap_file_path))

        
        if not os.path.exists(pcap_file_path):
            raise FileNotFoundError(f"{pcap_file_path} does not exist.")
        try:
            print(f"Converting {pcap_file_path} -> {csv_file_path} ...")
            convert_pcap_to_csv(pcap_file_path, csv_file_path)
            print("Conversion complete.")
        except Exception as e:
            print(f"Error occurred during conversion: {e}")
        try:
            print(f"Starting plots for {csv_file_path} ...")
            whatsapp_analysis.creating_plots(csv_file_path, group)
            print("Plots generated.")
        except Exception as e:
            print(f"Error occurred during plot generation: {e}")


if __name__ == "__main__":
    main()
