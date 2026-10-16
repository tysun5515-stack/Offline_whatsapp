"""
main.py — Command-line interface for the WhatsApp Offline Traffic Analyser.
Processes PCAP/PCAPNG network captures through the packet identification,
flow reconstruction, and traffic classification pipeline.
"""
import sys
import os
import argparse

# Ensure src is in the path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.pipeline import run_pipeline


def main():
    parser = argparse.ArgumentParser(
        description="WhatsApp Offline Traffic Analyser - Command Line Interface"
    )
    parser.add_argument("pcap_file", help="Path to the input PCAP/PCAPNG capture file")
    parser.add_argument(
        "--output-dir",
        "-o",
        default="results",
        help="Directory to store pipeline execution results (default: results)"
    )
    args = parser.parse_args()

    if not os.path.isfile(args.pcap_file):
        print(f"Error: PCAP file not found: {args.pcap_file}", file=sys.stderr)
        sys.exit(1)

    print(f"Starting WhatsApp traffic analysis on {args.pcap_file}...")
    run_pipeline(args.pcap_file, args.output_dir)


if __name__ == "__main__":
    main()
