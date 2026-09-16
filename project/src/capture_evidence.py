"""Capture metadata extraction and deterministic filtered-PCAP writers."""
import json
import os
import struct
from typing import Dict, Iterable, Set, Tuple

from src.pcap_reader import read_packets


def capture_metadata(path: str, file_format: str) -> Dict[str, object]:
    if file_format in ('json', 'csv'):
        return {}
    count, first, last = 0, None, None
    link_types = set()
    for timestamp, link_type, _frame in read_packets(path):
        count += 1
        first = timestamp if first is None or timestamp < first else first
        last = timestamp if last is None or timestamp > last else last
        link_types.add(link_type)
    if count == 0:
        raise ValueError('Capture contains no readable packet records.')
    return {
        'capture_start_ts': first, 'capture_end_ts': last, 'capture_packet_count': count,
        'capture_duration_s': max(0.0, last - first),
        'timestamp_precision': ('pcapng interface-defined' if file_format == 'pcapng'
                                else ('nanoseconds' if _is_nanosecond_capture(path, file_format) else 'microseconds')),
        'link_types': json.dumps(sorted(link_types)),
    }


def _is_nanosecond_capture(path: str, file_format: str) -> bool:
    with open(path, 'rb') as handle:
        magic = handle.read(4)
    return magic in (b'\xa1\xb2\x3c\x4d', b'\x4d\x3c\xb2\xa1')


def _pad(data: bytes) -> bytes:
    return data + b'\x00' * ((-len(data)) % 4)


def _pcapng_block(block_type: int, body: bytes) -> bytes:
    total = 12 + len(body)
    # Block type is read as a fixed network-order identifier by our reader;
    # block lengths and bodies follow the section byte order.
    return struct.pack('>I', block_type) + struct.pack('<I', total) + body + struct.pack('<I', total)


def write_filtered_capture(source_path: str, destination_path: str, packet_numbers: Set[int], output_format: str) -> int:
    """Re-read raw evidence and write selected frames only. Returns written packet count."""
    os.makedirs(os.path.dirname(destination_path), exist_ok=True)
    selected = [(ts, link, frame) for number, (ts, link, frame) in enumerate(read_packets(source_path), 1) if number in packet_numbers]
    if not selected:
        return 0
    if output_format == 'pcapng':
        _write_pcapng(destination_path, selected)
    else:
        _write_pcap(destination_path, selected)
    # Re-read validation also confirms the output is consumable by this application.
    if sum(1 for _ in read_packets(destination_path)) != len(selected):
        raise ValueError('Filtered capture validation failed: output packet count differs.')
    return len(selected)


def _write_pcap(path: str, packets: Iterable[Tuple[float, int, bytes]]) -> None:
    packets = list(packets)
    link_type = packets[0][1]
    if any(link != link_type for _, link, _ in packets):
        raise ValueError('Classic PCAP output cannot represent multiple link types; write PCAPNG instead.')
    with open(path, 'wb') as handle:
        handle.write(struct.pack('<IHHIIII', 0xA1B2C3D4, 2, 4, 0, 0, 262144, link_type))
        for timestamp, _link, frame in packets:
            seconds = int(timestamp)
            micros = max(0, int(round((timestamp - seconds) * 1_000_000)))
            if micros >= 1_000_000: seconds, micros = seconds + 1, 0
            handle.write(struct.pack('<IIII', seconds, micros, len(frame), len(frame)))
            handle.write(frame)


def _write_pcapng(path: str, packets: Iterable[Tuple[float, int, bytes]]) -> None:
    packets = list(packets)
    link_map: Dict[int, int] = {}
    with open(path, 'wb') as handle:
        # Section Header Block (little endian, version 1.0, unspecified length).
        handle.write(_pcapng_block(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1)))
        for _timestamp, link, _frame in packets:
            if link not in link_map:
                link_map[link] = len(link_map)
                # IDB with nanosecond resolution; keeps packet timestamps precise.
                options = struct.pack('<HHB3x', 9, 1, 9) + struct.pack('<HH', 0, 0)
                handle.write(_pcapng_block(1, struct.pack('<HHI', link, 0, 262144) + options))
        for timestamp, link, frame in packets:
            raw_ts = max(0, int(round(timestamp * 1_000_000_000)))
            body = struct.pack('<IIIII', link_map[link], raw_ts >> 32, raw_ts & 0xffffffff, len(frame), len(frame)) + _pad(frame)
            handle.write(_pcapng_block(6, body))
