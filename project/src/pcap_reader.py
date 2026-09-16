"""
pcap_reader.py: A pure-standard-library pcap and pcapng file reader.
"""

import struct
import io
from typing import Generator, Tuple, List, Optional
from dataclasses import dataclass

# --- Exceptions ---

class PcapReaderError(Exception):
    """Base exception for pcap reader errors."""
    pass

class InvalidCaptureFormatError(PcapReaderError):
    """Raised when the file magic number is unrecognized."""
    pass

class TruncatedCaptureError(PcapReaderError):
    """Raised when the file ends unexpectedly."""
    pass

class UnsupportedBlockError(PcapReaderError):
    """Raised when a required PCAPNG block cannot be processed."""
    pass

# --- Data Models ---

@dataclass
class InterfaceInfo:
    link_type: int
    ts_resol: int  # Power of 10 (e.g., 6 for micro, 9 for nano)

# --- Internal Helpers ---

def _read_exactly(stream: io.BufferedIOBase, n: int) -> bytes:
    data = stream.read(n)
    if len(data) < n:
        raise TruncatedCaptureError(f"Expected {n} bytes, got {len(data)}")
    return data

# --- Classic PCAP Parser ---

def _read_classic_pcap(stream: io.BufferedIOBase, first_4: bytes) -> Generator[Tuple[float, int, bytes], None, None]:
    # Magic numbers:
    # 0xa1b2c3d4: microsecond, native
    # 0xd4c3b2a1: microsecond, swapped
    # 0xa1b23c4d: nanosecond, native
    # 0x4d3cb2a1: nanosecond, swapped
    
    magics = {
        0xa1b2c3d4: ('>', 10**6),
        0xd4c3b2a1: ('<', 10**6),
        0xa1b23c4d: ('>', 10**9),
        0x4d3cb2a1: ('<', 10**9),
    }

    # We read first_4 as big-endian just to check the magic
    m = struct.unpack('>I', first_4)[0]
    if m not in magics:
        # Check little-endian interpretation of magic
        m_le = struct.unpack('<I', first_4)[0]
        if m_le in magics:
            endian, ts_divisor = magics[m_le]
        else:
            if first_4.startswith(b'RIFF'):
                raise InvalidCaptureFormatError(
                    f"File is a RIFF audio/media container (.wav/.avi/.webp), not a PCAP network packet capture (magic: 0x{m:08x})."
                )
            raise InvalidCaptureFormatError(
                f"Unknown Classic PCAP magic: 0x{m:08x}. Expected PCAP (0xa1b2c3d4, 0xd4c3b2a1) or PCAPNG header."
            )
    else:
        endian, ts_divisor = magics[m]

    # Global Header (24 bytes total, we already read 4)
    # Remaining: Version Major (2), Version Minor (2), ThisZone (4), SigFigs (4), SnapLen (4), Network (4)
    header_remainder = _read_exactly(stream, 20)
    # We only care about 'Network' (link type)
    network = struct.unpack(f"{endian}I", header_remainder[16:20])[0]

    # Packet Records
    # ts_sec (4), ts_usec (4), incl_len (4), orig_len (4)
    record_fmt = f"{endian}IIII"
    while True:
        buf = stream.read(16)
        if not buf:
            break
        if len(buf) < 16:
            # Bug 11 fix (truncated EOF): partial packet record at end of file;
            # yield all valid packets parsed so far rather than crashing.
            break
        
        ts_sec, ts_frac, incl_len, orig_len = struct.unpack(record_fmt, buf)
        timestamp = ts_sec + (ts_frac / ts_divisor)
        data = _read_exactly(stream, incl_len)
        yield (timestamp, network, data)

# --- PCAPNG Parser ---

def _read_pcapng(stream: io.BufferedIOBase) -> Generator[Tuple[float, int, bytes], None, None]:
    interfaces: List[InterfaceInfo] = []
    endian = '>'  # Default until SHB
    
    # PCAPNG Block: Type (4), Total Length (4), Body (var), Total Length (4)
    
    while True:
        buf = stream.read(8)
        if not buf:
            break
        if len(buf) < 8:
            raise TruncatedCaptureError("Truncated PCAPNG block header")
        
        # We don't know endianness for the first block (SHB) yet
        # But SHB magic is always checked to determine endianness
        block_type = struct.unpack('>I', buf[:4])[0]
        
        if block_type == 0x0A0D0D0A:  # Section Header Block
            # We must detect endianness here
            shb_body_start = _read_exactly(stream, 8) # Byte-Order Magic (4) + Version (4)
            bom = struct.unpack('>I', shb_body_start[:4])[0]
            if bom == 0x1A2B3C4D:
                endian = '>'
            elif bom == 0x4D3C2B1A:
                endian = '<'
            else:
                raise InvalidCaptureFormatError(f"Invalid PCAPNG BOM: 0x{bom:08x}")
            
            # Recalculate block length with correct endianness
            total_len = struct.unpack(f"{endian}I", buf[4:8])[0]
            # Skip rest of SHB body and trailing length
            _read_exactly(stream, total_len - 16)
            # Bug 11 fix (multi-SHB): clear interface list on each new section so
            # subsequent interface IDs (which reset to 0) point to THIS section's
            # interface descriptions, not a previous section's.
            interfaces.clear()
            continue

        # For other blocks, use the detected endianness
        total_len = struct.unpack(f"{endian}I", buf[4:8])[0]
        body_len = total_len - 12 # Subtract Type(4), Length(4), and trailing Length(4)
        
        if block_type == 0x00000001:  # Interface Description Block
            body = _read_exactly(stream, body_len)
            link_type = struct.unpack(f"{endian}H", body[:2])[0]
            # Options start at offset 8
            ts_resol = 6 # Default is microseconds
            options_data = body[8:]
            idx = 0
            while idx + 4 <= len(options_data):
                opt_code, opt_len = struct.unpack(f"{endian}HH", options_data[idx:idx+4])
                if opt_code == 0: # opt_endofopt
                    break
                if opt_code == 9: # if_tsresol
                    res_byte = options_data[idx+4]
                    # if MSB is 0, resolution is 10^-res
                    # if MSB is 1, resolution is 2^-res (not supported here for simplicity)
                    if res_byte & 0x80 == 0:
                        ts_resol = res_byte
                
                # Advance, ensuring 32-bit alignment
                idx += 4 + ((opt_len + 3) & ~3)
            
            interfaces.append(InterfaceInfo(link_type=link_type, ts_resol=ts_resol))
            _read_exactly(stream, 4) # Trailing length
            
        elif block_type == 0x00000006:  # Enhanced Packet Block
            body = _read_exactly(stream, body_len)
            if_id, ts_high, ts_low, incl_len = struct.unpack(f"{endian}IIII", body[:16])
            
            if if_id >= len(interfaces):
                raise UnsupportedBlockError(f"EPB references unknown interface ID {if_id}")
            
            iface = interfaces[if_id]
            ts_raw = (ts_high << 32) | ts_low
            timestamp = ts_raw * (10 ** -iface.ts_resol)
            
            # Packet data starts at offset 20
            packet_data = body[20:20+incl_len]
            yield (timestamp, iface.link_type, packet_data)
            _read_exactly(stream, 4) # Trailing length

        elif block_type == 0x00000002:  # Packet Block (Legacy)
            body = _read_exactly(stream, body_len)
            # Layout: if_id(2) drops(2) ts_high(4) ts_low(4) incl_len(4) orig_len(4)
            # That is 16 bytes of fixed header; packet data starts at offset 20
            # (orig_len at bytes 16..19 must be skipped).
            # Bug 11 fix: was body[16:…] which included orig_len bytes as packet data.
            if_id, drops, ts_high, ts_low, incl_len = struct.unpack(f"{endian}HHIII", body[:16])
            
            if if_id >= len(interfaces):
                raise UnsupportedBlockError(f"PB references unknown interface ID {if_id}")
            
            iface = interfaces[if_id]
            ts_raw = (ts_high << 32) | ts_low
            timestamp = ts_raw * (10 ** -iface.ts_resol)
            
            # orig_len sits at bytes 16..19; packet data starts at byte 20.
            packet_data = body[20:20+incl_len]
            yield (timestamp, iface.link_type, packet_data)
            _read_exactly(stream, 4) # Trailing length
            
        else:
            # Skip unknown block
            _read_exactly(stream, body_len + 4)

# --- Public API ---

def read_packets(path: str) -> Generator[Tuple[float, int, bytes], None, None]:
    """
    Reads packets from a pcap or pcapng file.
    
    Yields:
        (timestamp, link_type, raw_frame)
    """
    with open(path, 'rb') as f:
        # Determine file type by reading first 4 bytes
        first_4 = f.read(4)
        if len(first_4) < 4:
            return

        if first_4 == b'\x0a\x0d\x0d\x0a':
            # PCAPNG (Section Header Block type)
            # Put back the first 4 bytes for easier parsing
            f.seek(0)
            yield from _read_pcapng(f)
        else:
            # Classic PCAP (hopefully)
            yield from _read_classic_pcap(f, first_4)
