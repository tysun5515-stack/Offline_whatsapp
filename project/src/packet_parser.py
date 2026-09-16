"""
packet_parser.py: Parses raw network frames into packet metadata records.
"""

import struct
import socket
from typing import Optional, Dict, Any, Tuple

def parse_tls_client_hello_sni(tcp_payload: bytes) -> Optional[str]:
    """
    Parses a TLS ClientHello handshake record and extracts the SNI hostname.
    
    Walks the actual structure:
    client_version (2) -> random (32) -> session_id (1 + var) -> 
    cipher_suites (2 + var) -> compression_methods (1 + var) -> extensions (2 + var)
    and searches for the server_name extension (0x0000).
    """
    if len(tcp_payload) < 9:
        return None
    
    # Handshake Layer starts at offset 5 of the TCP payload
    # Check Handshake Type (1 byte)
    handshake_type = tcp_payload[5]
    if handshake_type != 0x01:  # 0x01 is ClientHello
        return None
    
    # client_version starts at offset 9 (2 bytes)
    # random starts at offset 11 (32 bytes)
    idx = 43  # 9 + 2 + 32
    
    if idx >= len(tcp_payload):
        return None
    
    # Session ID Length (1 byte)
    session_id_len = tcp_payload[idx]
    idx += 1 + session_id_len
    
    if idx + 2 > len(tcp_payload):
        return None
    
    # Cipher Suites Length (2 bytes)
    cipher_suites_len = struct.unpack('!H', tcp_payload[idx : idx + 2])[0]
    idx += 2 + cipher_suites_len
    
    if idx >= len(tcp_payload):
        return None
    
    # Compression Methods Length (1 byte)
    compression_methods_len = tcp_payload[idx]
    idx += 1 + compression_methods_len
    
    if idx + 2 > len(tcp_payload):
        return None  # No extensions present
    
    # Extensions Length (2 bytes)
    extensions_len = struct.unpack('!H', tcp_payload[idx : idx + 2])[0]
    idx += 2
    
    extensions_end = idx + extensions_len
    if extensions_end > len(tcp_payload):
        extensions_end = len(tcp_payload)
        
    # Walk the extensions
    while idx + 4 <= extensions_end:
        ext_type, ext_len = struct.unpack('!HH', tcp_payload[idx : idx + 4])
        idx += 4
        if idx + ext_len > extensions_end:
            break
        
        ext_data = tcp_payload[idx : idx + ext_len]
        if ext_type == 0x0000:  # server_name extension
            if len(ext_data) >= 2:
                list_len = struct.unpack('!H', ext_data[0:2])[0]
                s_idx = 2
                while s_idx + 3 <= len(ext_data):
                    name_type = ext_data[s_idx]
                    name_len = struct.unpack('!H', ext_data[s_idx + 1 : s_idx + 3])[0]
                    s_idx += 3
                    if s_idx + name_len <= len(ext_data):
                        if name_type == 0x00:  # host_name
                            try:
                                return ext_data[s_idx : s_idx + name_len].decode('utf-8', errors='ignore')
                            except Exception:
                                pass
                    s_idx += name_len
        idx += ext_len
        
    return None

def parse_dns_query(udp_payload: bytes) -> Optional[str]:
    """
    Parses the question section of a DNS query packet to extract the queried name.
    Skips the 12-byte header, reads QDCOUNT, and walks the length-prefixed labels.
    """
    if len(udp_payload) < 12:
        return None
    
    qdcount = struct.unpack('!H', udp_payload[4:6])[0]
    if qdcount == 0:
        return None
    
    try:
        parts = []
        idx = 12
        # Walk length-prefixed labels for the first question
        while idx < len(udp_payload):
            length = udp_payload[idx]
            if length == 0:
                idx += 1
                break
            
            # Handle standard label pointer compression
            if (length & 0xC0) == 0xC0:
                # Compression pointers are 2 bytes, skip
                idx += 2
                break
                
            idx += 1
            if idx + length > len(udp_payload):
                break
                
            part = udp_payload[idx : idx + length].decode('utf-8', errors='ignore')
            parts.append(part)
            idx += length
            
        if parts:
            return ".".join(parts)
    except Exception:
        pass
        
    return None

def get_ip_header_offset(link_type: int, raw_frame: bytes) -> Tuple[Optional[int], Optional[int]]:
    """
    Strips link-layer headers based on link_type.
    Returns (offset, ethertype) where:
      - offset is the index of the start of the IP header in raw_frame.
      - ethertype is 0x0800 for IPv4 or 0x86DD for IPv6.
    Returns (None, None) if link type is unsupported, or frame is truncated/invalid.
    """
    # 1. LINKTYPE_ETHERNET (Ethernet)
    if link_type == 1:
        if len(raw_frame) < 14:
            return None, None
        ethertype = struct.unpack('!H', raw_frame[12:14])[0]
        offset = 14
        # Handle 802.1Q VLAN tags (can be nested/QinQ)
        while ethertype in (0x8100, 0x88A8):
            if len(raw_frame) < offset + 4:
                return None, None
            ethertype = struct.unpack('!H', raw_frame[offset + 2 : offset + 4])[0]
            offset += 4
        return offset, ethertype
        
    # Bug 12 fix: Add LINKTYPE_NULL (0) and LINKTYPE_LOOP (108) used by local loopback
    elif link_type in (0, 108):
        if len(raw_frame) < 4:
            return None, None
        # Family is usually 4 bytes. IPv4 is 2, IPv6 is 24/28 depending on OS
        family = struct.unpack('<I', raw_frame[0:4])[0]
        if family == 2:
            return 4, 0x0800
        elif family in (24, 28, 30):
            return 4, 0x86DD
        # Fallback heuristic if endianness or family values are weird
        version = (raw_frame[4] >> 4) & 0x0F
        if version == 4:
            return 4, 0x0800
        elif version == 6:
            return 4, 0x86DD
        return None, None
        
    # 2. LINKTYPE_RAW (Raw IP, starts directly with IP header)
    # Some platforms use link type 12 as raw IP as well.
    elif link_type in (101, 12):
        if len(raw_frame) < 1:
            return None, None
        version = (raw_frame[0] >> 4) & 0x0F
        if version == 4:
            return 0, 0x0800
        elif version == 6:
            return 0, 0x86DD
        return None, None
        
    # 3. LINKTYPE_LINUX_SLL (Linux Cooked Capture v1)
    elif link_type == 113:
        if len(raw_frame) < 16:
            return None, None
        ethertype = struct.unpack('!H', raw_frame[14:16])[0]
        return 16, ethertype
        
    # 4. LINKTYPE_LINUX_SLL2 (Linux Cooked Capture v2)
    elif link_type == 276:
        if len(raw_frame) < 20:
            return None, None
        ethertype = struct.unpack('!H', raw_frame[0:2])[0]
        return 20, ethertype
        
    return None, None

def parse_packet(packet_no: int, timestamp: float, link_type: int, raw_frame: bytes) -> Dict[str, Any]:
    """
    Parses a raw network frame into a metadata record with exact fields:
    packet_no, timestamp, src_ip, dst_ip, src_port, dst_port, protocol, length, 
    tcp_udp_flags, is_tls, is_quic, dns_query, sni, direction (direction is None).
    """
    record = {
        "packet_no": packet_no,
        "timestamp": timestamp,
        "src_ip": None,
        "dst_ip": None,
        "src_port": None,
        "dst_port": None,
        "protocol": None,
        "length": len(raw_frame),
        "tcp_udp_flags": None,
        "is_tls": False,
        "is_quic": False,
        "dns_query": None,
        "sni": None,
        "direction": None,
        "ip_ttl": None,
        "is_stun_binding": False,
        "stun_mapped_address": None,
        "tcp_window_size": None,
    }
    
    offset, ethertype = get_ip_header_offset(link_type, raw_frame)
    if offset is None or ethertype is None:
        return record
        
    ip_proto = None
    trans_offset = None
    
    # Parse IP Header
    if ethertype == 0x0800:  # IPv4
        if len(raw_frame) < offset + 20:
            return record
        version_ihl = raw_frame[offset]
        version = (version_ihl >> 4) & 0x0F
        ihl = version_ihl & 0x0F
        if version != 4 or ihl < 5:
            return record
        
        # Total IPv4 header length
        ip_hdr_len = ihl * 4
        if len(raw_frame) < offset + ip_hdr_len:
            return record
            
        ip_proto = raw_frame[offset + 9]
        record["ip_ttl"] = raw_frame[offset + 8]   # TTL is byte 8 of IPv4 header
        
        # Extract IPs
        src_bytes = raw_frame[offset + 12 : offset + 16]
        dst_bytes = raw_frame[offset + 16 : offset + 20]
        record["src_ip"] = f"{src_bytes[0]}.{src_bytes[1]}.{src_bytes[2]}.{src_bytes[3]}"
        record["dst_ip"] = f"{dst_bytes[0]}.{dst_bytes[1]}.{dst_bytes[2]}.{dst_bytes[3]}"
        
        trans_offset = offset + ip_hdr_len
        
    elif ethertype == 0x86DD:  # IPv6
        if len(raw_frame) < offset + 40:
            return record
        version = (raw_frame[offset] >> 4) & 0x0F
        if version != 6:
            return record
            
        next_hdr = raw_frame[offset + 6]
        
        # Extract IPs using socket.inet_ntop for proper format
        try:
            record["src_ip"] = socket.inet_ntop(socket.AF_INET6, raw_frame[offset + 8 : offset + 24])
            record["dst_ip"] = socket.inet_ntop(socket.AF_INET6, raw_frame[offset + 24 : offset + 40])
        except Exception:
            return record
            
        trans_offset = offset + 40
        
        # Walk IPv6 extension headers if present
        ext_hdrs = {0, 43, 44, 51, 60, 135}
        while next_hdr in ext_hdrs:
            if len(raw_frame) < trans_offset + 2:
                return record
            curr_hdr = next_hdr
            next_hdr = raw_frame[trans_offset]
            if curr_hdr == 44:  # Fragment header
                hdr_len = 8
            elif curr_hdr == 51:  # AH header
                hdr_len = (raw_frame[trans_offset + 1] + 2) * 4
            else:
                hdr_len = (raw_frame[trans_offset + 1] + 1) * 8
            
            trans_offset += hdr_len
            
        ip_proto = next_hdr
        
    else:
        # Unsupported IP version
        return record
        
    if trans_offset is None or trans_offset >= len(raw_frame):
        return record
        
    # Parse Transport Protocol
    if ip_proto == 6:  # TCP
        record["protocol"] = "TCP"
        if len(raw_frame) < trans_offset + 20:
            return record
            
        src_port, dst_port = struct.unpack('!HH', raw_frame[trans_offset : trans_offset + 4])
        record["src_port"] = src_port
        record["dst_port"] = dst_port
        
        window_size = struct.unpack('!H', raw_frame[trans_offset + 14 : trans_offset + 16])[0]
        record["tcp_window_size"] = window_size
        
        # TCP Flags
        flags_byte = raw_frame[trans_offset + 13]
        flags_list = []
        if flags_byte & 0x02: flags_list.append("SYN")
        if flags_byte & 0x10: flags_list.append("ACK")
        if flags_byte & 0x01: flags_list.append("FIN")
        if flags_byte & 0x04: flags_list.append("RST")
        if flags_byte & 0x08: flags_list.append("PSH")
        if flags_byte & 0x20: flags_list.append("URG")
        if flags_byte & 0x40: flags_list.append("ECE")
        if flags_byte & 0x80: flags_list.append("CWR")
        record["tcp_udp_flags"] = ",".join(flags_list)
        
        # TCP Payload
        data_offset = (raw_frame[trans_offset + 12] >> 4) & 0x0F
        tcp_payload_offset = trans_offset + (data_offset * 4)
        tcp_payload = raw_frame[tcp_payload_offset :]
        
        # TLS detection & parsing on port 443
        if src_port == 443 or dst_port == 443:
            if len(tcp_payload) >= 5:
                rec_type = tcp_payload[0]
                version_major = tcp_payload[1]
                # Standard TLS record content types (20-23) and SSL/TLS versions (3.x)
                if rec_type in (20, 21, 22, 23) and version_major == 3:
                    record["is_tls"] = True
                    if rec_type == 22:  # Handshake
                        sni = parse_tls_client_hello_sni(tcp_payload)
                        if sni:
                            record["sni"] = sni
                            
    elif ip_proto == 17:  # UDP
        record["protocol"] = "UDP"
        if len(raw_frame) < trans_offset + 8:
            return record
            
        src_port, dst_port = struct.unpack('!HH', raw_frame[trans_offset : trans_offset + 4])
        record["src_port"] = src_port
        record["dst_port"] = dst_port
        
        udp_payload = raw_frame[trans_offset + 8 :]
        
        # DNS detection & parsing on port 53
        if src_port == 53 or dst_port == 53:
            dns_query = parse_dns_query(udp_payload)
            if dns_query:
                record["dns_query"] = dns_query
                
        # QUIC heuristic on UDP port 443:
        if src_port == 443 or dst_port == 443:
            if len(udp_payload) >= 1:
                first_byte = udp_payload[0]
                if (first_byte & 0xC0) == 0xC0:
                    record["is_quic"] = True

        # STUN binding request/response parsing:
        if len(udp_payload) >= 20:
            try:
                msg_type, msg_len, magic = struct.unpack('!HHI', udp_payload[0:8])
                if magic == 0x2112A442:
                    record["is_stun_binding"] = True
                    
                    if msg_type == 0x0101: # Binding Response
                        idx = 20
                        end = min(20 + msg_len, len(udp_payload))
                        while idx + 4 <= end:
                            attr_type, attr_len = struct.unpack('!HH', udp_payload[idx:idx+4])
                            idx += 4
                            if idx + attr_len > end:
                                break
                            
                            if attr_type == 0x0020: # XOR-MAPPED-ADDRESS
                                attr_val = udp_payload[idx:idx+attr_len]
                                if len(attr_val) >= 8:
                                    family = attr_val[1]
                                    if family == 0x01: # IPv4
                                        x_port = struct.unpack('!H', attr_val[2:4])[0]
                                        x_ip = struct.unpack('!I', attr_val[4:8])[0]
                                        
                                        real_port = x_port ^ (magic >> 16)
                                        real_ip = x_ip ^ magic
                                        
                                        real_ip_str = f"{(real_ip >> 24) & 0xFF}.{(real_ip >> 16) & 0xFF}.{(real_ip >> 8) & 0xFF}.{real_ip & 0xFF}"
                                        record["stun_mapped_address"] = f"{real_ip_str}:{real_port}"
                                    elif family == 0x02 and len(attr_val) >= 20: # IPv6
                                        x_port = struct.unpack('!H', attr_val[2:4])[0]
                                        real_port = x_port ^ (magic >> 16)
                                        
                                        # IPv6 address is XORed with magic cookie (4 bytes) + transaction ID (12 bytes)
                                        # These are bytes 4 to 20 of the STUN header
                                        magic_txn_id = udp_payload[4:20]
                                        x_ip_bytes = attr_val[4:20]
                                        real_ip_bytes = bytes(a ^ b for a, b in zip(x_ip_bytes, magic_txn_id))
                                        
                                        try:
                                            import socket
                                            real_ip_str = socket.inet_ntop(socket.AF_INET6, real_ip_bytes)
                                            record["stun_mapped_address"] = f"[{real_ip_str}]:{real_port}"
                                        except Exception:
                                            pass
                                        
                            idx += attr_len
                            padding = (4 - (attr_len % 4)) % 4
                            idx += padding
            except struct.error:
                pass
                
        # Bug 12 fix: STUN Method 2 (WhatsApp 86-byte binding requests)
        # Moved out of the `elif` that was attached to `if len >= 20` because 
        # an 86-byte raw frame implies 44 bytes UDP payload, so it always hit
        # the first branch and never the elif.
        if not record.get("is_stun_binding") and len(raw_frame) == 86 and (src_port == 3478 or dst_port == 3478):
            record["is_stun_binding"] = True
                    
    return record
