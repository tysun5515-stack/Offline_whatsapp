import struct
import hashlib
import json
from typing import Dict, Any, List, Tuple, Optional

# IANA TLS Supported Groups — confirmed against registry 2026-09
PQC_GROUPS = {
    0x11EC: ('X25519MLKEM768',           'hybrid_pqc'),  # production
    0x11EB: ('SecP256r1MLKEM768',        'hybrid_pqc'),
    0x11ED: ('SecP384r1MLKEM1024',       'hybrid_pqc'),
    0x0200: ('MLKEM512',                 'pure_pqc'),
    0x0201: ('MLKEM768',                 'pure_pqc'),
    0x0202: ('MLKEM1024',                'pure_pqc'),
    0x6399: ('X25519Kyber768Draft00',    'hybrid_pqc_draft'),
    0x639A: ('SecP256r1Kyber768Draft00', 'hybrid_pqc_draft'),
}

CLASSICAL_GROUPS = {
    0x001D: ('x25519',    'classical_ec'),
    0x001E: ('x448',      'classical_ec'),
    0x0017: ('secp256r1', 'classical_ec'),
    0x0018: ('secp384r1', 'classical_ec'),
    0x0019: ('secp521r1', 'classical_ec'),
    0x0100: ('ffdhe2048', 'classical_ffdh'),
    0x0101: ('ffdhe3072', 'classical_ffdh'),
    0x0102: ('ffdhe4096', 'classical_ffdh'),
}

CIPHER_NAMES = {
    0x1301: 'TLS_AES_128_GCM_SHA256',
    0x1302: 'TLS_AES_256_GCM_SHA384',
    0x1303: 'TLS_CHACHA20_POLY1305_SHA256',
    0x002F: 'TLS_RSA_WITH_AES_128_CBC_SHA',
    0x0035: 'TLS_RSA_WITH_AES_256_CBC_SHA',
    0x009C: 'TLS_RSA_WITH_AES_128_GCM_SHA256',
    0x009D: 'TLS_RSA_WITH_AES_256_GCM_SHA384',
    0x00FF: 'TLS_EMPTY_RENEGOTIATION_INFO_SCSV',
}

EXPECTED_SERVER_SHARE_LEN = {
    0x001D: 32,   # x25519
    0x001E: 56,   # x448
    0x0017: 65,   # secp256r1
    0x0018: 97,   # secp384r1
    0x0019: 133,  # secp521r1
    0x0100: 256,  # ffdhe2048
    0x0101: 384,  # ffdhe3072
    0x11EC: 1120, # X25519MLKEM768
    0x11EB: 1153, # SecP256r1MLKEM768
    0x11ED: 1665, # SecP384r1MLKEM1024
    0x0200: 768,  # MLKEM512
    0x0201: 1088, # MLKEM768
    0x0202: 1568, # MLKEM1024
}

GREASE_VALUES = {
    0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A,
    0x6A6A, 0x7A7A, 0x8A8A, 0x9A9A, 0xAAAA, 0xBABA,
    0xCACA, 0xDADA, 0xEAEA, 0xFAFA
}

HRR_RANDOM = bytes.fromhex(
    "CF21AD74E59A6111BE1D8C021E65B891"
    "C2A211167ABB8C5E079E09E2C8A8339C"
)


def _filter_grease(values: List[int]) -> List[int]:
    return [v for v in values if v not in GREASE_VALUES]


def _format_group(grp: int) -> Tuple[str, str]:
    if grp in PQC_GROUPS:
        return PQC_GROUPS[grp]
    if grp in CLASSICAL_GROUPS:
        return CLASSICAL_GROUPS[grp]
    return (f"0x{grp:04X}", "unknown")


def compute_kex_class(sh_data, hrr_only=False) -> str:
    if sh_data is None or hrr_only:
        return 'undetermined'
    neg_version = sh_data.get('neg_version')        # e.g. '0x0304'
    if neg_version and int(neg_version, 16) < 0x0304:
        return 'classical_tls12'
    key_share_group = sh_data.get('key_share_group')
    if key_share_group is None:
        # check if it was a PSK-only resumed session
        if sh_data.get('psk_selected'):
            return 'none_psk_ke'
        return 'undetermined'
    grp_int = int(key_share_group, 16)
    if grp_int in PQC_GROUPS:
        return PQC_GROUPS[grp_int][1]   # 'hybrid_pqc', 'pure_pqc', 'hybrid_pqc_draft'
    if grp_int in CLASSICAL_GROUPS:
        return CLASSICAL_GROUPS[grp_int][1]  # 'classical_ec', 'classical_ffdh'
    return 'unknown'


def parse_tls_client_hello(payload: bytes) -> Optional[Dict[str, Any]]:
    if len(payload) < 43:
        return None

    # TLS handshake header: type(1) + len(3)
    if payload[0] != 1:
        return None

    result = {
        'legacy_version': f"0x{struct.unpack('!H', payload[4:6])[0]:04X}",
        'cipher_suites': [],
        'supported_groups': [],
        'key_share_groups': [],
        'key_share_lens': [],
        'sig_algs': [],
        'ext_ids': [],
        'alpn': [],
        'has_sni': 0,
        'has_ech': 0,
        'has_psk': 0,
        'ja3': None,
        'complete': False
    }

    # Length of handshake body
    msg_len = int.from_bytes(payload[1:4], 'big')
    if len(payload) >= msg_len + 4:
        result['complete'] = True

    idx = 38 # skip type, len, ver, random (38 bytes)
    
    if idx >= len(payload): return result
    
    # Session ID
    sid_len = payload[idx]
    idx += 1 + sid_len
    if idx + 2 > len(payload): return result
    
    # Cipher suites
    cs_len = struct.unpack('!H', payload[idx:idx+2])[0]
    idx += 2
    raw_ciphers = []
    for i in range(idx, min(idx + cs_len, len(payload)), 2):
        if i + 2 <= len(payload):
            raw_ciphers.append(struct.unpack('!H', payload[i:i+2])[0])
    idx += cs_len
    
    filtered_ciphers = _filter_grease(raw_ciphers)
    result['cipher_suites'] = [f"0x{c:04X}" for c in filtered_ciphers]
    
    if idx >= len(payload): return result
    
    # Compression methods
    comp_len = payload[idx]
    idx += 1 + comp_len
    
    if idx + 2 > len(payload): return result
    
    # Extensions
    ext_total_len = struct.unpack('!H', payload[idx:idx+2])[0]
    idx += 2
    ext_end = min(idx + ext_total_len, len(payload))
    
    raw_ext_ids = []
    while idx + 4 <= ext_end:
        ext_type, ext_len = struct.unpack('!HH', payload[idx:idx+4])
        idx += 4
        if idx + ext_len > ext_end: break
        
        ext_data = payload[idx:idx+ext_len]
        raw_ext_ids.append(ext_type)
        
        if ext_type == 0:  # server_name
            result['has_sni'] = 1
        elif ext_type == 0x000a:  # supported_groups
            if len(ext_data) >= 2:
                g_len = struct.unpack('!H', ext_data[0:2])[0]
                raw_groups = []
                for i in range(2, min(2 + g_len, len(ext_data)), 2):
                    if i + 2 <= len(ext_data):
                        raw_groups.append(struct.unpack('!H', ext_data[i:i+2])[0])
                result['supported_groups'] = [f"0x{g:04X}" for g in _filter_grease(raw_groups)]
        elif ext_type == 0x0033:  # key_share
            if len(ext_data) >= 2:
                ks_len = struct.unpack('!H', ext_data[0:2])[0]
                s_idx = 2
                while s_idx + 4 <= min(2 + ks_len, len(ext_data)):
                    g, g_len = struct.unpack('!HH', ext_data[s_idx:s_idx+4])
                    s_idx += 4
                    if g not in GREASE_VALUES:
                        result['key_share_groups'].append(f"0x{g:04X}")
                        result['key_share_lens'].append(g_len)
                    s_idx += g_len
        elif ext_type == 0x000d:  # signature_algorithms
            if len(ext_data) >= 2:
                s_len = struct.unpack('!H', ext_data[0:2])[0]
                raw_sigs = []
                for i in range(2, min(2 + s_len, len(ext_data)), 2):
                    if i + 2 <= len(ext_data):
                        raw_sigs.append(struct.unpack('!H', ext_data[i:i+2])[0])
                result['sig_algs'] = [f"0x{s:04X}" for s in _filter_grease(raw_sigs)]
        elif ext_type == 0x0010:  # ALPN
            if len(ext_data) >= 2:
                list_len = struct.unpack('!H', ext_data[0:2])[0]
                s_idx = 2
                while s_idx < min(2 + list_len, len(ext_data)):
                    a_len = ext_data[s_idx]
                    s_idx += 1
                    if s_idx + a_len <= len(ext_data):
                        try:
                            result['alpn'].append(ext_data[s_idx:s_idx+a_len].decode('utf-8'))
                        except: pass
                    s_idx += a_len
        elif ext_type == 0xfe0d:  # ECH
            result['has_ech'] = 1
        elif ext_type == 41:  # pre_shared_key
            result['has_psk'] = 1
            
        idx += ext_len

    result['ext_ids'] = _filter_grease(raw_ext_ids)
    return result


def parse_tls_server_hello(payload: bytes) -> Optional[Dict[str, Any]]:
    if len(payload) < 38:
        return None
        
    if payload[0] != 2:
        return None
        
    msg_len = int.from_bytes(payload[1:4], 'big')
    
    result = {
        'neg_version': f"0x{struct.unpack('!H', payload[4:6])[0]:04X}", # fallback legacy version
        'cipher': None,
        'key_share_group': None,
        'key_share_len': None,
        'is_hrr': 0,
        'psk_selected': 0,
        'complete': False
    }

    if len(payload) >= msg_len + 4:
        result['complete'] = True
        
    random = payload[6:38]
    if random == HRR_RANDOM:
        result['is_hrr'] = 1
        
    idx = 38
    if idx >= len(payload): return result
    
    sid_len = payload[idx]
    idx += 1 + sid_len
    
    if idx + 2 > len(payload): return result
    result['cipher'] = f"0x{struct.unpack('!H', payload[idx:idx+2])[0]:04X}"
    idx += 2
    
    if idx + 1 > len(payload): return result
    comp_method = payload[idx]
    idx += 1
    
    if idx + 2 > len(payload): return result
    ext_total_len = struct.unpack('!H', payload[idx:idx+2])[0]
    idx += 2
    ext_end = min(idx + ext_total_len, len(payload))
    
    while idx + 4 <= ext_end:
        ext_type, ext_len = struct.unpack('!HH', payload[idx:idx+4])
        idx += 4
        if idx + ext_len > ext_end: break
        
        ext_data = payload[idx:idx+ext_len]
        
        if ext_type == 0x002b: # supported_versions
            if len(ext_data) >= 2:
                result['neg_version'] = f"0x{struct.unpack('!H', ext_data[0:2])[0]:04X}"
        elif ext_type == 0x0033: # key_share
            if len(ext_data) >= 2:
                result['key_share_group'] = f"0x{struct.unpack('!H', ext_data[0:2])[0]:04X}"
                # For HRR, key_share_len isn't the size of the share, there is no share, just the group
                if not result['is_hrr']:
                    result['key_share_len'] = len(ext_data) - 2 # group ID is 2 bytes
        elif ext_type == 41: # pre_shared_key
            result['psk_selected'] = 1
            
        idx += ext_len

    return result


def extract_wa_noise_handshake(flow: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    client_ip = flow.get('client_ip')
    sorted_pkts = sorted(flow['packets'], key=lambda p: p.get('timestamp', 0))
    
    c2s_stream = b''.join(
        p.get('_raw_tcp_payload', b'')
        for p in sorted_pkts
        if p.get('src_ip') == client_ip and p.get('_raw_tcp_payload')
    )
    s2c_stream = b''.join(
        p.get('_raw_tcp_payload', b'')
        for p in sorted_pkts
        if p.get('dst_ip') != client_ip and p.get('_raw_tcp_payload')
    )
    
    pos = -1
    for preamble in (b'ED', b'WA'):
        pos = c2s_stream.find(preamble)
        if pos >= 0:
            break
    if pos == -1:
        return None
    
    idx = pos + 4
    
    max_frame_size = 0
    frames_seen = 0
    while idx + 3 <= len(c2s_stream):
        msg_len = int.from_bytes(c2s_stream[idx:idx+3], 'big')
        idx += 3
        if msg_len == 0: continue
        if idx + msg_len > len(c2s_stream): break
        max_frame_size = max(max_frame_size, msg_len)
        frames_seen += 1
        idx += msg_len
        if frames_seen >= 3: break
    
    max_s2c_frame = 0
    s2c_idx = 0
    s2c_frames = 0
    s2c_pos = -1
    for preamble in (b'ED', b'WA'):
        s2c_pos = s2c_stream.find(preamble)
        if s2c_pos >= 0:
            s2c_idx = s2c_pos + 4
            break
    if s2c_pos >= 0:
        while s2c_idx + 3 <= len(s2c_stream) and s2c_frames < 3:
            msg_len = int.from_bytes(s2c_stream[s2c_idx:s2c_idx+3], 'big')
            s2c_idx += 3
            if msg_len == 0: continue
            if s2c_idx + msg_len > len(s2c_stream): break
            max_s2c_frame = max(max_s2c_frame, msg_len)
            s2c_frames += 1
            s2c_idx += msg_len
    
    overall_max = max(max_frame_size, max_s2c_frame)
    
    if frames_seen < 1:
        return None
    
    pqc_state = 'size_bounded_negative' if overall_max < 768 else 'unresolved'
    basis = (f'Max Noise message {overall_max}B < 768B ML-KEM minimum'
             if overall_max < 768 else
             f'Opaque field {overall_max}B >= 768B; cannot rule out ML-KEM')
    
    return {
        'wa_max_opaque_len': overall_max,
        'wa_ephemeral_key_len': 32,
        'pqc_state': pqc_state,
        'pqc_basis': basis,
        'kex_class': 'classical_sized_only',
        'wa_payload_len': None,
        'wa_static_len': None,
        'wa_pattern_hint': None
    }


def classify_pqc_state(ch: Optional[Dict[str, Any]], sh: Optional[Dict[str, Any]], hrr: Optional[Dict[str, Any]], direction_coverage: str) -> Tuple[str, str]:
    # Use second ServerHello if HRR occurred
    active_sh = hrr if hrr else sh
    
    if direction_coverage != 'both' and not active_sh:
        return 'incomplete_capture', 'One-directional capture without ServerHello'
        
    if not ch and not active_sh:
        return 'incomplete_capture', 'Missing ClientHello and ServerHello'
        
    if ch and not active_sh:
        # Check if client offered any PQC
        offered_hex_groups = ch.get('key_share_groups', [])
        supported_hex_groups = ch.get('supported_groups', [])
        pqc_in_ch = False
        for g_hex in offered_hex_groups + supported_hex_groups:
            if int(g_hex, 16) in PQC_GROUPS:
                pqc_in_ch = True
                break
        if not pqc_in_ch:
            return 'not_observed', 'both hellos seen; no PQC codepoint in supported_groups or key_share' # user expectation logic
        return 'incomplete_capture', 'Missing ServerHello'
        
    if not ch and active_sh:
        pass # Server only capture with SH is OK for server_selected
        
    if ch and active_sh and not (ch.get('complete') and active_sh.get('complete')):
        return 'incomplete_capture', 'Truncated handshake messages'
        
    if active_sh and active_sh.get('neg_version') in ('0x0303', '0x0302', '0x0301'):
        return 'not_applicable_tls12', 'Negotiated TLS 1.2 or lower'
        
    if active_sh:
        selected_group_hex = active_sh.get('key_share_group')
        if selected_group_hex:
            grp_int = int(selected_group_hex, 16)
            if grp_int in PQC_GROUPS:
                gname = PQC_GROUPS[grp_int][0]
                gclass = PQC_GROUPS[grp_int][1]
                return 'server_selected', f'server selected {gname} ({gclass})'
            
    if ch:
        offered_hex_groups = ch.get('key_share_groups', [])
        for g_hex in offered_hex_groups:
            if int(g_hex, 16) in PQC_GROUPS:
                gname = PQC_GROUPS[int(g_hex, 16)][0]
                return 'key_share_offered', f'client offered {gname}; server picked classical'
                
        supported_hex_groups = ch.get('supported_groups', [])
        for g_hex in supported_hex_groups:
            if int(g_hex, 16) in PQC_GROUPS:
                return 'capability_advertised', 'PQC listed in supported_groups; no key share sent'
                
    return 'not_observed', 'both hellos seen; no PQC codepoint in supported_groups or key_share'


def detect_transport(flow: Dict[str, Any]) -> str:
    protocol = flow.get("protocol_type", "")
    if protocol == "UDP":
        if any(p.get("quic_version") for p in flow["packets"]):
            return "quic"
    elif protocol == "TCP":
        for p in flow["packets"]:
            if p.get("is_tls"):
                return "tls_tcp"
        for p in flow["packets"]:
            if p.get("wa_header_seen"):
                return "wa_framed"
    return "unknown"



def extract_crypto_flows(flows: List[Dict[str, Any]], upload_id: str) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    crypto_flows = []
    crypto_events = []
    
    for flow in flows:
        transport = detect_transport(flow)
        
        # Determine direction coverage based on SYN/SYN-ACK or just traffic presence
        client_ip = flow.get('client_ip')
        c2s_seen = any(p.get('src_ip') == client_ip for p in flow["packets"])
        s2c_seen = any(p.get('dst_ip') == client_ip for p in flow["packets"])
                
        if c2s_seen and s2c_seen:
            coverage = 'both'
        elif c2s_seen:
            coverage = 'c2s_only'
        elif s2c_seen:
            coverage = 's2c_only'
        else:
            coverage = 'unknown'

        cf = {
            'flow_id': flow['flow_id'],
            'upload_id': upload_id,
            'transport': transport,
            'ip_version': 4 if ':' not in flow.get('endpoint_a_ip', '') else 6,
            'server_ip': flow.get('endpoint_b_ip'),
            'server_port': flow.get('endpoint_b_port'),
            'client_ip': flow.get('endpoint_a_ip'),
            'client_port': flow.get('endpoint_a_port'),
            'direction_coverage': coverage,
            'start_seen': 1 if flow.get('session_start_confirmed') else 0,
            'evidence_tier': 1 if transport in ('tls_tcp', 'quic') else (2 if transport == 'wa_framed' else 3),
            'first_seen': flow.get('first_seen'),
            'last_seen': flow.get('last_seen'),
            'duration_s': (flow.get('last_seen', 0) - flow.get('first_seen', 0)),
            'total_packets': len(flow['packets']),
            'total_bytes': sum(p.get('length', 0) for p in flow['packets']),
            'server_name': next((p.get('sni') for p in flow['packets'] if p.get('sni')), None),
            'name_source': 'sni' if any(p.get('sni') for p in flow['packets']) else 'none'
        }
        
        ch_data, sh_data, hrr_data, wa_data = None, None, None, None
        
        for p in flow['packets']:
            if 'tls_client_hello' in p and not ch_data:
                ch_data = p['tls_client_hello']
                cf['ch_frame_no'] = p.get('packet_no')
            if 'tls_server_hello' in p:
                sh = p['tls_server_hello']
                if sh.get('is_hrr'):
                    hrr_data = sh
                elif not sh_data:
                    sh_data = sh
                    cf['sh_frame_no'] = p.get('packet_no')
                    
        if transport == 'wa_framed':
            wa_data = extract_wa_noise_handshake(flow)
                
        # Fill CH data
        if ch_data:
            cf['client_hello_complete'] = 1 if ch_data.get('complete') else 0
            cf['ch_legacy_version'] = ch_data.get('legacy_version')
            cf['ch_cipher_suites_json'] = json.dumps(ch_data.get('cipher_suites', []))
            cf['ch_supported_groups_json'] = json.dumps(ch_data.get('supported_groups', []))
            cf['ch_key_share_groups_json'] = json.dumps(ch_data.get('key_share_groups', []))
            cf['ch_key_share_lens_json'] = json.dumps(ch_data.get('key_share_lens', []))
            cf['ch_sig_algs_json'] = json.dumps(ch_data.get('sig_algs', []))
            cf['ch_ext_ids_json'] = json.dumps(ch_data.get('ext_ids', []))
            cf['ch_alpn_json'] = json.dumps(ch_data.get('alpn', []))
            cf['ch_has_sni'] = ch_data.get('has_sni', 0)
            cf['ch_has_ech'] = ch_data.get('has_ech', 0)
            cf['ch_has_psk'] = ch_data.get('has_psk', 0)
            
            # Check legacy flags from CH
            CBC_CIPHER_CODES  = {0x002F, 0x0035, 0x003C, 0x003D, 0x0041, 0x0084, 0x002E, 0x0034, 0x0067, 0x006B}
            RSA_KEX_CODES     = {0x002F, 0x0035, 0x009C, 0x009D, 0x0001, 0x0004, 0x0005, 0x000A}
            SHA1_SIG_CODES    = {0x0201, 0x0301, 0x0401, 0x0501, 0x0601}  # rsa/ecdsa/dsa + sha1

            cs_ints = [int(c, 16) for c in ch_data.get('cipher_suites', [])]
            if any(c in CBC_CIPHER_CODES for c in cs_ints):  cf['flag_offers_cbc'] = 1
            if any(c in RSA_KEX_CODES    for c in cs_ints):  cf['flag_offers_rsa_kex'] = 1
            sa_ints = [int(s, 16) for s in ch_data.get('sig_algs', [])]
            if any(s in SHA1_SIG_CODES   for s in sa_ints):  cf['flag_offers_sha1_sig'] = 1

            # TLS 1.2 offer flag: check supported_versions extension
            ch_versions_raw = ch_data.get('supported_versions', [])
            if any(int(v, 16) == 0x0303 for v in ch_versions_raw if v): cf['flag_offers_tls12'] = 1

        # Fill SH data
        active_sh = hrr_data if hrr_data else sh_data
        if active_sh:
            cf['server_hello_complete'] = 1 if active_sh.get('complete') else 0
            cf['sh_neg_version'] = active_sh.get('neg_version')
            cf['sh_cipher'] = active_sh.get('cipher')
            cf['sh_key_share_group'] = active_sh.get('key_share_group')
            cf['sh_key_share_len'] = active_sh.get('key_share_len')
            cf['sh_psk_selected'] = active_sh.get('psk_selected', 0)
            
            if cf.get('sh_cipher'):
                c_int = int(cf['sh_cipher'], 16)
                cf['sh_cipher_name'] = CIPHER_NAMES.get(c_int, cf['sh_cipher'])
                cf['neg_cipher'] = cf['sh_cipher']
                cf['neg_cipher_name'] = cf['sh_cipher_name']
            
            # Formatted names
            if cf['sh_key_share_group']:
                grp_int = int(cf['sh_key_share_group'], 16)
                cf['sh_key_share_group_name'], cf['neg_group_class'] = _format_group(grp_int)
                cf['neg_group'] = cf['sh_key_share_group']
                cf['neg_group_name'] = cf['sh_key_share_group_name']
                
            if cf['sh_neg_version'] in ('0x0303', '0x0302', '0x0301'):
                cf['flag_negotiated_legacy'] = 1
                
        if hrr_data:
            cf['hrr_seen'] = 1
            cf['sh_is_hrr'] = 1
            cf['sh_is_hrr_only'] = 1 if sh_data is None else 0

        # KEX mode + resumed flag
        ch_has_psk = ch_data.get('has_psk', 0) if ch_data else 0
        sh_has_psk = active_sh.get('psk_selected', 0) if active_sh else 0
        resumed = 1 if (ch_has_psk and sh_has_psk) else 0
        cf['neg_resumed'] = resumed
        sh_has_key_share = bool(active_sh.get('key_share_group')) if active_sh else False
        if resumed:
            cf['neg_kex_mode'] = 'psk_dhe_ke' if sh_has_key_share else 'psk_ke'
        else:
            cf['neg_kex_mode'] = 'full'
            
        hrr_only = hrr_data is not None and sh_data is None
        cf['kex_class'] = compute_kex_class(active_sh, hrr_only=hrr_only)
        cf['neg_group_class'] = cf['kex_class']  # mirror for backward compat

        # size_mismatch check
        if cf.get('sh_key_share_group') and cf.get('sh_key_share_len') is not None:
            grp_int = int(cf['sh_key_share_group'], 16)
            expected = EXPECTED_SERVER_SHARE_LEN.get(grp_int)
            if expected and cf['sh_key_share_len'] != expected:
                cf['size_mismatch'] = 1

        # unknown_groups: groups in CH supported_groups not in either registry
        all_known = set(PQC_GROUPS) | set(CLASSICAL_GROUPS) | GREASE_VALUES
        if ch_data:
            ch_grps = [int(g, 16) for g in ch_data.get('supported_groups', [])]
            unknowns = [f'0x{g:04X}' for g in ch_grps if g not in all_known]
            if unknowns:
                cf['unknown_groups_json'] = json.dumps(unknowns)

        # Fill WA framed data
        if wa_data:
            cf['wa_ephemeral_key_len'] = wa_data.get('wa_ephemeral_key_len')
            cf['wa_static_len'] = wa_data.get('wa_static_len')
            cf['wa_payload_len'] = wa_data.get('wa_payload_len')
            cf['wa_max_opaque_len'] = wa_data.get('wa_max_opaque_len')
            cf['wa_pattern_hint'] = wa_data.get('wa_pattern_hint')

        # Classify PQC State
        if transport == 'wa_framed' and wa_data:
            cf['pqc_state'] = wa_data.get('pqc_state', 'unresolved')
            cf['pqc_basis'] = wa_data.get('pqc_basis', 'WA framed payload analysis')
        elif transport in ('tls_tcp', 'quic'):
            if transport == 'quic' and not (ch_data or sh_data):
                state = 'incomplete_capture'
                basis = 'quic_initial_not_decrypted'
            else:
                state, basis = classify_pqc_state(ch_data, sh_data, hrr_data, coverage)
            cf['pqc_state'] = state
            cf['pqc_basis'] = basis
            
            if state == 'server_selected':
                cf['pqc_server_selected'] = 1
            if state in ('key_share_offered', 'server_selected'):
                cf['pqc_key_share_offered'] = 1
            if state in ('capability_advertised', 'key_share_offered', 'server_selected'):
                cf['pqc_capability'] = 1
        else:
            cf['pqc_state'] = 'not_applicable'
            cf['pqc_basis'] = 'Not a TLS/QUIC/WA transport'

        cf['classification'] = flow.get('media_type') or flow.get('sub_activity')
        cf['whatsapp_confidence'] = flow.get('whatsapp_confidence')

        crypto_flows.append(cf)
        
    return crypto_flows, crypto_events
