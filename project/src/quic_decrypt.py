import struct
import binascii
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

QUIC_V1_SALT = bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")

def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    h = hmac.HMAC(salt, hashes.SHA256())
    h.update(ikm)
    return h.finalize()

def hkdf_expand_label(secret: bytes, label: str, context: bytes, length: int) -> bytes:
    label_bytes = label.encode("ascii")
    hkdf_label = struct.pack("!H", length) + struct.pack("B", 6 + len(label_bytes)) + b"tls13 " + label_bytes + struct.pack("B", len(context)) + context
    hkdf = HKDFExpand(algorithm=hashes.SHA256(), length=length, info=hkdf_label)
    return hkdf.derive(secret)

def decode_varint(data, offset):
    v = data[offset]
    length = 1 << (v >> 6)
    val = v & 0x3F
    for i in range(1, length):
        val = (val << 8) + data[offset+i]
    return val, offset+length

QUIC_SECRETS = {}

def decrypt_quic_initial(payload: bytes, is_client: bool, flow_key: tuple = None):
    if len(payload) < 5: return None
    first_byte = payload[0]
    if (first_byte & 0xC0) != 0xC0: return None
    packet_type = (first_byte & 0x30) >> 4
    if packet_type != 0: return None
    quic_version = struct.unpack("!I", payload[1:5])[0]
    if quic_version != 1: return None
    
    dcid_len = payload[5]
    if len(payload) < 6 + dcid_len: return None
    dcid = payload[6:6+dcid_len]
    
    if is_client:
        initial_secret = hkdf_extract(QUIC_V1_SALT, dcid)
        if flow_key:
            QUIC_SECRETS[flow_key] = initial_secret
    else:
        initial_secret = QUIC_SECRETS.get(flow_key) if flow_key else None
        if not initial_secret:
            # fallback, though it'll likely be wrong unless the server reused the SCID as DCID
            initial_secret = hkdf_extract(QUIC_V1_SALT, dcid)
    
    if is_client:
        secret = hkdf_expand_label(initial_secret, "client in", b"", 32)
    else:
        secret = hkdf_expand_label(initial_secret, "server in", b"", 32)
        
    key = hkdf_expand_label(secret, "quic key", b"", 16)
    iv = hkdf_expand_label(secret, "quic iv", b"", 12)
    hp_key = hkdf_expand_label(secret, "quic hp", b"", 16)
    
    idx = 6 + dcid_len
    scid_len = payload[idx]
    idx += 1 + scid_len
    
    token_len, idx = decode_varint(payload, idx)
    idx += token_len
    
    length, idx = decode_varint(payload, idx)
    pn_offset = idx
    
    sample_offset = pn_offset + 4
    if sample_offset + 16 > len(payload): return None
    sample = payload[sample_offset : sample_offset+16]
    
    cipher = Cipher(algorithms.AES(hp_key), modes.ECB())
    encryptor = cipher.encryptor()
    mask = encryptor.update(sample)[:5]
    
    header = bytearray(payload[:pn_offset+4])
    header[0] ^= mask[0] & 0x0F
    
    pn_len = (header[0] & 0x03) + 1
    
    pn = 0
    for i in range(pn_len):
        header[pn_offset+i] ^= mask[i+1]
        pn = (pn << 8) + header[pn_offset+i]
        
    header = bytes(header[:pn_offset+pn_len])
    
    nonce = bytearray(iv)
    for i in range(pn_len):
        nonce[12-pn_len+i] ^= header[pn_offset+i]
        
    ciphertext_len = length - pn_len
    if pn_offset + pn_len + ciphertext_len > len(payload):
        return None
    full_ciphertext = payload[pn_offset+pn_len : pn_offset+pn_len+ciphertext_len]
    tag = full_ciphertext[-16:]
    data = full_ciphertext[:-16]
    
    payload_cipher = Cipher(algorithms.AES(key), modes.GCM(bytes(nonce), tag))
    decryptor = payload_cipher.decryptor()
    
    try:
        decryptor.authenticate_additional_data(header)
        cleartext = decryptor.update(data) + decryptor.finalize()
        return cleartext
    except Exception as e:
        return None

# Parse CRYPTO frames from decrypted QUIC payload
def parse_crypto_frames(cleartext: bytes):
    idx = 0
    tls_data = b""
    while idx < len(cleartext):
        frame_type = cleartext[idx]
        if frame_type == 0x00: # PADDING
            idx += 1
            continue
        elif frame_type == 0x06: # CRYPTO
            idx += 1
            offset, idx = decode_varint(cleartext, idx)
            length, idx = decode_varint(cleartext, idx)
            tls_data += cleartext[idx:idx+length]
            idx += length
        elif frame_type == 0x01: # PING
            idx += 1
        elif frame_type == 0x02: # ACK
            # Simplified skip for ACK
            idx += 1
            _, idx = decode_varint(cleartext, idx) # largest acked
            _, idx = decode_varint(cleartext, idx) # delay
            ack_range_count, idx = decode_varint(cleartext, idx)
            _, idx = decode_varint(cleartext, idx) # first ack range
            for _ in range(ack_range_count):
                _, idx = decode_varint(cleartext, idx) # gap
                _, idx = decode_varint(cleartext, idx) # range
        else:
            # Other frames, break
            break
    return tls_data

if __name__ == "__main__":
    from src.pcap_reader import _read_classic_pcap
    from src.packet_parser import parse_packet
    import sys
    import os

    pcap_file = os.path.join(os.path.dirname(__file__), "..", "..", "..", "capture A", "2.pcap")
    print("Testing QUIC decryption on:", pcap_file)
    try:
        with open(pcap_file, 'rb') as f:
            magic = f.read(4)
            for ts, net, data in _read_classic_pcap(f, magic):
                rec = parse_packet(data, net, ts)
                if rec.get("is_quic"):
                    udp_payload = data[-rec.get("udp_payload_len", len(data)):] # Hack to get udp payload
                    # Actually parse_packet doesn't return raw udp, we can modify packet_parser to do so.
    except Exception as e:
        print(e)
