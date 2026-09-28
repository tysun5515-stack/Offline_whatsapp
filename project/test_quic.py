import binascii
from src.quic_decrypt import decrypt_quic_initial, hkdf_extract, hkdf_expand_label, decode_varint

def test_quic():
    # RFC 9001 Appendix A.1
    # DCID: 8394c8f03e515708
    # Packet:
    packet_hex = "c100000001088394c8f03e5157080000449e7b9aec34d1b1c98dd7689fb8ec11d242b123dc9bd8bab936b47d92ec356c0bab7df5976d27cd449f63300099f3991c260ec4c60d17b31f8429157bb35a1282a643a8d2262cad67500cadb8e7378c8eb7539ec4d4905fed1bee1fc8aafba17c750e2c7ace01e6005f80fcb7df62f26786fe91ec41e17dcc0a5d46816cbdf4492bfec3fb85292ebdae0cc430b5da909c2bd2c66cb1e8b7eb3a0050800b411d331405e3230a17300d86ed973d097960fc03bf6cc131d279cfce1d2f7f3cb7927bbbd8b7f83e6012e8b0a1a09d3cdba420df20c926a8d052a20fc107c11f71485fa6be48ba"
    payload = binascii.unhexlify(packet_hex)
    
    # 1. First byte
    assert payload[0] == 0xc1
    
    from src.quic_decrypt import QUIC_V1_SALT, hkdf_extract, hkdf_expand_label
    dcid = binascii.unhexlify("8394c8f03e515708")
    initial_secret = hkdf_extract(QUIC_V1_SALT, dcid)
    secret = hkdf_expand_label(initial_secret, "client in", b"", 32)
    key = hkdf_expand_label(secret, "quic key", b"", 16)
    iv = hkdf_expand_label(secret, "quic iv", b"", 12)
    hp_key = hkdf_expand_label(secret, "quic hp", b"", 16)
    
    print("secret:", binascii.hexlify(secret))
    print("key:", binascii.hexlify(key))
    print("iv:", binascii.hexlify(iv))
    print("hp:", binascii.hexlify(hp_key))
    
    decrypted = decrypt_quic_initial(payload, True)
    if decrypted:
        print("Decrypted!", binascii.hexlify(decrypted))
    else:
        print("Failed to decrypt")

if __name__ == '__main__':
    test_quic()
