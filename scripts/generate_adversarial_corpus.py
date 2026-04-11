#!/usr/bin/env python3
"""
Generate adversarial TLS corpus files for testing.
Creates 10 .bin files in tests/adversarial/corpus/
"""
import os
import random
import struct

# Create corpus directory if not exists
os.makedirs('tests/adversarial/corpus', exist_ok=True)

def write_bin(filename, data):
    """Write binary data to corpus file."""
    with open(f"tests/adversarial/corpus/{filename}", "wb") as f:
        f.write(data)

# Base TLS header for most test cases
def make_base_header(length):
    """Create TLS record + handshake header."""
    return bytes.fromhex(f"16 03 01 00 {length:02x}") + bytes.fromhex("01 00 00") + struct.pack(">H", length-5)

# 1. truncated_before_cipher_list.bin
print("Generating: truncated_before_cipher_list.bin")
hdr = bytes.fromhex("16 03 01 00 40"  # TLS record: handshake, TLS 1.2, 64 bytes
                     "01 00 00 3c"  # Handshake: ClientHello, 60 bytes
                     "03 03"        # TLS 1.2
                     "00 01"        # Random[0:2]
                     "00 00"        # Random[2:4] (truncated)
                     "00"           # Session ID length (0)
                     "00 02"        # Cipher suites length (2 bytes... but truncated)
                    )
write_bin("truncated_before_cipher_list.bin", hdr)

# 2. truncated_mid_extension.bin
print("Generating: truncated_mid_extension.bin")
ext_data = bytes.fromhex("00 02"       # Cipher suites length
                         "c0 2b"       # TLS_AES_128_GCM_SHA256
                         "01"          # Session ID length
                         "00"          # Session ID
                         "00 1a"       # Extensions length (26 bytes)
                         "00 00"       # Extension: server_name (SNI)
                         "00 06"       # Extension length (6 bytes)
                         "00 04"       # Server name list length
                         "00 02"       # Name type: hostname
                         "00 02"       # Name length (2 bytes... but truncated)
                        )
full_hdr = hdr[:-1] + struct.pack(">H", len(hdr)-5+len(ext_data)) + ext_data
write_bin("truncated_mid_extension.bin", full_hdr)

# 3. empty_cipher_list.bin
print("Generating: empty_cipher_list.bin")
empty_ciphers = hdr[:-1] + struct.pack(">H", 0) + bytes.fromhex("00"  # Session ID length
                                                         "00"  # Extensions length
                                                        )
write_bin("empty_cipher_list.bin", empty_ciphers)

# 4. all_grease_ciphers.bin
print("Generating: all_grease_ciphers.bin")
grease_ciphers = bytes.fromhex("00 0a"  # Cipher list length (10 bytes)
                                "0a 0a"  # GREASE
                                "1a 1a"  # GREASE
                                "2a 2a"  # GREASE
                                "3a 3a"  # GREASE
                                "4a 4a"  # GREASE
                               )
grease_full = hdr[:-1] + struct.pack(">H", len(hdr)-5+len(grease_ciphers)) + grease_ciphers + bytes.fromhex("00")
write_bin("all_grease_ciphers.bin", grease_full)

# 5. max_length_sni_255_chars.bin
print("Generating: max_length_sni_255_chars.bin")
max_sni = b"a" * 255
sni_ext = bytes.fromhex("00 1a") + struct.pack(">H", len(max_sni)+5) + bytes.fromhex("00") + struct.pack(">H", len(max_sni)+3) + bytes.fromhex("00 00") + max_sni
sni_full = hdr[:-1] + struct.pack(">H", len(hdr)-5+2) + bytes.fromhex("00 02 c0 2b") + bytes.fromhex("00") + sni_ext
write_bin("max_length_sni_255_chars.bin", sni_full)

# 6. sni_with_null_byte.bin
print("Generating: sni_with_null_byte.bin")
null_sni = b"example\x00.com"
sni_null_ext = bytes.fromhex("00 10") + struct.pack(">H", len(null_sni)+5) + bytes.fromhex("00") + struct.pack(">H", len(null_sni)+3) + bytes.fromhex("00 00") + null_sni
sni_null_full = hdr[:-1] + struct.pack(">H", len(hdr)-5+2) + bytes.fromhex("00 02 c0 2b") + bytes.fromhex("00") + sni_null_ext
write_bin("sni_with_null_byte.bin", sni_null_full)

# 7. overflow_extension_length.bin
print("Generating: overflow_extension_length.bin")
overflow_ext = bytes.fromhex("00 1a") + struct.pack(">H", 255) + bytes.fromhex("00 04") + struct.pack(">H", 2) + bytes.fromhex("00 02") + b"ab"
overflow_full = hdr[:-1] + struct.pack(">H", len(hdr)-5+2) + bytes.fromhex("00 02 c0 2b") + bytes.fromhex("00") + overflow_ext
write_bin("overflow_extension_length.bin", overflow_full)

# 8. duplicate_extension_types.bin
print("Generating: duplicate_extension_types.bin")
dup_ext = bytes.fromhex("00 1a") + struct.pack(">H", 22) + \
           bytes.fromhex("00 00") + struct.pack(">H", 6) + struct.pack(">H", 4) + bytes.fromhex("00 02") + struct.pack(">H", 2) + b"ab" + \
           bytes.fromhex("00 00") + struct.pack(">H", 6) + struct.pack(">H", 4) + bytes.fromhex("00 02") + struct.pack(">H", 2) + b"cd"
dup_full = hdr[:-1] + struct.pack(">H", len(hdr)-5+2) + bytes.fromhex("00 02 c0 2b") + bytes.fromhex("00") + dup_ext
write_bin("duplicate_extension_types.bin", dup_full)

# 9. zero_length_clienthello.bin
print("Generating: zero_length_clienthello.bin")
zero_hello = bytes.fromhex("16 03 01 00 05") + bytes.fromhex("01 00 00 00")
write_bin("zero_length_clienthello.bin", zero_hello)

# 10. random_garbage_512_bytes.bin
print("Generating: random_garbage_512_bytes.bin")
random_garbage = bytes([random.randint(0, 255) for _ in range(512)])
write_bin("random_garbage_512_bytes.bin", random_garbage)

print("\nGenerated 10 adversarial corpus files in tests/adversarial/corpus/")
print("Files:")
for f in os.listdir('tests/adversarial/corpus'):
    if f.endswith('.bin'):
        size = os.path.getsize(f'tests/adversarial/corpus/{f}')
        print(f"  {f} ({size} bytes)")
