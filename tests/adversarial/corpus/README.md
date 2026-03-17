# Adversarial TLS Input Corpus

Purpose: Reproducible byte sequences that previously caused parser crashes or incorrect JA4 generation.

## Format
- One `.bin` file per edge case
- File name: descriptive of the anomaly (e.g., `truncated_before_cipher_list.bin`)
- Each entry below documents:
  - Source (fuzzer, manual crafting, real-world capture)
  - Expected parser behavior (ValueError, None, or valid ClientHello)
  - Expected JA4 behavior (valid string or controlled crash)

## Files

### truncated_before_cipher_list.bin
- **Source:** Manual crafting
- **Parser:** ValueError (incomplete handshake)
- **JA4:** Not applicable (parser fails before JA4)
- **Notes:** ClientHello truncated immediately after TLS version

### truncated_mid_extension.bin
- **Source:** Manual crafting
- **Parser:** ValueError (extension length mismatch)
- **JA4:** Not applicable
- **Notes:** Extension list claims 20 bytes but only 10 provided

### empty_cipher_list.bin
- **Source:** Hypothesis fuzzer
- **Parser:** Valid ClientHello with empty cipher list
- **JA4:** Valid string (empty cipher hash)
- **Notes:** Some clients send empty cipher list during session resumption

### all_grease_ciphers.bin
- **Source:** Manual crafting
- **Parser:** Valid ClientHello
- **JA4:** Valid string (all-GREASE cipher hash)
- **Notes:** All cipher suites are GREASE values (0x0A0A, 0x1A1A, etc.)

### max_length_sni_255_chars.bin
- **Source:** Manual crafting
- **Parser:** Valid ClientHello
- **JA4:** Valid string (255-char SNI hash)
- **Notes:** SNI field at maximum allowed length (255 bytes)

### sni_with_null_byte.bin
- **Source:** Real-world capture (malicious traffic)
- **Parser:** Valid ClientHello
- **JA4:** Valid string (null byte included in hash)
- **Notes:** SNI contains embedded null byte

### overflow_extension_length.bin
- **Source:** Hypothesis fuzzer
- **Parser:** ValueError (extension overflow)
- **JA4:** Not applicable
- **Notes:** Extension length exceeds remaining packet bytes

### duplicate_extension_types.bin
- **Source:** Manual crafting
- **Parser:** Valid ClientHello (per RFC 8446, duplicates allowed)
- **JA4:** Valid string (duplicate extensions in hash)
- **Notes:** Same extension type appears twice

### zero_length_clienthello.bin
- **Source:** Hypothesis fuzzer
- **Parser:** ValueError (empty handshake)
- **JA4:** Not applicable
- **Notes:** Zero-length ClientHello record

### random_garbage_512_bytes.bin
- **Source:** Hypothesis fuzzer
- **Parser:** ValueError (invalid TLS format)
- **JA4:** Not applicable
- **Notes:** 512 bytes of random data
