"""
Pure-Python TLS ClientHello Parser.
High-performance, zero-dependency parser for JA4 fingerprinting.
Eliminates Scapy IPC overhead.
"""

from typing import Dict, List, Optional
import struct

def parse_client_hello(data: bytes) -> Optional[Dict]:
    """
    Parse a raw TLS ClientHello record.
    Returns a dict compatible with Scapy's TLSParser output or None on failure.
    Memory: O(N) linear pass. Never raises.
    """
    try:
        # 1. TLS Record Header (5 bytes)
        # 0: Content Type (0x16 = Handshake)
        # 1-2: Version
        # 3-4: Length
        if len(data) < 5 or data[0] != 0x16:
            return None
        
        record_len = struct.unpack("!H", data[3:5])[0]
        # Allow for data being larger than one record (peek buffer)
        # but the record itself must be complete in the buffer.
        if len(data) < 5 + record_len:
            return None
        
        # 2. Handshake Header (4 bytes)
        # 0: Handshake Type (0x01 = ClientHello)
        # 1-3: Length
        pos = 5
        if data[pos] != 0x01:
            return None
        
        hs_len = struct.unpack("!I", b"\x00" + data[pos+1:pos+4])[0]
        if record_len < 4 + hs_len:
            return None
        
        pos += 4
        
        # 3. ClientHello Body
        # 0-1: Version (Legacy)
        # 2-33: Random (32 bytes)
        # 34: Session ID Length
        if len(data) < pos + 35:
            return None
        
        legacy_version = struct.unpack("!H", data[pos:pos+2])[0]
        pos += 34 # Version + Random
        
        session_id_len = data[pos]
        pos += 1 + session_id_len
        
        # 4. Cipher Suites
        if len(data) < pos + 2:
            return None
        cs_len = struct.unpack("!H", data[pos:pos+2])[0]
        pos += 2
        
        if len(data) < pos + cs_len:
            return None
        
        cipher_suites = []
        for i in range(0, cs_len, 2):
            cipher_suites.append(struct.unpack("!H", data[pos+i:pos+i+2])[0])
        pos += cs_len
        
        # 5. Compression Methods
        if len(data) < pos + 1:
            return None
        cm_len = data[pos]
        pos += 1 + cm_len
        
        # 6. Extensions
        fields = {
            "version": legacy_version,
            "cipher_suites": cipher_suites,
            "extensions": [],
            "sni": "",
            "alpn": [],
            "supported_versions": [],
            "supported_groups": [],
            "signature_algorithms": [],
        }
        
        if len(data) < pos + 2:
            # No extensions is valid in very old TLS
            return fields
            
        exts_total_len = struct.unpack("!H", data[pos:pos+2])[0]
        pos += 2
        
        exts_end = pos + exts_total_len
        if len(data) < exts_end:
            return fields # Truncated extensions? Fail open.
            
        while pos + 4 <= exts_end:
            ext_type = struct.unpack("!H", data[pos:pos+2])[0]
            ext_len = struct.unpack("!H", data[pos+2:pos+4])[0]
            pos += 4
            
            if pos + ext_len > exts_end:
                break
                
            fields["extensions"].append(ext_type)
            ext_data = data[pos:pos+ext_len]
            
            # Parse specific extensions needed for JA4
            if ext_type == 0: # server_name (SNI)
                try:
                    # 0-1: List Length
                    # 2: Name Type (0 = host_name)
                    # 3-4: Name Length
                    if len(ext_data) >= 5 and ext_data[2] == 0:
                        name_len = struct.unpack("!H", ext_data[3:5])[0]
                        if len(ext_data) >= 5 + name_len:
                            fields["sni"] = ext_data[5:5+name_len].decode("ascii", errors="ignore")
                except Exception:
                    pass
            elif ext_type == 16: # ALPN
                try:
                    # 0-1: List Length
                    if len(ext_data) >= 3:
                        alpn_len = struct.unpack("!H", ext_data[0:2])[0]
                        alpn_pos = 2
                        while alpn_pos < 2 + alpn_len:
                            p_len = ext_data[alpn_pos]
                            alpn_pos += 1
                            if alpn_pos + p_len <= len(ext_data):
                                fields["alpn"].append(
                                    ext_data[alpn_pos:alpn_pos+p_len].decode("ascii", errors="ignore")
                                )
                            alpn_pos += p_len
                except Exception:
                    pass
            elif ext_type == 43: # supported_versions
                try:
                    # 0: List Length
                    if len(ext_data) >= 3:
                        v_len = ext_data[0]
                        for i in range(1, v_len, 2):
                            fields["supported_versions"].append(
                                struct.unpack("!H", ext_data[i:i+2])[0]
                            )
                except Exception:
                    pass
            elif ext_type == 10: # supported_groups
                try:
                    if len(ext_data) >= 4:
                        g_len = struct.unpack("!H", ext_data[0:2])[0]
                        for i in range(2, 2 + g_len, 2):
                            fields["supported_groups"].append(
                                struct.unpack("!H", ext_data[i:i+2])[0]
                            )
                except Exception:
                    pass
            elif ext_type == 13: # signature_algorithms
                try:
                    if len(ext_data) >= 4:
                        s_len = struct.unpack("!H", ext_data[0:2])[0]
                        for i in range(2, 2 + s_len, 2):
                            fields["signature_algorithms"].append(
                                struct.unpack("!H", ext_data[i:i+2])[0]
                            )
                except Exception:
                    pass
            
            pos += ext_len
            
        return fields

    except Exception:
        return None
