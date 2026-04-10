#!/usr/bin/env python3
"""
Generate anonymized residential IP addresses for ASN testing.
Creates 500+ realistic residential IPs with last-octet randomization.
"""
import os
import random


def generate_residential_ips(count=500):
    """Generate anonymized residential IP addresses."""
    
    # Common residential IP ranges (private and public)
    residential_ranges = [
        # Private ranges (RFC 1918)
        "192.168.{}.{}",
        "10.{}.{}.{}",
        "172.{}.{}.{}",
        # Public ranges that are typically residential
        "71.{}.{}.{}",    # Comcast
        "72.{}.{}.{}",    # Comcast
        "73.{}.{}.{}",    # Comcast
        "74.{}.{}.{}",    # Comcast
        "75.{}.{}.{}",    # Comcast
        "76.{}.{}.{}",    # Comcast
        "96.{}.{}.{}",    # Verizon
        "97.{}.{}.{}",    # Verizon
        "98.{}.{}.{}",    # Verizon
        "99.{}.{}.{}",    # Verizon
        "100.{}.{}.{}",   # Verizon
    ]
    
    ips = set()
    
    # Generate IPs from each range
    for range_template in residential_ranges:
        if "172." in range_template:
            # 172.16.0.0/12 - only 16-31 for third octet
            for i in range(16, 32):
                for j in range(0, 256):
                    if len(ips) >= count:
                        break
                    # Randomize last octet for anonymization
                    last_octet = random.randint(1, 254)
                    ip = range_template.format(i, j, last_octet)
                    ips.add(ip)
        elif "10." in range_template:
            # 10.0.0.0/8 - all octets variable
            for i in range(0, 256):
                for j in range(0, 256):
                    if len(ips) >= count:
                        break
                    last_octet = random.randint(1, 254)
                    ip = range_template.format(i, j, last_octet)
                    ips.add(ip)
        elif "192.168" in range_template:
            # 192.168.0.0/16
            for i in range(0, 256):
                if len(ips) >= count:
                    break
                last_octet = random.randint(1, 254)
                ip = range_template.format(i, last_octet)
                ips.add(ip)
        else:
            # Public ranges - use random octets
            for i in range(0, 256):
                for j in range(0, 256):
                    if len(ips) >= count:
                        break
                    last_octet = random.randint(1, 254)
                    ip = range_template.format(i, j, last_octet)
                    ips.add(ip)
    
    return list(ips)[:count]

if __name__ == '__main__':
    os.makedirs('tests/fp_corpus/data', exist_ok=True)
    
    print("Generating anonymized residential IPs...")
    ips = generate_residential_ips(500)
    
    with open('tests/fp_corpus/data/residential_ips.txt', 'w') as f:
        f.write('\n'.join(ips))
    
    print(f"✓ Generated {len(ips)} anonymized residential IPs")
    print(f"  First 5: {ips[:5]}")
    print(f"  Last 5: {ips[-5:]}")
    print("  File: tests/fp_corpus/data/residential_ips.txt")
