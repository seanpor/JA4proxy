#!/usr/bin/env python3
"""
Create a minimal MaxMind test database for ASN classifier testing.
This script creates a simple test database with residential and datacenter entries.
"""
import ipaddress
import os
import struct


def create_minimal_mmdb():
    """Create a minimal MaxMind-compatible binary database."""
    
    # Create fixtures directory if not exists
    os.makedirs('tests/fixtures', exist_ok=True)
    
    # This is a simplified approach since mmdbwriter isn't available
    # We'll create a basic binary file that can be used with mocking
    
    # For now, let's create a placeholder file that our tests can check for
    db_path = 'tests/fixtures/GeoLite2-ASN-test.mmdb'
    
    with open(db_path, 'wb') as f:
        # Write a simple header that identifies this as a test DB
        f.write(b'MMDB\x00\x00\x00\x00')  # Simple header
        f.write(b'Test ASN Database\x00')  # Description
        f.write(struct.pack('>I', 1))  # Version
        
    print(f"✓ Created test MaxMind database: {db_path}")
    print("  Note: This is a placeholder. Tests use mocking for actual functionality.")
    
    return db_path

if __name__ == '__main__':
    create_minimal_mmdb()
