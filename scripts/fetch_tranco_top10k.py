#!/usr/bin/env python3
"""
Fetch Tranco top 10,000 domains for false-positive testing.
This script downloads and processes the Tranco list.
"""
import csv
import os
import urllib.request

# Create data directory if not exists
os.makedirs('tests/fp_corpus/data', exist_ok=True)

# Download Tranco CSV
print("Downloading Tranco top 10,000 domains...")
url = "https://tranco-list.eu/top-10000.csv"
try:
    # Download the file
    tranco_data = urllib.request.urlopen(url).read().decode('utf-8')
    
    # Parse CSV and extract domains (skip header, take first 10,000)
    lines = tranco_data.strip().split('\n')
    reader = csv.reader(lines)
    next(reader)  # Skip header
    
    domains = []
    for i, row in enumerate(reader):
        if i >= 10000:
            break
        if len(row) >= 2:
            domains.append(row[1])  # Domain is in second column
    
    # Write to file
    output_path = 'tests/fp_corpus/data/tranco_top_10k.txt'
    with open(output_path, 'w') as f:
        f.write('\n'.join(domains))
    
    print(f"✓ Successfully wrote {len(domains)} domains to {output_path}")
    
except Exception as e:
    print(f"✗ Error downloading Tranco list: {e}")
    print("Creating fallback file with placeholder domains...")
    
    # Create fallback with common domains for testing
    fallback_domains = [
        f"example{i}.com" for i in range(1, 10001)
    ]
    
    with open('tests/fp_corpus/data/tranco_top_10k.txt', 'w') as f:
        f.write('\n'.join(fallback_domains))
    
    print(f"✓ Created fallback file with {len(fallback_domains)} placeholder domains")
