# False-Positive Test Data

## Files

### tranco_top_10k.txt
- **Source:** Tranco list (https://tranco-list.eu) — top 10,000 domains
- **Format:** One domain per line
- **Purpose:** DGA false-positive rate testing
- **Update:** Quarterly via `scripts/update_tranco.py`
- **Last Updated:** 2024-03-16
- **Provenance:** Downloaded from https://tranco-list.eu/top-10000.csv

### residential_ips.txt
- **Source:** Anonymized residential IPs from public datasets
- **Format:** One IP per line (IPv4 only)
- **Count:** 500+ IPs
- **Purpose:** ASN classification false-positive testing
- **Anonymization:** Last octet randomized; /24 preserved
- **Method:** Generated from common residential ranges (192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12)
- **Update Cadence:** Never (static dataset)

### browser_keepalive_timestamps.csv
- **Source:** Real browser timing from Chrome/Firefox/Safari
- **Format:** browser,timestamp1,timestamp2,...
- **Browsers:** Chrome, Firefox, Safari
- **Samples:** 100+ connections per browser
- **Collection:** Manual capture from clean VMs
- **Last Updated:** 2024-03-16

### known_good_ja4_fingerprints.txt
- **Source:** JA4+ project database
- **Format:** One JA4 fingerprint per line
- **Count:** 100+ fingerprints
- **Purpose:** Baseline for fingerprint analysis
- **Provenance:** Extracted from ja4plus.com public dataset

## Provenance Summary
- **tranco_top_10k.txt**: Downloaded 2024-03-16 from https://tranco-list.eu/top-10000.csv
- **residential_ips.txt**: Generated 2024-03-16 from public datasets with last-octet randomization
- **Update Cadence**: Quarterly for Tranco, never for anonymized IPs
- **Anonymization**: Documented in scripts/generate_residential_ips.py
