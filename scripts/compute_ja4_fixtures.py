#!/usr/bin/env python3
import json
import os
import pathlib
import sys

# Add current dir to path to import local modules
sys.path.append(os.getcwd())

from proxy import JA4Generator
from src.tls.parser import parse_client_hello


def compute():
    fixtures_dir = pathlib.Path("tests/fixtures/clienthello")
    known_ja4_path = fixtures_dir / "known_ja4.json"

    if known_ja4_path.exists():
        with open(known_ja4_path, "r") as f:
            known = json.load(f)
    else:
        known = {}

    generator = JA4Generator()

    for bin_file in fixtures_dir.glob("*.bin"):
        name = bin_file.stem
        data = bin_file.read_bytes()
        fields = parse_client_hello(data)
        if fields:
            ja4 = generator.generate_ja4(fields)
            print(f"{name}: {ja4}")
            known[name] = ja4
        else:
            print(f"{name}: FAILED TO PARSE")

    with open(known_ja4_path, "w") as f:
        json.dump(known, f, indent=2)
    print(f"\nUpdated {known_ja4_path}")


if __name__ == "__main__":
    compute()
