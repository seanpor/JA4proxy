# ClientHello Fixtures

Binary TLS ClientHello captures for JA4 parity testing between the Python and Go parsers.

## Capture new fixtures

```bash
python3 scripts/capture_clienthello.py chrome_tls13 9443
# In another terminal: curl --tlsv1.3 https://127.0.0.1:9443/ -k
```

## Expected JA4 fingerprints

| File | Expected JA4 | Tool | TLS version |
|------|-------------|------|-------------|
| curl_tls13.bin | (run `python3 -c "from src.security.tls_parser import ...` to verify) | curl --tlsv1.3 | TLS 1.3 |

Run `GOROOT=/snap/go/current go test ./internal/tls/ -run TestJA4_FixturesParity -v` to verify.
