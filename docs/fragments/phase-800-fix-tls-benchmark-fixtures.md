- **Fix three broken TLS benchmarks (Phase 800)**: `BenchmarkClientHelloParse`,
  `BenchmarkJA4Compute` and `BenchmarkClientHelloParseAdversarial` failed on every
  run. `generateTestClientHello()` hand-assembled bytes that were not a
  well-formed ClientHello — it omitted the 2-byte record length and the 4-byte
  handshake header, so the parser read two bytes of the *random* field as the
  record length, giving "TLS record too large" or "truncated ClientHello"
  depending on the draw. The fixtures now delegate to `buildClientHelloBytes`,
  the same builder the package's passing parser tests use. Separately, the
  adversarial benchmark asserted that truncated and non-TLS buffers must parse
  *successfully*, which is backwards — rejection is the path being measured.
  Adds `TestBenchmarkFixturesAreValid`, because `go test` does not run benchmarks
  without `-bench`, so a rotted fixture is otherwise invisible to `make test` —
  which is how this survived unnoticed.
