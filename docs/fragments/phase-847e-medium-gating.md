- **MEDIUM findings are now gated — on new findings only.** The PR regression gate
  scans each touched surface once at `MEDIUM,HIGH,CRITICAL` and judges the two
  bands against two separate records, so neither can make the other look dirty.
  A touched surface that carries a MEDIUM finding which is neither recorded in
  `security/baseline-medium.json` nor waived now fails the PR.
- **The MEDIUM surface was measured before it was gated.** `scripts/medium_inventory.py`
  scanned every deployed surface and recorded the result in
  `security/medium-inventory.md`: 152 unwaived MEDIUM findings, 119 of them with
  a published fix, 149 of them in third-party images. The scope was chosen from
  those numbers, not from a preference.
- **The MEDIUM record is a ratchet, not a baseline.** It may only shrink: a new
  MEDIUM finding is never absorbed into the record, it has to be fixed or waived
  with a justification and an expiry. `tests/unit/test_medium_ratchet.py` holds
  the committed ceiling, so raising it is a reviewed edit to a test rather than
  something a file can do to itself.
- **The monitor measures MEDIUM too.** It counts the band in the same scan pass
  as HIGH/CRITICAL and reports it against the committed record, so the backlog
  is visible without the monitor ever blocking a merge.
- **The shared Trivy parser stopped discarding findings it was not asked about.**
  It filtered to HIGH/CRITICAL unconditionally, so a MEDIUM scan parsed as "no
  findings at all" — and a comma-separated severity band was interpreted as the
  *characters* of the string. Both faults were silent, and both are fixed.
