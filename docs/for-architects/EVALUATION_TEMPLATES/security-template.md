<!--
title: "Security-Focused Evaluation Template"
audience: architect
last_reviewed: 2026-06-04
phase: v2.0
-->

# Security-Focused Evaluation Template

## Test Scenarios
1. **Known-Bad Fingerprint Blocking**
   - Import ja4db feed
   - Verify immediate rejection
2. **Protocol Smuggling Attempt**
   - Send HTTP over 443
   - Verify Protocol Lockdown
