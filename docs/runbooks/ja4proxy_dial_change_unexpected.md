<!--
title: "ja4proxy dial change unexpected Runbook"
audience: oncall, sre
last_reviewed: 2026-04-10
phase: 86
-->

# Runbook: ja4proxy_dial_change_unexpected

## Severity
WARNING (dial changed without matching change ticket) → CRITICAL (dial set to extreme value >80 or <5)

## What is happening
The JA4proxy dial setting has changed. Dial controls the security
pipeline aggressiveness (0=monitor only, 100=maximum enforcement).
An unexpected change could indicate unauthorised access, misconfiguration,
or an automated response to an attack that wasn't communicated.

## Impact
- **High (CRITICAL):** Dial at extreme value (>80 or <5). May cause
  massive false positives (too high) or allow attack traffic through
  (too low).
- **Medium (WARNING):** Dial changed by an unknown source. Could be
  legitimate but undocumented.

## Diagnosis
1. Check current dial value:
   ```bash
   curl -sf http://<node>:8090/api/v1/health/deep | python3 -c "import sys,json; print(json.load(sys.stdin)['dial'])"
   ```
2. Check who changed it (audit log in Management UI):
   ```bash
   curl -sf http://localhost:8090/api/v1/events | python3 -c "
import sys, json
for line in sys.stdin:
    if line.startswith('data: '):
        event = json.loads(line[6:])
        if event.get('type') == 'dial_change':
            print(json.dumps(event, indent=2))
"
   ```
3. Check if a change ticket exists in your ITSM (ServiceNow, Jira, etc.):
   - Search for recent tickets with "JA4proxy" and "dial".
4. Check if dial change was triggered by an automated response:
   ```bash
   redis-cli -h <redis-host> GET ja4proxy:dial:last_change_source
   ```

## Resolution
**If change was authorised (ticket found):**
- Update the alert annotation to reflect the ticket number.
- No further action needed.

**If change was unauthorised:**
1. Immediately reset dial to the previous value:
   ```bash
   curl -sf -X PUT http://localhost:8090/api/v1/dial \
     -H "Content-Type: application/json" \
     -d '{"value": <previous-value>}'
   ```
2. Rotate Management API credentials.
3. Audit Management API access logs for unauthorised access.
4. File a security incident.

**If automated response (attack mitigation):**
- Verify the attack is still ongoing.
- If attack has subsided, return dial to normal:
  ```bash
  curl -sf -X PUT http://localhost:8090/api/v1/dial \
    -H "Content-Type: application/json" \
    -d '{"value": 25}'
  ```

## Escalation
Page SecOps lead immediately if dial was changed without authorisation.
Escalate to CISO if evidence suggests unauthorised access to management API.
