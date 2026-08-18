<!--
title: Good Traffic Profile
audience: reference
last_reviewed: 2026-08-18
phase: 827
-->

# The Good Traffic Profile

> **Purpose.** This project's governing asymmetry (`CLAUDE.md`) says a blocked
> real user costs far more than a missed bot. That rule is unusable until
> "real user" is written down. This file is that definition for the reference
> deployment: **a public web form, served to Irish consumers.**
>
> It is not background reading. It is the acceptance specification for
> detection tuning, and it is executed by
> `tests/fp_corpus/test_good_traffic_profile.py`. If a change to a detector,
> threshold, or signal makes that suite fail, the change is wrong by default —
> not the suite.

---

## 1. The user we must never block

A person filling out a form. Concretely:

| Dimension | Expected | Notes |
|---|---|---|
| **Client** | A stock browser — Chrome, Safari, Firefox, Edge | Desktop or mobile, current or one/two versions behind |
| **Network** | Residential fixed line or mobile | **Not** a datacentre or hosting ASN |
| **Origin ASN** | A known Irish consumer ISP | Eir, Vodafone IE, Three IE, Sky IE, Virgin Media IE |
| **Country** | `IE`, overwhelmingly | See §2 — the exception matters |
| **Session length** | **Up to 30 minutes** on one form | Long idle gaps are normal, not evidence |
| **Requests** | Very few — often **1–3 in total** | A form is loaded, filled, submitted |
| **Timing** | Irregular, human-paced | Bursty on load, then silent while typing |
| **TLS** | TLS 1.3 (1.2 for older mobiles), ALPN `h2` | JA4 varies with browser *and version* |

Two properties of this profile are load-bearing and easy to get wrong:

**The session is slow.** Thirty minutes of near-silence between a page load and
a submit is *the expected shape*, not an anomaly. Any signal that reads a long
quiet connection, or a return after a long gap, as suspicious will hit this
population first and hardest.

**The requests are few.** A legitimate user generating 1–3 connections is
indistinguishable, *by volume alone*, from a scanner deliberately staying under
a rate limit. Volume can therefore never be the sole discriminator. See §4 —
this is where the current implementation was getting it wrong.

## 2. Legitimate traffic that looks wrong

These are rarer, and every one of them is a real customer. They must survive.

- **The holidaymaker.** Same person, same browser, filling the same form from
  Spain or Portugal. Country is a weak prior, never a verdict — a country
  blacklist that includes anywhere Irish people take holidays is a business
  decision, not a security one.
- **The corporate VPN / roaming mobile user.** Egress country and ASN may not
  match the user's location at all.
- **Carrier-grade NAT.** This is the big one. Irish mobile networks put very
  large numbers of subscribers behind small pools of public addresses. **Many
  unrelated real people share one IP, and one /24 can front thousands of
  subscribers.** Any per-IP or per-subnet penalty is therefore a penalty on a
  crowd, not on a person.
- **The returning applicant.** Starts the form, gives up, comes back next day
  from a different DHCP lease or a different network entirely.

## 3. What "bad" looks like by contrast

Good and bad traffic are *not* separated by volume. They are separated by
**uniformity and provenance**:

| | Good | Bad |
|---|---|---|
| Fingerprints | Many — every browser/version/platform differs | One, or very few, repeated exactly |
| ASN type | Consumer ISP | Hosting, VPS, cloud, bulletproof |
| Timing | Irregular, human | Regular, machine-paced, or perfectly uniform |
| Outcome | Overwhelmingly allowed | A meaningful block rate |
| Purpose | Completes a form | Never completes anything |

The single most reliable discriminator available to us is **fingerprint
diversity**. Twenty real people are twenty-ish different clients. Twenty scanner
IPs are one tool wearing one JA4. Volume shape is the *same* for both; the
fingerprint spread is not.

## 4. The false positive this profile exposed

Writing this profile down immediately surfaced a live defect, which is the
point of writing it down.

`SlowScanDetector` fired on shape alone: **≥20 unique IPs in a /24, averaging
≤3 requests each, within 5 minutes.** It applied no block-rate gate and no
provenance gate.

That is a verbatim description of §1 and §2 combined — a busy five minutes on a
CGNAT'd Irish mobile /24, where 20 different real people each load the form
once. And the consequence was not merely a cosmetic dashboard entry:

1. The detector writes `analytics:slowscan:<subnet>` with a **30-minute TTL**.
2. `internal/security/analytics_signals.go` reads that key and adds
   **+30 to the risk score of every connection from that /24**.
3. Thresholds are flag 20 / rate_limit 35 / tarpit 55 / block 70. +30 puts a
   subscriber one small signal away from being rate-limited, and well inside
   tarpit range once anything else contributes.
4. The TTL is 30 minutes — **exactly the length of the form session in §1**, so
   the penalty outlives the very interaction it interrupts.

Note the collision is worst for mobile users, who are simultaneously the most
CGNAT'd and the most likely to be mid-form on a slow connection.

**The fix applied** (phase-827) is to require *corroboration* rather than
loosening the shape test: a slow-scan finding now also requires the group to
share a dominant characteristic — `slow_scan.min_shared_share`, default `0.80`,
i.e. 80% of sampled connections agreeing on some dimension such as JA4. Twenty
real browsers do not agree; one tool across twenty IPs does. The shape gate is
unchanged, so genuine slow scans are still caught.

The campaign detector was already safe by accident: its `block_rate >= 0.70`
gate is corroboration of the same kind. Slow-scan was the one detector that had
none.

## 5. Rules this profile imposes

1. **Volume alone never convicts.** Few requests is the good user's signature
   too. Any low-volume detection needs a second, independent agreeing signal.
2. **Never penalise a shared address without evidence of uniformity.** Per-IP
   and per-subnet penalties land on CGNAT crowds. Require a shared fingerprint,
   a hosting ASN, or a real block rate first.
3. **Slowness is not evidence.** No signal may treat a 30-minute session, a
   long idle gap, or a delayed return visit as inherently suspicious.
4. **Country is a prior, never a verdict.** `IE` is the norm; not-`IE` is a
   holiday.
5. **Consumer ASN is exculpatory; hosting ASN is probative.** This is the
   strongest provenance signal available and it is currently under-used —
   see §6.
6. **Fingerprint diversity is the discriminator.** Prefer it over volume,
   timing, or geography whenever it is available.

## 6. Provenance (closed)

`ASNClassifier.Classify()` used to resolve the ASN number and organisation name
for every connection and then **discard both**, keeping only a risk signal.
`ConnectionContext` carried `Country` but no ASN, so the ECS event had no
`client.as.number`, and `src/analytics/correlation.py` declared `asn` and
`asn_org` dimensions that nothing could populate. Rule 5 was unenforceable: the
detectors could not tell a consumer ISP /24 from a hosting provider /24 using
data the hot path had already computed.

That is now plumbed end to end:

- `ASNClassifier.ClassifyAndLookup()` returns the signals **and** the resolved
  ASN/organisation from the same traversal — one DB read, not two. `Classify()`
  remains as a wrapper so existing callers are untouched.
- `ConnectionContext.ASN` / `.ASNOrg` carry it through the pipeline.
- `cmd/ja4pd` emits `client.as.number` and `client.as.organization.name`.

Three properties are asserted rather than assumed, because each is a silent
failure if it regresses:

1. **Provenance is recorded on the paths that produce no signal at all.** A
   residential/mobile IP is the common case for legitimate traffic and yields
   no risk signal — an implementation that only recorded ASN alongside a signal
   would leave exactly the traffic we most need to identify unlabelled.
2. **Absence stays distinguishable from a result.** Classifier disabled, DB
   missing, lookup failed, IP unparseable → zero and empty string, never a
   guess. A fabricated ASN is worse than none: it invites an operator to act on
   provenance that was never observed.
3. **The Tor path reports no ASN**, because it short-circuits before any DB
   read. Asserted explicitly so that filling it in later is a deliberate
   choice.

Guarded by `internal/security/asn_provenance_test.go` and
`TestAsnProvenanceReachesCorrelation` in the FP corpus (which pins the ECS key
names on both sides — a rename in either language would otherwise empty the
dimension with no test failing).

**Still open:** nothing consumes provenance as a *gate* yet. `min_shared_share`
corroborates on client identity only. Using "this /24 is a consumer ISP" to
further protect it, and "this /24 is a hosting provider" to lower the bar,
is the natural next step now that the data is available.
