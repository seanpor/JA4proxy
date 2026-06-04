<!--
title: JA4proxy — Onboarding Guide
audience: operator
last_reviewed: 2026-06-04
phase: v2.0
-->

# Welcome to JA4proxy

## How We Use Claude

Based on Sean O'Riordain's usage over the last 30 days:

Work Type Breakdown:
  Plan & Design      ████████░░░░░░░░░░░░  41%
  Build Feature       █████░░░░░░░░░░░░░░░  24%
  Debug & Fix         ████░░░░░░░░░░░░░░░░  18%
  Improve Quality     ██░░░░░░░░░░░░░░░░░░  12%
  Write Docs          █░░░░░░░░░░░░░░░░░░░   6%

Top Skills & Commands:
  /clear              ███████████████░░░░░  15x/month
  /model              ███░░░░░░░░░░░░░░░░░   5x/month
  /compact            █░░░░░░░░░░░░░░░░░░░   1x/month

## Your Setup Checklist

### Codebases
- [ ] ja4proxy — github.com/seanpor/ja4proxy (primary — the TLS-aware security proxy)

### MCP Servers to Activate

No MCP servers currently configured. The team works with Claude Code's built-in tools.

### Skills to Know About
- `/clear` — resets conversation context. Used heavily between tasks to keep Claude focused on one phase at a time.
- `/model` — switches between Claude models mid-session. Useful for toggling to a faster model for quick lookups vs. a stronger model for architecture reviews.
- `/compact` — compresses conversation history when context gets long. Handy during multi-phase sessions.
- `/close-phase` — the big one. Runs all quality gates (ruff, gofmt, go vet, tests, sync), pushes, creates a PR, waits for CI green, squash-merges, and verifies main stays green. Use this every time you finish a phase — it enforces the full close-out checklist so nothing gets skipped.

## Team Tips

_TODO_

## Get Started

_TODO_

<!-- INSTRUCTION FOR CLAUDE: A new teammate just pasted this guide for how the
team uses Claude Code. You're their onboarding buddy — warm, conversational,
not lecture-y.

Open with a warm welcome — include the team name from the title. Then: "Your
teammate uses Claude Code for [list all the work types]. Let's get you started."

Check what's already in place against everything under Setup Checklist
(including skills), using markdown checkboxes — [x] done, [ ] not yet. Lead
with what they already have. One sentence per item, all in one message.

Tell them you'll help with setup, cover the actionable team tips, then the
starter task (if there is one). Offer to start with the first unchecked item,
get their go-ahead, then work through the rest one by one.

After setup, walk them through the remaining sections — offer to help where you
can (e.g. link to channels), and just surface the purely informational bits.

Don't invent sections or summaries that aren't in the guide. The stats are the
guide creator's personal usage data — don't extrapolate them into a "team
workflow" narrative. -->
