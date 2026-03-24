#!/usr/bin/env python3
"""
Sync Roadmap Script
Generates TODO.md and PROJECT_STATUS.md from docs/phases/manifest.yaml
"""

import os
import yaml
from datetime import datetime

MANIFEST_PATH = "docs/phases/manifest.yaml"
TODO_PATH = "docs/phases/TODO.md"
STATUS_PATH = "docs/PROJECT_STATUS.md"

def load_manifest():
    with open(MANIFEST_PATH, "r") as f:
        return yaml.safe_load(f)

def generate_todo(manifest):
    lines = [
        "# JA4proxy Phase TODO List",
        "",
        "This document tracks the remaining work for both historical phases (gaps identified post-completion) and upcoming planned phases. Each item links to a detailed, actionable TDD work plan.",
        "",
    ]
    
    # Critical Gaps
    lines.append("## 🔴 Critical Gaps in Completed Phases (<= 15)")
    lines.append("")
    
    for phase_id, data in manifest["phases"].items():
        if data["status"] == "PARTIAL":
            lines.append(f"### Phase {phase_id} — {data['name']}")
            for gap in data.get("gaps", []):
                lines.append(f"*   **Gap:** {gap}")
            lines.append(f"*   **Status:** **PARTIAL** ({data['summary']})")
            if "action_plan" in data:
                # Adjust path for TODO.md which is in docs/phases/
                plan_file = os.path.basename(data["action_plan"])
                lines.append(f"*   **Action Plan:** [{plan_file}]({plan_file})")
            lines.append("")

    # In Progress
    lines.append("---")
    lines.append("")
    lines.append("## 🟡 Phases In Progress")
    lines.append("")
    
    for phase_id, data in manifest["phases"].items():
        if data["status"] in ["IN PROGRESS", "NEARLY DONE"]:
            lines.append(f"### Phase {phase_id} — {data['name']}")
            for task in data.get("tasks_remaining", []):
                lines.append(f"*   **Task:** {task}")
            lines.append(f"*   **Status:** **{data['status']}** ({data['summary']})")
            if "action_plan" in data:
                plan_file = os.path.basename(data["action_plan"])
                lines.append(f"*   **Action Plan:** [{plan_file}]({plan_file})")
            lines.append("")

    # Planned / Open
    lines.append("---")
    lines.append("")
    lines.append("## 🔵 Planned & Open Phases")
    lines.append("")
    
    for phase_id in sorted(manifest["phases"].keys()):
        data = manifest["phases"][phase_id]
        if data["status"] in ["OPEN", "DEFERRED", "PROPOSED"]:
            lines.append(f"### Phase {phase_id} — {data['name']}")
            lines.append(f"*   **Status:** **{data['status']}** ({data['summary']})")
            if "action_plan" in data:
                plan_file = os.path.basename(data["action_plan"])
                lines.append(f"*   **Action Plan:** [{plan_file}]({plan_file})")
            lines.append("")

    with open(TODO_PATH, "w") as f:
        f.write("\n".join(lines))

def generate_status(manifest):
    date_str = datetime.now().strftime("%Y-%m-%d")
    
    # Find current phase (first non-COMPLETE)
    next_phase = "N/A"
    for phase_id in sorted(manifest["phases"].keys()):
        if manifest["phases"][phase_id]["status"] != "COMPLETE":
            next_phase = f"Phase {phase_id} ({manifest['phases'][phase_id]['name']})"
            break

    lines = [
        "# JA4 Proxy - Project Status",
        "",
        f"## Current Status: {next_phase} Next",
        "",
        f"**Last Updated:** {date_str}",
        "",
        "## Epics & Roadmap",
        "",
    ]
    
    for epic in manifest["epics"]:
        lines.append(f"### {epic['name']}")
        lines.append(epic['description'])
        lines.append("")
        lines.append("| Phase | Name | Status | Summary |")
        lines.append("|-------|------|--------|---------|")
        for phase_id in epic["phases"]:
            p = manifest["phases"][phase_id]
            lines.append(f"| {phase_id} | {p['name']} | {p['status']} | {p['summary']} |")
        lines.append("")

    lines.append("## Phase Completion Details")
    lines.append("")
    lines.append("| Phase | Name | Status | Test Coverage | Documentation |")
    lines.append("|-------|------|--------|---------------|---------------|")
    for phase_id in sorted(manifest["phases"].keys()):
        p = manifest["phases"][phase_id]
        lines.append(f"| {phase_id} | {p['name']} | {p['status']} | {p.get('test_coverage', 'N/A')} | {p.get('doc_status', 'N/A')} |")
    
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("*Generated automatically from docs/phases/manifest.yaml*")

    with open(STATUS_PATH, "w") as f:
        f.write("\n".join(lines))

if __name__ == "__main__":
    manifest = load_manifest()
    generate_todo(manifest)
    generate_status(manifest)
    print(f"Successfully synced {TODO_PATH} and {STATUS_PATH} from manifest.")
