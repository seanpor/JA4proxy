#!/usr/bin/env python3
"""
Documentation Link Fixer
Uses the reports/workspace_audit.json to fix broken internal links in Markdown files.
Attempts to find the correct file in the workspace and update the link with the relative path.
"""

import json
import os
import re
from pathlib import Path


def find_file(name, all_files):
    """Find the best match for a filename in all_files."""
    # Direct match
    if name in all_files:
        return name

    # Base name match
    base = os.path.basename(name)
    matches = [f for f in all_files if os.path.basename(f) == base]
    if len(matches) == 1:
        return matches[0]

    # Try with common prefixes
    for prefix in ["src/security/", "src/", "scripts/", "docs/"]:
        if f"{prefix}{name}" in all_files:
            return f"{prefix}{name}"

    return None


def fix_links():
    audit_path = Path("reports/workspace_audit.json")
    if not audit_path.exists():
        print("Error: reports/workspace_audit.json not found. Run WIT first.")
        return

    with open(audit_path, "r") as f:
        audit = json.load(f)

    broken = audit.get("broken_references", {})
    all_files = set()
    for root, dirs, files in os.walk("."):
        for f in files:
            p = os.path.join(root, f).strip("./")
            if not any(
                part in {".git", "node_modules", "__pycache__"} for part in p.split("/")
            ):
                all_files.add(p)

    fixed_count = 0
    for src, refs in broken.items():
        if not src.endswith(".md"):
            continue

        src_path = Path(src)
        if not src_path.exists():
            continue

        with open(src_path, "r") as f:
            content = f.read()

        new_content = content
        for ref in refs:
            # Skip external links
            if ref.startswith("http"):
                continue

            # Skip globs/wildcards
            if "*" in ref:
                continue

            target = find_file(ref, all_files)
            if target:
                # Calculate relative path from src to target
                src_dir = os.path.dirname(src)
                rel_target = os.path.relpath(target, src_dir)

                # Replace the link in content
                # Search for [text](ref) or `ref`
                # Escaping special chars in ref for regex
                ref_esc = re.escape(ref)

                # Replace in Markdown links: [text](ref)
                new_content = re.sub(
                    f"\\[(.*?)\\]\\({ref_esc}\\)", f"[\\1]({rel_target})", new_content
                )
                # Replace in inline code: `ref`
                new_content = re.sub(f"`{ref_esc}`", f"`{rel_target}`", new_content)

                if new_content != content:
                    fixed_count += 1
                    content = new_content

        if content != new_content or fixed_count > 0:
            with open(src_path, "w") as f:
                f.write(new_content)
            print(f"Fixed links in {src}")

    print(f"Finished fixing {fixed_count} references.")


if __name__ == "__main__":
    fix_links()
