#!/usr/bin/env python3
import os
import subprocess
import sys
import re

def check_makefile():
    print("=== Meta-Lint: Makefile Analysis ===")
    
    # 1. Check for recursion and basic syntax
    try:
        subprocess.check_output(["make", "-n", "help"], stderr=subprocess.STDOUT)
        print("  ✓ Basic syntax & variable recursion check: PASS")
    except subprocess.CalledProcessError as e:
        print(f"  ❌ Makefile syntax error or recursion detected:\n{e.output.decode()}")
        return False

    # 2. Check for .PHONY consistency
    with open("Makefile", "r") as f:
        content = f.read()
    
    # Match all .PHONY lines, handling potential backslash continuations
    phony_matches = re.findall(r"^\.PHONY:(.*?)(?:(?<!\\)\n|\Z)", content, re.MULTILINE | re.DOTALL)
    all_phony = set()
    for match in phony_matches:
        # Remove backslashes and split
        clean_match = match.replace("\\", " ")
        all_phony.update(clean_match.split())
    
    # Simple regex for top-level targets
    targets = re.findall(r"^([a-zA-Z0-9_-]+):", content, re.MULTILINE)
    
    missing_phony = []
    for t in targets:
        # Ignore all, help, etc if they are standard but check the rest
        if t not in all_phony:
            # Check if it looks like a file
            if not os.path.exists(t):
                missing_phony.append(t)
    
    if missing_phony:
        print(f"  ! Warning: Targets not marked .PHONY: {', '.join(missing_phony)}")
    else:
        print("  ✓ .PHONY consistency: PASS")

    print("=== Meta-Lint: Script Integrity ===")
    # Check for shebangs in scripts
    scripts_dir = "scripts"
    if os.path.exists(scripts_dir):
        for s in os.listdir(scripts_dir):
            if s.endswith((".sh", ".py")):
                path = os.path.join(scripts_dir, s)
                with open(path, "r") as f:
                    try:
                        first_line = f.readline()
                        if not first_line.startswith("#!"):
                            print(f"  ! Warning: {path} is missing a shebang")
                    except Exception:
                        pass

    print("=== Meta-Lint complete ===")
    return True

def verify_documentation_commands():
    print("=== Meta-Lint: Documentation Command Sync ===")
    docs = ["README.md", "docs/OPERATIONS_GUIDE.md"]
    
    try:
        with open("Makefile", "r") as f:
            makefile_content = f.read()
        make_targets = set(re.findall(r"^([a-zA-Z0-9_-]+):", makefile_content, re.MULTILINE))
    except Exception as e:
        print(f"  ! Error: Could not parse Makefile targets: {e}")
        return False

    all_valid = True
    for doc in docs:
        if not os.path.exists(doc): continue
        with open(doc, "r") as f:
            content = f.read()
        
        # Find make commands in code blocks: `make target` or ```bash\nmake target\n```
        cmds = re.findall(r"`make (.*?)`", content)
        blocks = re.findall(r"```bash\n(.*?)\n```", content, re.DOTALL)
        for b in blocks:
            for line in b.split("\n"):
                if line.strip().startswith("make "):
                    cmds.append(line.strip().replace("make ", ""))

        for cmd in cmds:
            target = cmd.split()[0]
            target = target.strip(".,;:!")
            if target not in make_targets and target != "start-all.sh" and not target.startswith("."):
                print(f"  ❌ {doc}: Command \u0027make {target}\u0027 referenced but target missing in Makefile")
                all_valid = False
                
    if all_valid:
        print("  ✓ Documentation commands are synchronized with Makefile")
    return all_valid

if __name__ == "__main__":
    if not check_makefile() or not verify_documentation_commands():
        sys.exit(1)
