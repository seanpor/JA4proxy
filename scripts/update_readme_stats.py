#!/usr/bin/env python3
import re
import subprocess
from pathlib import Path

def get_counts():
    result = subprocess.run(['python3', 'scripts/count_lines.py'], capture_output=True, text=True)
    counts = {}
    for line in result.stdout.split('\n'):
        if 'proxy' in line or 'Tests' in line or 'Scripts' in line or 'Infrastructure' in line:
            parts = line.split()
            if len(parts) >= 3:
                name = " ".join(parts[:-2]).strip()
                val = parts[-1].replace(',', '')
                counts[name] = int(val)
    return counts

def main():
    counts = get_counts()
    readme = Path('README.md')
    content = readme.read_text()

    # Map count categories to README labels
    mapping = {
        "Python proxy": ("Python proxy core", counts.get("Python proxy", 0)),
        "Go proxy": ("Go proxy core", counts.get("Go proxy", 0)),
        "Tests": ("Tests", counts.get("Tests (Python)", 0) + counts.get("Tests (Go)", 0)),
        "Scripts": ("Supporting services", counts.get("Scripts (Shell)", 0) + counts.get("Scripts (Python)", 0) + counts.get("Scripts (Lua/Redis)", 0)),
        "Infrastructure": ("Infrastructure", counts.get("Infrastructure (Docker)", 0) + counts.get("Infrastructure (YAML)", 0) + counts.get("Infrastructure (JSON)", 0) + counts.get("Infrastructure (config)", 0))
    }

    total = sum(counts.values())
    
    for key, (label, val) in mapping.items():
        pattern = rf'\| \*\*({label})\*\* \| ~[\d,]+ \|'
        replacement = f'| **{label}** | ~{val:,} |'
        content = re.sub(pattern, replacement, content)

    # Update total
    content = re.sub(r'\| \*\*Total\*\* \| \*\*~[\d,]+\*\* \|', f'| **Total** | **~{total:,}** |', content)

    readme.write_text(content)
    print("✅ README.md codebase statistics updated.")

if __name__ == '__main__':
    main()
