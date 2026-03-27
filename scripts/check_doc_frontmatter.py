#!/usr/bin/env python3
"""
Documentation Frontmatter Validator

Validates that all documentation files have required frontmatter and updates last_reviewed dates.

Usage:
    python3 scripts/check_doc_frontmatter.py [--fix]
    
    --fix: Automatically update last_reviewed dates (default: dry run)
"""

import os
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import List, Tuple, Optional

# Configuration
REQUIRED_FRONTMATTER = [
    "title",
    "audience", 
    "last_reviewed",
    "phase"
]

EXEMPT_DIRS = [
    "phases",      # Phase files have different structure
    "decisions",    # ADR files have different structure
    "api",         # Auto-generated files
    "reports"      # Generated reports
]

EXEMPT_FILES = [
    "PROJECT_STATUS.md",  # Auto-generated from manifest
    "TODO.md"            # Auto-generated from manifest
]

class FrontmatterError(Exception):
    """Exception for frontmatter validation errors."""
    pass

class DocumentValidator:
    def __init__(self, fix_mode: bool = False):
        self.fix_mode = fix_mode
        self.errors = []
        self.warnings = []
        self.files_checked = 0
        self.files_fixed = 0

    def _extract_frontmatter(self, content: str) -> dict:
        """Extract frontmatter from HTML comment block."""
        # Match HTML comment block at start of file
        match = re.match(r'<!--\n(.*?)\n-->', content, re.DOTALL)
        if not match:
            return {}
        
        frontmatter = {}
        for line in match.group(1).strip().split('\n'):
            if ':' in line:
                key, value = line.split(':', 1)
                frontmatter[key.strip()] = value.strip()
        
        return frontmatter

    def _validate_frontmatter(self, file_path: Path, frontmatter: dict) -> bool:
        """Validate frontmatter against requirements."""
        valid = True
        missing = []
        
        for required in REQUIRED_FRONTMATTER:
            if required not in frontmatter:
                missing.append(required)
                valid = False
        
        if missing:
            self.errors.append((file_path, f"Missing frontmatter: {', '.join(missing)}"))
        
        # Check last_reviewed date format
        if 'last_reviewed' in frontmatter:
            date_str = frontmatter['last_reviewed']
            try:
                datetime.strptime(date_str, '%Y-%m-%d')
            except ValueError:
                self.errors.append((file_path, f"Invalid last_reviewed date format: {date_str}"))
                valid = False
        
        # Check for stale last_reviewed (> 180 days)
        if 'last_reviewed' in frontmatter:
            date_str = frontmatter['last_reviewed']
            try:
                review_date = datetime.strptime(date_str, '%Y-%m-%d')
                days_stale = (datetime.now() - review_date).days
                if days_stale > 180:
                    self.warnings.append((file_path, f"Stale last_reviewed: {days_stale} days old"))
                    if self.fix_mode:
                        frontmatter['last_reviewed'] = datetime.now().strftime('%Y-%m-%d')
                        self.files_fixed += 1
            except ValueError:
                pass  # Already reported as error
        
        return valid

    def _check_file(self, file_path: Path) -> bool:
        """Check a single documentation file."""
        # Check if file is exempt
        if file_path.name in EXEMPT_FILES:
            return True
            
        try:
            content = file_path.read_text(encoding='utf-8')
            frontmatter = self._extract_frontmatter(content)
            
            if not frontmatter:
                # Check if this is a phase file (different format)
                if 'phases' in str(file_path) or 'decisions' in str(file_path):
                    return True
                
                self.errors.append((file_path, "Missing frontmatter block"))
                return False
            
            return self._validate_frontmatter(file_path, frontmatter)
            
        except Exception as e:
            self.errors.append((file_path, f"Error reading file: {e}"))
            return False

    def validate_directory(self, dir_path: Path) -> None:
        """Validate all markdown files in a directory."""
        for file_path in dir_path.rglob('*.md'):
            # Skip exempt directories
            if any(exempt in str(file_path) for exempt in EXEMPT_DIRS):
                continue
            
            self.files_checked += 1
            self._check_file(file_path)

    def print_results(self) -> None:
        """Print validation results."""
        print(f"\n{'='*60}")
        print(f"Documentation Frontmatter Validation Results")
        print(f"{'='*60}")
        print(f"Files checked: {self.files_checked}")
        print(f"Files fixed: {self.files_fixed}")
        print(f"Errors: {len(self.errors)}")
        print(f"Warnings: {len(self.warnings)}")
        
        if self.errors:
            print(f"\n{'='*60}")
            print("ERRORS (missing or invalid frontmatter):")
            print(f"{'='*60}")
            for file_path, error in self.errors:
                print(f"  📄 {file_path}")
                print(f"     ❌ {error}")
        
        if self.warnings:
            print(f"\n{'='*60}")
            print("WARNINGS (stale or issues):")
            print(f"{'='*60}")
            for file_path, warning in self.warnings:
                print(f"  📄 {file_path}")
                print(f"     ⚠️  {warning}")
        
        if not self.errors and not self.warnings:
            print(f"\n✅ All documentation files have valid frontmatter!")
        
        print(f"\n{'='*60}\n")

    def run(self, docs_dir: Path = Path('docs')) -> bool:
        """Run validation on documentation directory."""
        print(f"Validating documentation in {docs_dir}...")
        self.validate_directory(docs_dir)
        self.print_results()
        
        return len(self.errors) == 0


def main():
    """Main entry point."""
    fix_mode = '--fix' in sys.argv
    
    validator = DocumentValidator(fix_mode=fix_mode)
    success = validator.run()
    
    if not success:
        print("❌ Frontmatter validation failed!")
        sys.exit(1)
    else:
        print("✅ Frontmatter validation passed!")
        sys.exit(0)


if __name__ == '__main__':
    main()