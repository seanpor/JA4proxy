#!/usr/bin/env python3
"""
Test-to-Code Ratio Calculator

Calculates the ratio of test code to production code.
"""

import os
import subprocess
from pathlib import Path


def count_lines_in_directory(directory: str, extensions: list) -> int:
    """Count lines of code in files with specified extensions."""
    lines = 0
    for root, dirs, files in os.walk(directory):
        for file in files:
            if any(file.endswith(ext) for ext in extensions):
                filepath = os.path.join(root, file)
                try:
                    with open(filepath, 'r', encoding='utf-8') as f:
                        lines += sum(1 for line in f if line.strip() and not line.strip().startswith('#'))
                except (UnicodeDecodeError, PermissionError):
                    pass
    return lines


def count_test_lines() -> int:
    """Count lines in test files."""
    return count_lines_in_directory('tests', ['.py'])


def count_production_lines() -> int:
    """Count lines in production code."""
    # Python production code
    python_lines = count_lines_in_directory('src', ['.py'])
    
    # Go production code
    go_lines = 0
    if os.path.exists('cmd'):
        go_lines += count_lines_in_directory('cmd', ['.go'])
    if os.path.exists('internal'):
        go_lines += count_lines_in_directory('internal', ['.go'])
    
    return python_lines + go_lines


def get_test_count() -> int:
    """Get current test count from pytest."""
    try:
        result = subprocess.run(
            ['python3', '-m', 'pytest', 'tests/', '--collect-only', '-q'],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        # Parse test count from output
        for line in result.stdout.split('\n'):
            if 'collected' in line:
                parts = line.split()
                for part in parts:
                    if part.isdigit():
                        return int(part)
        return 0
    except Exception as e:
        print(f"Warning: Could not get test count: {e}")
        return 0


def main():
    """Main entry point."""
    print("=" * 60)
    print("JA4proxy — Test-to-Code Ratio")
    print("=" * 60)
    
    # Count lines
    test_lines = count_test_lines()
    prod_lines = count_production_lines()
    test_count = get_test_count()
    
    # Calculate ratios
    if prod_lines > 0:
        line_ratio = test_lines / prod_lines
        test_per_prod = test_count / prod_lines if prod_lines > 0 else 0
    else:
        line_ratio = 0
        test_per_prod = 0
    
    # Print results
    print(f"\n📊 Code Metrics:")
    print(f"  Production code: {prod_lines:,} lines")
    print(f"  Test code:      {test_lines:,} lines")
    print(f"  Test count:     {test_count:,} tests")
    print(f"\n📈 Ratios:")
    print(f"  Test-to-code (lines): {line_ratio:.2f}:1")
    print(f"  Tests per prod line:  {test_per_prod:.4f}")
    print(f"  Target:              ≥1.3:1")
    
    # Status
    if line_ratio >= 1.3:
        status = "✅ EXCELLENT"
        color = "\033[92m"
    elif line_ratio >= 1.0:
        status = "⚠️  GOOD"
        color = "\033[93m"
    else:
        status = "❌ LOW"
        color = "\033[91m"
    
    print(f"\n{color}Status: {status}\033[0m")
    
    if line_ratio < 1.3:
        print(f"\n💡 Suggestion: Add more tests to reach the 1.3:1 target ratio.")
        print(f"   Needed: {int((1.3 * prod_lines) - test_lines):,} more test lines")
    
    print("=" * 60)


if __name__ == '__main__':
    main()