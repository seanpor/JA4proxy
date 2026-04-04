#!/usr/bin/env python3
import os
import re
import sys

def get_python_metrics():
    metrics = set()
    # Scoped strictly to Proxy Core
    search_paths = ['proxy.py', 'src/']
    for path in search_paths:
        if os.path.isfile(path):
            content = open(path, 'r', encoding='utf-8').read()
            matches = re.findall(r'(?:Counter|Gauge|Histogram)\(["\'](ja4proxy_[^"\']+)["\']', content)
            metrics.update(matches)
        elif os.path.isdir(path):
            for root, _, files in os.walk(path):
                for f in files:
                    if f.endswith('.py'):
                        content = open(os.path.join(root, f), 'r', encoding='utf-8').read()
                        matches = re.findall(r'(?:Counter|Gauge|Histogram)\(["\'](ja4proxy_[^"\']+)["\']', content)
                        metrics.update(matches)
    return metrics

def get_go_metrics():
    metrics = set()
    for root, _, files in os.walk('internal'):
        for f in files:
            if f.endswith('.go'):
                content = open(os.path.join(root, f), 'r', encoding='utf-8').read()
                matches = re.findall(r'Name:\s*["\'](ja4proxy_[^"\']+)["\']', content)
                metrics.update(matches)
    return metrics

def main():
    py_metrics = get_python_metrics()
    go_metrics = get_go_metrics()
    missing_in_go = py_metrics - go_metrics
    if missing_in_go:
        print("❌ Missing Proxy Core metrics in Go:")
        for m in sorted(missing_in_go):
            print(f"  - {m}")
        sys.exit(1)
    else:
        print("✅ Go implementation has all Proxy Core metrics.")
        sys.exit(0)

if __name__ == '__main__':
    main()
