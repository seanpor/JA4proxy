#!/usr/bin/env python3
"""
TLS Traffic Generator for JA4proxy Performance Testing

Generates realistic TLS traffic with a mix of:
- Legitimate clients (10-20%) using browser-like TLS configurations
- Malicious clients (80-90%) using tool/malware-like TLS configurations

Each profile creates real TLS connections with distinct ClientHello fingerprints.
The proxy extracts JA4 fingerprints from these ClientHello messages.
"""

import random
import time
import argparse
import sys
import ssl
import socket
import os
from dataclasses import dataclass
from typing import List, Dict, Optional
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed


class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'


@dataclass
class ClientProfile:
    """Profile for a simulated TLS client"""
    name: str
    description: str
    malicious: bool
    request_rate: float  # connections per second
    attack_type: Optional[str] = None
    # TLS configuration
    tls_min_version: int = ssl.TLSVersion.TLSv1_2
    tls_max_version: int = ssl.TLSVersion.TLSv1_3
    ciphers: str = "DEFAULT"
    alpn: Optional[List[str]] = None
    sni: str = "backend"


# Legitimate client profiles — browser-like TLS configs, low rate
LEGITIMATE_CLIENTS = [
    ClientProfile(
        name="Chrome_Windows",
        description="Google Chrome on Windows — modern TLS 1.3",
        malicious=False,
        request_rate=0.5,
        tls_min_version=ssl.TLSVersion.TLSv1_2,
        tls_max_version=ssl.TLSVersion.TLSv1_3,
        ciphers="ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS",
        alpn=["h2", "http/1.1"],
        sni="backend",
    ),
    ClientProfile(
        name="Firefox_MacOS",
        description="Mozilla Firefox on macOS — modern TLS 1.3",
        malicious=False,
        request_rate=0.3,
        tls_min_version=ssl.TLSVersion.TLSv1_2,
        tls_max_version=ssl.TLSVersion.TLSv1_3,
        ciphers="ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:!aNULL:!MD5:!DSS:!RC4",
        alpn=["h2", "http/1.1"],
        sni="backend",
    ),
    ClientProfile(
        name="Safari_iOS",
        description="Safari on iOS — modern TLS 1.3",
        malicious=False,
        request_rate=0.4,
        tls_min_version=ssl.TLSVersion.TLSv1_2,
        tls_max_version=ssl.TLSVersion.TLSv1_3,
        ciphers="ECDHE+AESGCM:ECDHE+CHACHA20:ECDHE+AES:DHE+AESGCM:!aNULL:!MD5",
        alpn=["h2", "http/1.1"],
        sni="backend",
    ),
]

# Malicious client profiles — tool-like TLS configs, high rate
MALICIOUS_CLIENTS = [
    ClientProfile(
        name="Sliver_C2",
        description="Sliver C2 agent — Go TLS stack, no ALPN",
        malicious=True,
        request_rate=20.0,
        attack_type="C2 Communication",
        tls_min_version=ssl.TLSVersion.TLSv1_2,
        tls_max_version=ssl.TLSVersion.TLSv1_3,
        ciphers="ECDHE+AESGCM:ECDHE+CHACHA20:!aNULL:!MD5",
        alpn=None,  # C2 tools often skip ALPN
        sni="backend",
    ),
    ClientProfile(
        name="CobaltStrike_Beacon",
        description="Cobalt Strike Beacon — older TLS, limited ciphers",
        malicious=True,
        request_rate=15.0,
        attack_type="C2 Communication",
        tls_min_version=ssl.TLSVersion.TLSv1_2,
        tls_max_version=ssl.TLSVersion.TLSv1_2,  # CS beacon often TLS 1.2 only
        ciphers="AES256-SHA:AES128-SHA:AES256-GCM-SHA384:AES128-GCM-SHA256",
        alpn=None,
        sni="backend",
    ),
    ClientProfile(
        name="Python_Requests_Bot",
        description="Python requests library — bot/scraper tool",
        malicious=True,
        request_rate=30.0,
        attack_type="Scraping",
        tls_min_version=ssl.TLSVersion.TLSv1_2,
        tls_max_version=ssl.TLSVersion.TLSv1_3,
        ciphers="DEFAULT",  # Python default ciphers are distinctive
        alpn=None,
        sni="backend",
    ),
    ClientProfile(
        name="Credential_Stuffer",
        description="Credential stuffing tool — minimal TLS",
        malicious=True,
        request_rate=50.0,
        attack_type="Credential Stuffing",
        tls_min_version=ssl.TLSVersion.TLSv1_2,
        tls_max_version=ssl.TLSVersion.TLSv1_2,
        ciphers="AES128-SHA:AES256-SHA:DES-CBC3-SHA",
        alpn=None,
        sni="backend",
    ),
    ClientProfile(
        name="Evilginx_Phishing",
        description="Evilginx phishing proxy — Go TLS stack",
        malicious=True,
        request_rate=10.0,
        attack_type="Phishing",
        tls_min_version=ssl.TLSVersion.TLSv1_2,
        tls_max_version=ssl.TLSVersion.TLSv1_3,
        ciphers="ECDHE+AESGCM:ECDHE+CHACHA20:!aNULL:!MD5",
        alpn=None,
        sni="backend",
    ),
]


def create_ssl_context(profile: ClientProfile) -> ssl.SSLContext:
    """Create an SSLContext that produces a distinct ClientHello fingerprint."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = profile.tls_min_version
    ctx.maximum_version = profile.tls_max_version
    
    try:
        ctx.set_ciphers(profile.ciphers)
    except ssl.SSLError:
        ctx.set_ciphers("DEFAULT")
    
    if profile.alpn:
        ctx.set_alpn_protocols(profile.alpn)
    
    return ctx


class TrafficGenerator:
    """Generates real TLS traffic to test JA4proxy"""
    
    def __init__(self, target_host="localhost", target_port=443,
                 duration=60, good_traffic_percent=15, workers=50):
        self.target_host = target_host
        self.target_port = target_port
        self.duration = duration
        self.good_traffic_percent = good_traffic_percent
        self.workers = workers
        
        self.stats = defaultdict(lambda: {
            "connections": 0, "success": 0, "blocked": 0, "errors": 0
        })
        self.start_time = None
        self.running = True
        
    def make_tls_connection(self, profile: ClientProfile) -> Dict:
        """Make a real TLS connection through the proxy/LB."""
        result = {
            "profile": profile.name,
            "status": None,
            "blocked": False,
            "error": None,
        }
        
        sock = None
        tls_sock = None
        try:
            ctx = create_ssl_context(profile)
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((self.target_host, self.target_port))
            
            # Wrap with TLS — this sends the ClientHello
            tls_sock = ctx.wrap_socket(sock, server_hostname=profile.sni)
            
            # If we get here, TLS handshake succeeded — connection was allowed
            # Send a simple HTTP request over TLS
            request = (
                f"GET / HTTP/1.1\r\n"
                f"Host: {profile.sni}\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            ).encode()
            tls_sock.send(request)
            
            # Try to read response
            try:
                response = tls_sock.recv(4096)
                if response:
                    result["status"] = "connected"
                    self.stats[profile.name]["success"] += 1
                else:
                    result["status"] = "empty_response"
                    self.stats[profile.name]["success"] += 1
            except socket.timeout:
                # Might be tarpitted
                result["status"] = "timeout_reading"
                result["blocked"] = True
                self.stats[profile.name]["blocked"] += 1
                
        except ssl.SSLError as e:
            # TLS handshake failed — could be blocked
            result["error"] = f"TLS: {e}"
            result["blocked"] = True
            self.stats[profile.name]["blocked"] += 1
        except ConnectionRefusedError:
            result["error"] = "Connection refused"
            result["blocked"] = True
            self.stats[profile.name]["blocked"] += 1
        except ConnectionResetError:
            result["error"] = "Connection reset"
            result["blocked"] = True
            self.stats[profile.name]["blocked"] += 1
        except socket.timeout:
            result["error"] = "Connection timeout"
            result["blocked"] = True
            self.stats[profile.name]["blocked"] += 1
        except Exception as e:
            result["error"] = str(e)
            self.stats[profile.name]["errors"] += 1
        finally:
            try:
                if tls_sock:
                    tls_sock.close()
                elif sock:
                    sock.close()
            except Exception:
                pass
        
        self.stats[profile.name]["connections"] += 1
        return result
    
    def worker(self, profile: ClientProfile, num_connections: int):
        """Worker that generates TLS connections for a client profile."""
        interval = 1.0 / profile.request_rate if profile.request_rate > 0 else 1.0
        
        for i in range(num_connections):
            if not self.running:
                break
                
            try:
                result = self.make_tls_connection(profile)
                
                if result["blocked"]:
                    if random.random() < 0.1:  # Log 10% of blocks
                        print(f"{Colors.WARNING}✗ BLOCKED{Colors.ENDC} {profile.name} ({result.get('error', 'blocked')})")
                elif result["error"]:
                    if random.random() < 0.2:
                        print(f"{Colors.FAIL}✗ ERROR{Colors.ENDC} {profile.name}: {result['error']}")
                elif random.random() < 0.05:  # Log 5% of success
                    print(f"{Colors.OKGREEN}✓{Colors.ENDC} {profile.name} -> {result['status']}")
                    
            except Exception as e:
                if random.random() < 0.1:
                    print(f"{Colors.FAIL}Exception: {e}{Colors.ENDC}")
            
            time.sleep(interval)
    
    def print_stats(self):
        """Print traffic generation statistics."""
        elapsed = time.time() - self.start_time
        
        print(f"\n{Colors.HEADER}{'='*85}{Colors.ENDC}")
        print(f"{Colors.HEADER}TLS Traffic Statistics (Elapsed: {elapsed:.1f}s){Colors.ENDC}")
        print(f"{Colors.HEADER}{'='*85}{Colors.ENDC}\n")
        
        total = sum(s["connections"] for s in self.stats.values())
        total_ok = sum(s["success"] for s in self.stats.values())
        total_blocked = sum(s["blocked"] for s in self.stats.values())
        total_errors = sum(s["errors"] for s in self.stats.values())
        
        print(f"{Colors.BOLD}Overall:{Colors.ENDC}")
        print(f"  Total Connections: {total:,}")
        if total > 0:
            print(f"  Successful:        {total_ok:,} ({total_ok/total*100:.1f}%)")
            print(f"  Blocked:           {total_blocked:,} ({total_blocked/total*100:.1f}%)")
            print(f"  Errors:            {total_errors:,} ({total_errors/total*100:.1f}%)")
            print(f"  Connections/sec:   {total/elapsed:.2f}")
        
        # Separate legitimate vs malicious
        legit_ok = sum(self.stats[p.name]["success"] for p in LEGITIMATE_CLIENTS if p.name in self.stats)
        legit_total = sum(self.stats[p.name]["connections"] for p in LEGITIMATE_CLIENTS if p.name in self.stats)
        legit_blocked = sum(self.stats[p.name]["blocked"] for p in LEGITIMATE_CLIENTS if p.name in self.stats)
        
        mal_ok = sum(self.stats[p.name]["success"] for p in MALICIOUS_CLIENTS if p.name in self.stats)
        mal_total = sum(self.stats[p.name]["connections"] for p in MALICIOUS_CLIENTS if p.name in self.stats)
        mal_blocked = sum(self.stats[p.name]["blocked"] for p in MALICIOUS_CLIENTS if p.name in self.stats)
        
        print(f"\n{Colors.BOLD}Security Effectiveness:{Colors.ENDC}")
        if legit_total > 0:
            print(f"  {Colors.OKGREEN}Legitimate traffic:{Colors.ENDC} {legit_ok}/{legit_total} allowed ({legit_ok/legit_total*100:.1f}%), {legit_blocked} blocked")
        if mal_total > 0:
            print(f"  {Colors.FAIL}Malicious traffic:{Colors.ENDC}  {mal_blocked}/{mal_total} blocked ({mal_blocked/mal_total*100:.1f}%), {mal_ok} leaked through")
        
        print(f"\n{Colors.BOLD}By Profile:{Colors.ENDC}\n")
        print(f"{'Profile':<25} {'Type':<12} {'Conns':<10} {'OK':<10} {'Blocked':<10} {'Errors':<10}")
        print("-" * 77)
        
        for name, stats in sorted(self.stats.items(), key=lambda x: x[1]["connections"], reverse=True):
            profile = next((p for p in LEGITIMATE_CLIENTS + MALICIOUS_CLIENTS if p.name == name), None)
            ptype = f"{Colors.FAIL}Malicious{Colors.ENDC}" if profile and profile.malicious else f"{Colors.OKGREEN}Legit{Colors.ENDC}"
            print(f"{name:<25} {ptype:<21} {stats['connections']:<10} {stats['success']:<10} {stats['blocked']:<10} {stats['errors']:<10}")
        
        print(f"\n{Colors.HEADER}{'='*85}{Colors.ENDC}\n")
    
    def run(self):
        """Run traffic generation."""
        print(f"{Colors.HEADER}")
        print("╔════════════════════════════════════════════════════════════════════╗")
        print("║          JA4proxy TLS Traffic Generator                           ║")
        print("╚════════════════════════════════════════════════════════════════════╝")
        print(f"{Colors.ENDC}\n")
        
        print(f"Configuration:")
        print(f"  Target:            {self.target_host}:{self.target_port}")
        print(f"  Duration:          {self.duration}s")
        print(f"  Good Traffic:      {self.good_traffic_percent}%")
        print(f"  Bad Traffic:       {100 - self.good_traffic_percent}%")
        print(f"  Workers:           {self.workers}")
        print()
        
        self.start_time = time.time()
        
        num_good = max(1, int(self.workers * self.good_traffic_percent / 100))
        num_bad = self.workers - num_good
        
        # Calculate connections per worker based on duration and rate
        max_connections = max(10, self.duration * 5)
        
        print(f"Spawning clients:")
        print(f"  {Colors.OKGREEN}✓ {num_good} legitimate clients{Colors.ENDC}")
        print(f"  {Colors.FAIL}✗ {num_bad} malicious clients{Colors.ENDC}")
        print()
        
        with ThreadPoolExecutor(max_workers=self.workers) as executor:
            tasks = []
            
            for i in range(num_good):
                profile = random.choice(LEGITIMATE_CLIENTS)
                future = executor.submit(self.worker, profile, max_connections)
                tasks.append(future)
            
            for i in range(num_bad):
                profile = random.choice(MALICIOUS_CLIENTS)
                future = executor.submit(self.worker, profile, max_connections)
                tasks.append(future)
            
            print(f"{Colors.OKBLUE}TLS traffic generation started...{Colors.ENDC}")
            print(f"Press Ctrl+C to stop early\n")
            
            try:
                time.sleep(self.duration)
            except KeyboardInterrupt:
                print(f"\n{Colors.WARNING}Stopping...{Colors.ENDC}")
            
            self.running = False
            
            for future in as_completed(tasks):
                try:
                    future.result()
                except Exception as e:
                    pass
        
        self.print_stats()
        
        print(f"{Colors.OKCYAN}Tip:{Colors.ENDC} Check Grafana at http://localhost:3001")
        print(f"{Colors.OKCYAN}Tip:{Colors.ENDC} Check Prometheus at http://localhost:9091")
        print()


def main():
    parser = argparse.ArgumentParser(
        description="Generate realistic TLS traffic for JA4proxy testing",
    )
    parser.add_argument("--target-host", default=os.environ.get("TARGET_HOST", "proxy"), help="Target host (default: proxy)")
    parser.add_argument("--target-port", type=int, default=int(os.environ.get("TARGET_PORT", "8080")), help="Target port (default: 8080)")
    parser.add_argument("--duration", type=int, default=60, help="Duration in seconds (default: 60)")
    parser.add_argument("--good-percent", type=int, default=15, help="Percent legitimate traffic (default: 15)")
    parser.add_argument("--workers", type=int, default=50, help="Worker threads (default: 50)")
    
    args = parser.parse_args()
    
    if not 0 <= args.good_percent <= 100:
        print(f"{Colors.FAIL}Error: --good-percent must be 0-100{Colors.ENDC}")
        sys.exit(1)
    
    generator = TrafficGenerator(
        target_host=args.target_host,
        target_port=args.target_port,
        duration=args.duration,
        good_traffic_percent=args.good_percent,
        workers=args.workers
    )
    
    try:
        generator.run()
    except KeyboardInterrupt:
        print(f"\n{Colors.WARNING}Interrupted{Colors.ENDC}")
        sys.exit(0)


if __name__ == "__main__":
    main()
