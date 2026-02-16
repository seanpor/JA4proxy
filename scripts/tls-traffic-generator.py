#!/usr/bin/env python3
"""
TLS Traffic Generator for JA4proxy Performance Testing

This script generates realistic TLS traffic with a mix of:
- Legitimate customers (10-20%)
- Malicious attackers (80-90%) with various attack patterns
- Different JA4 fingerprints for each client type

It simulates real-world scenarios including:
- Normal browsing patterns
- DDoS attacks
- Credential stuffing
- Bot traffic
- Scrapers
"""

import asyncio
import random
import time
import argparse
import sys
from dataclasses import dataclass
from typing import List, Dict, Optional
from collections import defaultdict
import ssl
import socket
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed


# Color codes for output
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


@dataclass
class ClientProfile:
    """Profile for a simulated client"""
    name: str
    ja4_fingerprint: str
    user_agent: str
    request_rate: float  # requests per second
    malicious: bool
    attack_type: Optional[str] = None
    ip_prefix: str = "192.168"
    

# Legitimate client profiles (10-20% of traffic)
LEGITIMATE_CLIENTS = [
    ClientProfile(
        name="Chrome_Windows",
        ja4_fingerprint="t13d1516h2_8daaf6152771_02713d6af862",
        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        request_rate=0.5,  # 1 request every 2 seconds
        malicious=False,
        ip_prefix="203.0.113"  # Legitimate IP range
    ),
    ClientProfile(
        name="Firefox_MacOS",
        ja4_fingerprint="t13d1715h2_9c79135e478e_cd85d2e88c81",
        user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
        request_rate=0.3,
        malicious=False,
        ip_prefix="198.51.100"
    ),
    ClientProfile(
        name="Safari_iOS",
        ja4_fingerprint="t13d1516h2_3b5074b1b5a0_626360150d4b",
        user_agent="Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
        request_rate=0.4,
        malicious=False,
        ip_prefix="198.51.100"
    ),
]

# Malicious client profiles (80-90% of traffic)
MALICIOUS_CLIENTS = [
    # DDoS botnet
    ClientProfile(
        name="Mirai_Botnet",
        ja4_fingerprint="t10d151415_deadbeef1337_attackertools",
        user_agent="Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
        request_rate=50.0,  # 50 requests per second
        malicious=True,
        attack_type="DDoS",
        ip_prefix="192.168"
    ),
    # Credential stuffing
    ClientProfile(
        name="CredentialStuffer",
        ja4_fingerprint="t12d090909_ba640532068b_b186095e22b6",
        user_agent="python-requests/2.31.0",
        request_rate=20.0,
        malicious=True,
        attack_type="Credential Stuffing",
        ip_prefix="10.0"
    ),
    # Web scraper
    ClientProfile(
        name="AggressiveScraper",
        ja4_fingerprint="t13d1516h2_scraperbot99_norespect4robots",
        user_agent="Mozilla/5.0 (compatible; ScraperBot/1.0)",
        request_rate=10.0,
        malicious=True,
        attack_type="Scraping",
        ip_prefix="172.16"
    ),
    # Vulnerability scanner
    ClientProfile(
        name="VulnScanner",
        ja4_fingerprint="t13d1516h2_scanner666_exploitkid",
        user_agent="Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)",
        request_rate=5.0,
        malicious=True,
        attack_type="Scanning",
        ip_prefix="192.168"
    ),
    # API abuse
    ClientProfile(
        name="APIAbuser",
        ja4_fingerprint="t13d1516h2_apiabuse123_ratelimitignored",
        user_agent="curl/8.0.1",
        request_rate=30.0,
        malicious=True,
        attack_type="API Abuse",
        ip_prefix="10.0"
    ),
]


class TrafficGenerator:
    """Generates realistic TLS traffic to JA4proxy"""
    
    def __init__(self, 
                 proxy_host: str = "localhost",
                 proxy_port: int = 8443,
                 backend_host: str = "localhost", 
                 backend_port: int = 8081,
                 duration: int = 60,
                 good_traffic_percent: int = 15,
                 workers: int = 50):
        self.proxy_host = proxy_host
        self.proxy_port = proxy_port
        self.backend_host = backend_host
        self.backend_port = backend_port
        self.duration = duration
        self.good_traffic_percent = good_traffic_percent
        self.workers = workers
        
        self.stats = defaultdict(lambda: {"requests": 0, "success": 0, "blocked": 0, "errors": 0})
        self.start_time = None
        self.running = True
        
    def generate_ip(self, prefix: str, client_id: int) -> str:
        """Generate a unique IP for a client"""
        parts = prefix.split('.')
        if len(parts) == 2:
            return f"{prefix}.{(client_id // 256) % 256}.{client_id % 256}"
        elif len(parts) == 3:
            return f"{prefix}.{client_id % 256}"
        return f"{prefix}"
    
    def make_request(self, profile: ClientProfile, client_id: int, request_num: int) -> Dict:
        """Make a single HTTP request simulating a TLS client"""
        ip = self.generate_ip(profile.ip_prefix, client_id)
        
        # Random endpoint selection
        endpoints = [
            "/",
            "/api/health",
            "/api/echo",
            "/api/products",
            "/api/users/profile",
        ]
        
        # Malicious clients might hit sensitive endpoints more
        if profile.malicious:
            endpoints.extend([
                "/admin/login",
                "/api/admin",
                "/.env",
                "/wp-admin",
                "/api/users/1/delete",
            ] * 3)  # Weight malicious endpoints
        
        endpoint = random.choice(endpoints)
        
        # Build URL - in production this would go through the proxy
        # For now, we'll hit the backend directly with custom headers to simulate
        url = f"http://{self.backend_host}:{self.backend_port}{endpoint}"
        
        headers = {
            "User-Agent": profile.user_agent,
            "X-Forwarded-For": ip,
            "X-JA4-Fingerprint": profile.ja4_fingerprint,
            "X-Real-IP": ip,
        }
        
        result = {
            "profile": profile.name,
            "ip": ip,
            "endpoint": endpoint,
            "status": None,
            "blocked": False,
            "error": None,
        }
        
        try:
            response = requests.get(url, headers=headers, timeout=5)
            result["status"] = response.status_code
            
            # Check if request was blocked
            if response.status_code == 403 or response.status_code == 429:
                result["blocked"] = True
                self.stats[profile.name]["blocked"] += 1
            elif response.status_code < 400:
                self.stats[profile.name]["success"] += 1
                
        except requests.exceptions.RequestException as e:
            result["error"] = str(e)
            self.stats[profile.name]["errors"] += 1
        
        self.stats[profile.name]["requests"] += 1
        return result
    
    def worker(self, profile: ClientProfile, client_id: int, num_requests: int):
        """Worker function that generates traffic for a single client"""
        interval = 1.0 / profile.request_rate if profile.request_rate > 0 else 1.0
        
        for i in range(num_requests):
            if not self.running:
                break
                
            try:
                result = self.make_request(profile, client_id, i)
                
                # Log interesting events
                if result["blocked"]:
                    print(f"{Colors.WARNING}✗ BLOCKED{Colors.ENDC} {profile.name} ({result['ip']}) -> {result['endpoint']}")
                elif result["error"]:
                    print(f"{Colors.FAIL}✗ ERROR{Colors.ENDC} {profile.name}: {result['error']}")
                elif random.random() < 0.05:  # Log 5% of successful requests
                    print(f"{Colors.OKGREEN}✓{Colors.ENDC} {profile.name} ({result['ip']}) -> {result['endpoint']}")
                    
            except Exception as e:
                print(f"{Colors.FAIL}Exception in worker: {e}{Colors.ENDC}")
            
            time.sleep(interval)
    
    def print_stats(self):
        """Print current statistics"""
        elapsed = time.time() - self.start_time
        
        print(f"\n{Colors.HEADER}{'='*80}{Colors.ENDC}")
        print(f"{Colors.HEADER}Traffic Generation Statistics (Elapsed: {elapsed:.1f}s){Colors.ENDC}")
        print(f"{Colors.HEADER}{'='*80}{Colors.ENDC}\n")
        
        total_requests = sum(s["requests"] for s in self.stats.values())
        total_success = sum(s["success"] for s in self.stats.values())
        total_blocked = sum(s["blocked"] for s in self.stats.values())
        total_errors = sum(s["errors"] for s in self.stats.values())
        
        print(f"{Colors.BOLD}Overall:{Colors.ENDC}")
        print(f"  Total Requests:  {total_requests:,}")
        print(f"  Successful:      {total_success:,} ({total_success/total_requests*100:.1f}%)" if total_requests > 0 else "  Successful:      0")
        print(f"  Blocked:         {total_blocked:,} ({total_blocked/total_requests*100:.1f}%)" if total_requests > 0 else "  Blocked:         0")
        print(f"  Errors:          {total_errors:,} ({total_errors/total_requests*100:.1f}%)" if total_requests > 0 else "  Errors:          0")
        print(f"  Requests/sec:    {total_requests/elapsed:.2f}")
        
        print(f"\n{Colors.BOLD}By Client Profile:{Colors.ENDC}\n")
        print(f"{'Profile':<30} {'Type':<15} {'Requests':<12} {'Success':<12} {'Blocked':<12} {'Errors':<12}")
        print("-" * 90)
        
        for profile_name, stats in sorted(self.stats.items(), key=lambda x: x[1]["requests"], reverse=True):
            # Find profile to get type
            profile = next((p for p in LEGITIMATE_CLIENTS + MALICIOUS_CLIENTS if p.name == profile_name), None)
            profile_type = f"{Colors.FAIL}Malicious{Colors.ENDC}" if profile and profile.malicious else f"{Colors.OKGREEN}Legitimate{Colors.ENDC}"
            
            print(f"{profile_name:<30} {profile_type:<24} {stats['requests']:<12} {stats['success']:<12} {stats['blocked']:<12} {stats['errors']:<12}")
        
        print(f"\n{Colors.HEADER}{'='*80}{Colors.ENDC}\n")
    
    def run(self):
        """Run the traffic generation"""
        print(f"{Colors.HEADER}")
        print("╔════════════════════════════════════════════════════════════════════╗")
        print("║          JA4proxy TLS Traffic Generator & Performance Test         ║")
        print("╚════════════════════════════════════════════════════════════════════╝")
        print(f"{Colors.ENDC}\n")
        
        print(f"Configuration:")
        print(f"  Backend:           {self.backend_host}:{self.backend_port}")
        print(f"  Duration:          {self.duration}s")
        print(f"  Good Traffic:      {self.good_traffic_percent}%")
        print(f"  Bad Traffic:       {100 - self.good_traffic_percent}%")
        print(f"  Worker Threads:    {self.workers}")
        print(f"  Legitimate Clients: {len(LEGITIMATE_CLIENTS)}")
        print(f"  Malicious Clients:  {len(MALICIOUS_CLIENTS)}")
        print()
        
        self.start_time = time.time()
        
        # Calculate how many clients of each type
        num_good = max(1, int(self.workers * self.good_traffic_percent / 100))
        num_bad = self.workers - num_good
        
        print(f"Spawning clients:")
        print(f"  {Colors.OKGREEN}✓ {num_good} legitimate clients{Colors.ENDC}")
        print(f"  {Colors.FAIL}✗ {num_bad} malicious clients{Colors.ENDC}")
        print()
        
        # Calculate requests per client
        requests_per_client = max(10, int(self.duration * 2))  # At least some requests
        
        tasks = []
        
        # Create legitimate client tasks
        with ThreadPoolExecutor(max_workers=self.workers) as executor:
            for i in range(num_good):
                profile = random.choice(LEGITIMATE_CLIENTS)
                future = executor.submit(self.worker, profile, i, requests_per_client)
                tasks.append(future)
            
            # Create malicious client tasks
            for i in range(num_bad):
                profile = random.choice(MALICIOUS_CLIENTS)
                future = executor.submit(self.worker, profile, num_good + i, requests_per_client)
                tasks.append(future)
            
            print(f"{Colors.OKBLUE}Traffic generation started...{Colors.ENDC}")
            print(f"Press Ctrl+C to stop early\n")
            
            try:
                # Wait for duration or until all tasks complete
                time.sleep(self.duration)
            except KeyboardInterrupt:
                print(f"\n{Colors.WARNING}Stopping traffic generation...{Colors.ENDC}")
                self.running = False
            
            # Wait for all workers to finish
            for future in as_completed(tasks):
                try:
                    future.result()
                except Exception as e:
                    print(f"Task error: {e}")
        
        # Print final statistics
        self.print_stats()
        
        print(f"{Colors.OKCYAN}Tip:{Colors.ENDC} Check metrics at http://localhost:9090/metrics")
        print(f"{Colors.OKCYAN}Tip:{Colors.ENDC} Check Grafana at http://localhost:3001")
        print(f"{Colors.OKCYAN}Tip:{Colors.ENDC} Check Prometheus at http://localhost:9091")
        print()


def main():
    parser = argparse.ArgumentParser(
        description="Generate realistic TLS traffic for JA4proxy testing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run for 60 seconds with 15%% good traffic
  python3 tls-traffic-generator.py --duration 60 --good-percent 15
  
  # Run for 5 minutes with 100 workers
  python3 tls-traffic-generator.py --duration 300 --workers 100
  
  # Run with 90%% good traffic (mostly legitimate)
  python3 tls-traffic-generator.py --duration 120 --good-percent 90
        """
    )
    
    parser.add_argument(
        "--backend-host",
        default="localhost",
        help="Backend host (default: localhost)"
    )
    parser.add_argument(
        "--backend-port",
        type=int,
        default=8081,
        help="Backend port (default: 8081)"
    )
    parser.add_argument(
        "--duration",
        type=int,
        default=60,
        help="Test duration in seconds (default: 60)"
    )
    parser.add_argument(
        "--good-percent",
        type=int,
        default=15,
        help="Percentage of legitimate traffic (default: 15)"
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=50,
        help="Number of concurrent workers (default: 50)"
    )
    
    args = parser.parse_args()
    
    # Validate arguments
    if not 0 <= args.good_percent <= 100:
        print(f"{Colors.FAIL}Error: --good-percent must be between 0 and 100{Colors.ENDC}")
        sys.exit(1)
    
    if args.workers < 1:
        print(f"{Colors.FAIL}Error: --workers must be at least 1{Colors.ENDC}")
        sys.exit(1)
    
    # Create and run generator
    generator = TrafficGenerator(
        backend_host=args.backend_host,
        backend_port=args.backend_port,
        duration=args.duration,
        good_traffic_percent=args.good_percent,
        workers=args.workers
    )
    
    try:
        generator.run()
    except KeyboardInterrupt:
        print(f"\n{Colors.WARNING}Interrupted by user{Colors.ENDC}")
        sys.exit(0)


if __name__ == "__main__":
    main()
