# subdomain_scan.py

import sys
import logging
from scanner.advanced_checks import subdomain_scan

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python subdomain_scan.py <domain>")
        sys.exit(1)
    domain = sys.argv[1]
    results = subdomain_scan(domain)
    if results:
        for result in results:
            print(f"Discovered Subdomain: {result['subdomain']}, IPs: {', '.join(result['ips'])}")
    else:
        print("No subdomains found.")
