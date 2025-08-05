# scanner/scanner.py

import logging
from concurrent.futures import ThreadPoolExecutor
import requests
import urllib.parse
from datetime import datetime

from . import crawler, checks
from scanner.advanced_checks import check_csrf, check_directory_traversal, check_file_inclusion, subdomain_scan


from datetime import datetime

def compute_risk(vuln):
    """
    Simple risk scoring based on vulnerability type.
    You can refine this logic as needed.
    """
    risk_mapping = {
        "SQL Injection": "High",
        "XSS": "Medium",
        "Missing Security Headers": "Medium",
        "Potential CSRF Vulnerability": "High",
        "Directory Traversal Vulnerability": "High",
        "File Inclusion Vulnerability": "High"
    }
    return risk_mapping.get(vuln.get("type"), "Low")

class WebVulnScanner:
    def __init__(self, target_url, max_depth=2, max_workers=10, include_subdomains=False):
        """
        Initialize scanner with:
          - target_url: the website to scan
          - max_depth: maximum depth for crawling
          - max_workers: number of concurrent threads
          - include_subdomains: if True, perform subdomain scanning and add discovered URLs
        """
        self.target_url = target_url.rstrip("/")
        self.max_depth = max_depth
        self.visited_urls = set()
        self.vulnerabilities = []  # List to store vulnerability findings
        self.session = requests.Session()
        self.max_workers = max_workers
        self.include_subdomains = include_subdomains

    def run(self):
        logging.info(f"Starting crawl for: {self.target_url}")
        # Crawl the main target URL
        crawler.crawl(self.target_url, self.session, self.visited_urls, self.max_depth)
        logging.info(f"Crawling complete. Total URLs found: {len(self.visited_urls)}")
        
        # Optionally perform subdomain scanning
        if self.include_subdomains:
            domain = urllib.parse.urlparse(self.target_url).netloc
            logging.info(f"Performing subdomain scan for domain: {domain}")
            discovered_subdomains = subdomain_scan(domain)
            for item in discovered_subdomains:
                # Construct a URL for each discovered subdomain (assuming http)
                subdomain_url = f"http://{item['subdomain']}"
                self.visited_urls.add(subdomain_url)
                logging.info(f"Discovered subdomain: {subdomain_url}")
        
        # Run vulnerability checks concurrently
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = [executor.submit(self.scan_url, url) for url in self.visited_urls]
            for future in futures:
                try:
                    future.result()
                except Exception as e:
                    logging.error(f"Error scanning URL: {e}")
        return self.vulnerabilities

    def scan_url(self, url):
        # Basic checks:
        sec_vuln = checks.check_security_headers(url, self.session)
        if sec_vuln:
            self.vulnerabilities.extend(sec_vuln)
        sql_vulns = checks.check_sql_injection(url, self.session)
        if sql_vulns:
            self.vulnerabilities.extend(sql_vulns)
        xss_vulns = checks.check_xss(url, self.session)
        if xss_vulns:
            self.vulnerabilities.extend(xss_vulns)
        # Advanced checks:
        csrf_vulns = check_csrf(url, self.session)
        if csrf_vulns:
            self.vulnerabilities.extend(csrf_vulns)
        dir_trav_vulns = check_directory_traversal(url, self.session)
        if dir_trav_vulns:
            self.vulnerabilities.extend(dir_trav_vulns)
        file_incl_vulns = check_file_inclusion(url, self.session)
        if file_incl_vulns:
            self.vulnerabilities.extend(file_incl_vulns)

    def generate_report(self, filename="vuln_report.csv",scan_duration=0):
        try:
            import csv
            now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            with open(filename, mode="w", newline='', encoding="utf-8") as csvfile:
                fieldnames = ["timestamp", "url", "type", "parameter", "payload", "details", "risk","scan_duration"]
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                for vuln in self.vulnerabilities:
                    writer.writerow({
                        "timestamp": now,
                        "url": vuln.get("url", ""),
                        "type": vuln.get("type", ""),
                        "parameter": vuln.get("parameter", ""),
                        "payload": vuln.get("payload", ""),
                        "details": vuln.get("details", ""),
                        "risk": compute_risk(vuln),
                        "scan_duration": scan_duration

                    })
            logging.info(f"Report generated successfully: {filename}")
        except Exception as e:
            logging.error(f"Error generating report: {e}")
