import re
import urllib.parse
import logging
import requests

def check_security_headers(url, session):
    """
    Check if basic security headers are present in the response from the given URL.
    
    Returns:
        A list containing a vulnerability dictionary if any required header is missing,
        otherwise an empty list.
    """
    vulns = []
    logging.info(f"Checking security headers for {url}")
    try:
        response = session.get(url, timeout=15)
        headers = response.headers
        missing = []
        required_headers = [
            "X-Frame-Options",
            "X-XSS-Protection",
            "X-Content-Type-Options",
            "Content-Security-Policy"
        ]
        for header in required_headers:
            if header not in headers:
                missing.append(header)
        if missing:
            vuln = {
                "url": url,
                "type": "Missing Security Headers",
                "details": f"Missing: {', '.join(missing)}"
            }
            logging.warning(f"Security header vulnerability found: {vuln}")
            vulns.append(vuln)
    except requests.exceptions.ReadTimeout:
        logging.warning(f"Timeout occurred while checking security headers for {url}")
    except Exception as e:
        logging.exception(f"Error checking security headers for {url}: {e}")
    return vulns

def check_sql_injection(url, session):
    """
    Check for SQL Injection vulnerabilities by injecting common payloads into GET parameters.
    
    Returns:
        A list of vulnerability dictionaries if any vulnerabilities are found,
        otherwise an empty list.
    """
    logging.info(f"Checking SQL Injection for {url}")
    vulnerabilities = []
    try:
        parsed = urllib.parse.urlparse(url)
        qs = urllib.parse.parse_qs(parsed.query)
        if not qs:
            return []
        # Expanded payload list for SQL injection
        payloads = [
            "'", "\"", 
            "' OR '1'='1", "\" OR \"1\"=\"1",
            "'; DROP TABLE users; --", 
            "' OR 1=1--", 
            "' OR '1'='1' /*"
        ]
        for param, values in qs.items():
            original_value = values[0]
            for payload in payloads:
                test_value = original_value + payload
                new_query = parsed.query.replace(f"{param}={original_value}", f"{param}={test_value}")
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
                try:
                    response = session.get(test_url, timeout=10)
                except requests.exceptions.ReadTimeout:
                    logging.warning(f"Timeout during SQL Injection check for {test_url}")
                    continue
                if re.search(r"SQL syntax|sql error|mysql_fetch_array|ORA-|syntax error", response.text, re.IGNORECASE):
                    vuln = {
                        "url": test_url,
                        "type": "SQL Injection",
                        "parameter": param,
                        "payload": payload
                    }
                    logging.warning(f"SQL Injection vulnerability found: {vuln}")
                    vulnerabilities.append(vuln)
                    break  # Stop trying further payloads for this parameter
    except Exception as e:
        logging.exception(f"Error checking SQL Injection for {url}: {e}")
    return vulnerabilities

def check_xss(url, session):
    """
    Check for Cross-Site Scripting (XSS) vulnerabilities by injecting various payloads
    into GET parameters.
    
    Returns:
        A list of vulnerability dictionaries if any vulnerabilities are found,
        otherwise an empty list.
    """
    logging.info(f"Checking XSS for {url}")
    vulnerabilities = []
    try:
        parsed = urllib.parse.urlparse(url)
        qs = urllib.parse.parse_qs(parsed.query)
        if not qs:
            return []
        # Expanded payload list for XSS
        payloads = [
            "<script>alert('XSS')</script>",
            "'><script>alert(1)</script>",
            "<img src=x onerror=alert('XSS')>",
            '"><svg/onload=alert("XSS")>',
            "';alert(String.fromCharCode(88,83,83))//"
        ]
        for param, values in qs.items():
            original_value = values[0]
            for payload in payloads:
                encoded_payload = urllib.parse.quote(payload)
                new_query = parsed.query.replace(f"{param}={original_value}", f"{param}={encoded_payload}")
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
                try:
                    response = session.get(test_url, timeout=15)
                except requests.exceptions.ReadTimeout:
                    logging.warning(f"Timeout during XSS check for {test_url}")
                    continue
                if payload in response.text:
                    vuln = {
                        "url": test_url,
                        "type": "XSS",
                        "parameter": param,
                        "payload": payload
                    }
                    logging.warning(f"XSS vulnerability found: {vuln}")
                    vulnerabilities.append(vuln)
                    break
    except Exception as e:
        logging.exception(f"Error checking XSS for {url}: {e}")
    return vulnerabilities