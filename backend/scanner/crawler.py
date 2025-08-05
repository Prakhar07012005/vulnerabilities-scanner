# scanner/crawler.py

import urllib.parse
import logging
import requests
from bs4 import BeautifulSoup

def normalize_url(url):
    """
    Normalize URL to avoid duplicates.
    """
    parsed = urllib.parse.urlparse(url)
    normalized = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    return normalized.rstrip("/")

def crawl(target_url, session, visited_urls, max_depth, current_depth=0):
    """
    Recursively crawl the target website up to max_depth.
    """
    normalized = normalize_url(target_url)
    if current_depth > max_depth or normalized in visited_urls:
        return
    visited_urls.add(normalized)
    logging.info(f"Crawling: {normalized}")
    try:
        response = session.get(normalized, timeout=5)
        content_type = response.headers.get("Content-Type", "")
        if "text/html" not in content_type:
            return
        soup = BeautifulSoup(response.text, "html.parser")
        # Extract all anchor links
        for link in soup.find_all("a", href=True):
            next_url = urllib.parse.urljoin(normalized, link['href'])
            # Only crawl URLs within the target domain
            if next_url.startswith(target_url):
                crawl(next_url, session, visited_urls, max_depth, current_depth + 1)
    except Exception as e:
        logging.error(f"Error crawling {normalized}: {e}")
