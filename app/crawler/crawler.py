"""
Website Crawler + Form Discovery module.

Design notes for viva:
- Stays within the same registrable domain (no scope creep to external sites).
- Enforces MAX_PAGES and MAX_DEPTH to avoid runaway crawls (safety + performance).
- REQUEST_DELAY_SECONDS throttles requests to avoid hammering the target (politeness / avoids
  being mistaken for a DoS attempt).
- Uses BeautifulSoup4 to parse <a> tags (page discovery) and <form> tags (form discovery).
"""
import time
import requests
import tldextract
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup

from app.config import settings

# suffix_list_urls=() forces tldextract to use its bundled snapshot instead of
# fetching the public suffix list over the network on every run.
_TLD_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=())


class Crawler:
    def __init__(self, start_url: str, max_pages: int = None, max_depth: int = None):
        self.start_url = start_url
        self.max_pages = max_pages or settings.MAX_PAGES
        self.max_depth = max_depth or settings.MAX_DEPTH
        self.root_domain = self._registrable_domain(start_url)

        self.visited = set()
        self.pages = []      # list of {"url": ..., "status_code": ..., "html": ...}
        self.forms = []      # list of {"url": ..., "method": ..., "action": ..., "inputs": [...]}

        self.session = requests.Session()
        self.session.headers.update({"User-Agent": settings.USER_AGENT})

    def _registrable_domain(self, url: str) -> str:
        ext = _TLD_EXTRACTOR(url)
        return f"{ext.domain}.{ext.suffix}"

    def _same_domain(self, url: str) -> bool:
        try:
            return self._registrable_domain(url) == self.root_domain
        except Exception:
            return False

    def _extract_links(self, base_url: str, soup: BeautifulSoup):
        links = set()
        for a in soup.find_all("a", href=True):
            href = urljoin(base_url, a["href"]).split("#")[0]
            parsed = urlparse(href)
            if parsed.scheme in ("http", "https") and self._same_domain(href):
                links.add(href)
        return links

    def _extract_forms(self, base_url: str, soup: BeautifulSoup):
        forms = []
        for form in soup.find_all("form"):
            action = urljoin(base_url, form.get("action") or base_url)
            method = (form.get("method") or "get").lower()
            inputs = []
            for inp in form.find_all(["input", "textarea", "select"]):
                name = inp.get("name")
                if name:
                    inputs.append({
                        "name": name,
                        "type": inp.get("type", "text"),
                    })
            forms.append({
                "page_url": base_url,
                "action": action,
                "method": method,
                "inputs": inputs,
            })
        return forms

    def crawl(self):
        queue = [(self.start_url, 0)]

        while queue and len(self.visited) < self.max_pages:
            url, depth = queue.pop(0)
            if url in self.visited or depth > self.max_depth:
                continue

            try:
                resp = self.session.get(url, timeout=settings.REQUEST_TIMEOUT_SECONDS)
            except requests.RequestException:
                continue

            self.visited.add(url)
            self.pages.append({
                "url": url,
                "status_code": resp.status_code,
                "headers": dict(resp.headers),
                "html": resp.text if "text/html" in resp.headers.get("Content-Type", "") else "",
            })

            if "text/html" in resp.headers.get("Content-Type", ""):
                soup = BeautifulSoup(resp.text, "html.parser")
                self.forms.extend(self._extract_forms(url, soup))

                if depth < self.max_depth:
                    for link in self._extract_links(url, soup):
                        if link not in self.visited:
                            queue.append((link, depth + 1))

            time.sleep(settings.REQUEST_DELAY_SECONDS)

        return self.pages, self.forms
