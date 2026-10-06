"""Turn a URL into the 30 features of the phishing dataset, so the trained model can score real links.

The rules follow the dataset's published feature definitions (Mohammad, Thabtah and McCluskey).
A feature is left as None, for the KNN imputer to fill in, when its coding in the training data
contradicts the published rule, when it needs a service that no longer exists, or when a lookup
or the page download fails.
"""
import ipaddress
import re
import socket
import ssl
import sys
import time
import warnings
from dataclasses import dataclass, field
from datetime import datetime, timezone
from functools import lru_cache
from typing import Optional
from urllib.parse import urljoin, urlsplit

import certifi
import requests
import tldextract
from bs4 import BeautifulSoup
from urllib3.exceptions import InsecureRequestWarning

from networksecurity.exception.exception import NetworkSecurityException
from networksecurity.logging.logger import logging

## Value codes used by the dataset
LEGITIMATE, SUSPICIOUS, PHISHING = 1, 0, -1

FEATURE_COLUMNS = (
    "having_IP_Address", "URL_Length", "Shortining_Service", "having_At_Symbol",
    "double_slash_redirecting", "Prefix_Suffix", "having_Sub_Domain", "SSLfinal_State",
    "Domain_registeration_length", "Favicon", "port", "HTTPS_token", "Request_URL",
    "URL_of_Anchor", "Links_in_tags", "SFH", "Submitting_to_email", "Abnormal_URL",
    "Redirect", "on_mouseover", "RightClick", "popUpWidnow", "Iframe", "age_of_domain",
    "DNSRecord", "web_traffic", "Page_Rank", "Google_Index", "Links_pointing_to_page",
    "Statistical_report",
)

## Never measured; the imputer fills these from the most similar training rows
_REVERSED = "its values in the training data contradict the published rule"
NOT_MEASURED = {
    "Prefix_Suffix": "its values in the training data don't match the published rule (87% of sites coded as having a '-')",
    "Shortining_Service": _REVERSED,
    "double_slash_redirecting": _REVERSED,
    "Domain_registeration_length": _REVERSED,
    "HTTPS_token": _REVERSED,
    "Abnormal_URL": _REVERSED,
    "Redirect": "the training data uses only 0 and 1, which doesn't match the published 3-level rule",
    "Page_Rank": "Google no longer publishes PageRank",
    "Google_Index": "needs a search engine API",
    "Links_pointing_to_page": "needs a backlink service",
    "Statistical_report": "needs phishing blocklist reports",
}

## Thresholds from the published rules
URL_LENGTH_LEGITIMATE_BELOW = 54
URL_LENGTH_SUSPICIOUS_UP_TO = 75
REQUEST_URL_LEGITIMATE_BELOW = 0.22
ANCHOR_LEGITIMATE_BELOW = 0.31
ANCHOR_SUSPICIOUS_UP_TO = 0.67
LINKS_IN_TAGS_LEGITIMATE_BELOW = 0.17
LINKS_IN_TAGS_SUSPICIOUS_UP_TO = 0.81
DOMAIN_MIN_AGE_DAYS = 182
TRAFFIC_RANK_LEGITIMATE_BELOW = 100_000

FETCH_TIMEOUT_SECONDS = 10
MAX_PAGE_BYTES = 2_000_000
MAX_REDIRECTS = 5
USER_AGENT = "Mozilla/5.0 (compatible; NetworkSecurity-URL-checker/1.0)"

## Bundled public suffix list, so nothing is downloaded at runtime
_split_domain = tldextract.TLDExtract(suffix_list_urls=())


class BlockedAddressError(Exception):
    """The host resolves to a private, local or reserved address, so it is not contacted."""


@dataclass
class URLCheck:
    url: str
    final_url: Optional[str]
    features: dict
    notes: list = field(default_factory=list)


# ---------- rules on the URL text (no network) ----------

def parse_url(url: str):
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValueError(f"Not an http or https URL: {url!r}")
    try:
        parts.port
    except ValueError as e:
        raise ValueError(f"Invalid port in URL: {url!r}") from e
    return parts


def is_ip_host(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        # Decimal (3232235777) or hex (0xC0A80001) forms of an IPv4 address
        return bool(re.fullmatch(r"\d+|0x[0-9a-fA-F]+", host))


def registered_domain(host: str) -> str:
    parts = _split_domain(host)
    return f"{parts.domain}.{parts.suffix}" if parts.suffix else parts.domain


def url_text_features(url: str) -> dict:
    parts = parse_url(url)
    host = parts.hostname
    subdomains = [label for label in _split_domain(host).subdomain.split(".") if label and label != "www"]

    if len(url) < URL_LENGTH_LEGITIMATE_BELOW:
        url_length = LEGITIMATE
    elif len(url) <= URL_LENGTH_SUSPICIOUS_UP_TO:
        url_length = SUSPICIOUS
    else:
        url_length = PHISHING

    return {
        "having_IP_Address": PHISHING if is_ip_host(host) else LEGITIMATE,
        "URL_Length": url_length,
        "having_At_Symbol": PHISHING if "@" in url else LEGITIMATE,
        "having_Sub_Domain": [LEGITIMATE, SUSPICIOUS][len(subdomains)] if len(subdomains) < 2 else PHISHING,
        "port": LEGITIMATE if parts.port in (None, 80, 443) else PHISHING,
    }


# ---------- rules on the downloaded page (no network) ----------

def _share_level(share: float, legitimate_below: float, suspicious_up_to: Optional[float] = None) -> int:
    if share < legitimate_below:
        return LEGITIMATE
    if suspicious_up_to is not None and share <= suspicious_up_to:
        return SUSPICIOUS
    return PHISHING


def page_features(html: str, page_url: str) -> dict:
    soup = BeautifulSoup(html, "html.parser")
    site = registered_domain(urlsplit(page_url).hostname)

    def is_external(link: str) -> bool:
        try:
            host = urlsplit(urljoin(page_url, link.strip())).hostname
        except ValueError:
            return False  # malformed link, e.g. a broken IPv6 address
        return bool(host) and registered_domain(host) != site

    features = {}

    objects = [tag["src"] for tag in soup.find_all(["img", "audio", "video", "source", "embed"]) if tag.get("src")]
    external_objects = sum(is_external(src) for src in objects) / len(objects) if objects else 0.0
    features["Request_URL"] = _share_level(external_objects, REQUEST_URL_LEGITIMATE_BELOW)

    anchors = [a.get("href", "").strip() for a in soup.find_all("a")]
    if anchors:
        unsafe = sum(
            not href or href.startswith("#") or href.lower().startswith("javascript:") or is_external(href)
            for href in anchors
        )
        features["URL_of_Anchor"] = _share_level(unsafe / len(anchors), ANCHOR_LEGITIMATE_BELOW, ANCHOR_SUSPICIOUS_UP_TO)
    else:
        # A page without links in its raw HTML (often built by JavaScript) is left to the imputer
        features["URL_of_Anchor"] = None

    tag_links = [tag["src"] for tag in soup.find_all("script") if tag.get("src")]
    tag_links += [tag["href"] for tag in soup.find_all("link") if tag.get("href")]
    tag_links += [tag["content"] for tag in soup.find_all("meta") if tag.get("content", "").startswith("http")]
    external_tag_links = sum(is_external(link) for link in tag_links) / len(tag_links) if tag_links else 0.0
    features["Links_in_tags"] = _share_level(external_tag_links, LINKS_IN_TAGS_LEGITIMATE_BELOW, LINKS_IN_TAGS_SUSPICIOUS_UP_TO)

    sfh = LEGITIMATE
    sends_to_email = bool(re.search(r"\bmail\s*\(", html))
    for form in soup.find_all("form"):
        if not form.has_attr("action"):
            continue  # no action attribute submits to the page itself
        action = form["action"].strip()
        if action.lower().startswith("mailto:"):
            sends_to_email = True
        if action in ("", "about:blank"):
            sfh = PHISHING
        elif is_external(action) and sfh != PHISHING:
            sfh = SUSPICIOUS
    features["SFH"] = sfh
    features["Submitting_to_email"] = PHISHING if sends_to_email else LEGITIMATE

    icons = [
        tag["href"] for tag in soup.find_all("link", href=True)
        if "icon" in " ".join(tag.get("rel", [])).lower()
    ]
    features["Favicon"] = PHISHING if any(is_external(icon) for icon in icons) else LEGITIMATE

    features["on_mouseover"] = PHISHING if re.search(
        r"onmouseover\s*=\s*[\"'][^\"']*window\.status", html, re.I) else LEGITIMATE
    features["RightClick"] = PHISHING if re.search(
        r"event\.button\s*===?\s*2|oncontextmenu\s*=\s*[\"']\s*return\s+false", html, re.I) else LEGITIMATE
    features["popUpWidnow"] = PHISHING if re.search(r"\bprompt\s*\(", html) else LEGITIMATE

    def is_hidden(frame) -> bool:
        style = frame.get("style", "").replace(" ", "").lower()
        return (
            frame.get("frameborder") == "0" or frame.get("border") == "0"
            or "display:none" in style or "visibility:hidden" in style
            or frame.get("width") in ("0", "0px") or frame.get("height") in ("0", "0px")
        )
    features["Iframe"] = PHISHING if any(is_hidden(f) for f in soup.find_all(["iframe", "frame"])) else LEGITIMATE

    return features


# ---------- network lookups ----------

def _check_public(host: str) -> None:
    """Raise BlockedAddressError unless every address of the host is a public internet address."""
    addresses = {info[4][0] for info in socket.getaddrinfo(host, None)}
    if not all(ipaddress.ip_address(address.split("%")[0]).is_global for address in addresses):
        raise BlockedAddressError(host)


def dns_feature(host: str) -> int:
    try:
        socket.getaddrinfo(host, None)
        return LEGITIMATE
    except socket.gaierror:
        return PHISHING


@dataclass
class FetchedPage:
    final_url: str
    html: str
    redirects: int
    status_code: int


def fetch_page(url: str) -> FetchedPage:
    """Download the page HTML (no JavaScript), checking every redirect hop against private addresses."""
    session = requests.Session()
    session.headers["User-Agent"] = USER_AGENT
    current, redirects = url, 0
    while True:
        _check_public(parse_url(current).hostname)
        try:
            response = session.get(current, allow_redirects=False, stream=True,
                                   timeout=FETCH_TIMEOUT_SECONDS, verify=certifi.where())
        except requests.exceptions.SSLError:
            # The certificate check is scored separately; still read the page
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", InsecureRequestWarning)
                response = session.get(current, allow_redirects=False, stream=True,
                                       timeout=FETCH_TIMEOUT_SECONDS, verify=False)
        if response.is_redirect and redirects < MAX_REDIRECTS:
            current = urljoin(current, response.headers["Location"])
            redirects += 1
            response.close()
            continue
        break

    body = b""
    for chunk in response.iter_content(64 * 1024):
        body += chunk
        if len(body) >= MAX_PAGE_BYTES:
            break
    response.close()
    content_type = response.headers.get("Content-Type", "")
    html = body.decode(response.encoding or "utf-8", errors="replace") if "html" in content_type.lower() else ""
    return FetchedPage(final_url=current, html=html, redirects=redirects, status_code=response.status_code)


def ssl_feature(url: str) -> Optional[int]:
    """Trusted certificate = 1, HTTPS with an untrusted certificate = 0, no HTTPS = -1."""
    parts = parse_url(url)
    if parts.scheme != "https":
        return PHISHING
    context = ssl.create_default_context(cafile=certifi.where())
    try:
        _check_public(parts.hostname)
        with socket.create_connection((parts.hostname, parts.port or 443), timeout=FETCH_TIMEOUT_SECONDS) as sock:
            with context.wrap_socket(sock, server_hostname=parts.hostname):
                return LEGITIMATE
    except ssl.SSLCertVerificationError:
        return SUSPICIOUS
    except (OSError, ssl.SSLError, BlockedAddressError):
        return None


@lru_cache(maxsize=1024)
def domain_age_feature(domain: str) -> Optional[int]:
    """Registered at least 6 months ago = 1, younger or not registered = -1 (RDAP lookup)."""
    try:
        response = requests.get(f"https://rdap.org/domain/{domain}", timeout=FETCH_TIMEOUT_SECONDS,
                                headers={"User-Agent": USER_AGENT})
        if response.status_code == 404:
            return PHISHING
        if not response.ok:
            return None
        events = {event.get("eventAction"): event.get("eventDate") for event in response.json().get("events", [])}
        registered = datetime.fromisoformat(events["registration"].replace("Z", "+00:00"))
        age_days = (datetime.now(timezone.utc) - registered).days
        return LEGITIMATE if age_days >= DOMAIN_MIN_AGE_DAYS else PHISHING
    except (requests.RequestException, KeyError, ValueError, AttributeError):
        return None


@lru_cache(maxsize=1024)
def traffic_feature(domain: str) -> Optional[int]:
    """Tranco rank (replaces Alexa) under 100,000 = 1, ranked lower = 0, not in the top million = -1."""
    for attempt in range(2):
        try:
            response = requests.get(f"https://tranco-list.eu/api/ranks/domain/{domain}",
                                    timeout=FETCH_TIMEOUT_SECONDS, headers={"User-Agent": USER_AGENT})
        except requests.RequestException:
            return None
        if response.status_code == 429 and attempt == 0:
            time.sleep(1.5)  # the API allows about one request per second
            continue
        if response.status_code == 404:
            return PHISHING
        if not response.ok:
            return None
        ranks = response.json().get("ranks", [])
        if not ranks:
            return PHISHING
        latest = max(ranks, key=lambda r: r["date"])["rank"]
        return LEGITIMATE if latest < TRAFFIC_RANK_LEGITIMATE_BELOW else SUSPICIOUS
    return None


# ---------- putting it together ----------

class URLFeatureExtractor:
    def __init__(self, fetch_pages: bool = True):
        self.fetch_pages = fetch_pages

    def extract(self, url: str) -> URLCheck:
        url = url.strip()
        if not url:
            raise ValueError("URL is empty")
        # Without a scheme, try HTTPS first and fall back to HTTP
        candidates = [url] if "://" in url else [f"https://{url}", f"http://{url}"]
        for candidate in candidates:
            parse_url(candidate)

        try:
            features = dict.fromkeys(FEATURE_COLUMNS)
            notes = []
            checked = candidates[0]
            host = parse_url(checked).hostname
            ip_host = is_ip_host(host)

            features["DNSRecord"] = PHISHING if ip_host else dns_feature(host)
            resolves = ip_host or features["DNSRecord"] == LEGITIMATE
            if not resolves:
                notes.append("the domain does not resolve, so the page was not downloaded")

            page = None
            if self.fetch_pages and resolves:
                error = None
                for candidate in candidates:
                    try:
                        page = fetch_page(candidate)
                        checked = candidate
                        break
                    except BlockedAddressError:
                        error = "the address is private or local, so it was not contacted"
                        break
                    except (requests.RequestException, OSError, ValueError) as e:
                        error = f"the page could not be downloaded ({type(e).__name__})"
                if page is None:
                    notes.append(error)
                elif not page.html.strip():
                    # Some large sites send bots an empty page (e.g. HTTP 202 or 503)
                    notes.append(f"the site returned no HTML content (HTTP {page.status_code}), so page features were imputed")

            features.update(url_text_features(checked))
            if page is not None and page.html.strip():
                features.update(page_features(page.html, page.final_url))
            if resolves:
                features["SSLfinal_State"] = ssl_feature(page.final_url if page else checked)
            elif parse_url(checked).scheme == "http":
                features["SSLfinal_State"] = PHISHING

            if ip_host:
                # No domain name: nothing to look up, and not a ranked site
                features["age_of_domain"] = PHISHING
                features["web_traffic"] = PHISHING
            else:
                domain = registered_domain(host)
                features["age_of_domain"] = domain_age_feature(domain)
                features["web_traffic"] = traffic_feature(domain)

            for name in NOT_MEASURED:
                features[name] = None

            logging.info(f"URL features for {checked}: {features}")
            return URLCheck(url=checked, final_url=page.final_url if page else None, features=features, notes=notes)
        except Exception as e:
            raise NetworkSecurityException(e, sys)
