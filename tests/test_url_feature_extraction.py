"""Offline tests for the URL feature extractor: no websites, DNS or lookup services are contacted."""
import pytest

from networksecurity.components.url_feature_extraction import (
    FEATURE_COLUMNS, LEGITIMATE, NOT_MEASURED, PHISHING, SUSPICIOUS,
    BlockedAddressError, URLFeatureExtractor, _check_public, is_ip_host,
    page_features, parse_url, url_text_features,
)


# ---------- URL text ----------

def test_plain_url_looks_legitimate():
    assert url_text_features("https://github.com/login") == {
        "having_IP_Address": LEGITIMATE,
        "URL_Length": LEGITIMATE,
        "having_At_Symbol": LEGITIMATE,
        "having_Sub_Domain": LEGITIMATE,
        "port": LEGITIMATE,
    }


@pytest.mark.parametrize("host", ["192.0.2.15", "2001:db8::1", "3232235777", "0xC0A80001"])
def test_ip_hosts_are_detected(host):
    assert is_ip_host(host)


def test_ip_address_url_is_flagged():
    assert url_text_features("http://192.0.2.15/paypal/login.php")["having_IP_Address"] == PHISHING


@pytest.mark.parametrize("length, expected", [(53, LEGITIMATE), (54, SUSPICIOUS), (75, SUSPICIOUS), (76, PHISHING)])
def test_url_length_thresholds(length, expected):
    base = "http://example.com/"
    url = base + "a" * (length - len(base))
    assert len(url) == length
    assert url_text_features(url)["URL_Length"] == expected


@pytest.mark.parametrize("url, expected", [
    ("https://www.example.com/", LEGITIMATE),      # www is not counted
    ("https://mail.example.com/", SUSPICIOUS),
    ("https://a.b.example.com/", PHISHING),
    ("https://news.bbc.co.uk/", SUSPICIOUS),       # co.uk is one public suffix
])
def test_sub_domain_levels(url, expected):
    assert url_text_features(url)["having_Sub_Domain"] == expected


def test_at_symbol_and_non_standard_port():
    features = url_text_features("https://user@mail.google.com:8443/x")
    assert features["having_At_Symbol"] == PHISHING
    assert features["port"] == PHISHING


@pytest.mark.parametrize("url", ["ftp://example.com/file", "not a url", "http:///no-host", "http://example.com:99999/"])
def test_invalid_urls_are_rejected(url):
    with pytest.raises(ValueError):
        parse_url(url)


# ---------- page HTML ----------

SUSPICIOUS_PAGE = """
<html><head>
  <link rel="icon" href="https://evil.example.net/f.ico">
  <script src="/app.js"></script>
</head><body>
  <a href="#">x</a><a href="javascript:void(0)">y</a><a href="/about">z</a><a href="http://[broken">bad</a>
  <form action="about:blank"><input></form>
  <iframe src="x" frameborder="0"></iframe>
  <img src="https://cdn.other.org/a.png"><img src="/b.png">
</body></html>
"""


def test_suspicious_page_features():
    features = page_features(SUSPICIOUS_PAGE, "https://example.com/login")
    assert features["Request_URL"] == PHISHING        # 1 of 2 images from another domain
    assert features["URL_of_Anchor"] == SUSPICIOUS    # 2 of 4 anchors go nowhere
    assert features["Links_in_tags"] == SUSPICIOUS    # 1 of 2 tag links is external
    assert features["SFH"] == PHISHING                # form submits to about:blank
    assert features["Favicon"] == PHISHING
    assert features["Iframe"] == PHISHING


def test_clean_page_features():
    html = """<html><head><link rel="icon" href="/favicon.ico"></head><body>
      <a href="/a">a</a><a href="/b">b</a><a href="https://www.example.com/c">c</a>
      <form action="/search"></form><img src="/logo.png"></body></html>"""
    features = page_features(html, "https://example.com/")
    assert all(value == LEGITIMATE for value in features.values()), features


def test_page_without_links_leaves_anchor_feature_to_imputer():
    assert page_features("<html><body>hello</body></html>", "https://example.com/")["URL_of_Anchor"] is None


@pytest.mark.parametrize("html, feature", [
    ('<form action="mailto:a@b.com"></form>', "Submitting_to_email"),
    ('<a onmouseover="window.status=\'x\'">a</a>', "on_mouseover"),
    ('<body oncontextmenu="return false">', "RightClick"),
    ("<script>if (event.button == 2) {}</script>", "RightClick"),
    ("<script>prompt('password')</script>", "popUpWidnow"),
    ('<iframe src="x" style="display: none"></iframe>', "Iframe"),
])
def test_page_tricks_are_flagged(html, feature):
    assert page_features(html, "https://example.com/")[feature] == PHISHING


def test_form_posting_to_another_domain_is_suspicious():
    html = '<form action="https://collector.example.net/steal"></form>'
    assert page_features(html, "https://example.com/")["SFH"] == SUSPICIOUS


# ---------- safety and assembly ----------

@pytest.mark.parametrize("host", ["127.0.0.1", "10.0.0.5", "192.168.1.1", "169.254.169.254", "::1"])
def test_private_addresses_are_never_contacted(host):
    with pytest.raises(BlockedAddressError):
        _check_public(host)


def test_extract_returns_all_30_features_with_unmeasured_left_blank():
    # An IP address host with page fetching off needs no network at all
    check = URLFeatureExtractor(fetch_pages=False).extract("http://192.0.2.15/paypal/login.php")
    assert tuple(check.features) == FEATURE_COLUMNS
    assert all(check.features[name] is None for name in NOT_MEASURED)
    assert check.features["having_IP_Address"] == PHISHING
    assert check.features["SSLfinal_State"] == PHISHING     # plain HTTP
    assert check.features["DNSRecord"] == PHISHING          # no domain name


def test_extract_rejects_empty_url():
    with pytest.raises(ValueError):
        URLFeatureExtractor().extract("   ")
