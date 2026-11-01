"""Tests for IOC classification and threat-intel enrichment."""

from sochandoff.enrich import IntelFeed, classify_ioc


def test_classify_ip():
    assert classify_ioc("194.26.135.12") == "ip"


def test_classify_domain():
    assert classify_ioc("finance-secure-login.com") == "domain"


def test_classify_hash():
    assert classify_ioc("a94a8fe5ccb19ba61c4c0873d391e987982fbbd3") == "hash"


def test_classify_unknown():
    assert classify_ioc("not an ioc") == "unknown"


def test_known_bad_ip_flagged():
    feed = IntelFeed(demo=True)
    verdict = feed.lookup("194.26.135.12")
    assert verdict.is_bad is True
    assert verdict.score >= 50


def test_unknown_ioc_is_clean():
    feed = IntelFeed(demo=True)
    verdict = feed.lookup("8.8.8.8")
    assert verdict.is_bad is False
