"""Pure tests for the Phase 10 applicability (unverified-prerequisite) rules."""

from __future__ import annotations

import pytest

from app.modules.vulnerability.applicability import (
    RULE_FEATURE_COUNT,
    RULE_PATTERN_COUNT,
    observed_features,
    unverified_prerequisite,
)


@pytest.mark.parametrize(
    ("description", "expected"),
    [
        ("The HTTP/2 protocol allows a denial of service (Rapid Reset).", "http2"),
        ("A buffer overflow in the mod_lua multipart parser.", "mod_lua"),
        ("Some mod_proxy configurations allow request smuggling.", "mod_proxy"),
        ("Bypass in the DIGEST authenticator.", "digest_auth"),
        ("Buffer overflow in yaSSL, as used in MySQL.", "tls"),
        ("Allows remote database servers to cause a denial of service.", "client_side"),
        # Names nothing in the table: no prerequisite.
        ("Path traversal in path normalization.", None),
        ("Integer overflow in the range filter module.", None),
        (None, None),
        ("", None),
    ],
)
def test_unverified_prerequisite_matches_rule_features(
    description: str | None, expected: str | None
) -> None:
    assert unverified_prerequisite(description, observed=set()) == expected


def test_observed_feature_is_not_flagged() -> None:
    text = "ALPACA is an application layer protocol content confusion attack on TLS servers."
    assert unverified_prerequisite(text, observed=set()) == "tls"
    assert unverified_prerequisite(text, observed={"tls"}) is None


def test_first_unobserved_feature_is_reported_when_several_match() -> None:
    # HTTP/2 over TLS: with TLS observed, the unobserved HTTP/2 is reported.
    text = "An HTTP/2 SSL connection that is TCP congested will be leaked."
    assert unverified_prerequisite(text, observed={"tls"}) == "http2"


def test_observed_features_only_tls_from_service_names() -> None:
    assert observed_features(["http", "ssl/http", None]) == {"tls"}
    assert observed_features(["https"]) == {"tls"}
    assert observed_features(["http", "mysql", None]) == set()


def test_rule_counts_are_reported() -> None:
    # Reported in benchmark results (pre-registered M3); keeps them honest.
    assert RULE_FEATURE_COUNT >= 1 and RULE_PATTERN_COUNT >= RULE_FEATURE_COUNT
