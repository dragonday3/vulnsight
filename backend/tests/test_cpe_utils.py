"""Tests for the CPE 2.2 -> 2.3 conversion helper.

Pure-function tests, no I/O: `to_cpe23` never touches the network, Redis,
or the DB, so these just assert exact string output (or `None` for
malformed input) against a table of real nmap-shaped inputs.
"""

from __future__ import annotations

import pytest

from app.modules.vulnerability.cpe_utils import nvd_aliases, to_cpe23


@pytest.mark.parametrize(
    ("cpe22", "expected_cpe23"),
    [
        # Plain part/vendor/product/version -- the common case.
        ("cpe:/a:nginx:nginx:1.24.0", "cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*"),
        # OS CPE (part="o").
        ("cpe:/o:linux:linux_kernel:5.4", "cpe:2.3:o:linux:linux_kernel:5.4:*:*:*:*:*:*:*"),
        # update + edition fields present (language still absent).
        (
            "cpe:/a:vendor:product:1.0:beta1:pro",
            "cpe:2.3:a:vendor:product:1.0:beta1:pro:*:*:*:*:*",
        ),
        # All 7 CPE 2.2 fields present.
        (
            "cpe:/a:vendor:product:1.0:beta1:pro:en",
            "cpe:2.3:a:vendor:product:1.0:beta1:pro:en:*:*:*:*",
        ),
        # Empty (unspecified) trailing field maps to "*", not a blank
        # segment.
        ("cpe:/a:vendor:product:", "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*"),
    ],
)
def test_to_cpe23_converts_valid_input(cpe22: str, expected_cpe23: str) -> None:
    assert to_cpe23(cpe22) == expected_cpe23


@pytest.mark.parametrize(
    "cpe22",
    [
        "notacpe:foo",  # wrong prefix entirely
        "cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*",  # already-2.3, not 2.2
        "cpe:/a:v:p:v:u:e:l:extra",  # 8 fields -- more than the 7 CPE 2.2 allows
        "cpe:/a:vendor:prod uct:1.0",  # unsafe character (space) in a field
        "cpe:/a:vendor:prod;rm -rf:1.0",  # unsafe characters (shell metacharacters)
        "cpe:/a:vendor:my~app:1.0",  # literal tilde: packed-edition separator, unhandled
        "cpe:/a:vendor:my%7eapp:1.0",  # percent-encoded tilde, decodes to the same
        "",  # empty string
    ],
)
def test_to_cpe23_returns_none_for_malformed_input(cpe22: str) -> None:
    assert to_cpe23(cpe22) is None


@pytest.mark.parametrize(
    ("cpe23", "expected"),
    [
        (
            "cpe:2.3:a:igor_sysoev:nginx:1.13.2:*:*:*:*:*:*:*",
            ["cpe:2.3:a:f5:nginx:1.13.2:*:*:*:*:*:*:*"],
        ),
        (
            "cpe:2.3:a:elasticsearch:elasticsearch:1.4.2:*:*:*:*:*:*:*",
            ["cpe:2.3:a:elastic:elasticsearch:1.4.2:*:*:*:*:*:*:*"],
        ),
        # Jetty: vendor rename plus nmap's "X.vYYYYMMDD" split into version/update.
        (
            "cpe:2.3:a:mortbay:jetty:9.4.37.v20210219:*:*:*:*:*:*:*",
            ["cpe:2.3:a:eclipse:jetty:9.4.37:20210219:*:*:*:*:*:*"],
        ),
        # Jetty version without the date suffix: vendor rename only.
        (
            "cpe:2.3:a:mortbay:jetty:9.4.37:*:*:*:*:*:*:*",
            ["cpe:2.3:a:eclipse:jetty:9.4.37:*:*:*:*:*:*:*"],
        ),
        (
            "cpe:2.3:a:mysql:mysql:5.5.23:*:*:*:*:*:*:*",
            ["cpe:2.3:a:oracle:mysql:5.5.23:*:*:*:*:*:*:*"],
        ),
        # Not in the alias table, or malformed: no aliases.
        ("cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*", []),
        ("cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*", []),
        ("not-a-cpe", []),
    ],
)
def test_nvd_aliases(cpe23: str, expected: list[str]) -> None:
    assert nvd_aliases(cpe23) == expected
