"""Checks for upgrade_test.evaluate (stdlib only): run with `py test_upgrade_eval.py`."""

from upgrade_test import evaluate

FIXED_IN = {"CVE-OLD": "2.4.50", "CVE-OLD2": "2.4.51", "CVE-NEW": "2.4.56"}


def test_matrix_recall_and_claim():
    after2 = {
        "CVE-OLD": {"state": "verified", "verification_reason": "cve_not_matched"},
        "CVE-OLD2": {"state": "open"},  # missed
        "CVE-NEW": {"state": "verified", "verification_reason": "cve_not_matched"},  # wrong
    }
    m = evaluate({"CVE-OLD", "CVE-OLD2", "CVE-NEW", "CVE-UNLISTED"}, after2, after2, FIXED_IN)
    u1 = m["u1"]
    assert u1["denominator"] == 3 and u1["expected_verified"] == 2
    assert u1["matrix"]["exp_verified"]["not_verified"] == ["CVE-OLD2"]
    assert u1["matrix"]["exp_not_verified"]["verified"] == ["CVE-NEW"]
    assert u1["false_verified"] == 1 and u1["verified_recall"] == "1/2"
    assert not u1["claim_met"]
    assert m["u3"]["not_listed"] == ["CVE-UNLISTED"]


def test_u2_and_u4():
    after2 = {
        "CVE-2021-41773": {"state": "verified"},
        "CVE-2024-38474": {"state": "accepted"},
        "CVE-2022-36760": {"state": "open"},
    }
    after3 = {**after2, "CVE-2022-36760": {"state": "verified"}}  # a failed rescan verified one
    m = evaluate(set(after2), after2, after3, {})
    assert m["u2"]["all_hold"]
    assert m["u4"]["state_changes_in_failed_rescan"] == ["CVE-2022-36760"]
    assert not m["u4"]["zero_changes"]


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            fn()
            print("ok", name)
