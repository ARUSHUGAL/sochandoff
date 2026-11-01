"""Tests for loading cases and building the report."""

from pathlib import Path

from sochandoff.report import build_report, load_cases

SAMPLE = Path(__file__).parent.parent / "sochandoff" / "data" / "sample_cases.json"


def test_sample_loads():
    cases = load_cases(SAMPLE)
    assert len(cases) == 6


def test_report_hides_closed_cases():
    cases = load_cases(SAMPLE)
    report = build_report(cases, use_color=False)
    # The closed cert case should not appear in the open list.
    assert "SOC-1019" not in report


def test_report_flags_dropped_cases():
    cases = load_cases(SAMPLE)
    report = build_report(cases, use_color=False)
    assert "DROPPED-CASE GUARD" in report
    # The unassigned, long-open phishing case must be flagged.
    assert "SOC-1042" in report


def test_report_has_no_ansi_when_color_off():
    cases = load_cases(SAMPLE)
    report = build_report(cases, use_color=False)
    assert "\033[" not in report
