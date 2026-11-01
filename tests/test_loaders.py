"""Tests for file loading and validation."""

import json

import pytest

from sochandoff.loaders import CaseError, load_cases, validate

GOOD = {
    "id": "X-1", "title": "t", "severity": "high", "status": "new",
    "opened_at": "2026-10-31T06:00:00Z", "last_update": "2026-10-31T07:00:00Z",
}


def test_valid_case_loads():
    assert validate([GOOD])[0].id == "X-1"


def test_collects_every_problem_with_position():
    bad = [dict(GOOD, severity="spicy"), {"id": "X-2"}, dict(GOOD, last_update="yesterday")]
    with pytest.raises(CaseError) as info:
        validate(bad)
    text = "\n".join(info.value.problems)
    assert "case #1 (X-1): bad severity 'spicy'" in text
    assert "case #2 (X-2): missing 'title'" in text
    assert "case #3" in text and "ISO 8601" in text


def test_unknown_field_reported():
    with pytest.raises(CaseError, match="unknown field"):
        validate([dict(GOOD, colour="red")])


def test_duplicate_id_reported():
    with pytest.raises(CaseError, match="duplicate id"):
        validate([GOOD, dict(GOOD)])


def test_not_a_list():
    with pytest.raises(CaseError):
        validate({"id": "x"})


def test_bad_json_is_friendly(tmp_path):
    p = tmp_path / "cases.json"
    p.write_text("[{oops")
    with pytest.raises(CaseError, match="not valid JSON"):
        load_cases(p)


def test_csv_loads_and_coerces(tmp_path):
    p = tmp_path / "cases.csv"
    p.write_text(
        "id,title,severity,status,opened_at,last_update,watch,shifts_open,iocs\n"
        "C-1,VPN brute force,high,new,2026-10-31T06:00:00Z,2026-10-31T07:00:00Z,"
        "yes,2,1.2.3.4;evil.com\n"
    )
    case = load_cases(p)[0]
    assert case.watch is True
    assert case.shifts_open == 2
    assert case.iocs == ["1.2.3.4", "evil.com"]


def test_json_round_trip(tmp_path):
    p = tmp_path / "cases.json"
    p.write_text(json.dumps([GOOD]))
    assert len(load_cases(p)) == 1
