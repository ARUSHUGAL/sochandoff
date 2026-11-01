"""Tests for the case model and risk logic."""

from datetime import datetime, timedelta, timezone

import pytest

from sochandoff.model import Case


def _iso(hours_ago: float) -> str:
    return (datetime.now(timezone.utc) - timedelta(hours=hours_ago)).isoformat()


def make_case(**overrides):
    base = dict(
        id="T-1",
        title="test",
        severity="medium",
        status="investigating",
        opened_at=_iso(48),
        last_update=_iso(1),
        assignee="a.analyst",
        shifts_open=0,
        acknowledged=True,
    )
    base.update(overrides)
    return Case(**base)


def test_bad_severity_rejected():
    with pytest.raises(ValueError):
        make_case(severity="spicy")


def test_bad_status_rejected():
    with pytest.raises(ValueError):
        make_case(status="vibing")


def test_closed_case_is_not_open():
    assert make_case(status="closed").is_open is False


def test_critical_outranks_low():
    high = make_case(severity="critical")
    low = make_case(severity="low")
    assert high.risk_score() > low.risk_score()


def test_watch_bumps_score():
    plain = make_case()
    watched = make_case(watch=True)
    assert watched.risk_score() > plain.risk_score()


def test_drop_guard_flags_unassigned_stale_case():
    case = make_case(assignee="unassigned", last_update=_iso(20), shifts_open=4)
    flagged, reason = case.drop_risk()
    assert flagged is True
    assert "no owner" in reason


def test_drop_guard_flags_unacked_critical():
    case = make_case(severity="critical", acknowledged=False)
    flagged, reason = case.drop_risk()
    assert flagged is True
    assert "not acknowledged" in reason


def test_drop_guard_clears_healthy_case():
    case = make_case(
        assignee="a.analyst",
        last_update=_iso(1),
        shifts_open=0,
        acknowledged=True,
    )
    flagged, _ = case.drop_risk()
    assert flagged is False


def test_closed_case_never_at_risk():
    case = make_case(status="closed", assignee="unassigned", shifts_open=9)
    flagged, _ = case.drop_risk()
    assert flagged is False
