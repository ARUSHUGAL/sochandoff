"""Data model and risk scoring for SOC cases.

A "case" is one open investigation an analyst is tracking. The scoring here
decides how a case is ranked in the handoff and whether it gets flagged as at
risk of being dropped between shifts.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

# Severity weights. Higher = more urgent. These drive the ranking so the
# incoming shift sees the scariest cases first.
SEVERITY_WEIGHT = {
    "critical": 100,
    "high": 70,
    "medium": 40,
    "low": 15,
    "info": 5,
}

# Status weights. An open, actively-worked case matters more at handoff than
# one already contained or closed.
STATUS_WEIGHT = {
    "new": 30,
    "investigating": 25,
    "containment": 20,
    "monitoring": 10,
    "closed": 0,
}

VALID_SEVERITIES = set(SEVERITY_WEIGHT)
VALID_STATUSES = set(STATUS_WEIGHT)


@dataclass
class Thresholds:
    """Tunable limits for the dropped-case guard. Overridden by config."""

    stale_hours: float = 8.0      # no update for longer than this = stale
    max_shifts_open: int = 3      # open across this many shifts = drifting


# Process-wide thresholds. The CLI replaces these from the config file.
THRESHOLDS = Thresholds()


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_time(value: str) -> datetime:
    """Parse an ISO 8601 timestamp, tolerating a trailing 'Z'."""
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


@dataclass
class Case:
    """One open SOC investigation."""

    id: str
    title: str
    severity: str
    status: str
    opened_at: str
    last_update: str
    assignee: str = "unassigned"
    shifts_open: int = 0
    notes: str = ""
    watch: bool = False
    acknowledged: bool = False
    tags: list[str] = field(default_factory=list)
    # Indicators of compromise tied to this case: IPs, domains, file hashes.
    # These drive threat-intel enrichment and cross-shift memory.
    iocs: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.severity = self.severity.lower().strip()
        self.status = self.status.lower().strip()
        if self.severity not in VALID_SEVERITIES:
            raise ValueError(
                f"case {self.id}: bad severity '{self.severity}'. "
                f"use one of: {', '.join(sorted(VALID_SEVERITIES))}"
            )
        if self.status not in VALID_STATUSES:
            raise ValueError(
                f"case {self.id}: bad status '{self.status}'. "
                f"use one of: {', '.join(sorted(VALID_STATUSES))}"
            )

    @property
    def is_open(self) -> bool:
        return self.status != "closed"

    @property
    def hours_since_update(self) -> float:
        return (_now() - _parse_time(self.last_update)).total_seconds() / 3600.0

    def risk_score(self) -> int:
        """Rank score. Higher means show it sooner in the handoff."""
        score = SEVERITY_WEIGHT[self.severity] + STATUS_WEIGHT[self.status]
        # Cases that have survived several shifts are drifting — bump them up.
        score += min(self.shifts_open, 5) * 8
        # Explicit watch items always float toward the top.
        if self.watch:
            score += 25
        # Stale, un-updated open cases are the dangerous ones.
        if self.is_open and self.hours_since_update > THRESHOLDS.stale_hours:
            score += 15
        return score

    def drop_risk(self) -> tuple[bool, str]:
        """The 'dropped case' guard.

        Returns (at_risk, reason). A case is flagged when it looks likely to
        fall through the crack between shifts.
        """
        if not self.is_open:
            return False, ""
        reasons = []
        if self.shifts_open >= THRESHOLDS.max_shifts_open:
            reasons.append(f"open across {self.shifts_open} shifts")
        if self.hours_since_update > THRESHOLDS.stale_hours:
            reasons.append(f"no update in {self.hours_since_update:.0f}h")
        if self.assignee == "unassigned":
            reasons.append("no owner assigned")
        if self.severity in ("critical", "high") and not self.acknowledged:
            reasons.append(f"{self.severity} and not acknowledged")
        return (bool(reasons), "; ".join(reasons))
