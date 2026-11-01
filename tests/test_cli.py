"""End-to-end CLI tests. Memory goes to a temp dir via --config."""

import json

import pytest

from sochandoff import model
from sochandoff.cli import main
from sochandoff.enrich import IntelFeed


@pytest.fixture
def cfg(tmp_path):
    p = tmp_path / "config.toml"
    p.write_text(f'[memory]\npath = "{tmp_path / "mem.json"}"\n')
    yield str(p)
    model.THRESHOLDS.stale_hours = 8.0
    model.THRESHOLDS.max_shifts_open = 3


def test_text_runs(cfg, capsys):
    assert main(["--config", cfg, "--no-color"]) == 0
    assert "DROPPED-CASE GUARD" in capsys.readouterr().out


def test_markdown_export(cfg, tmp_path):
    out = tmp_path / "handoff.md"
    assert main(["--config", cfg, "-f", "md", "-o", str(out)]) == 0
    text = out.read_text()
    assert text.startswith("# SOC Shift Handoff")
    assert "- [ ] **SOC-1042**" in text


def test_json_export_and_memory(cfg, capsys):
    main(["--config", cfg, "-f", "json"])
    first = json.loads(capsys.readouterr().out)
    assert first["open_cases"] == 5
    main(["--config", cfg, "-f", "json"])
    second = json.loads(capsys.readouterr().out)
    phish = next(c for c in second["cases"] if c["id"] == "SOC-1042")
    assert phish["memory"], "second run should recall the first"


def test_invalid_file_lists_problems(cfg, tmp_path, capsys):
    bad = tmp_path / "bad.json"
    bad.write_text('[{"id": "Z"}]')
    assert main(["--config", cfg, str(bad)]) == 1
    assert "missing 'title'" in capsys.readouterr().err


def test_config_thresholds_apply(tmp_path, capsys):
    p = tmp_path / "c.toml"
    p.write_text(f'[thresholds]\nstale_hours = 100000\nmax_shifts_open = 99\n'
                 f'[memory]\npath = "{tmp_path / "m.json"}"\n')
    try:
        main(["--config", str(p), "-f", "json", "--no-intel"])
        data = json.loads(capsys.readouterr().out)
        # Only owner / ack reasons can fire now, never staleness.
        assert all("no update" not in c["at_risk_reason"] for c in data["cases"])
    finally:
        model.THRESHOLDS.stale_hours = 8.0
        model.THRESHOLDS.max_shifts_open = 3


def test_missing_explicit_config_errors(capsys):
    assert main(["--config", "/nope/config.toml"]) == 1


def test_live_intel_falls_back_when_network_fails(monkeypatch):
    import urllib.request

    def boom(*a, **k):
        raise OSError("network down")

    monkeypatch.setattr(urllib.request, "urlopen", boom)
    feed = IntelFeed(live=True, abuseipdb_key="k")
    assert feed.lookup("194.26.135.12").source == "bundled-feed"


def test_live_intel_uses_abuseipdb(monkeypatch):
    import io
    import urllib.request

    class Resp(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    body = b'{"data": {"abuseConfidenceScore": 97, "totalReports": 41, "countryCode": "RU"}}'
    monkeypatch.setattr(urllib.request, "urlopen", lambda *a, **k: Resp(body))
    v = IntelFeed(live=True, abuseipdb_key="k").lookup("203.0.113.9")
    assert v.source == "abuseipdb-live"
    assert v.is_bad and "97%" in v.summary
