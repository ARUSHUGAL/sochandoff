"""Tests for feeds, team memory, audit log and redaction. No network."""

import json
import multiprocessing as mp
import os
import stat

import pytest

from sochandoff.audit import write_audit
from sochandoff.cli import main
from sochandoff.enrich import IntelFeed
from sochandoff.feeds import FEEDS, FeedIndex, parse, update_feeds
from sochandoff.loaders import validate
from sochandoff.memory import ShiftMemory, SqliteMemory, open_memory
from sochandoff.redact import Redactor, reveal

FAKE = {
    FEEDS["feodo"].url: json.dumps([{"ip_address": "50.16.16.211", "malware": "Emotet"},
                                    {"ip_address": "not-an-ip"}]).encode(),
    FEEDS["spamhaus-drop"].url: b"; Spamhaus DROP\n1.10.16.0/20 ; SBL256894\nbad line\n",
    FEEDS["openphish"].url: b"https://evil-login.com/a/b\nhttp://1.2.3.4/x\n",
    FEEDS["et-compromised"].url: b"# comment\n50.16.16.211\n8.8.4.4\n",
    FEEDS["cins"].url: b"45.142.212.61\n",
    FEEDS["blocklist-de"].url: b"",  # empty feed must not wipe the old copy
}


# ---------------------------------------------------------------- feeds

def test_parsers_skip_junk():
    assert parse(FEEDS["feodo"], FAKE[FEEDS["feodo"].url])["exact"] == {"50.16.16.211": "Emotet"}
    assert parse(FEEDS["spamhaus-drop"], FAKE[FEEDS["spamhaus-drop"].url])["cidr"] == [["1.10.16.0/20", ""]]
    assert list(parse(FEEDS["openphish"], FAKE[FEEDS["openphish"].url])["exact"]) == ["evil-login.com"]


def test_update_and_lookup_offline(tmp_path):
    report = update_feeds(tmp_path, get=lambda url: FAKE[url])
    assert report["feodo"] == "1 entries"
    assert report["blocklist-de"].startswith("error: feed was empty")
    feed = IntelFeed(feeds_dir=tmp_path)
    v = feed.lookup("50.16.16.211")
    assert v.is_bad and v.source == "feodo"
    assert "Emotet" in v.summary and "+1 more feed" in v.summary
    assert feed.lookup("1.10.20.5").source == "spamhaus-drop"      # inside the CIDR
    assert feed.lookup("evil-login.com").is_bad
    assert not feed.lookup("9.9.9.9").is_bad


def test_one_feed_failing_does_not_stop_others(tmp_path):
    def flaky(url):
        if "spamhaus" in url:
            raise OSError("timeout")
        return FAKE[url]
    report = update_feeds(tmp_path, get=flaky)
    assert report["spamhaus-drop"].startswith("error")
    assert report["feodo"] == "1 entries"


def test_demo_list_never_judges_real_data(tmp_path):
    # 194.26.135.12 is in the bundled demo list. Without demo=True it is unknown.
    assert not IntelFeed(feeds_dir=tmp_path).lookup("194.26.135.12").is_bad
    assert IntelFeed(feeds_dir=tmp_path, demo=True).lookup("194.26.135.12").is_bad


def test_stale_feed_flagged(tmp_path):
    (tmp_path / "old.json").write_text(json.dumps(
        {"name": "old", "updated": "2020-01-01T00:00:00+00:00", "exact": {}, "cidr": []}))
    assert FeedIndex(tmp_path).stale


# ---------------------------------------------------------------- memory

@pytest.mark.parametrize("cls", [ShiftMemory, SqliteMemory])
def test_backends_agree(tmp_path, cls):
    path = tmp_path / ("m.db" if cls is SqliteMemory else "m.json")
    m = cls(path, shift_gap_hours=6)
    m.record("1.2.3.4", "A", now="2026-10-31T06:00:00+00:00")
    m.save()
    m2 = cls(path, shift_gap_hours=6)
    assert m2.recall("1.2.3.4").seen_count == 1
    m2.record("1.2.3.4", "B", now="2026-10-31T06:30:00+00:00")   # same shift
    m2.record("1.2.3.4", "B", now="2026-10-31T15:00:00+00:00")   # next shift
    m2.save()
    r = cls(path, shift_gap_hours=6).recall("1.2.3.4")
    assert r.seen_count == 2
    assert set(r.case_ids) == {"A", "B"}
    assert r.last_seen_by


def test_json_two_analysts_do_not_overwrite(tmp_path):
    path = tmp_path / "team.json"
    a, b = ShiftMemory(path), ShiftMemory(path)          # both load an empty file
    a.record("1.1.1.1", "A", now="2026-10-31T06:00:00+00:00")
    b.record("2.2.2.2", "B", now="2026-10-31T06:00:00+00:00")
    a.save()
    b.save()                                              # must merge, not clobber
    after = ShiftMemory(path)
    assert after.recall("1.1.1.1").is_repeat and after.recall("2.2.2.2").is_repeat
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600


def _writer(path, n, backend):
    m = open_memory(backend, path)
    for i in range(n):
        m.record(f"10.0.{os.getpid() % 250}.{i}", f"C{i}")
    m.save()


@pytest.mark.parametrize("backend,name", [("json", "p.json"), ("sqlite", "p.db")])
def test_parallel_writers(tmp_path, backend, name):
    path = str(tmp_path / name)
    ctx = mp.get_context("spawn")
    procs = [ctx.Process(target=_writer, args=(path, 20, backend)) for _ in range(4)]
    for p in procs:
        p.start()
    for p in procs:
        p.join(30)
        assert p.exitcode == 0
    m = open_memory(backend, path)
    if backend == "json":
        assert len(m._data) == 80
    else:
        assert len(m._snapshot) == 80


def test_bad_backend():
    with pytest.raises(ValueError):
        open_memory("postgres")


# ---------------------------------------------------------------- audit

def test_audit_line_has_no_case_content(tmp_path):
    path = tmp_path / "audit.jsonl"
    write_audit({"source": "thehive", "case_ids": ["HIVE-1"], "status": "ok"}, path)
    write_audit({"source": "file:x.json", "status": "error"}, path)
    lines = [json.loads(x) for x in path.read_text().splitlines()]
    assert len(lines) == 2
    assert lines[0]["case_ids"] == ["HIVE-1"] and lines[0]["user"] and lines[0]["host"]
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600


def test_cli_writes_audit(tmp_path, capsys):
    cfg = tmp_path / "c.toml"
    log = tmp_path / "a.jsonl"
    cfg.write_text(f'[memory]\npath = "{tmp_path / "m.json"}"\n[audit]\npath = "{log}"\n')
    assert main(["--config", str(cfg), "-f", "json"]) == 0
    capsys.readouterr()
    rec = json.loads(log.read_text().splitlines()[-1])
    assert rec["status"] == "ok" and rec["source"] == "sample" and rec["open_cases"] == 5
    assert "Phishing" not in log.read_text()      # titles never logged


# ---------------------------------------------------------------- redact

CASES = validate([{
    "id": "SOC-1", "title": "Beacon from WS-118 to 50.16.16.211 (evil-login.com)",
    "severity": "high", "status": "new", "opened_at": "2026-10-31T06:00:00Z",
    "last_update": "2026-10-31T07:00:00Z", "assignee": "a.patel",
    "notes": "mailed jane.doe@acme.com, hash a94a8fe5ccb19ba61c4c0873d391e987982fbbd3, v6 2001:db8::1",
    "iocs": ["50.16.16.211", "evil-login.com"],
}])


def test_redact_hides_values_and_reveal_restores(tmp_path):
    mp_ = tmp_path / "map.json"
    r = Redactor(mp_, extra_patterns=[r"\bWS-\d+\b"])
    r.learn(CASES)
    text = f"{CASES[0].title} owner={CASES[0].assignee} {CASES[0].notes} at 21:56:22"
    out = r.redact(text)
    r.save()
    for secret in ("50.16.16.211", "evil-login.com", "a.patel", "jane.doe@acme.com",
                   "a94a8fe5", "WS-118", "2001:db8::1"):
        assert secret not in out, secret
    assert "SOC-1" not in text or "SOC-1" in out          # case ids stay readable
    assert "21:56:22" in out                              # times are not IPv6
    assert reveal(out, mp_) == text
    assert stat.S_IMODE(os.stat(mp_).st_mode) == 0o600


def test_tokens_stable_across_runs(tmp_path):
    mp_ = tmp_path / "map.json"
    a = Redactor(mp_)
    first = a.redact("50.16.16.211")
    a.save()
    assert Redactor(mp_).redact("50.16.16.211") == first


def test_cli_redact_then_reveal(tmp_path, capsys):
    cfg = tmp_path / "c.toml"
    cfg.write_text(f'[memory]\npath = "{tmp_path / "m.json"}"\n'
                   f'[redact]\nmap = "{tmp_path / "map.json"}"\n')
    out = tmp_path / "h.md"
    assert main(["--config", str(cfg), "-f", "md", "--redact", "-o", str(out)]) == 0
    red = out.read_text()
    assert "194.26.135.12" not in red and "a.patel" not in red and "IP-" in red
    assert stat.S_IMODE(os.stat(out).st_mode) == 0o600
    assert main(["--config", str(cfg), "--reveal", str(out)]) == 0
    assert "194.26.135.12" in capsys.readouterr().out
