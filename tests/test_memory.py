"""Tests for cross-shift memory."""

from sochandoff.memory import ShiftMemory


def test_first_sight_is_not_a_repeat(tmp_path):
    mem = ShiftMemory(store_path=tmp_path / "mem.json")
    assert mem.recall("1.2.3.4").is_repeat is False


def test_recall_after_record(tmp_path):
    store = tmp_path / "mem.json"
    mem = ShiftMemory(store_path=store)
    mem.record("1.2.3.4", "SOC-1")
    mem.save()

    # A fresh instance reading the same store should now recall it.
    mem2 = ShiftMemory(store_path=store)
    recall = mem2.recall("1.2.3.4")
    assert recall.is_repeat is True
    assert recall.seen_count == 1
    assert "SOC-1" in recall.case_ids


def test_new_shift_increments_count(tmp_path):
    store = tmp_path / "mem.json"
    mem = ShiftMemory(store_path=store, shift_gap_hours=6)
    mem.record("1.2.3.4", "SOC-1", now="2026-10-31T06:00:00+00:00")
    mem.record("1.2.3.4", "SOC-2", now="2026-10-31T14:00:00+00:00")  # 8h later
    mem.save()
    recall = ShiftMemory(store_path=store).recall("1.2.3.4")
    assert recall.seen_count == 2
    assert set(recall.case_ids) == {"SOC-1", "SOC-2"}


def test_same_shift_reruns_do_not_inflate(tmp_path):
    mem = ShiftMemory(store_path=tmp_path / "mem.json", shift_gap_hours=6)
    for minute in ("00", "05", "10"):
        mem.record("1.2.3.4", "SOC-1", now=f"2026-10-31T06:{minute}:00+00:00")
    assert mem.recall("1.2.3.4").seen_count == 1
