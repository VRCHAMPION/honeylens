import os

import pytest

from honeylens.pipeline.tailer import Tailer


def read_all(t, n=1000):
    res = t.read(n)
    t.commit(res)
    return [ln.data for ln in res.lines], res


def test_reads_complete_lines_only(tmp_path):
    p = tmp_path / "cowrie.json"
    p.write_bytes(b"one\ntwo\nthr")
    t = Tailer([str(tmp_path / "cowrie.json*")])
    lines, _ = read_all(t)
    assert lines == [b"one", b"two"]
    with open(p, "ab") as fh:
        fh.write(b"ee\n")
    assert read_all(t)[0] == [b"three"]
    assert read_all(t)[0] == []


def test_offsets_survive_restart(tmp_path):
    p = tmp_path / "cowrie.json"
    p.write_bytes(b"a\nb\n")
    t = Tailer([str(p)])
    read_all(t)
    saved = [(s.key, s.path, s.offset, s.head_hash) for s in t.states.values()]
    with open(p, "ab") as fh:
        fh.write(b"c\n")
    t2 = Tailer([str(p)])
    t2.load_offsets(saved)
    assert read_all(t2)[0] == [b"c"]


def test_uncommitted_read_is_retried(tmp_path):
    p = tmp_path / "cowrie.json"
    p.write_bytes(b"a\nb\n")
    t = Tailer([str(p)])
    t.read(10)  # simulate DB failure: no commit
    assert read_all(t)[0] == [b"a", b"b"]


def test_rotation_by_rename(tmp_path):
    p = tmp_path / "cowrie.json"
    p.write_bytes(b"1\n2\n")
    t = Tailer([str(tmp_path / "cowrie.json*")])
    assert read_all(t)[0] == [b"1", b"2"]
    with open(p, "ab") as fh:
        fh.write(b"3\n")
    os.rename(p, tmp_path / "cowrie.json.2026-10-01")  # Cowrie daily rotation
    p.write_bytes(b"4\n")
    lines, _ = read_all(t)
    assert sorted(lines) == [b"3", b"4"]


def test_truncation_restarts_from_zero(tmp_path):
    p = tmp_path / "cowrie.json"
    p.write_bytes(b"x" * 100 + b"\n")
    t = Tailer([str(p)])
    read_all(t)
    p.write_bytes(b"new\n")
    assert read_all(t)[0] == [b"new"]


def test_oversized_lines_skipped(tmp_path):
    p = tmp_path / "cowrie.json"
    p.write_bytes(b"ok1\n" + b"Z" * 300000 + b"\nok2\n" + b"Y" * 2000 + b"\n")
    t = Tailer([str(p)], max_line_bytes=1000)
    lines, res = read_all(t)
    assert lines == [b"ok1", b"ok2"]
    assert res.oversized == 2
    assert t.lag_bytes() == 0


def test_symlinks_ignored(tmp_path):
    target = tmp_path / "secret.txt"
    target.write_bytes(b"secret\n")
    try:
        (tmp_path / "cowrie.json").symlink_to(target)
    except OSError as exc:
        if os.name == "nt" and getattr(exc, "winerror", None) == 1314:
            pytest.skip("Creating symlinks requires Windows Developer Mode or elevated privileges")
        raise
    t = Tailer([str(tmp_path / "cowrie.json*")])
    assert read_all(t)[0] == []


def test_rename_is_reported_for_saving(tmp_path):
    p = tmp_path / "cowrie.json"
    p.write_bytes(b"1\n")
    t = Tailer([str(tmp_path / "cowrie.json*")])
    read_all(t)
    os.rename(p, tmp_path / "cowrie.json.2026-10-01")
    res = t.read(10)
    pending = t.pending_offsets(res)
    assert any(s.path.endswith(".2026-10-01") for s in pending.values())
    t.commit(res)
    assert t.pending_offsets(t.read(10)) == {}
