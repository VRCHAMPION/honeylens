"""Follow growing log files safely, like ``tail -F`` but crash-proof.

Problems this solves (all tested in tests/test_tailer.py):

* **Persisted offsets** - we remember the byte position per file, so a restart
  continues where it stopped instead of re-reading or skipping.
* **Rotation** - Cowrie renames ``cowrie.json`` to ``cowrie.json.YYYY-MM-DD`` at
  midnight and opens a new file. We identify files by device+inode (which
  survives a rename), finish the old file, then start the new one at 0.
* **Truncation / inode reuse** - if a file becomes smaller than our offset, or
  its first bytes change, it is a new file: start again at 0.
* **Partial lines** - a line without a trailing newline is still being written;
  we leave it for the next poll.
* **Oversized lines** - a line longer than the limit is skipped in chunks
  without ever loading it fully into memory, and counted.
"""

from __future__ import annotations

import glob
import hashlib
import os
from dataclasses import dataclass, field

HEAD_BYTES = 64
READ_CHUNK = 65536


@dataclass
class FileState:
    """Where we are in one file."""

    key: str
    path: str
    offset: int = 0
    head_hash: str | None = None


@dataclass
class Line:
    """One complete line read from a file."""

    key: str
    path: str
    data: bytes
    end_offset: int


@dataclass
class ReadResult:
    """Lines read in one poll plus counters."""

    lines: list[Line] = field(default_factory=list)
    oversized: int = 0
    # Offsets that moved forward without producing lines (skipped oversized data).
    skipped_to: dict[str, int] = field(default_factory=dict)


def file_key(st: os.stat_result) -> str:
    """Stable identity of a file across renames: ``device:inode``."""
    return f"{st.st_dev}:{st.st_ino}"


def head_hash(path: str) -> str | None:
    """Hash of the first 64 bytes, or None if the file is still shorter than that."""
    try:
        with open(path, "rb") as fh:
            head = fh.read(HEAD_BYTES)
    except OSError:
        return None
    return hashlib.sha256(head).hexdigest() if len(head) == HEAD_BYTES else None


class Tailer:
    """Reads new complete lines from every file matching the glob patterns."""

    def __init__(self, patterns: list[str], max_line_bytes: int = 65536) -> None:
        self.patterns = [p for p in patterns if p]
        self.max_line_bytes = max_line_bytes
        self.states: dict[str, FileState] = {}
        self.renamed: set[str] = set()  # keys whose path changed (rotation) - saved with the next batch

    def load_offsets(self, rows: list[tuple[str, str, int, str | None]]) -> None:
        """Restore saved offsets: rows of (key, path, offset, head_hash)."""
        for key, path, offset, hh in rows:
            self.states[key] = FileState(key, path, int(offset), hh)

    def discover(self) -> list[FileState]:
        """Find current files, oldest first so rotated files finish before new ones."""
        found: dict[str, tuple[float, FileState]] = {}
        for pattern in self.patterns:
            for path in glob.glob(pattern):
                if not os.path.isfile(path) or os.path.islink(path):
                    continue  # never follow symlinks planted in the log folder
                try:
                    st = os.stat(path)
                except OSError:
                    continue
                key = file_key(st)
                state = self.states.get(key)
                hh = head_hash(path)
                if state is None:
                    state = FileState(key, path, 0, hh)
                    self.states[key] = state
                else:
                    if state.path != path:
                        self.renamed.add(key)  # renamed by rotation: same inode, new name
                    state.path = path
                    if st.st_size < state.offset:
                        state.offset, state.head_hash = 0, hh  # truncated
                    elif state.head_hash and hh and state.head_hash != hh:
                        state.offset, state.head_hash = 0, hh  # inode reused by a new file
                    elif state.head_hash is None and hh:
                        state.head_hash = hh
                found[key] = (st.st_mtime, state)
        return [s for _, s in sorted(found.values(), key=lambda x: (x[0], x[1].path))]

    def lag_bytes(self) -> int:
        """Bytes written to tracked files that we have not read yet."""
        total = 0
        for state in self.states.values():
            try:
                total += max(0, os.path.getsize(state.path) - state.offset)
            except OSError:
                continue
        return total

    def read(self, max_lines: int) -> ReadResult:
        """Read up to ``max_lines`` complete lines across all files.

        Offsets in ``self.states`` are NOT advanced here: the caller calls
        :meth:`commit` only after the database transaction succeeded.
        """
        result = ReadResult()
        for state in self.discover():
            if len(result.lines) >= max_lines:
                break
            self._read_file(state, max_lines - len(result.lines), result)
        return result

    def _read_file(self, state: FileState, budget: int, result: ReadResult) -> None:
        try:
            fh = open(state.path, "rb")  # noqa: SIM115 - closed in finally
        except OSError:
            return
        try:
            fh.seek(state.offset)
            pos = state.offset
            buf = b""
            skipping = False
            while budget > 0:
                chunk = fh.read(READ_CHUNK)
                if not chunk:
                    break
                buf += chunk
                while budget > 0:
                    nl = buf.find(b"\n")
                    if nl < 0:
                        if len(buf) > self.max_line_bytes:
                            # Discard the giant partial line; keep skipping until newline.
                            pos += len(buf)
                            buf = b""
                            if not skipping:
                                result.oversized += 1
                                skipping = True
                            result.skipped_to[state.key] = pos
                        break
                    line, buf = buf[:nl], buf[nl + 1 :]
                    pos += nl + 1
                    if skipping:
                        skipping = False  # end of the oversized line
                        result.skipped_to[state.key] = pos
                        continue
                    if len(line) > self.max_line_bytes:
                        result.oversized += 1
                        result.skipped_to[state.key] = pos
                        continue
                    result.lines.append(Line(state.key, state.path, line, pos))
                    budget -= 1
        finally:
            fh.close()

    def commit(self, result: ReadResult) -> dict[str, FileState]:
        """Advance offsets after a successful DB commit. Returns changed states."""
        changed: dict[str, FileState] = {}
        self.renamed.clear()
        for key, off in result.skipped_to.items():
            st = self.states.get(key)
            if st and off > st.offset:
                st.offset = off
                changed[key] = st
        for line in result.lines:
            st = self.states.get(line.key)
            if st and line.end_offset > st.offset:
                st.offset = line.end_offset
                changed[line.key] = st
        return changed

    def pending_offsets(self, result: ReadResult) -> dict[str, FileState]:
        """Offsets as they WILL be after commit (written in the same DB transaction)."""
        out: dict[str, FileState] = {}
        for key in self.renamed:
            st = self.states.get(key)
            if st:
                out[key] = FileState(key, st.path, st.offset, st.head_hash)
        for key, off in result.skipped_to.items():
            st = self.states.get(key)
            if st:
                out[key] = FileState(key, st.path, max(off, st.offset), st.head_hash)
        for line in result.lines:
            st = self.states.get(line.key)
            if st:
                cur = out.get(line.key)
                best = max(line.end_offset, cur.offset if cur else st.offset)
                out[line.key] = FileState(line.key, st.path, best, st.head_hash)
        return out
