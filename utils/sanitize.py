from __future__ import annotations

import re
from pathlib import Path


def safe_resolved_file_path(raw: str) -> Path:
    """
    Resolve and normalize a user-supplied path. Does not guarantee the file exists.
    Rejects obvious path injection (e.g. null bytes).
    """
    if "\x00" in raw:
        raise ValueError("Invalid path")
    p = Path(raw).expanduser().resolve(strict=False)
    return p


def safe_log_fragment(text: str, max_len: int = 2000) -> str:
    """Truncate untrusted text for UI / logs."""
    t = text.replace("\r", " ").replace("\n", " ")
    t = re.sub(r"\s+", " ", t).strip()
    if len(t) > max_len:
        return t[: max_len - 3] + "..."
    return t
