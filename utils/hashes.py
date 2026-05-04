from __future__ import annotations

import hashlib
from pathlib import Path


def file_hashes(path: Path, chunk_size: int = 1024 * 1024) -> tuple[str, str]:
    """Return (sha256_hex, md5_hex) for a file without loading it fully into memory."""
    sha = hashlib.sha256()
    md5 = hashlib.md5()
    with path.open("rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            sha.update(chunk)
            md5.update(chunk)
    return sha.hexdigest(), md5.hexdigest()
