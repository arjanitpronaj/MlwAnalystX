"""
Hybrid Analysis / Falcon Sandbox screenshot extraction.

These are the **same VM desktop captures** shown on https://www.hybrid-analysis.com/ when you
open a report (Falcon Sandbox guest desktop during execution), not user-uploaded files.

The public API typically returns them as JSON objects with base64 in ``image`` and sometimes
``thumbnail`` (OpenAPI ``SampleScreenshot``: name, image, date).
"""

from __future__ import annotations

import base64
import binascii
import json
from io import BytesIO
from typing import Any, Callable
from urllib.parse import urlparse

LogFn = Callable[[str], None]

try:
    from PIL import Image as PILImage

    _HAS_PIL = True
except ImportError:
    _HAS_PIL = False


def merge_screenshot_json_payloads(a: Any, b: Any) -> Any:
    """Merge list items from both SHA and job screenshot JSON responses."""
    lists: list[list[Any]] = []

    def collect(x: Any) -> None:
        if isinstance(x, list):
            lists.append(x)
        elif isinstance(x, dict):
            inner = x.get("screenshots") or x.get("items") or x.get("data") or x.get("results")
            if isinstance(inner, list):
                lists.append(inner)
            if isinstance(x.get("images"), list):
                lists.append(x["images"])

    collect(a)
    collect(b)
    if not lists:
        return b if _json_nonempty(b) else a
    seen: set[str] = set()
    out: list[Any] = []
    for lst in lists:
        for it in lst:
            key = _item_fingerprint(it)
            if key in seen:
                continue
            seen.add(key)
            out.append(it)
    return out


def _item_fingerprint(it: Any) -> str:
    if isinstance(it, dict):
        try:
            return json.dumps(it, sort_keys=True, default=str)[:400]
        except (TypeError, ValueError):
            return str(id(it))
    return str(it)[:400]


def _json_nonempty(x: Any) -> bool:
    if x is None:
        return False
    if isinstance(x, list):
        return len(x) > 0
    if isinstance(x, dict):
        return len(x) > 0
    return True


def _is_raster_image(blob: bytes) -> bool:
    if len(blob) < 24:
        return False
    if blob.startswith(b"\x89PNG\r\n\x1a\n"):
        return True
    if blob.startswith(b"\xff\xd8\xff"):
        return True
    if blob.startswith(b"GIF87a") or blob.startswith(b"GIF89a"):
        return True
    if blob.startswith(b"RIFF") and len(blob) > 12 and blob[8:12] == b"WEBP":
        return True
    if blob.startswith(b"BM"):
        return True
    if len(blob) >= 6 and blob[:4] == b"\x00\x00\x01\x00":
        return True  # ICO
    if len(blob) >= 4 and blob[:2] in (b"II", b"MM"):
        return True  # TIFF
    return False


def _pil_recognizes_image(blob: bytes) -> bool:
    if not _HAS_PIL or len(blob) < 8:
        return False
    try:
        with PILImage.open(BytesIO(blob)) as im:
            im.load()
        return True
    except Exception:
        return False


def _is_sandbox_screenshot_bytes(blob: bytes) -> bool:
    """True if bytes are a decodable raster (desktop capture) for PDF embedding."""
    if not blob or len(blob) < 8:
        return False
    if _is_raster_image(blob):
        return True
    return _pil_recognizes_image(blob)


def _b64_decode_to_image(raw: str, max_bytes: int) -> bytes:
    s = raw.strip()
    if s.startswith("data:") and "," in s:
        s = s.split(",", 1)[-1].strip()
    if len(s) < 40:
        return b""
    if s.startswith("http://") or s.startswith("https://"):
        return b""
    pad = (-len(s)) % 4
    if pad:
        s += "=" * pad
    try:
        out = base64.b64decode(s, validate=False)
    except (binascii.Error, ValueError):
        return b""
    if not out or len(out) > max_bytes:
        return b""
    if _is_sandbox_screenshot_bytes(out):
        return out
    return b""


def _iter_screenshot_dicts(raw: Any, depth: int = 0) -> Any:
    if depth > 16 or raw is None:
        return
    if isinstance(raw, list):
        for x in raw:
            yield from _iter_screenshot_dicts(x, depth + 1)
    elif isinstance(raw, dict):
        ks = set(raw.keys())
        shot_keys = {
            "image",
            "Image",
            "image_base64",
            "thumbnail",
            "Thumbnail",
            "thumb",
            "screen",
            "snapshot",
            "preview",
            "picture",
        }
        if ks & shot_keys:
            yield raw
        elif ("name" in ks or "id" in ks) and ("date" in ks or "time" in ks or "timestamp" in ks) and len(ks) <= 28:
            yield raw
        for v in raw.values():
            yield from _iter_screenshot_dicts(v, depth + 1)


def _harvest_b64_strings(obj: Any, max_bytes: int, found_blobs: list[bytes], depth: int = 0) -> None:
    if depth > 16 or len(found_blobs) >= 48:
        return
    if isinstance(obj, str) and len(obj) > 400:
        b = _b64_decode_to_image(obj, max_bytes)
        if b:
            found_blobs.append(b)
    elif isinstance(obj, dict):
        for v in obj.values():
            _harvest_b64_strings(v, max_bytes, found_blobs, depth + 1)
    elif isinstance(obj, list):
        for x in obj[:200]:
            _harvest_b64_strings(x, max_bytes, found_blobs, depth + 1)


def _binary_paths_for_item(
    item: dict[str, Any],
    *,
    job_id: str,
    report_sha256: str,
    idx: int,
    environment_id: Any,
) -> list[str]:
    refs: list[str] = []
    ref = item.get("screenshot") or item.get("path") or item.get("url") or item.get("reference")
    if isinstance(ref, str) and ref.strip():
        parsed = urlparse(ref)
        if parsed.scheme and parsed.netloc:
            refs.append(ref.strip())
        candidate_path = parsed.path if parsed.scheme and parsed.netloc else ref.strip()
        if candidate_path.startswith("/"):
            refs.append(candidate_path)
        else:
            refs.append(f"/report/{job_id}/screenshots/{candidate_path.lstrip('/')}")
    token = item.get("id") or item.get("name") or item.get("slot") or item.get("index")
    if token is not None:
        tok = str(token).strip()
        if tok and not tok.startswith("http"):
            refs.append(f"/report/{job_id}/screenshots/{tok}")
            refs.append(f"/report/{job_id}/screenshot/{tok}")
            refs.append(f"/report/{job_id}/screenshots/{tok}/raw")
    refs.append(f"/report/{report_sha256}/screenshots/{idx}")
    refs.append(f"/report/{report_sha256}/screenshots/{idx - 1}")
    refs.append(f"/report/{report_sha256}/screenshot/{idx}")
    refs.append(f"/report/{job_id}/screenshots/{idx}")
    refs.append(f"/report/{job_id}/screenshot/{idx}")
    refs.append(f"/report/{job_id}/screenshots/{idx}/raw")
    if environment_id is not None and report_sha256:
        comp = f"{report_sha256}:{environment_id}"
        refs.append(f"/report/{comp}/screenshots/{idx}")
        refs.append(f"/report/{comp}/screenshot/{idx}")
        refs.append(f"/report/{comp}/screenshots/{idx}/raw")
    return refs


def extract_screenshot_images(
    screenshots_raw: Any,
    *,
    get_binary: Callable[[str, int], bytes | None],
    job_id: str,
    report_sha256: str,
    environment_id: Any,
    max_bytes: int,
    max_images: int,
    log: LogFn,
) -> list[dict[str, Any]]:
    """
    Returns list of {name, timestamp, bytes} for PDF embedding.
    """
    out: list[dict[str, Any]] = []
    seen_sig: set[str] = set()

    def add_blob(blob: bytes, name: str, ts: str) -> None:
        if len(out) >= max_images:
            return
        sig = str(len(blob)) + ":" + blob[:32].hex()
        if sig in seen_sig:
            return
        seen_sig.add(sig)
        out.append({"name": name, "timestamp": ts, "bytes": blob})

    items: list[dict[str, Any]] = []
    for d in _iter_screenshot_dicts(screenshots_raw):
        if isinstance(d, dict):
            items.append(d)

    for idx, item in enumerate(items, start=1):
        if not isinstance(item, dict):
            continue
        ts = str(item.get("date") or item.get("time") or item.get("timestamp") or item.get("created_at") or "")
        name = str(item.get("name") or item.get("id") or item.get("slot") or f"screenshot_{idx}")
        blob = b""
        for key in (
            "image",
            "Image",
            "thumbnail",
            "Thumbnail",
            "thumb",
            "image_base64",
            "picture",
            "screen",
            "snapshot",
            "preview",
            "screenshot_data",
            "data",
            "content",
        ):
            v = item.get(key)
            if isinstance(v, str) and len(v) > 40:
                blob = _b64_decode_to_image(v, max_bytes)
                if blob:
                    break
        if not blob:
            ss = item.get("screenshot")
            if isinstance(ss, str) and len(ss) > 200 and not ss.strip().lower().startswith("http"):
                blob = _b64_decode_to_image(ss, max_bytes)
        if blob:
            add_blob(blob, name, ts)
            continue
        ref = item.get("screenshot") or item.get("path") or item.get("url") or item.get("reference")
        if isinstance(ref, str) and ref.strip().startswith(("http://", "https://", "/")):
            b = get_binary(ref.strip(), max_bytes)
            if b and _is_sandbox_screenshot_bytes(b):
                add_blob(b, name, ts)
                continue
        seen_paths: set[str] = set()
        for path in _binary_paths_for_item(item, job_id=job_id, report_sha256=report_sha256, idx=idx, environment_id=environment_id):
            if path in seen_paths:
                continue
            seen_paths.add(path)
            b = get_binary(path, max_bytes)
            if b and _is_sandbox_screenshot_bytes(b):
                add_blob(b, name, ts)
                break

    orphan: list[bytes] = []
    _harvest_b64_strings(screenshots_raw, max_bytes, orphan)
    for i, blob in enumerate(orphan, start=1):
        add_blob(blob, f"embedded_image_{i}", "")

    if len(out) >= max_images:
        log(f"Extracted {len(out)} Falcon Sandbox VM desktop screenshot(s) (API JSON / refs).")
        return out

    bases: list[str] = [f"/report/{job_id}"]
    if report_sha256 and environment_id is not None:
        bases.append(f"/report/{report_sha256}:{environment_id}")
    if report_sha256:
        bases.append(f"/report/{report_sha256}")

    # Only hit numeric/binary routes when JSON had no decodable desktop frames (avoids hundreds of GETs).
    if len(out) == 0:
        stop_probe = False
        for base in bases:
            for i in range(0, 32):
                for suffix in (
                    f"/screenshots/{i}",
                    f"/screenshot/{i}",
                    f"/screenshots/{i}/raw",
                    f"/screenshots/{i}/file",
                    f"/screenshots/desktop/{i}",
                    f"/desktop-screenshots/{i}",
                ):
                    if len(out) >= max_images:
                        stop_probe = True
                        break
                    path = f"{base}{suffix}"
                    b = get_binary(path, max_bytes)
                    if b and _is_sandbox_screenshot_bytes(b):
                        add_blob(b, f"sandbox_desktop_{i}", "")
                if stop_probe:
                    break
            if stop_probe:
                break

    if out:
        log(f"Extracted {len(out)} Falcon Sandbox VM desktop screenshot(s) for PDF.")
    else:
        log("No VM desktop screenshots decoded: check GET /report/{{job}}/screenshots (JSON with image/thumbnail) and API key privileges.")
    return out
