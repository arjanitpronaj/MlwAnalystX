from __future__ import annotations

import gzip
import json
import time
from collections.abc import Callable
from urllib.parse import urlparse
from typing import Any

import requests

from pathlib import Path

from config.defaults import Settings

from .models import SampleStateResult, SubmissionResult

LogFn = Callable[[str], None]


class HybridAnalysisError(Exception):
    pass


class HybridAnalysisClient:
    """
    Minimal Falcon Sandbox (Hybrid Analysis) API v2 client with retries,
    timeouts, and structured logging hooks for SOC-style observability.
    """

    def __init__(
        self,
        api_key: str,
        settings: Settings | None = None,
        log: LogFn | None = None,
    ) -> None:
        self._api_key = api_key.strip()
        self._settings = settings or Settings()
        self._log = log or (lambda _m: None)
        self._session = requests.Session()
        self._session.headers.update(
            {
                "api-key": self._api_key,
                "User-Agent": "Falcon Sandbox",
                "Accept": "application/json",
            }
        )

    def close(self) -> None:
        self._session.close()

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        data: dict[str, Any] | None = None,
        files: dict[str, Any] | None = None,
        stream: bool = False,
    ) -> requests.Response:
        if path.startswith("http://") or path.startswith("https://"):
            url = path
        else:
            url = f"{self._settings.api_base_url.rstrip('/')}{path}"
        timeout = (self._settings.connect_timeout_sec, self._settings.read_timeout_sec)
        attempt = 0
        last_exc: Exception | None = None
        while attempt < self._settings.max_retries:
            attempt += 1
            t0 = time.perf_counter()
            self._log(f"→ {method} {path} (attempt {attempt}/{self._settings.max_retries})")
            try:
                if files:
                    self._rewind_files(files)
                resp = self._session.request(
                    method,
                    url,
                    params=params,
                    data=data,
                    files=files,
                    timeout=timeout,
                    stream=stream,
                )
            except requests.RequestException as exc:
                last_exc = exc
                self._log(f"✗ transport error on {path}: {exc!s}")
                self._sleep_backoff(attempt)
                continue

            elapsed_ms = int((time.perf_counter() - t0) * 1000)
            limits = resp.headers.get("Api-Limits")
            if limits:
                self._log(f"← {resp.status_code} {path} ({elapsed_ms} ms) [Api-Limits: {limits}]")
            else:
                self._log(f"← {resp.status_code} {path} ({elapsed_ms} ms)")

            if resp.status_code == 429:
                ra = resp.headers.get("Retry-After")
                self._log("⚠ rate limited (429); backing off" + (f", Retry-After={ra}" if ra else ""))
                self._sleep_backoff(attempt, retry_after=ra)
                continue
            if resp.status_code in (500, 502, 503, 504):
                self._log(f"⚠ server/transient {resp.status_code}; retrying")
                self._sleep_backoff(attempt)
                continue

            if last_exc:
                last_exc = None
            return resp

        if last_exc:
            raise HybridAnalysisError(f"Request failed after retries: {path}") from last_exc
        raise HybridAnalysisError(f"Request failed after retries: {path}")

    def _sleep_backoff(self, attempt: int, retry_after: str | None = None) -> None:
        if retry_after:
            try:
                time.sleep(min(float(retry_after), 120.0))
                return
            except ValueError:
                pass
        delay = self._settings.retry_backoff_base_sec * (2 ** (attempt - 1))
        time.sleep(min(delay, 60.0))

    def submit_file(self, file_path: str, environment_id: int) -> SubmissionResult:
        path = "/submit/file"
        fname = Path(file_path).name
        data = {"environment_id": str(environment_id)}
        self._log(f"submit payload fields: {sorted(data.keys())}")
        with open(file_path, "rb") as fh:
            files = {"file": (fname, fh, "application/octet-stream")}
            fh.seek(0)
            resp = self._request("POST", path, data=data, files=files)
            if resp.status_code in (200, 201):
                payload = resp.json()
                return SubmissionResult(
                    job_id=payload.get("job_id"),
                    submission_id=payload.get("submission_id"),
                    environment_id=payload.get("environment_id"),
                    sha256=payload.get("sha256"),
                    raw=payload,
                )
        body = self._safe_body(resp)
        raise HybridAnalysisError(f"Submit failed ({resp.status_code}): {body}")

    def get_report_state(self, job_id: str) -> SampleStateResult:
        path = f"/report/{job_id}/state"
        resp = self._request("GET", path)
        if resp.status_code != 200:
            body = self._safe_body(resp)
            raise HybridAnalysisError(f"State failed ({resp.status_code}): {body}")
        payload = resp.json()
        return SampleStateResult(
            state=payload.get("state"),
            error=payload.get("error"),
            error_type=payload.get("error_type"),
            raw=payload,
        )

    def get_report_summary(self, job_id: str) -> dict[str, Any]:
        path = f"/report/{job_id}/summary"
        resp = self._request("GET", path)
        if resp.status_code == 410:
            return resp.json()
        if resp.status_code != 200:
            body = self._safe_body(resp)
            raise HybridAnalysisError(f"Summary failed ({resp.status_code}): {body}")
        return resp.json()

    def get_report_summary_by_sha256(self, sha256: str) -> dict[str, Any]:
        path = f"/report/{sha256}/summary"
        resp = self._request("GET", path)
        if resp.status_code == 410:
            return resp.json()
        if resp.status_code != 200:
            body = self._safe_body(resp)
            raise HybridAnalysisError(f"Summary-by-sha failed ({resp.status_code}): {body}")
        return resp.json()

    def get_report_processes(self, sha256: str) -> Any | None:
        return self.get_json_optional(f"/report/{sha256}/processes")

    def get_report_dropped_files(self, sha256: str) -> Any | None:
        return self.get_json_optional(f"/report/{sha256}/dropped-files")

    def get_report_screenshots(self, sha256: str) -> Any | None:
        return self.get_json_optional(f"/report/{sha256}/screenshots")

    def get_report_memory_dumps(self, sha256: str) -> Any | None:
        return self.get_json_optional(f"/report/{sha256}/memory-dumps")

    def get_report_strings(self, sha256: str) -> Any | None:
        return self.get_json_optional(f"/report/{sha256}/strings")

    def get_report_pcap(self, sha256: str, *, max_bytes: int = 200 * 1024 * 1024) -> bytes | None:
        return self.get_binary_optional(f"/report/{sha256}/pcap", max_bytes=max_bytes)

    def get_report_json(self, job_id: str) -> dict[str, Any] | list[Any]:
        path = f"/report/{job_id}/report/json"
        resp = self._request("GET", path)
        if resp.status_code != 200:
            body = self._safe_body(resp)
            raise HybridAnalysisError(f"Report JSON failed ({resp.status_code}): {body}")
        raw = resp.content
        if raw[:2] == b"\x1f\x8b":
            raw = gzip.decompress(raw)
        text = raw.decode("utf-8", errors="replace")
        return json.loads(text)

    def get_queue_size(self) -> dict[str, Any] | None:
        path = "/system/queue-size"
        resp = self._request("GET", path)
        if resp.status_code != 200:
            return None
        try:
            return resp.json()
        except json.JSONDecodeError:
            return None

    def get_json_optional(self, path: str) -> Any | None:
        """GET JSON; returns None on non-200 (used for supplemental report slices)."""
        resp = self._request("GET", path)
        if resp.status_code != 200:
            return None
        try:
            return resp.json()
        except json.JSONDecodeError:
            return None

    def get_binary_optional(self, path_or_url: str, *, max_bytes: int = 2 * 1024 * 1024) -> bytes | None:
        """
        GET binary payload and return bytes.
        Returns None when unavailable, non-200, or larger than max_bytes.
        """
        parsed = urlparse(path_or_url)
        path = parsed.path if parsed.scheme and parsed.netloc else path_or_url
        resp = self._request("GET", path)
        if resp.status_code != 200:
            return None
        blob = resp.content
        if not blob or len(blob) > max_bytes:
            return None
        return blob

    @staticmethod
    def _safe_body(resp: requests.Response, limit: int = 4000) -> str:
        try:
            t = resp.text
        except Exception:
            return "<unreadable body>"
        if len(t) > limit:
            return t[:limit] + "…"
        return t

    @staticmethod
    def _rewind_files(files: dict[str, Any]) -> None:
        for value in files.values():
            if not isinstance(value, tuple) or len(value) < 2:
                continue
            handle = value[1]
            if hasattr(handle, "seek"):
                try:
                    handle.seek(0)
                except OSError:
                    pass

