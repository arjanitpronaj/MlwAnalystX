from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class SubmissionResult:
    job_id: str | None
    submission_id: str | None
    environment_id: int | None
    sha256: str | None
    raw: dict[str, Any]


@dataclass
class SampleStateResult:
    state: str | None
    error: str | None
    error_type: str | None
    raw: dict[str, Any]
