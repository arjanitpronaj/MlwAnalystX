from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class LifecyclePhase(str, Enum):
    IDLE = "idle"
    SUBMITTED = "submitted"
    QUEUED = "queued"
    RUNNING = "running"
    REPORTING = "reporting"  # sandbox SUCCESS; downloading summary / full JSON
    FINISHED = "finished"
    FAILED = "failed"


@dataclass
class LifecycleSnapshot:
    phase: LifecyclePhase = LifecyclePhase.IDLE
    api_state: str | None = None
    elapsed_sec: float = 0.0
    progress_pct: float = 0.0
    eta_sec: float | None = None
    job_id: str | None = None
    submission_id: str | None = None
    error_message: str | None = None
    milestones: list[tuple[float, str]] = field(default_factory=list)

    def add_milestone(self, t: float, label: str) -> None:
        self.milestones.append((t, label))


def map_api_state_to_phase(api_state: str | None) -> LifecyclePhase:
    if not api_state:
        return LifecyclePhase.SUBMITTED
    s = api_state.upper()
    if s in ("IN_QUEUE", "QUEUED"):
        return LifecyclePhase.QUEUED
    if s in ("IN_PROGRESS", "RUNNING"):
        return LifecyclePhase.RUNNING
    if s in ("SUCCESS", "PARTIAL_SUCCESS"):
        return LifecyclePhase.REPORTING
    if s in ("ERROR", "FAILED"):
        return LifecyclePhase.FAILED
    return LifecyclePhase.RUNNING
