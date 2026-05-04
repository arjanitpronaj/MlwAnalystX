from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    """Application defaults (Hybrid Analysis Falcon Sandbox API v2)."""

    api_base_url: str = "https://hybrid-analysis.com/api/v2"
    poll_interval_sec: float = 5.0
    poll_interval_in_progress_sec: float = 7.0
    poll_timeout_sec: float = 45 * 60
    connect_timeout_sec: float = 30.0
    read_timeout_sec: float = 600.0
    max_retries: int = 6
    retry_backoff_base_sec: float = 2.0
    max_upload_bytes: int = 100 * 1024 * 1024
    default_environment_id: int = 120
    post_success_settle_sec: float = 20.0
    max_embedded_screenshots: int = 8
    max_screenshot_bytes: int = 8 * 1024 * 1024
