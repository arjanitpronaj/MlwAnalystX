"""
MlwAnalystX — desktop malware triage client for Hybrid Analysis (Falcon Sandbox API v2).

Run from the project directory:
    python main.py
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ui.main_window import launch_app


def main() -> None:
    launch_app()


if __name__ == "__main__":
    main()
