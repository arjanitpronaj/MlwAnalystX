from __future__ import annotations

from enum import Enum
from typing import Any

from .behavior_extract import BehavioralProfile


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


def score_risk(
    summary: dict[str, Any],
    profile: BehavioralProfile,
    *,
    local_unknown: bool = False,
) -> tuple[RiskLevel, int, list[str]]:
    """
    Return (level, score 0-100, reasons).
    Combines Hybrid Analysis summary signals with local heuristics.
    """
    reasons: list[str] = []
    score = 0

    verdict = (summary.get("verdict") or "").lower()
    threat_level = summary.get("threat_level")
    threat_score = summary.get("threat_score") or 0
    av_detect = summary.get("av_detect") or 0
    total_proc = summary.get("total_processes") or len(profile.processes)
    vx_family = summary.get("vx_family") or ""

    suspicious_domains = profile.raw_highlights.get("suspicious_domain_hits") or []

    if suspicious_domains:
        score += 40
        reasons.append("Contact with suspicious TLD / high-risk domain patterns")

    if verdict in ("malicious", "suspicious"):
        score += 35
        reasons.append(f"Sandbox verdict: {verdict}")

    if isinstance(threat_level, int) and threat_level >= 2:
        score += min(20, threat_level * 6)
        reasons.append(f"Elevated sandbox threat level ({threat_level})")

    if isinstance(threat_score, int) and threat_score >= 50:
        score += min(25, threat_score // 4)
        reasons.append(f"High sandbox threat score ({threat_score})")

    if isinstance(av_detect, int) and av_detect >= 10:
        score += 20
        reasons.append(f"Elevated AV detection count ({av_detect})")

    if isinstance(total_proc, int) and total_proc >= 25:
        score += 15
        reasons.append("High process fan-out (many spawned processes)")

    if profile.persistence_indicators:
        score += min(20, 5 * len(profile.persistence_indicators[:5]))
        reasons.append("Possible persistence or autorun-related behavior observed")

    if vx_family and str(vx_family).lower() not in ("clean", "none", ""):
        score += 10
        reasons.append(f"Attributed malware family: {vx_family}")

    if local_unknown and verdict not in ("malicious", "suspicious"):
        score += 28
        reasons.append("Limited reputation context (unknown sample heuristics)")

    if verdict == "no specific threat" and score < 15 and not suspicious_domains:
        reasons.append("Sandbox summary indicates no specific threat")

    score = max(0, min(100, score))

    if score >= 65:
        return RiskLevel.HIGH, score, reasons
    if score >= 35:
        return RiskLevel.MEDIUM, score, reasons
    return RiskLevel.LOW, score, reasons
