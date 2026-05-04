from __future__ import annotations

import math
import time
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any
import ipaddress

from api.hybrid_client import HybridAnalysisClient, HybridAnalysisError
from config.defaults import Settings
from core.lifecycle import LifecyclePhase, LifecycleSnapshot, map_api_state_to_phase
from utils.hashes import file_hashes

from .behavior_extract import BehavioralProfile, extract_from_ha_report
from .ha_screenshots import extract_screenshot_images, merge_screenshot_json_payloads
from .risk_engine import RiskLevel, score_risk

LogFn = Callable[[str], None]
ProgressFn = Callable[[LifecycleSnapshot], None]


@dataclass
class AnalysisOutcome:
    job_id: str | None
    submission_id: str | None
    summary: dict[str, Any]
    full_report: dict[str, Any] | list[Any]
    profile: BehavioralProfile
    risk: RiskLevel
    risk_score: int
    risk_reasons: list[str]
    behavior_summary: str
    key_findings: list[str]
    queue_wait_sec: float | None
    execution_phase_sec: float | None
    milestones: list[tuple[float, str]] = field(default_factory=list)
    terminal_api_state: str | None = None
    error: str | None = None
    auto_pdf_path: Path | None = None
    supplemental: dict[str, Any] = field(default_factory=dict)


class AnalysisService:
    def __init__(self, settings: Settings | None = None) -> None:
        self._settings = settings or Settings()

    def run(
        self,
        api_key: str,
        file_path: Path,
        environment_id: int,
        log: LogFn,
        progress: ProgressFn,
        *,
        sha256: str | None = None,
        md5: str | None = None,
    ) -> AnalysisOutcome:
        client = HybridAnalysisClient(api_key, self._settings, log=log)
        t_submit = time.perf_counter()
        milestones: list[tuple[float, str]] = []
        snap = LifecycleSnapshot(phase=LifecyclePhase.SUBMITTED, progress_pct=5.0)
        milestones.append((0.0, "Client initialized; preparing submission"))

        try:
            sub = client.submit_file(str(file_path), environment_id)
        except HybridAnalysisError as exc:
            snap.phase = LifecyclePhase.FAILED
            snap.error_message = str(exc)
            progress(snap)
            client.close()
            raise

        job_id = sub.job_id
        sub_id = sub.submission_id
        milestones.append((time.perf_counter() - t_submit, "Submission accepted by Hybrid Analysis"))
        snap.job_id = job_id
        snap.submission_id = sub_id
        snap.phase = LifecyclePhase.SUBMITTED
        progress(snap)

        if not job_id:
            err = "Missing job_id in submission response"
            snap.phase = LifecyclePhase.FAILED
            snap.error_message = err
            progress(snap)
            client.close()
            raise HybridAnalysisError(err)

        last_state: str | None = None
        queue_started: float | None = None
        run_started: float | None = None
        poll_n = 0
        queue_extra = 0.0

        error_retried = False
        while True:
            poll_n += 1
            elapsed = time.perf_counter() - t_submit
            snap.elapsed_sec = elapsed

            try:
                st = client.get_report_state(job_id)
            except HybridAnalysisError as exc:
                log(f"⚠ state poll error: {exc}; retrying after interval")
                time.sleep(self._settings.poll_interval_sec)
                continue

            api_state = (st.state or "").upper()
            if api_state != last_state:
                milestones.append((elapsed, f"API state → {api_state}"))
                last_state = api_state

            if api_state == "IN_QUEUE" and queue_started is None:
                queue_started = time.perf_counter()
            if api_state == "IN_PROGRESS" and run_started is None:
                run_started = time.perf_counter()

            phase = map_api_state_to_phase(st.state)
            snap.phase = phase
            snap.api_state = st.state

            if phase == LifecyclePhase.QUEUED and poll_n % 10 == 1:
                q = client.get_queue_size()
                queue_extra = 0.0
                if isinstance(q, dict):
                    try:
                        n = int(q.get("size") or q.get("queue") or 0)
                        queue_extra = min(12.0, n * 0.35)
                    except (TypeError, ValueError):
                        pass

            elapsed_queue = (time.perf_counter() - queue_started) if queue_started else 0.0
            elapsed_run = (time.perf_counter() - run_started) if run_started else 0.0

            snap.progress_pct = self._estimate_progress(phase, elapsed_queue, elapsed_run, queue_extra)
            snap.eta_sec = None

            if st.error:
                snap.error_message = str(st.error)

            progress(snap)

            if api_state in ("SUCCESS", "PARTIAL_SUCCESS"):
                break
            if api_state == "ERROR":
                if not error_retried:
                    error_retried = True
                    log("Sandbox state is ERROR; waiting 60s and retrying state once.")
                    time.sleep(60.0)
                    continue
                break

            time.sleep(30.0)

        final_state = last_state or ""
        queue_wait = (run_started - queue_started) if queue_started and run_started else None
        exec_time = (time.perf_counter() - run_started) if run_started else None

        snap.phase = (
            LifecyclePhase.REPORTING
            if final_state in ("SUCCESS", "PARTIAL_SUCCESS")
            else LifecyclePhase.FAILED
        )
        snap.progress_pct = 93.0
        snap.eta_sec = None
        progress(snap)
        if final_state in ("SUCCESS", "PARTIAL_SUCCESS") and self._settings.post_success_settle_sec > 0:
            settle = self._settings.post_success_settle_sec
            log(f"Waiting {settle:.0f}s for deep report artifacts to settle before retrieval.")
            time.sleep(settle)

        summary: dict[str, Any] = {}
        full_report: dict[str, Any] | list[Any] = {}
        err_note: str | None = None
        try:
            summary = client.get_report_summary(job_id)
        except HybridAnalysisError as exc:
            err_note = f"Summary retrieval failed: {exc}"
            log(f"⚠ {err_note}")
        snap.progress_pct = 96.0
        snap.eta_sec = None
        progress(snap)

        try:
            full_report = client.get_report_json(job_id)
        except HybridAnalysisError as exc:
            msg = f"Full JSON report retrieval failed: {exc}"
            log(f"⚠ {msg}")
            if err_note:
                err_note += "; " + msg
            else:
                err_note = msg
        snap.progress_pct = 98.5
        snap.eta_sec = None
        progress(snap)

        supplemental: dict[str, Any] = {}
        report_sha256 = str(summary.get("sha256") or sub.sha256 or "").strip().lower()
        job_summary = dict(summary)
        if report_sha256:
            try:
                summary_by_sha = client.get_report_summary_by_sha256(report_sha256)
                supplemental["summary_by_sha"] = summary_by_sha
                if isinstance(summary_by_sha, dict):
                    merged = dict(summary_by_sha)
                    merged.update(job_summary)
                    summary = merged
            except HybridAnalysisError as exc:
                log(f"⚠ SHA summary unavailable, using job summary: {exc}")
                supplemental["summary_by_sha"] = summary

            def _json_meaningful(x: Any) -> bool:
                if x is None:
                    return False
                if isinstance(x, (list, dict)):
                    return len(x) > 0
                return True

            def safe_json(label: str, sha_path_call: Callable[[], Any | None], job_path: str) -> Any | None:
                data: Any = None
                try:
                    data = sha_path_call()
                except HybridAnalysisError as exc:
                    log(f"⚠ {label} via SHA unavailable: {exc}; trying job endpoint fallback.")
                if _json_meaningful(data):
                    return data
                return client.get_json_optional(job_path)

            def safe_bin(label: str, sha_bin_call: Callable[[], bytes | None], job_path: str) -> bytes | None:
                try:
                    data = sha_bin_call()
                    if data is not None:
                        return data
                except HybridAnalysisError as exc:
                    log(f"⚠ {label} via SHA unavailable: {exc}; trying job endpoint fallback.")
                return client.get_binary_optional(job_path, max_bytes=200 * 1024 * 1024)

            supplemental["processes"] = safe_json("processes", lambda: client.get_report_processes(report_sha256), f"/report/{job_id}/processes")
            supplemental["dropped_files"] = safe_json("dropped-files", lambda: client.get_report_dropped_files(report_sha256), f"/report/{job_id}/dropped-files")
            supplemental["dropped_files_v2"] = safe_json(
                "dropped-files-v2",
                lambda: client.get_json_optional(f"/report/{report_sha256}/dropped-files-v2"),
                f"/report/{job_id}/dropped-files-v2",
            )
            sha_sh: Any = None
            try:
                sha_sh = client.get_report_screenshots(report_sha256)
            except HybridAnalysisError as exc:
                log(f"⚠ screenshots via SHA: {exc}")
            job_sh = client.get_json_optional(f"/report/{job_id}/screenshots")
            supplemental["screenshots"] = merge_screenshot_json_payloads(sha_sh, job_sh)
            supplemental["memory_dumps"] = safe_json("memory-dumps", lambda: client.get_report_memory_dumps(report_sha256), f"/report/{job_id}/memory-dumps")
            supplemental["strings"] = safe_json("strings", lambda: client.get_report_strings(report_sha256), f"/report/{job_id}/strings")
            supplemental["pcap"] = safe_bin("pcap", lambda: client.get_report_pcap(report_sha256), f"/report/{job_id}/pcap")

            screenshot_images = extract_screenshot_images(
                supplemental.get("screenshots"),
                get_binary=lambda path, mb: client.get_binary_optional(path, max_bytes=mb),
                job_id=job_id,
                report_sha256=report_sha256,
                environment_id=summary.get("environment_id"),
                max_bytes=self._settings.max_screenshot_bytes,
                max_images=max(self._settings.max_embedded_screenshots, 36),
                log=log,
            )
            if screenshot_images:
                supplemental["screenshot_images"] = screenshot_images
            supplemental["pcap_summary"] = self._summarize_pcap_and_network(supplemental.get("pcap"), summary)

        profile = extract_from_ha_report(full_report, summary)
        verdict = (summary.get("verdict") or "").lower()
        unknown = verdict not in ("malicious", "suspicious", "no specific threat")
        risk, rscore, rreasons = score_risk(summary, profile, local_unknown=unknown)

        behavior_summary = self._build_behavior_summary(summary, profile)
        findings = self._key_findings(summary, profile, risk)

        outcome = AnalysisOutcome(
            job_id=job_id,
            submission_id=sub_id,
            summary=summary,
            full_report=full_report,
            profile=profile,
            risk=risk,
            risk_score=rscore,
            risk_reasons=rreasons,
            behavior_summary=behavior_summary,
            key_findings=findings,
            queue_wait_sec=queue_wait,
            execution_phase_sec=exec_time,
            milestones=milestones,
            terminal_api_state=final_state,
            error=err_note,
            auto_pdf_path=None,
            supplemental=supplemental,
        )
        try:
            from reporting.pdf_report import build_ioc_summary

            ioc = build_ioc_summary(summary, supplemental.get("processes") if isinstance(supplemental.get("processes"), list) else [], supplemental.get("dropped_files") if isinstance(supplemental.get("dropped_files"), list) else [])
            supplemental["ioc_summary"] = ioc
            supplemental["ioc_summary_text"] = "\n".join(
                [
                    "---- IOC SUMMARY ----",
                    f"HASHES:    {', '.join(ioc.get('hashes', [])) or 'none'}",
                    f"IPS:       {', '.join(ioc.get('ips', [])) or 'none'}",
                    f"DOMAINS:   {', '.join(ioc.get('domains', [])) or 'none'}",
                    f"URLS:      {', '.join(ioc.get('urls', [])) or 'none'}",
                    f"REGKEYS:   {', '.join(ioc.get('regkeys', [])) or 'none'}",
                    f"FILEPATHS: {', '.join(ioc.get('filepaths', [])) or 'none'}",
                    f"MUTEXES:   {', '.join(ioc.get('mutexes', [])) or 'none'}",
                    "---------------------",
                ]
            )
            mitre = summary.get("mitre_attcks") or summary.get("mitre_attacks") or []
            mitre_count = len(mitre) if isinstance(mitre, list) else 0
            screenshots_count = len(supplemental.get("screenshot_images") or [])
            supplemental["verdict_line"] = (
                f"VERDICT: {summary.get('verdict') or 'UNKNOWN'} | FAMILY: {summary.get('vx_family') or 'UNKNOWN'} | "
                f"SCORE: {summary.get('threat_score') or 0}/100 | SCREENSHOTS: {screenshots_count} embedded | "
                f"MITRE TECHNIQUES: {mitre_count} mapped"
            )
        except Exception:
            pass

        auto_pdf_path: Path | None = None
        if final_state in ("SUCCESS", "PARTIAL_SUCCESS"):
            snap.progress_pct = 99.2
            snap.eta_sec = None
            progress(snap)
            s256 = sha256 or file_hashes(file_path)[0]
            md5v = md5 or file_hashes(file_path)[1]
            dest_dir = Path.home() / "Downloads" / "MlwAnalystX"
            dest_dir.mkdir(parents=True, exist_ok=True)
            stem = str(job_id or s256[:16]).replace(":", "_").replace("/", "_")[:44]
            dest = dest_dir / f"MlwAnalystX_{stem}_{time.strftime('%Y%m%d_%H%M%S')}.pdff"
            try:
                from reporting.pdf_report import build_analysis_pdf

                build_analysis_pdf(outcome, source_file=file_path, sha256=s256, md5=md5v, dest_path=dest)
                auto_pdf_path = dest
                log(f"PDFF report generated automatically: {dest}")
            except OSError as exc:
                extra = f"Auto PDF export failed: {exc}"
                err_note = f"{err_note}; {extra}" if err_note else extra
                log(f"⚠ {extra}")

        snap.phase = (
            LifecyclePhase.FINISHED if final_state in ("SUCCESS", "PARTIAL_SUCCESS") else LifecyclePhase.FAILED
        )
        snap.progress_pct = 100.0
        snap.eta_sec = 0.0
        progress(snap)

        client.close()

        return replace(outcome, error=err_note, auto_pdf_path=auto_pdf_path)

    @staticmethod
    def _summarize_pcap_and_network(pcap_blob: Any, summary: dict[str, Any]) -> dict[str, Any]:
        streams = summary.get("network_streams") or []
        dns = summary.get("dns_requests") or []
        http = summary.get("http_requests") or []
        hosts = summary.get("compromised_hosts") or []

        unique_ips: set[str] = set()
        protocols: set[str] = set()
        bytes_total = 0

        if isinstance(streams, list):
            for entry in streams:
                if not isinstance(entry, dict):
                    continue
                for key in ("ip", "dst_ip", "src_ip", "destination_ip", "source_ip"):
                    val = entry.get(key)
                    if isinstance(val, str):
                        try:
                            ipaddress.ip_address(val)
                            unique_ips.add(val)
                        except ValueError:
                            pass
                proto = entry.get("protocol") or entry.get("transport")
                if proto:
                    protocols.add(str(proto))
                for bkey in ("bytes", "bytes_sent", "bytes_received", "size"):
                    try:
                        bytes_total += int(entry.get(bkey) or 0)
                    except (TypeError, ValueError):
                        pass

        return {
            "pcap_bytes": len(pcap_blob) if isinstance(pcap_blob, (bytes, bytearray)) else 0,
            "total_connections": len(streams) if isinstance(streams, list) else 0,
            "unique_ips": sorted(unique_ips),
            "protocols": sorted(protocols),
            "aggregate_stream_bytes": bytes_total,
            "dns_count": len(dns) if isinstance(dns, list) else 0,
            "http_count": len(http) if isinstance(http, list) else 0,
            "compromised_hosts_count": len(hosts) if isinstance(hosts, list) else 0,
        }

    def _estimate_progress(
        self,
        phase: LifecyclePhase,
        elapsed_queue: float,
        elapsed_run: float,
        queue_extra: float,
    ) -> float:
        if phase == LifecyclePhase.SUBMITTED:
            return 7.0
        if phase == LifecyclePhase.QUEUED:
            # Slow rise while queued; queue depth adds a small bump only.
            return min(34.0, 10.0 + queue_extra + 22.0 * (1.0 - math.exp(-max(0.0, elapsed_queue) / 240.0)))
        if phase == LifecyclePhase.RUNNING:
            # Asymptotic toward ~91% so we never sit at a flat 95% for long-running sandboxes.
            p = 32.0 + 59.0 * (1.0 - math.exp(-max(0.0, elapsed_run) / 420.0))
            return min(91.0, p)
        if phase == LifecyclePhase.REPORTING:
            return 93.0
        if phase == LifecyclePhase.FAILED:
            return min(90.0, 68.0 + min(22.0, elapsed_run * 0.04))
        if phase == LifecyclePhase.FINISHED:
            return 100.0
        return 9.0

    def _estimate_eta(
        self,
        phase: LifecyclePhase,
        time_left: float,
        elapsed_queue: float,
        elapsed_run: float,
    ) -> float | None:
        """Honest upper bound blended with a soft heuristic (never exceeds client timeout)."""
        if phase == LifecyclePhase.FINISHED:
            return 0.0
        if phase == LifecyclePhase.SUBMITTED:
            return max(20.0, min(time_left, 180.0))
        if phase == LifecyclePhase.QUEUED:
            heuristic = 45.0 + 650.0 * math.exp(-max(0.0, elapsed_queue) / 280.0)
            return max(20.0, min(time_left * 0.98, heuristic))
        if phase == LifecyclePhase.RUNNING:
            heuristic = 60.0 + 1400.0 * math.exp(-max(0.0, elapsed_run) / 520.0)
            return max(30.0, min(time_left * 0.98, heuristic))
        if phase == LifecyclePhase.REPORTING:
            return max(10.0, min(90.0, time_left * 0.95))
        if phase == LifecyclePhase.FAILED:
            return max(15.0, min(time_left, 120.0))
        return max(15.0, time_left)

    @staticmethod
    def _build_behavior_summary(summary: dict[str, Any], profile: BehavioralProfile) -> str:
        parts = []
        vx = summary.get("vx_family")
        if vx:
            parts.append(f"Family / classification signal: {vx}.")
        tp = summary.get("total_processes")
        tn = summary.get("total_network_connections")
        if isinstance(tp, int):
            parts.append(f"Processes observed (summary): {tp}.")
        if isinstance(tn, int):
            parts.append(f"Network connections (summary): {tn}.")
        if profile.persistence_indicators:
            parts.append("Persistence-related indicators were present in behavior or paths.")
        if not parts:
            parts.append("Review process, file, and network sections for detailed sandbox telemetry.")
        return " ".join(parts)

    @staticmethod
    def _key_findings(summary: dict[str, Any], profile: BehavioralProfile, risk: RiskLevel) -> list[str]:
        out: list[str] = []
        v = summary.get("verdict")
        if v:
            out.append(f"Verdict: {v}")
        if profile.domains[:5]:
            out.append("Notable domains: " + ", ".join(profile.domains[:5]))
        if profile.ips[:5]:
            out.append("Notable hosts / IPs: " + ", ".join(profile.ips[:5]))
        if profile.signatures[:5]:
            out.append("Signatures: " + "; ".join(profile.signatures[:5]))
        out.append(f"Composite risk tier: {risk.value}")
        return out
