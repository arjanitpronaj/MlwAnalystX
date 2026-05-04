from __future__ import annotations

import os
import platform
import queue
import subprocess
import threading
import time
from pathlib import Path
from typing import Any

import customtkinter as ctk
from tkinter import filedialog, messagebox

from analyzer.risk_engine import RiskLevel
from analyzer.service import AnalysisOutcome, AnalysisService
from api.hybrid_client import HybridAnalysisError
from config.defaults import Settings
from core.lifecycle import LifecyclePhase, LifecycleSnapshot
from reporting.pdf_report import build_analysis_pdf
from utils.hashes import file_hashes
from utils.sanitize import safe_resolved_file_path

_ENVIRONMENTS: list[tuple[str, int]] = [
    ("Windows 10 64 bit (120)", 120),
    ("Windows 11 64 bit (140)", 140),
    ("Windows 10 64 bit (160)", 160),
    ("Windows 7 32 bit (100)", 100),
    ("Linux Ubuntu 24.04 64 (330)", 330),
    ("macOS Tahoe ARM64 (430)", 430),
]


class MlwAnalystXApp(ctk.CTk):
    def __init__(self) -> None:
        super().__init__()
        self.title("MlwAnalystX — Hybrid Analysis Console")
        self.geometry("1280x820")
        self.minsize(1024, 680)
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("dark-blue")

        self._settings = Settings()
        self._reports_dir = Path.home() / "Downloads" / "MlwAnalystX"
        self._event_q: queue.Queue[tuple[str, Any]] = queue.Queue()
        self._selected_path: Path | None = None
        self._sha256 = ""
        self._md5 = ""
        self._last_outcome: AnalysisOutcome | None = None
        self._analysis_thread: threading.Thread | None = None
        self._start_monotonic: float | None = None

        self._build_layout()
        self.after(80, self._pump_queue)

    def _build_layout(self) -> None:
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        header = ctk.CTkFrame(self, fg_color="#0b1220", corner_radius=0)
        header.grid(row=0, column=0, sticky="ew")
        header.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(
            header,
            text="MlwAnalystX",
            font=ctk.CTkFont(size=22, weight="bold"),
            text_color="#4dd0e1",
        ).grid(row=0, column=0, padx=16, pady=12, sticky="w")
        ctk.CTkLabel(
            header,
            text="Falcon Sandbox · Hybrid Analysis API v2 · PDFF hybrid reporting",
            font=ctk.CTkFont(size=12),
            text_color="#90a4ae",
        ).grid(row=0, column=1, padx=8, pady=12, sticky="w")

        body = ctk.CTkFrame(self, fg_color="#0d1117")
        body.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 10))
        body.grid_columnconfigure(0, weight=2)
        body.grid_columnconfigure(1, weight=3)
        body.grid_columnconfigure(2, weight=2)
        body.grid_rowconfigure(1, weight=1)

        self._build_upload_panel(body)
        self._build_dashboard(body)
        self._build_log_panel(body)
        self._build_results_panel(body)

        foot = ctk.CTkFrame(self, fg_color="#0b1220", corner_radius=0)
        foot.grid(row=2, column=0, sticky="ew")
        ctk.CTkLabel(
            foot,
            text="Samples are only transmitted to Hybrid Analysis for sandbox execution — never executed locally by this client.",
            font=ctk.CTkFont(size=11),
            text_color="#78909c",
        ).pack(side="left", padx=14, pady=8)

    def _build_upload_panel(self, body: ctk.CTkFrame) -> None:
        up = ctk.CTkFrame(body, fg_color="#111823", corner_radius=10, border_width=1, border_color="#1f2a3a")
        up.grid(row=0, column=0, rowspan=2, sticky="nsew", padx=(8, 6), pady=8)
        up.grid_rowconfigure(12, weight=1)

        ctk.CTkLabel(up, text="Submission", font=ctk.CTkFont(size=16, weight="bold"), text_color="#b2ebf2").grid(
            row=0, column=0, columnspan=2, padx=12, pady=(12, 6), sticky="w"
        )

        ctk.CTkButton(up, text="Select suspicious file…", command=self._pick_file, fg_color="#00838f").grid(
            row=1, column=0, columnspan=2, padx=12, pady=6, sticky="ew"
        )

        self._lbl_name = ctk.CTkLabel(up, text="No file selected", anchor="w", text_color="#cfd8dc")
        self._lbl_name.grid(row=2, column=0, columnspan=2, padx=12, pady=2, sticky="ew")
        self._lbl_size = ctk.CTkLabel(up, text="Size: —", anchor="w", text_color="#90a4ae")
        self._lbl_size.grid(row=3, column=0, columnspan=2, padx=12, pady=2, sticky="ew")
        self._lbl_sha = ctk.CTkLabel(up, text="SHA256: —", anchor="w", text_color="#90a4ae", wraplength=340)
        self._lbl_sha.grid(row=4, column=0, columnspan=2, padx=12, pady=2, sticky="ew")
        self._lbl_md5 = ctk.CTkLabel(up, text="MD5: —", anchor="w", text_color="#90a4ae", wraplength=340)
        self._lbl_md5.grid(row=5, column=0, columnspan=2, padx=12, pady=2, sticky="ew")

        ctk.CTkLabel(
            up,
            text="Hybrid Analysis API key",
            text_color="#b0bec5",
            font=ctk.CTkFont(size=13, weight="bold"),
        ).grid(row=6, column=0, columnspan=2, padx=12, pady=(14, 2), sticky="w")
        ctk.CTkLabel(
            up,
            text="Paste your key here (Profile → API on hybrid-analysis.com). It is sent only as the api-key HTTP header — never logged in full.",
            text_color="#78909c",
            font=ctk.CTkFont(size=11),
            wraplength=320,
            justify="left",
        ).grid(row=7, column=0, columnspan=2, padx=12, pady=(0, 4), sticky="w")
        self._entry_key = ctk.CTkEntry(
            up,
            placeholder_text="Paste API key, then pick file and submit",
            show="•",
        )
        self._entry_key.grid(row=8, column=0, columnspan=2, padx=12, pady=4, sticky="ew")

        ctk.CTkLabel(up, text="Sandbox environment", text_color="#b0bec5").grid(row=9, column=0, padx=12, pady=(10, 2), sticky="sw")
        labels = [x[0] for x in _ENVIRONMENTS]
        self._combo_env = ctk.CTkComboBox(up, values=labels, width=320)
        self._combo_env.set(labels[0])
        self._combo_env.grid(row=10, column=0, columnspan=2, padx=12, pady=2, sticky="ew")

        self._btn_run = ctk.CTkButton(
            up,
            text="Submit to Hybrid Analysis",
            command=self._start_analysis,
            fg_color="#006064",
            hover_color="#00838f",
        )
        self._btn_run.grid(row=11, column=0, columnspan=2, padx=12, pady=16, sticky="ew")

        self._btn_pdf = ctk.CTkButton(up, text="Export PDFF report…", command=self._export_pdf, state="disabled", fg_color="#37474f")
        self._btn_pdf.grid(row=12, column=0, columnspan=2, padx=12, pady=(0, 14), sticky="ew")

    def _build_dashboard(self, body: ctk.CTkFrame) -> None:
        dash = ctk.CTkFrame(body, fg_color="#111823", corner_radius=10, border_width=1, border_color="#1f2a3a")
        dash.grid(row=0, column=1, sticky="nsew", padx=(6, 8), pady=(8, 4))
        dash.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(dash, text="Live analysis dashboard", font=ctk.CTkFont(size=16, weight="bold"), text_color="#b2ebf2").grid(
            row=0, column=0, columnspan=3, padx=12, pady=(10, 6), sticky="w"
        )

        def row(r: int, label: str) -> ctk.CTkLabel:
            ctk.CTkLabel(dash, text=label, text_color="#90a4ae").grid(row=r, column=0, padx=12, pady=4, sticky="w")
            v = ctk.CTkLabel(dash, text="—", anchor="w", text_color="#eceff1")
            v.grid(row=r, column=1, columnspan=2, padx=8, pady=4, sticky="ew")
            return v

        self._v_status = row(1, "Status")
        self._v_timer = row(2, "Elapsed (s)")
        self._v_eta = row(3, "Est. remaining (s)")
        self._v_progress = row(4, "Progress (est.)")
        self._v_job = row(5, "Job ID")
        self._v_sub = row(6, "Submission ID")
        self._v_api_state = row(7, "Raw API state")

        self._prog = ctk.CTkProgressBar(dash, height=16, progress_color="#26c6da")
        self._prog.set(0)
        self._prog.grid(row=8, column=0, columnspan=3, padx=12, pady=(8, 12), sticky="ew")

    def _build_log_panel(self, body: ctk.CTkFrame) -> None:
        logf = ctk.CTkFrame(body, fg_color="#111823", corner_radius=10, border_width=1, border_color="#1f2a3a")
        logf.grid(row=1, column=1, sticky="nsew", padx=(6, 8), pady=(4, 8))
        logf.grid_rowconfigure(1, weight=1)
        logf.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(logf, text="API communication log", font=ctk.CTkFont(size=16, weight="bold"), text_color="#ffcc80").grid(
            row=0, column=0, padx=12, pady=(10, 4), sticky="w"
        )
        self._log_box = ctk.CTkTextbox(logf, font=ctk.CTkFont(family="Consolas", size=11), fg_color="#05080d", text_color="#c8e6c9")
        self._log_box.grid(row=1, column=0, padx=10, pady=(0, 10), sticky="nsew")
        self._log_box.insert("end", "[" + time.strftime("%H:%M:%S") + "] Console ready. All HTTP steps will appear here.\n")

    def _build_results_panel(self, body: ctk.CTkFrame) -> None:
        res = ctk.CTkFrame(body, fg_color="#111823", corner_radius=10, border_width=1, border_color="#1f2a3a")
        res.grid(row=0, column=2, rowspan=2, sticky="nsew", padx=(0, 8), pady=8)
        res.grid_rowconfigure(4, weight=1)
        res.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(res, text="Results summary", font=ctk.CTkFont(size=16, weight="bold"), text_color="#ce93d8").grid(
            row=0, column=0, padx=12, pady=(12, 6), sticky="w"
        )
        self._v_risk = ctk.CTkLabel(res, text="Risk: —", font=ctk.CTkFont(size=20, weight="bold"), text_color="#eceff1")
        self._v_risk.grid(row=1, column=0, padx=12, pady=4, sticky="w")
        self._v_score = ctk.CTkLabel(res, text="Score: —", text_color="#b0bec5")
        self._v_score.grid(row=2, column=0, padx=12, pady=2, sticky="w")

        ctk.CTkLabel(res, text="Behavior synopsis", text_color="#90a4ae").grid(row=3, column=0, padx=12, pady=(10, 2), sticky="w")
        self._txt_behavior = ctk.CTkTextbox(res, height=120, font=ctk.CTkFont(size=12), fg_color="#0a101a")
        self._txt_behavior.grid(row=4, column=0, padx=10, pady=2, sticky="ew")

        ctk.CTkLabel(res, text="Key findings", text_color="#90a4ae").grid(row=5, column=0, padx=12, pady=(8, 2), sticky="w")
        self._txt_findings = ctk.CTkTextbox(res, height=160, font=ctk.CTkFont(size=12), fg_color="#0a101a")
        self._txt_findings.grid(row=6, column=0, padx=10, pady=(2, 8), sticky="ew")

        ctk.CTkLabel(res, text="Reports", text_color="#90a4ae").grid(row=7, column=0, padx=12, pady=(6, 2), sticky="w")
        ctk.CTkButton(res, text="Refresh Reports", command=self._refresh_reports, height=28, fg_color="#37474f").grid(
            row=8, column=0, padx=10, pady=(2, 6), sticky="ew"
        )
        self._reports_frame = ctk.CTkScrollableFrame(res, fg_color="#0a101a", height=180)
        self._reports_frame.grid(row=9, column=0, padx=10, pady=(0, 12), sticky="nsew")
        res.grid_rowconfigure(9, weight=1)
        self._refresh_reports()

    def _pick_file(self) -> None:
        path = filedialog.askopenfilename(title="Select sample for sandbox submission")
        if not path:
            return
        try:
            p = safe_resolved_file_path(path)
        except ValueError:
            messagebox.showerror("MlwAnalystX", "Invalid file path.")
            return
        if not p.is_file():
            messagebox.showerror("MlwAnalystX", "File does not exist.")
            return
        size = p.stat().st_size
        if size > self._settings.max_upload_bytes:
            messagebox.showerror("MlwAnalystX", "File exceeds Hybrid Analysis upload limits (~100 MB).")
            return
        self._selected_path = p
        self._lbl_name.configure(text=f"File: {p.name}")
        self._lbl_size.configure(text=f"Size: {size:,} bytes")
        try:
            sha, md5 = file_hashes(p)
            self._sha256, self._md5 = sha, md5
            self._lbl_sha.configure(text=f"SHA256: {sha}")
            self._lbl_md5.configure(text=f"MD5: {md5}")
        except OSError as exc:
            messagebox.showerror("MlwAnalystX", f"Could not read file: {exc}")
            return
        self._append_log(f"Local file bound: {p} ({size} bytes)")

    def _selected_environment_id(self) -> int:
        label = self._combo_env.get()
        for text, eid in _ENVIRONMENTS:
            if text == label:
                return eid
        return _ENVIRONMENTS[0][1]

    def _start_analysis(self) -> None:
        if self._analysis_thread and self._analysis_thread.is_alive():
            messagebox.showwarning("MlwAnalystX", "An analysis is already running.")
            return
        key = self._entry_key.get().strip()
        if not key:
            messagebox.showerror("MlwAnalystX", "API key is required.")
            return
        if not self._selected_path:
            messagebox.showerror("MlwAnalystX", "Select a file first.")
            return
        self._last_outcome = None
        self._btn_pdf.configure(state="disabled")
        self._btn_run.configure(state="disabled")
        self._clear_results()
        self._append_log("=== New submission started ===")
        self._start_monotonic = time.perf_counter()

        def worker() -> None:
            svc = AnalysisService(self._settings)
            api_log_lines: list[str] = []

            def log(msg: str) -> None:
                api_log_lines.append(msg)
                self._event_q.put(("log", msg))

            def prog(snap: LifecycleSnapshot) -> None:
                self._event_q.put(("status", snap))

            try:
                out = svc.run(
                    key,
                    self._selected_path,
                    self._selected_environment_id(),
                    log,
                    prog,
                    sha256=self._sha256,
                    md5=self._md5,
                )
                out.supplemental["api_log"] = api_log_lines
                self._event_q.put(("outcome", out))
            except HybridAnalysisError as exc:
                self._event_q.put(("fail", str(exc)))
            except Exception as exc:  # noqa: BLE001 — surface unexpected worker faults in UI
                self._event_q.put(("fail", f"{type(exc).__name__}: {exc}"))

        self._analysis_thread = threading.Thread(target=worker, daemon=True)
        self._analysis_thread.start()

    def _clear_results(self) -> None:
        self._v_risk.configure(text="Risk: —", text_color="#eceff1")
        self._v_score.configure(text="Score: —")
        self._txt_behavior.delete("1.0", "end")
        self._txt_findings.delete("1.0", "end")

    def _export_pdf(self) -> None:
        if not self._last_outcome or not self._selected_path:
            messagebox.showwarning("MlwAnalystX", "No completed analysis to export.")
            return
        dest = filedialog.asksaveasfilename(
            defaultextension=".pdff",
            filetypes=[("PDFF", "*.pdff"), ("PDF", "*.pdf")],
            initialfile=f"MlwAnalystX_{self._sha256[:16]}.pdff",
        )
        if not dest:
            return
        try:
            p = Path(dest)
            build_analysis_pdf(
                self._last_outcome,
                source_file=self._selected_path,
                sha256=self._sha256,
                md5=self._md5,
                dest_path=p,
            )
        except OSError as exc:
            messagebox.showerror("MlwAnalystX", f"PDFF export failed: {exc}")
            return
        self._append_log(f"PDFF report written: {p}")
        self._refresh_reports()
        messagebox.showinfo("MlwAnalystX", f"PDFF saved:\n{p}")

    def _append_log(self, line: str) -> None:
        ts = time.strftime("%H:%M:%S")
        self._log_box.insert("end", f"[{ts}] {line}\n")
        self._log_box.see("end")

    def _pump_queue(self) -> None:
        try:
            while True:
                kind, payload = self._event_q.get_nowait()
                if kind == "log":
                    self._append_log(str(payload))
                elif kind == "status":
                    self._apply_status(payload)
                elif kind == "outcome":
                    self._apply_outcome(payload)
                elif kind == "fail":
                    self._append_log(f"ERROR: {payload}")
                    self._v_status.configure(text="Status: failed")
                    messagebox.showerror("MlwAnalystX", str(payload))
                    self._btn_run.configure(state="normal")
        except queue.Empty:
            pass
        self.after(80, self._pump_queue)

    def _apply_status(self, snap: LifecycleSnapshot) -> None:
        phase = snap.phase.value.upper()
        if snap.phase == LifecyclePhase.REPORTING:
            label = "REPORTING — fetching summary / full JSON"
        else:
            label = phase
        self._v_status.configure(text=f"Status: {label}")
        self._v_timer.configure(text=f"Elapsed (s): {snap.elapsed_sec:,.1f}")
        if snap.eta_sec is not None:
            self._v_eta.configure(text=f"Est. remaining: {self._fmt_eta(snap.eta_sec)}")
        self._v_progress.configure(text=f"Progress (est.): {snap.progress_pct:,.1f}%")
        self._prog.set(max(0.0, min(1.0, snap.progress_pct / 100.0)))
        self._v_job.configure(text=f"Job ID: {snap.job_id or '—'}")
        self._v_sub.configure(text=f"Submission ID: {snap.submission_id or '—'}")
        self._v_api_state.configure(text=f"Raw API state: {snap.api_state or '—'}")

    @staticmethod
    def _fmt_eta(sec: float) -> str:
        if sec <= 0:
            return "0s"
        if sec < 90:
            return f"{sec:.0f}s"
        m, s = divmod(int(sec + 0.5), 60)
        if m < 60:
            return f"{m}m {s:02d}s"
        h, m = divmod(m, 60)
        return f"{h}h {m:02d}m"

    def _open_path(self, path: Path) -> None:
        path = path.resolve()
        try:
            if platform.system() == "Windows":
                os.startfile(str(path))  # type: ignore[attr-defined,no-untyped-call]
            elif platform.system() == "Darwin":
                subprocess.run(["open", str(path)], check=False)
            else:
                subprocess.run(["xdg-open", str(path)], check=False)
        except OSError as exc:
            self._append_log(f"Could not open file automatically: {exc}")

    def _refresh_reports(self) -> None:
        self._reports_dir.mkdir(parents=True, exist_ok=True)
        for w in self._reports_frame.winfo_children():
            w.destroy()
        reports = sorted(
            [*self._reports_dir.glob("*.pdff"), *self._reports_dir.glob("*.pdf")],
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )
        if not reports:
            ctk.CTkLabel(self._reports_frame, text="No reports yet.", text_color="#90a4ae").pack(anchor="w", padx=6, pady=6)
            return
        for p in reports[:120]:
            ts = time.strftime("%Y-%m-%d %H:%M", time.localtime(p.stat().st_mtime))
            btn = ctk.CTkButton(
                self._reports_frame,
                text=f"{p.name}\n{ts} • {p.stat().st_size/1024:.1f} KB",
                anchor="w",
                command=lambda x=p: self._open_path(x),
                fg_color="#1a2533",
                hover_color="#243447",
                height=46,
            )
            btn.pack(fill="x", padx=6, pady=4)

    def _apply_outcome(self, out: AnalysisOutcome) -> None:
        self._last_outcome = out
        self._btn_run.configure(state="normal")
        self._btn_pdf.configure(state="normal")
        self._v_status.configure(text=f"Status: {(out.terminal_api_state or 'DONE').upper()}")
        self._v_eta.configure(text="Est. remaining: complete")
        self._v_progress.configure(text="Progress (est.): 100.0%")
        self._prog.set(1.0)
        col = "#66bb6a"
        if out.risk == RiskLevel.MEDIUM:
            col = "#ffb74d"
        elif out.risk == RiskLevel.HIGH:
            col = "#ef5350"
        self._v_risk.configure(text=f"Risk: {out.risk.value}", text_color=col)
        self._v_score.configure(text=f"Score: {out.risk_score}/100")
        self._txt_behavior.insert("end", out.behavior_summary)
        self._txt_findings.insert("end", "\n".join(out.key_findings))
        if out.risk_reasons:
            self._txt_findings.insert("end", "\n\nRationale:\n- " + "\n- ".join(out.risk_reasons))
        if out.error:
            self._txt_findings.insert("end", f"\n\nWarnings:\n{out.error}")
        ioc_text = out.supplemental.get("ioc_summary_text") if isinstance(out.supplemental, dict) else None
        if isinstance(ioc_text, str) and ioc_text.strip():
            self._txt_findings.insert("end", f"\n\n{ioc_text}")
        verdict_line = out.supplemental.get("verdict_line") if isinstance(out.supplemental, dict) else None
        if isinstance(verdict_line, str) and verdict_line.strip():
            self._txt_findings.insert("end", f"\n\n{verdict_line}")
            self._append_log(verdict_line)
        self._append_log("=== Analysis cycle complete ===")
        if out.auto_pdf_path:
            self._append_log(f"PDFF (auto): {out.auto_pdf_path}")
            self.after(150, lambda p=out.auto_pdf_path: self._open_path(p))
        self._refresh_reports()


def launch_app() -> None:
    app = MlwAnalystXApp()
    app.mainloop()
