from __future__ import annotations

import ipaddress
import json
from io import BytesIO
from pathlib import Path
from typing import Any

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import Image, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
from reportlab.platypus.tableofcontents import TableOfContents

from analyzer.service import AnalysisOutcome
from config.defaults import Settings
from reporting.forensic_digest import build_forensic_digest


def _redact_nested_blobs(obj: Any, *, max_str: int = 120, depth: int = 0) -> Any:
    """Shrink huge base64 / binary strings for PDF JSON blocks."""
    if depth > 14:
        return "<max depth>"
    if isinstance(obj, dict):
        out: dict[str, Any] = {}
        for k, v in obj.items():
            lk = str(k).lower()
            if lk in ("image", "picture", "data", "content", "screenshot_data") and isinstance(v, str) and len(v) > max_str:
                out[k] = f"<elided {len(v)} chars>"
            else:
                out[k] = _redact_nested_blobs(v, max_str=max_str, depth=depth + 1)
        return out
    if isinstance(obj, list):
        return [_redact_nested_blobs(x, max_str=max_str, depth=depth + 1) for x in obj[:120]]
    if isinstance(obj, str) and len(obj) > 600:
        return obj[:max_str] + f"…<{len(obj)} chars total>"
    return obj


def _malware_classification_matrix(
    summary: dict[str, Any],
    digest: Any,
    outcome: AnalysisOutcome,
) -> list[tuple[str, str]]:
    tags = summary.get("classification_tags") if isinstance(summary.get("classification_tags"), list) else []
    blob = " ".join(str(t) for t in tags).lower()
    blob += " " + str(summary.get("vx_family") or "").lower()
    blob += " " + str(summary.get("verdict") or "").lower()
    for sc in summary.get("scanners") or []:
        if isinstance(sc, dict):
            blob += " " + str(sc.get("result") or sc.get("detected_as") or "").lower()
    for row in getattr(digest, "signature_rows", []) or []:
        for cell in row:
            blob += " " + str(cell).lower()
    hits = (
        "ransomware",
        "ransom",
        "trojan",
        "worm",
        "stealer",
        "dropper",
        "loader",
        "keylog",
        "spyware",
        "banker",
        "miner",
        "botnet",
        "backdoor",
        "wiper",
        "locker",
        "cryptor",
        "rootkit",
    )
    matched = sorted({h for h in hits if h in blob})
    eng = []
    for sc in summary.get("scanners") or []:
        if isinstance(sc, dict):
            r = str(sc.get("result") or sc.get("detected_as") or "").strip()
            if r:
                eng.append(f"{sc.get('name') or sc.get('engine')}: {r}")
    root = outcome.full_report
    fr_ok = isinstance(root, dict) and len(root) > 2
    return [
        ("Malware family (vx_family)", str(summary.get("vx_family") or "—")),
        ("Verdict", str(summary.get("verdict") or "—")),
        ("Threat score", f"{summary.get('threat_score') or 0}/100"),
        ("Threat level", str(summary.get("threat_level") or "—")),
        ("Classification tags", ", ".join(str(t) for t in tags) or "—"),
        ("Inferred categories (keyword scan on tags, family, AV, signatures)", ", ".join(matched) or "no keyword hits"),
        ("AV labels (first 12 engines)", "; ".join(eng[:12]) or "—"),
        ("Signature rows (digest)", str(len(getattr(digest, "signature_rows", []) or []))),
        ("MITRE rows (digest)", str(len(getattr(digest, "mitre_rows", []) or []))),
        ("Full JSON report loaded", "yes" if fr_ok else "no / empty / API denied"),
    ]


class _HADocTemplate(SimpleDocTemplate):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._report_id = ""
        self._classification = "UNKNOWN"

    def afterFlowable(self, flowable: Any) -> None:  # noqa: N802
        if isinstance(flowable, Paragraph):
            txt = flowable.getPlainText()
            style_name = getattr(flowable.style, "name", "")
            if style_name == "HA_H1":
                self.notify("TOCEntry", (0, txt, self.page))
            elif style_name == "HA_H2":
                self.notify("TOCEntry", (1, txt, self.page))


def build_analysis_pdf(
    outcome: AnalysisOutcome,
    *,
    source_file: Path,
    sha256: str,
    md5: str,
    dest_path: Path,
) -> Path:
    sup = outcome.supplemental or {}
    summary = outcome.summary if isinstance(outcome.summary, dict) else {}
    processes = sup.get("processes") if isinstance(sup.get("processes"), list) else []
    dropped = sup.get("dropped_files") if isinstance(sup.get("dropped_files"), list) else []
    strings = sup.get("strings") if isinstance(sup.get("strings"), list) else []
    memory_dumps = sup.get("memory_dumps")
    screenshots = sup.get("screenshot_images") if isinstance(sup.get("screenshot_images"), list) else []
    pcap_summary = sup.get("pcap_summary") if isinstance(sup.get("pcap_summary"), dict) else {}
    digest = build_forensic_digest(outcome.full_report, summary, sup, outcome.milestones)
    cfg = Settings()

    styles = getSampleStyleSheet()
    h1 = ParagraphStyle("HA_H1", parent=styles["Heading1"], textColor=colors.HexColor("#005f73"))
    h2 = ParagraphStyle("HA_H2", parent=styles["Heading2"], textColor=colors.HexColor("#0a9396"))
    body = ParagraphStyle("body", parent=styles["Normal"], fontSize=9, leading=12)
    mono = ParagraphStyle("mono", parent=body, fontName="Courier", fontSize=8, leading=10)
    small = ParagraphStyle("small", parent=body, fontSize=8)
    toc_entry = ParagraphStyle("toc_entry", parent=body, leftIndent=12)
    toc_entry_l2 = ParagraphStyle("toc_entry_l2", parent=body, leftIndent=26)

    dest_path.parent.mkdir(parents=True, exist_ok=True)
    doc = _HADocTemplate(str(dest_path), pagesize=letter, leftMargin=0.6 * inch, rightMargin=0.6 * inch, topMargin=0.6 * inch, bottomMargin=0.6 * inch)
    story: list[Any] = []

    verdict = str(summary.get("verdict") or "UNKNOWN").upper()
    score = str(summary.get("threat_score") or "0")
    family = str(summary.get("vx_family") or "UNKNOWN")
    verdict_color = _verdict_color(verdict)
    doc._report_id = str(outcome.job_id or "UNKNOWN")
    doc._classification = verdict

    # Cover
    story.append(Paragraph("Hybrid Analysis Report", ParagraphStyle("ct", parent=h1, fontSize=24)))
    story.append(Spacer(1, 0.15 * inch))
    story.append(Paragraph(f"<b>File Name:</b> {_esc(summary.get('submit_name') or source_file.name)}", body))
    story.append(Paragraph(f"<b>SHA256:</b> {_esc(summary.get('sha256') or sha256)}", mono))
    story.append(Paragraph(f"<b>Analysis Date:</b> {_esc(summary.get('analysis_start_time') or 'No activity observed — field not returned by API')}", body))
    story.append(Paragraph(f"<b>Environment:</b> {_esc(summary.get('environment_description') or 'No activity observed — field not returned by API')}", body))
    story.append(Paragraph(f"<b>Report ID:</b> {_esc(outcome.job_id or 'No activity observed — field not returned by API')}", body))
    story.append(Paragraph(f"<font color='{verdict_color}'><b>Verdict:</b> {_esc(verdict)}</font>", body))
    story.append(Paragraph(f"<b>Threat Score:</b> {_esc(score)}/100", body))
    story.append(Spacer(1, 0.12 * inch))
    cls_rows = _malware_classification_matrix(summary, digest, outcome)
    cls_tbl = Table(
        [[Paragraph(f"<b>{_esc(a)}</b>", body), Paragraph(_esc(b), mono)] for a, b in cls_rows],
        colWidths=[1.85 * inch, 4.25 * inch],
    )
    cls_tbl.setStyle(
        TableStyle(
            [
                ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#78909c")),
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#e0f7fa")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]
        )
    )
    story.append(cls_tbl)
    story.append(PageBreak())

    # Real TOC (filled after full layout)
    story.append(Paragraph("Table of Contents", h1))
    toc = TableOfContents()
    toc.levelStyles = [toc_entry, toc_entry_l2]
    story.append(toc)
    story.append(PageBreak())

    # Executive summary + API-derived narrative (matches analyzer panel)
    tags = summary.get("classification_tags") if isinstance(summary.get("classification_tags"), list) else []
    story.append(Paragraph("Executive Summary", h1))
    story.append(
        Paragraph(
            _esc(
                f"Verdict {verdict}, score {score}/100, family {family}. "
                f"Tags ({len(tags)}): {', '.join(str(x) for x in tags[:40]) or 'none'}. "
                f"Processes (API): {len(processes)}; processes (digest): {len(digest.process_rows)}; "
                f"files (digest): {len(digest.file_activity_rows)}; registry (digest): {len(digest.registry_rows)}; "
                f"signatures: {len(digest.signature_rows)}; MITRE: {len(digest.mitre_rows)}; "
                f"DNS (summary): {len(summary.get('dns_requests') or []) if isinstance(summary.get('dns_requests'), list) else 0}; "
                f"DNS (network digest): {len(digest.network_dns_rows)}; "
                f"streams: {len(summary.get('network_streams') or []) if isinstance(summary.get('network_streams'), list) else 0}."
            ),
            body,
        )
    )
    story.append(Paragraph("<b>Behavior summary (API-derived)</b>", h2))
    story.append(Paragraph(_esc(outcome.behavior_summary or "—"), body))
    story.append(Paragraph("<b>Key findings</b>", h2))
    for line in outcome.key_findings or ["—"]:
        story.append(Paragraph(_esc(f"• {line}"), body))
    story.append(Spacer(1, 0.08 * inch))
    story.append(Paragraph("Classification detail (API fields)", h2))
    signals = _extract_classification_signals(summary, outcome.full_report)
    story.append(_data_table(["Signal Type", "Value"], [[k, v] for k, v in signals], [1.8 * inch, 4.3 * inch], body, mono))
    story.append(PageBreak())

    # File information
    story.append(Paragraph("File Information", h1))
    rows = [
        ["File Name", summary.get("submit_name") or source_file.name],
        ["File Size", summary.get("size")],
        ["File Type", summary.get("type")],
        ["MIME Type", summary.get("mime_type")],
        ["Magic Bytes", summary.get("magic")],
        ["MD5", summary.get("md5") or md5],
        ["SHA1", summary.get("sha1")],
        ["SHA256", summary.get("sha256") or sha256],
        ["SSDEEP", summary.get("ssdeep")],
        ["Architecture", summary.get("pe_architecture")],
        ["Compile Time", summary.get("pe_compile_timestamp")],
        ["Packer", summary.get("packer_detected")],
    ]
    story.append(_kv_table(rows, body, mono))
    story.append(PageBreak())

    # AV scanner results
    story.append(Paragraph("AV Scanner Results", h1))
    scanners = summary.get("scanners") if isinstance(summary.get("scanners"), list) else []
    if scanners:
        scanner_rows = []
        detects = 0
        for x in scanners:
            if not isinstance(x, dict):
                continue
            status = str(x.get("status") or x.get("detected") or "")
            if status.lower() in ("true", "detected", "malicious", "yes", "1"):
                detects += 1
            scanner_rows.append([str(x.get("name") or x.get("engine") or ""), status, str(x.get("result") or x.get("detected_as") or "")])
        story.append(_data_table(["Engine Name", "Detection Status", "Detected As"], scanner_rows, [2.0 * inch, 1.5 * inch, 2.3 * inch], body, mono))
        story.append(Spacer(1, 0.1 * inch))
        story.append(Paragraph(f"Detected by {detects} out of {len(scanner_rows)} engines", body))
    else:
        story.append(Paragraph("No activity observed — scanners array not returned by API.", body))
    story.append(PageBreak())

    # Static analysis
    story.append(Paragraph("Static Analysis", h1))
    story.append(Paragraph("PE Sections", h2))
    pe_sections = summary.get("pe_sections") if isinstance(summary.get("pe_sections"), list) else []
    sec_rows: list[list[str]] = []
    for x in pe_sections:
        if not isinstance(x, dict):
            continue
        sec_rows.append(
            [
                str(x.get("name") or ""),
                str(x.get("virtual_size") or x.get("vsize") or ""),
                str(x.get("raw_size") or x.get("size") or ""),
                str(x.get("entropy") or ""),
                str(x.get("md5") or ""),
            ]
        )
    story.append(_data_table(["Name", "Virtual Size", "Raw Size", "Entropy", "MD5"], sec_rows, [1.0 * inch, 1.0 * inch, 1.0 * inch, 0.8 * inch, 2.3 * inch], body, mono))
    story.append(Spacer(1, 0.08 * inch))

    story.append(Paragraph("PE Imports", h2))
    pe_imports = summary.get("pe_imports") if isinstance(summary.get("pe_imports"), list) else []
    imp_rows: list[list[str]] = []
    for x in pe_imports:
        if isinstance(x, dict):
            funcs = x.get("imports") if isinstance(x.get("imports"), list) else []
            imp_rows.append([str(x.get("dll") or x.get("name") or ""), ", ".join(str(f) for f in funcs)])
    story.append(_data_table(["DLL Name", "Imported Functions"], imp_rows, [1.8 * inch, 4.3 * inch], body, mono))
    story.append(Spacer(1, 0.08 * inch))

    story.append(Paragraph("PE Exports", h2))
    pe_exports = summary.get("pe_exports") if isinstance(summary.get("pe_exports"), list) else []
    exp_rows = [[str(x)] for x in pe_exports]
    story.append(_data_table(["Exported Function"], exp_rows, [6.1 * inch], body, mono))
    story.append(Spacer(1, 0.08 * inch))

    story.append(Paragraph("Certificates", h2))
    certs = summary.get("certificates") if isinstance(summary.get("certificates"), list) else []
    cert_rows: list[list[str]] = []
    for c in certs:
        if isinstance(c, dict):
            cert_rows.append(
                [
                    str(c.get("subject") or ""),
                    str(c.get("issuer") or ""),
                    str(c.get("valid_from") or ""),
                    str(c.get("valid_to") or ""),
                    str(c.get("status") or ""),
                ]
            )
    story.append(_data_table(["Subject", "Issuer", "Valid From", "Valid To", "Status"], cert_rows, [1.2 * inch, 1.4 * inch, 1.1 * inch, 1.1 * inch, 1.3 * inch], body, mono))
    story.append(Spacer(1, 0.08 * inch))

    story.append(Paragraph("Strings", h2))
    effective_strings = strings if strings else digest.interesting_strings
    str_rows = [[str(s)] for s in effective_strings]
    story.extend(_chunked_tables(["String"], str_rows, [6.1 * inch], body, mono))
    story.append(PageBreak())

    # Process behavior
    story.append(Paragraph("Process Behavior", h1))
    process_rows_for_pdf: list[Any] = list(processes) if processes else []
    if not process_rows_for_pdf and digest.process_rows:
        process_rows_for_pdf = [
            {"pid": r[0], "parentpid": r[1], "name": r[2], "normalized_path": r[2], "cmdline": r[3]}
            for r in digest.process_rows
        ]
        story.append(
            Paragraph(
                "Process endpoint returned no list; rows below are merged from job summary and full-report digest (same sources as the web UI).",
                small,
            )
        )
        story.append(Spacer(1, 0.06 * inch))
    if process_rows_for_pdf:
        p_rows = []
        by_pid: dict[str, dict[str, Any]] = {}
        children: dict[str, list[str]] = {}
        for p in process_rows_for_pdf:
            if not isinstance(p, dict):
                continue
            pid = str(p.get("pid") or "")
            ppid = str(p.get("parentpid") or p.get("ppid") or "")
            by_pid[pid] = p
            children.setdefault(ppid, []).append(pid)
            p_rows.append(
                [
                    pid,
                    ppid,
                    str(p.get("name") or ""),
                    str(p.get("normalized_path") or p.get("path") or ""),
                    str(p.get("cmdline") or p.get("command_line") or ""),
                ]
            )
        story.append(Paragraph("Process Tree Diagram", h2))
        for line in _process_tree_lines(by_pid, children):
            story.append(Paragraph(_esc(line), mono))
        story.append(Spacer(1, 0.08 * inch))
        story.append(Paragraph("Per-Process Detail", h2))
        story.extend(
            _chunked_tables(
                ["PID", "Parent PID", "Name", "Full Path", "Command Line"],
                p_rows,
                [0.5 * inch, 0.7 * inch, 1.0 * inch, 1.8 * inch, 2.0 * inch],
                body,
                mono,
            )
        )
        story.append(Spacer(1, 0.08 * inch))
        story.append(Paragraph("Files Touched (per process)", h2))
        f_rows: list[list[str]] = []
        r_rows: list[list[str]] = []
        m_rows: list[list[str]] = []
        for p in process_rows_for_pdf:
            if not isinstance(p, dict):
                continue
            pid = str(p.get("pid") or "")
            for key, action in (("created_files", "created"), ("deleted_files", "deleted"), ("modified_files", "modified")):
                if isinstance(p.get(key), list):
                    for fp in p.get(key):
                        f_rows.append([pid, action, str(fp)])
            for key, action in (("registry_keys_set", "set"), ("registry_keys_deleted", "delete")):
                if isinstance(p.get(key), list):
                    for rk in p.get(key):
                        r_rows.append([pid, action, str(rk)])
            if isinstance(p.get("mutants"), list):
                for mt in p.get("mutants"):
                    m_rows.append([pid, str(mt)])
        story.extend(_chunked_tables(["PID", "Action", "Path"], f_rows, [0.6 * inch, 0.8 * inch, 4.7 * inch], body, mono))
        story.append(Spacer(1, 0.08 * inch))
        story.append(Paragraph("Registry Activity (per process)", h2))
        story.extend(_chunked_tables(["PID", "Action", "Registry Key"], r_rows, [0.6 * inch, 0.8 * inch, 4.7 * inch], body, mono))
        story.append(Spacer(1, 0.08 * inch))
        story.append(Paragraph("Mutexes Created", h2))
        story.extend(_chunked_tables(["PID", "Mutex"], m_rows, [0.7 * inch, 5.4 * inch], body, mono))
    else:
        story.append(
            Paragraph(
                "No process rows after merging API processes, summary, and digest. If the web UI shows a tree, check API key privileges for /processes and /report/json.",
                body,
            )
        )
    story.append(PageBreak())

    # Behavioral analysis sync block (full report + supplemental)
    story.append(Paragraph("Behavioral Analysis", h1))
    story.append(Paragraph("Process execution timeline", h2))
    proc_rows = [[r[0], r[1], r[2], r[3], r[4]] for r in digest.process_rows]
    story.extend(
        _chunked_tables(
            ["PID", "PPID", "Image/Name", "Command Line", "Source"],
            proc_rows,
            [0.55 * inch, 0.55 * inch, 1.3 * inch, 3.0 * inch, 0.7 * inch],
            body,
            mono,
        )
    )
    story.append(Spacer(1, 0.08 * inch))
    story.append(Paragraph("File system activity", h2))
    fs_rows = [[r[0], r[1], r[2], r[3]] for r in digest.file_activity_rows]
    story.extend(
        _chunked_tables(["Action", "Path", "Details", "Source"], fs_rows, [0.8 * inch, 2.7 * inch, 1.6 * inch, 1.0 * inch], body, mono)
    )
    story.append(Spacer(1, 0.08 * inch))
    story.append(Paragraph("Registry activity", h2))
    reg_rows = [[r[0], r[1], r[2]] for r in digest.registry_rows]
    story.extend(_chunked_tables(["Action", "Registry Key", "Value/Data"], reg_rows, [0.8 * inch, 3.2 * inch, 2.1 * inch], body, mono))
    story.append(PageBreak())

    story.append(Paragraph("Threat signatures (full report)", h2))
    story.extend(
        _chunked_tables(
            ["Threat / Name", "Category", "Description"],
            [[r[0], r[1], r[2]] for r in digest.signature_rows],
            [1.4 * inch, 1.0 * inch, 3.7 * inch],
            body,
            mono,
        )
    )
    story.append(Spacer(1, 0.08 * inch))
    story.append(Paragraph("MITRE ATT&CK (full report)", h2))
    story.extend(
        _chunked_tables(
            ["Tactic", "Technique", "ID", "Description"],
            [[r[0], r[1], r[2], r[3]] for r in digest.mitre_rows],
            [1.0 * inch, 1.0 * inch, 0.7 * inch, 3.4 * inch],
            body,
            mono,
        )
    )
    story.append(Spacer(1, 0.08 * inch))
    story.append(Paragraph("Mutexes and services / scheduled tasks (full report)", h2))
    story.extend(_chunked_tables(["Mutex"], [[r[0]] for r in digest.mutex_rows], [6.1 * inch], body, mono))
    story.append(Spacer(1, 0.06 * inch))
    story.extend(
        _chunked_tables(
            ["Name / item", "Path / command", "Kind"],
            [[r[0], r[1], r[2]] for r in digest.service_task_rows],
            [1.4 * inch, 4.0 * inch, 0.7 * inch],
            body,
            mono,
        )
    )
    story.append(Spacer(1, 0.08 * inch))
    story.append(Paragraph("Execution timeline (full report)", h2))
    story.extend(
        _chunked_tables(
            ["Time", "Type", "Detail"],
            [[r[0], r[1], r[2]] for r in digest.timeline_rows],
            [0.9 * inch, 0.9 * inch, 4.3 * inch],
            body,
            mono,
        )
    )
    story.append(PageBreak())

    # Network activity
    story.append(Paragraph("Network Activity", h1))
    story.append(Paragraph("DNS Queries", h2))
    dns_rows: list[list[str]] = []
    dns = summary.get("dns_requests") if isinstance(summary.get("dns_requests"), list) else []
    for d in dns:
        if isinstance(d, dict):
            dns_rows.append([str(d.get("domain") or d.get("host") or d), str(d.get("ip") or d.get("resolved_ip") or ""), str(d.get("timestamp") or d.get("time") or "")])
        else:
            dns_rows.append([str(d), "", ""])
    story.extend(_chunked_tables(["Domain Queried", "Resolved IP(s)", "Timestamp"], dns_rows, [2.5 * inch, 1.7 * inch, 1.9 * inch], body, mono))
    story.append(Spacer(1, 0.08 * inch))

    story.append(Paragraph("HTTP Requests", h2))
    http_rows: list[list[str]] = []
    http = summary.get("http_requests") if isinstance(summary.get("http_requests"), list) else []
    for h in http:
        if isinstance(h, dict):
            http_rows.append(
                [
                    str(h.get("method") or ""),
                    str(h.get("url") or h.get("uri") or ""),
                    str(h.get("user_agent") or ""),
                    str(h.get("response_code") or h.get("status") or ""),
                    str(h.get("content_length") or h.get("length") or ""),
                    str(h.get("timestamp") or h.get("time") or ""),
                ]
            )
        else:
            http_rows.append(["", str(h), "", "", "", ""])
    story.extend(
        _chunked_tables(
            ["Method", "Full URL", "User-Agent", "Response", "Length", "Timestamp"],
            http_rows,
            [0.6 * inch, 2.0 * inch, 1.2 * inch, 0.7 * inch, 0.6 * inch, 1.0 * inch],
            body,
            mono,
        )
    )
    story.append(Spacer(1, 0.08 * inch))

    story.append(Paragraph("Raw Connections", h2))
    conn_rows: list[list[str]] = []
    conns = summary.get("network_streams") if isinstance(summary.get("network_streams"), list) else []
    for c in conns:
        if isinstance(c, dict):
            src = f"{c.get('src_ip') or c.get('source_ip') or ''}:{c.get('src_port') or ''}"
            dst = f"{c.get('dst_ip') or c.get('destination_ip') or ''}:{c.get('dst_port') or ''}"
            conn_rows.append([src, dst, str(c.get("protocol") or c.get("transport") or ""), str(c.get("bytes_sent") or c.get("sent") or ""), str(c.get("bytes_received") or c.get("received") or "")])
        else:
            conn_rows.append(["", str(c), "", "", ""])
    story.extend(
        _chunked_tables(
            ["Source IP:Port", "Destination IP:Port", "Protocol", "Bytes Sent", "Bytes Received"],
            conn_rows,
            [1.5 * inch, 1.7 * inch, 0.8 * inch, 1.0 * inch, 1.1 * inch],
            body,
            mono,
        )
    )
    story.append(Spacer(1, 0.08 * inch))

    if digest.network_dns_rows or digest.network_http_rows or digest.network_ip_rows:
        story.append(Paragraph("Network flows (full JSON report — behavior.network)", h2))
        story.extend(
            _chunked_tables(
                ["Proto", "Domain / host", "IP", "Port", "Request / detail"],
                [[r[0], r[1], r[2], r[3], r[4] if len(r) > 4 else ""] for r in digest.network_dns_rows],
                [0.5 * inch, 1.6 * inch, 1.2 * inch, 0.5 * inch, 2.3 * inch],
                body,
                mono,
            )
        )
        story.append(Spacer(1, 0.06 * inch))
        story.extend(
            _chunked_tables(
                ["Proto", "URI / URL", "IP", "Port"],
                [[r[0], r[1], r[2], r[3]] for r in digest.network_http_rows],
                [0.5 * inch, 3.5 * inch, 1.2 * inch, 0.9 * inch],
                body,
                mono,
            )
        )
        story.append(Spacer(1, 0.06 * inch))
        story.extend(
            _chunked_tables(
                ["IP", "Port", "Proto", "Related domain"],
                [[r[0], r[1], r[2], r[3] if len(r) > 3 else ""] for r in digest.network_ip_rows],
                [1.3 * inch, 0.7 * inch, 0.8 * inch, 3.3 * inch],
                body,
                mono,
            )
        )
        story.append(Spacer(1, 0.08 * inch))

    story.append(Paragraph("Compromised / Flagged Hosts", h2))
    host_rows: list[list[str]] = []
    hosts = summary.get("compromised_hosts") if isinstance(summary.get("compromised_hosts"), list) else []
    for h in hosts:
        if isinstance(h, dict):
            host_rows.append([str(h.get("host") or h.get("ip") or h.get("domain") or ""), str(h.get("reason") or h.get("category") or "")])
        else:
            host_rows.append([str(h), ""])
    story.append(_data_table(["IP/Domain", "Reason"], host_rows, [2.5 * inch, 3.6 * inch], body, mono))
    story.append(Spacer(1, 0.08 * inch))
    story.append(Paragraph(f"PCAP Summary: {_esc(json.dumps(pcap_summary, ensure_ascii=False, default=str))}", small))
    story.append(PageBreak())

    # Dropped files
    story.append(Paragraph("Dropped Files", h1))
    if dropped:
        d_rows = []
        for d in dropped:
            if not isinstance(d, dict):
                continue
            d_rows.append(
                [
                    str(d.get("filename") or d.get("name") or ""),
                    str(d.get("filepath") or d.get("path") or ""),
                    str(d.get("size") or ""),
                    str(d.get("md5") or ""),
                    str(d.get("sha256") or ""),
                    str(d.get("verdict") or d.get("type") or ""),
                ]
            )
        story.extend(
            _chunked_tables(
                ["Name", "Drop Path", "Size", "MD5", "SHA256", "Verdict"],
                d_rows,
                [0.9 * inch, 1.5 * inch, 0.5 * inch, 1.0 * inch, 1.2 * inch, 0.8 * inch],
                body,
                mono,
            )
        )
    elif digest.dropped_file_rows:
        story.extend(
            _chunked_tables(
                ["SHA256 / hash", "Path / name", "Type / size"],
                [[r[0], r[1], r[2]] for r in digest.dropped_file_rows],
                [1.3 * inch, 3.5 * inch, 1.3 * inch],
                body,
                mono,
            )
        )
    else:
        story.append(Paragraph("No dropped-file rows from dropped-files or dropped-files-v2 API.", body))
    story.append(PageBreak())

    # Execution screenshots
    story.append(Paragraph("Execution Screenshots", h1))
    raw_sh = sup.get("screenshots")
    story.append(
        Paragraph(
            _esc(
                f"API screenshot JSON: type={type(raw_sh).__name__}; "
                f"embedded decodes for PDF: {len(screenshots)} image(s)."
            ),
            small,
        )
    )
    story.extend(_json_block("Screenshots API (redacted, large fields elided)", _redact_nested_blobs(raw_sh), mono, body, max_lines=400))
    shot_index_rows = digest.screenshot_index
    if shot_index_rows:
        story.append(_data_table(["#", "Name/Slot", "Reference"], shot_index_rows, [0.5 * inch, 1.8 * inch, 3.8 * inch], body, mono))
        story.append(Spacer(1, 0.08 * inch))
    if screenshots:
        for i, shot in enumerate(screenshots[: cfg.max_embedded_screenshots], start=1):
            if not isinstance(shot, dict):
                continue
            blob = shot.get("bytes")
            if not isinstance(blob, (bytes, bytearray)):
                continue
            ts = shot.get("timestamp") or shot.get("time") or "timestamp not returned by API"
            story.append(Paragraph(f"Screenshot #{i} — {_esc(ts)}", h2))
            try:
                img = Image(BytesIO(bytes(blob)))
                img._restrictSize(6.1 * inch, 8.5 * inch)
                story.append(img)
            except (OSError, ValueError) as exc:
                story.append(Paragraph(_esc(f"Image decode failed ({type(exc).__name__}); raw size {len(bytes(blob))} bytes."), body))
            story.append(Spacer(1, 0.06 * inch))
    else:
        if shot_index_rows:
            story.append(
                Paragraph(
                    "Screenshot metadata rows exist but no PNG/JPEG/GIF/WEBP/BMP bytes were produced. See redacted JSON block above for API payload shape.",
                    body,
                )
            )
        else:
            story.append(Paragraph("Screenshots endpoint returned no list/metadata for this job.", body))
    story.append(PageBreak())

    # Threat classification
    story.append(Paragraph("Threat Classification", h1))
    story.append(Paragraph(f"<font color='{verdict_color}'><b>Verdict:</b> {_esc(verdict)}</font>", body))
    story.append(Paragraph(f"<b>Malware Family:</b> {_esc(family)}", body))
    story.append(Paragraph(f"<b>Threat Score:</b> {_esc(score)}/100", body))
    story.extend(_json_block("Tags", summary.get("classification_tags"), mono, body))
    story.extend(_json_block("MITRE ATT&CK", summary.get("mitre_attcks") or summary.get("mitre_attacks"), mono, body))
    story.append(PageBreak())

    # IOC section
    story.append(Paragraph("Indicators of Compromise", h1))
    ioc = build_ioc_summary(summary, processes, dropped)
    _ioc_merge_digest(ioc, digest)
    story.append(Paragraph("FILE HASHES", h2))
    story.append(_data_table(["MD5", "SHA1", "SHA256", "File Name"], [[str(summary.get("md5") or ""), str(summary.get("sha1") or ""), str(summary.get("sha256") or ""), str(summary.get("submit_name") or source_file.name)]], [1.4 * inch, 1.4 * inch, 2.2 * inch, 1.1 * inch], body, mono))
    story.append(Spacer(1, 0.06 * inch))
    story.append(Paragraph("IP ADDRESSES", h2))
    story.append(_data_table(["IP"], [[x] for x in ioc["ips"]], [6.1 * inch], body, mono))
    story.append(Spacer(1, 0.06 * inch))
    story.append(Paragraph("DOMAINS", h2))
    story.append(_data_table(["Domain"], [[x] for x in ioc["domains"]], [6.1 * inch], body, mono))
    story.append(Spacer(1, 0.06 * inch))
    story.append(Paragraph("URLS", h2))
    story.append(_data_table(["URL"], [[x] for x in ioc["urls"]], [6.1 * inch], body, mono))
    story.append(Spacer(1, 0.06 * inch))
    story.append(Paragraph("REGISTRY KEYS", h2))
    story.append(_data_table(["Registry Key"], [[x] for x in ioc["regkeys"]], [6.1 * inch], body, mono))
    story.append(Spacer(1, 0.06 * inch))
    story.append(Paragraph("FILE PATHS", h2))
    story.append(_data_table(["Path"], [[x] for x in ioc["filepaths"]], [6.1 * inch], body, mono))
    story.append(Spacer(1, 0.06 * inch))
    story.append(Paragraph("MUTEX NAMES", h2))
    story.append(_data_table(["Mutex"], [[x] for x in ioc["mutexes"]], [6.1 * inch], body, mono))
    story.append(PageBreak())

    # Recommendations (data-tied)
    story.append(Paragraph("Recommendations", h1))
    story.append(Paragraph(_esc(build_recommendation_text(summary, ioc)), body))
    story.append(PageBreak())

    # Appendix
    story.append(Paragraph("Appendix", h1))
    story.append(Paragraph("Flattened summary keys (all scalar / compact JSON values returned by API)", h2))
    story.extend(
        _chunked_tables(
            ["Key", "Value"],
            [[k, v] for k, v in digest.classification_rows],
            [2.2 * inch, 3.9 * inch],
            body,
            mono,
        )
    )
    story.append(PageBreak())
    story.append(Paragraph("Telemetry path index (summary + report branches)", h2))
    for ln in digest.appendix_telemetry_lines[:900]:
        story.append(Paragraph(_esc(ln), mono))
    story.append(PageBreak())
    story.extend(_json_block("Analysis Environment", {"environment_description": summary.get("environment_description"), "environment_id": summary.get("environment_id")}, mono, body))
    story.extend(_json_block("Summary JSON (full)", summary, mono, body, max_lines=12000))
    story.extend(_json_block("Full report JSON (full)", outcome.full_report, mono, body, max_lines=12000))
    story.extend(_json_block("Memory Dump Notes", memory_dumps, mono, body))
    story.extend(_json_block("Hash Verification", {"md5": summary.get("md5"), "sha1": summary.get("sha1"), "sha256": summary.get("sha256")}, mono, body))

    doc.multiBuild(story, onFirstPage=_draw_page_frame, onLaterPages=_draw_page_frame)
    return dest_path


def build_ioc_summary(summary: dict[str, Any], processes: list[Any], dropped: list[Any]) -> dict[str, list[str]]:
    hashes = [str(x) for x in [summary.get("md5"), summary.get("sha1"), summary.get("sha256")] if x]
    ips: list[str] = []
    domains: list[str] = []
    urls: list[str] = []
    regkeys: list[str] = []
    filepaths: list[str] = []
    mutexes: list[str] = []
    for arr_name, sink in (("dns_requests", domains), ("compromised_hosts", domains), ("http_requests", urls), ("network_streams", ips)):
        arr = summary.get(arr_name)
        if isinstance(arr, list):
            for x in arr:
                sink.append(str(x))
    for p in processes:
        if not isinstance(p, dict):
            continue
        for key in ("registry_keys_set", "registry_keys_deleted"):
            if isinstance(p.get(key), list):
                for x in p.get(key):
                    if isinstance(x, dict):
                        regkeys.append(str(x.get("key") or x.get("path") or x.get("name") or x))
                    else:
                        regkeys.append(str(x))
        for key in ("created_files", "deleted_files"):
            if isinstance(p.get(key), list):
                filepaths.extend(str(x) for x in p.get(key))
        if isinstance(p.get("mutants"), list):
            mutexes.extend(str(x) for x in p.get("mutants"))
    for d in dropped:
        if isinstance(d, dict):
            if d.get("sha256"):
                hashes.append(str(d.get("sha256")))
            if d.get("filepath") or d.get("path"):
                filepaths.append(str(d.get("filepath") or d.get("path")))
    return {
        "hashes": sorted(set(hashes)),
        "ips": sorted(set(ips)),
        "domains": sorted(set(domains)),
        "urls": sorted(set(urls)),
        "regkeys": sorted(set(regkeys)),
        "filepaths": sorted(set(filepaths)),
        "mutexes": sorted(set(mutexes)),
    }


def build_recommendation_text(summary: dict[str, Any], ioc: dict[str, list[str]]) -> str:
    verdict = str(summary.get("verdict") or "unknown").lower()
    if verdict in ("malicious", "suspicious"):
        return (
            f"Contain hosts that contacted: {', '.join(ioc['ips'][:10]) or 'No activity observed — API returned no IP indicators'}. "
            f"Block domains: {', '.join(ioc['domains'][:10]) or 'No activity observed — API returned no domain indicators'}. "
            f"Monitor process and registry artifacts from IOC block for detection coverage."
        )
    return "No activity observed — API verdict does not indicate malicious or suspicious behavior requiring containment."


def _json_block(
    title: str,
    payload: Any,
    mono: ParagraphStyle,
    body: ParagraphStyle,
    *,
    max_lines: int = 8000,
) -> list[Any]:
    out: list[Any] = [Paragraph(_esc(title), body)]
    if payload in (None, [], {}):
        out.append(Paragraph("No activity observed — endpoint returned empty payload.", body))
        out.append(Spacer(1, 0.06 * inch))
        return out
    try:
        blob = json.dumps(payload, indent=2, ensure_ascii=False, default=str)
    except (TypeError, ValueError):
        blob = str(payload)
    lines = blob.splitlines()
    cap = min(len(lines), max_lines)
    for i, ln in enumerate(lines[:cap]):
        if i > 0 and i % 95 == 0:
            out.append(PageBreak())
            out.append(Paragraph(_esc(f"{title} (continued)"), body))
        out.append(Paragraph(_esc(ln), mono))
    if len(lines) > cap:
        out.append(Paragraph(_esc(f"… truncated after {cap} lines ({len(lines)} total)."), body))
    out.append(Spacer(1, 0.06 * inch))
    return out


def _process_tree_lines(by_pid: dict[str, dict[str, Any]], children: dict[str, list[str]]) -> list[str]:
    roots = [pid for pid in by_pid.keys() if str(by_pid.get(pid, {}).get("parentpid") or by_pid.get(pid, {}).get("ppid") or "") not in by_pid]
    roots = roots or list(by_pid.keys())
    out: list[str] = []

    def walk(pid: str, depth: int) -> None:
        node = by_pid.get(pid) or {}
        prefix = "  " * depth + ("- " if depth else "")
        out.append(f"{prefix}{pid} | {node.get('name') or ''} | {node.get('normalized_path') or node.get('path') or ''}")
        for ch in children.get(pid, []):
            if ch != pid:
                walk(ch, depth + 1)

    for root in roots[:80]:
        walk(root, 0)
    return out or ["No activity observed — no process hierarchy returned by API."]


def _draw_page_frame(canvas: Any, doc: _HADocTemplate) -> None:
    canvas.saveState()
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(colors.HexColor("#546e7a"))
    canvas.drawString(doc.leftMargin, doc.height + doc.topMargin + 8, f"Report ID: {doc._report_id}")
    canvas.drawRightString(doc.pagesize[0] - doc.rightMargin, doc.height + doc.topMargin + 8, f"Classification: {doc._classification}")
    canvas.drawCentredString(doc.pagesize[0] / 2.0, 0.35 * inch, f"Page {canvas.getPageNumber()}")
    canvas.restoreState()


def _chunked_tables(
    headers: list[str],
    rows: list[list[str]],
    widths: list[float],
    body: ParagraphStyle,
    mono: ParagraphStyle,
    *,
    chunk_size: int = 90,
) -> list[Any]:
    blocks: list[Any] = []
    if not rows:
        return [_data_table(headers, rows, widths, body, mono)]
    total = len(rows)
    for start in range(0, total, chunk_size):
        end = min(start + chunk_size, total)
        blocks.append(_data_table(headers, rows[start:end], widths, body, mono))
        if end < total:
            blocks.append(Spacer(1, 0.04 * inch))
            blocks.append(Paragraph(_esc(f"(continued: rows {start + 1}–{end} of {total})"), body))
    return blocks


def _ioc_merge_digest(ioc: dict[str, list[str]], digest: Any) -> None:
    for row in getattr(digest, "network_dns_rows", []) or []:
        if len(row) > 1 and row[1]:
            ioc.setdefault("domains", []).append(str(row[1]))
        if len(row) > 2 and row[2]:
            ip = str(row[2])
            if _looks_like_ip(ip):
                ioc.setdefault("ips", []).append(ip)
    for row in getattr(digest, "network_http_rows", []) or []:
        if len(row) > 1 and row[1]:
            ioc.setdefault("urls", []).append(str(row[1]))
        if len(row) > 2 and row[2] and _looks_like_ip(str(row[2])):
            ioc.setdefault("ips", []).append(str(row[2]))
    for row in getattr(digest, "network_ip_rows", []) or []:
        if row and row[0]:
            ioc.setdefault("ips", []).append(str(row[0]))
    for row in getattr(digest, "mutex_rows", []) or []:
        if row and row[0]:
            ioc.setdefault("mutexes", []).append(str(row[0]))
    for row in getattr(digest, "registry_rows", []) or []:
        if len(row) > 1 and row[1]:
            ioc.setdefault("regkeys", []).append(str(row[1]))
    for row in getattr(digest, "file_activity_rows", []) or []:
        if len(row) > 1 and row[1]:
            ioc.setdefault("filepaths", []).append(str(row[1]))
    for key in ("ips", "domains", "urls", "mutexes", "regkeys", "filepaths", "hashes"):
        if key in ioc and isinstance(ioc[key], list):
            ioc[key] = sorted(set(ioc[key]))


def _looks_like_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s.strip().split("%", 1)[0])
        return True
    except ValueError:
        return False


def _data_table(headers: list[str], rows: list[list[str]], widths: list[float], body: ParagraphStyle, mono: ParagraphStyle) -> Table:
    if not rows:
        rows = [["No activity observed — endpoint returned empty payload."] + [""] * (len(headers) - 1)]
    data = [[Paragraph(f"<b>{_esc(h)}</b>", body) for h in headers]]
    data.extend([[Paragraph(_esc(c), mono) for c in r] for r in rows])
    t = Table(data, colWidths=widths, repeatRows=1)
    t.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1d3557")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                ("GRID", (0, 0), (-1, -1), 0.2, colors.HexColor("#b0bec5")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f1f5f9")]),
            ]
        )
    )
    return t


def _kv_table(rows: list[list[Any]], body: ParagraphStyle, mono: ParagraphStyle) -> Table:
    data = [[Paragraph(_esc(str(k)), body), Paragraph(_esc(str(v) if v is not None else "No activity observed — field not returned by API"), mono)] for k, v in rows]
    t = Table(data, colWidths=[2.1 * inch, 4.0 * inch])
    t.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.2, colors.HexColor("#90a4ae")), ("VALIGN", (0, 0), (-1, -1), "TOP")]))
    return t


def _verdict_color(verdict: str) -> str:
    v = verdict.lower()
    if v == "malicious":
        return "#d32f2f"
    if v == "suspicious":
        return "#ef6c00"
    if v in ("clean", "no specific threat"):
        return "#2e7d32"
    return "#616161"


def _extract_classification_signals(summary: dict[str, Any], full_report: dict[str, Any] | list[Any]) -> list[tuple[str, str]]:
    rows: list[tuple[str, str]] = []
    rows.append(("Verdict", str(summary.get("verdict") or "No activity observed — field not returned by API")))
    rows.append(("Threat Score", str(summary.get("threat_score") or "No activity observed — field not returned by API")))
    rows.append(("Family", str(summary.get("vx_family") or "No activity observed — field not returned by API")))
    tags = summary.get("classification_tags") if isinstance(summary.get("classification_tags"), list) else []
    if tags:
        rows.append(("Classification Tags", ", ".join(str(x) for x in tags[:30])))
    else:
        rows.append(("Classification Tags", "No activity observed — API returned empty tags"))
    text_blob_parts: list[str] = []
    for source in (
        summary.get("vx_family"),
        summary.get("verdict"),
        summary.get("threat_level"),
        ", ".join(str(x) for x in tags),
    ):
        if source:
            text_blob_parts.append(str(source))
    if isinstance(full_report, dict):
        sigs = full_report.get("signatures")
        if isinstance(sigs, list):
            for s in sigs[:80]:
                if isinstance(s, dict):
                    text_blob_parts.append(str(s.get("name") or s.get("threat") or s.get("description") or ""))
                else:
                    text_blob_parts.append(str(s))
    blob = " ".join(text_blob_parts).lower()
    families = []
    for key in ("ransom", "trojan", "worm", "backdoor", "stealer", "dropper", "loader", "botnet", "spyware", "keylogger"):
        if key in blob:
            families.append(key)
    rows.append(("Detected Classification Keywords", ", ".join(sorted(set(families))) if families else "No activity observed — none present in API text fields"))
    return rows


def _esc(text: str) -> str:
    return str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


__all__ = ["build_analysis_pdf", "build_ioc_summary"]
