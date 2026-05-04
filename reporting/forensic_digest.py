"""
Deep extraction of Falcon Sandbox / Hybrid Analysis telemetry for long-form forensic PDFs.
Handles multiple JSON shapes defensively (missing keys are normal across sample types).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any


def _as_list(x: Any) -> list[Any]:
    if x is None:
        return []
    if isinstance(x, list):
        return x
    if isinstance(x, dict):
        return [x]
    return []


def _s(v: Any, limit: int = 2000) -> str:
    if v is None:
        return ""
    t = str(v).replace("\r", " ").replace("\n", " ")
    if len(t) > limit:
        return t[: limit - 1] + "…"
    return t


def _uniq(seq: list[str], cap: int | None = None) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for x in seq:
        x = x.strip()
        if not x or x in seen:
            continue
        seen.add(x)
        out.append(x)
        if cap is not None and len(out) >= cap:
            break
    return out


def _flatten_summary_kv(summary: dict[str, Any], prefix: str = "") -> list[tuple[str, str]]:
    rows: list[tuple[str, str]] = []
    for k, v in summary.items():
        key = f"{prefix}{k}" if not prefix else f"{prefix}.{k}"
        if isinstance(v, (dict, list)):
            try:
                compact = json.dumps(v, ensure_ascii=False, default=str)[:1800]
            except (TypeError, ValueError):
                compact = str(v)[:1800]
            rows.append((key, compact))
        else:
            rows.append((key, _s(v, 4000)))
    rows.sort(key=lambda x: x[0].lower())
    return rows


def _dig(root: dict[str, Any], *path: str) -> Any:
    cur: Any = root
    for p in path:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(p)
    return cur


def _enrich_root_from_summary(root: dict[str, Any], summary: dict[str, Any]) -> dict[str, Any]:
    """
    When full /report/{job}/report/json is empty or 403, the job summary often still
    contains processes, network, and registry slices matching the web UI.
    """
    if not isinstance(summary, dict):
        return root
    out = dict(root)
    beh = dict(out.get("behavior") or {}) if isinstance(out.get("behavior"), dict) else {}

    if summary.get("processes"):
        if not out.get("processes"):
            out["processes"] = summary["processes"]
        if not beh.get("processes"):
            beh["processes"] = summary["processes"]

    pt = summary.get("process_tree")
    if isinstance(pt, dict) and not out.get("process_tree"):
        out["process_tree"] = pt
    if isinstance(pt, dict) and not beh.get("process_tree"):
        beh["process_tree"] = pt

    for key in ("signatures", "mitre_attcks", "mitre_attacks"):
        if summary.get(key) and not out.get(key):
            out[key] = summary[key]

    for rk in ("registry_keys_set", "registry_keys_deleted", "registry_keys_monitored"):
        if summary.get(rk) and not beh.get(rk):
            beh[rk] = summary[rk]

    for fk in ("extracted_files", "dropped_files", "files_created", "files_modified", "files_deleted", "file_created"):
        if summary.get(fk) and not out.get(fk):
            out[fk] = summary[fk]

    synth_flows: list[dict[str, Any]] = []
    for d in _as_list(summary.get("dns_requests")):
        if isinstance(d, dict):
            synth_flows.append(
                {
                    "protocol": "DNS",
                    "domain": d.get("domain") or d.get("host"),
                    "ip": d.get("ip") or d.get("resolved_ip"),
                    "request": d.get("request") or d.get("query"),
                }
            )
        elif isinstance(d, str) and d:
            synth_flows.append({"protocol": "DNS", "domain": d, "ip": "", "request": ""})
    for h in _as_list(summary.get("http_requests")):
        if isinstance(h, dict):
            synth_flows.append(
                {
                    "protocol": str(h.get("method") or "HTTP"),
                    "url": h.get("url") or h.get("uri"),
                    "uri": h.get("uri"),
                    "ip": h.get("host") or h.get("ip"),
                    "dport": h.get("port"),
                }
            )
    for c in _as_list(summary.get("network_streams")):
        if isinstance(c, dict):
            synth_flows.append(
                {
                    "protocol": c.get("protocol") or c.get("transport"),
                    "ip": c.get("dst_ip") or c.get("destination_ip"),
                    "domain": c.get("domain") or c.get("host"),
                    "dport": c.get("dst_port") or c.get("dport"),
                    "src_ip": c.get("src_ip") or c.get("source_ip"),
                }
            )

    if synth_flows:
        net = dict(beh.get("network") or {}) if isinstance(beh.get("network"), dict) else {}
        cur = _as_list(net.get("flows"))
        net["flows"] = cur + synth_flows
        beh["network"] = net

    if beh:
        out["behavior"] = beh
    return out


@dataclass
class ForensicDigest:
    """Structured material for a multi-section autopsy-style PDF."""

    exec_flow_narrative: list[str] = field(default_factory=list)
    process_rows: list[list[str]] = field(default_factory=list)
    file_activity_rows: list[list[str]] = field(default_factory=list)
    registry_rows: list[list[str]] = field(default_factory=list)
    network_dns_rows: list[list[str]] = field(default_factory=list)
    network_http_rows: list[list[str]] = field(default_factory=list)
    network_ip_rows: list[list[str]] = field(default_factory=list)
    mutex_rows: list[list[str]] = field(default_factory=list)
    service_task_rows: list[list[str]] = field(default_factory=list)
    signature_rows: list[list[str]] = field(default_factory=list)
    mitre_rows: list[list[str]] = field(default_factory=list)
    screenshot_index: list[list[str]] = field(default_factory=list)
    dropped_file_rows: list[list[str]] = field(default_factory=list)
    child_report_rows: list[list[str]] = field(default_factory=list)
    memory_string_rows: list[list[str]] = field(default_factory=list)
    classification_rows: list[list[str]] = field(default_factory=list)
    timeline_rows: list[list[str]] = field(default_factory=list)
    interesting_strings: list[str] = field(default_factory=list)
    appendix_telemetry_lines: list[str] = field(default_factory=list)


def _collect_process_rows(root: dict[str, Any]) -> list[list[str]]:
    rows: list[list[str]] = []
    seen: set[str] = set()

    def add_row(pid: str, ppid: str, name: str, cmd: str, src: str) -> None:
        key = f"{pid}|{name}|{cmd[:120]}"
        if key in seen:
            return
        seen.add(key)
        rows.append([_s(pid, 32), _s(ppid, 32), _s(name, 500), _s(cmd, 1200), _s(src, 40)])

    candidates: list[Any] = []
    candidates.extend(_as_list(root.get("processes")))
    beh = root.get("behavior")
    if isinstance(beh, dict):
        candidates.extend(_as_list(beh.get("processes")))
        candidates.extend(_as_list(beh.get("processtree")))
    candidates.extend(_as_list(_dig(root, "behavior", "processes")))

    for p in candidates:
        if not isinstance(p, dict):
            continue
        pid = p.get("pid") or p.get("process_id") or p.get("kpid") or ""
        ppid = p.get("ppid") or p.get("parent_id") or ""
        if isinstance(p.get("parent"), dict):
            ppid = ppid or p["parent"].get("pid") or p["parent"].get("process_id") or ""
        name = p.get("path") or p.get("process_name") or p.get("name") or ""
        cmd = p.get("command_line") or p.get("cmdline") or p.get("args") or ""
        add_row(str(pid), str(ppid), str(name), str(cmd), "processes")

    # Flatten process_tree
    def walk_tree(node: Any, src: str) -> None:
        if not isinstance(node, dict):
            return
        pid = node.get("pid") or node.get("process_id") or ""
        ppid = ""
        par = node.get("parent")
        if isinstance(par, dict):
            ppid = str(par.get("pid") or par.get("process_id") or "")
        name = node.get("path") or node.get("process_name") or node.get("name") or ""
        cmd = node.get("command_line") or node.get("cmdline") or ""
        add_row(str(pid), ppid, str(name), str(cmd), src)
        for ch in _as_list(node.get("children")):
            walk_tree(ch, src)

    for key in ("process_tree",):
        pt = root.get(key)
        if isinstance(pt, dict):
            walk_tree(pt, "process_tree")
        beh = root.get("behavior")
        if isinstance(beh, dict) and isinstance(beh.get("process_tree"), dict):
            walk_tree(beh["process_tree"], "behavior.process_tree")

    return rows[:800]


def _collect_file_rows(
    root: dict[str, Any], supplemental: dict[str, Any], summary: dict[str, Any] | None = None
) -> list[list[str]]:
    rows: list[list[str]] = []
    seen: set[str] = set()

    def add(action: str, path: str, extra: str, src: str) -> None:
        path = _s(path, 1500)
        if not path or path in seen:
            return
        seen.add(path)
        rows.append([_s(action, 40), path, _s(extra, 800), _s(src, 60)])

    for key in ("extracted_files", "dropped_files", "files_created", "files_modified", "files_deleted", "file_created"):
        block = root.get(key) or _dig(root, "behavior", key)
        for item in _as_list(block):
            if isinstance(item, dict):
                pth = item.get("path") or item.get("name") or item.get("filepath") or item.get("sha256") or ""
                act = item.get("action") or item.get("type") or "artifact"
                ex = item.get("type_tags") or item.get("size") or item.get("sha256") or ""
                add(str(act), str(pth), str(ex), key)
            elif isinstance(item, str):
                add("path", item, "", key)

    beh = root.get("behavior")
    if isinstance(beh, dict):
        for item in _as_list(beh.get("files")):
            if isinstance(item, dict):
                add(
                    str(item.get("event") or item.get("action") or "file"),
                    str(item.get("path") or item.get("srcpath") or ""),
                    str(item.get("type") or ""),
                    "behavior.files",
                )

    raw_drop = supplemental.get("dropped_files_v2")
    if isinstance(raw_drop, list):
        for item in raw_drop:
            if isinstance(item, dict):
                add(
                    "dropped",
                    str(item.get("path") or item.get("name") or item.get("sha256") or ""),
                    str(item.get("type") or item.get("size") or ""),
                    "API dropped-files-v2",
                )
    elif isinstance(raw_drop, dict):
        for item in _as_list(raw_drop.get("files") or raw_drop.get("dropped_files")):
            if isinstance(item, dict):
                add("dropped", str(item.get("path") or item.get("name") or ""), str(item.get("sha256") or ""), "API")

    sum_d = summary if isinstance(summary, dict) else {}
    for p in _as_list(sum_d.get("processes")):
        if not isinstance(p, dict):
            continue
        pid = str(p.get("pid") or "")
        for key, act in (("created_files", "created"), ("deleted_files", "deleted"), ("modified_files", "modified")):
            for fp in _as_list(p.get(key)):
                add(act, str(fp), f"pid={pid}", "summary.processes")
    return rows[:900]


def _collect_registry_rows(root: dict[str, Any], summary: dict[str, Any] | None = None) -> list[list[str]]:
    rows: list[list[str]] = []
    beh = root.get("behavior")
    if not isinstance(beh, dict):
        beh = {}
    blocks = [
        beh.get("registry_keys_set"),
        beh.get("registry_keys_deleted"),
        beh.get("registry_keys_monitored"),
        root.get("registry_keys_set"),
    ]
    seen: set[str] = set()
    for block in blocks:
        for item in _as_list(block):
            if isinstance(item, dict):
                k = str(item.get("key") or item.get("path") or item.get("name") or "")
                v = str(item.get("value") or item.get("data") or "")
                act = str(item.get("action") or item.get("event") or "registry")
                line = f"{act}|{k}|{v}"
                if k and line not in seen:
                    seen.add(line)
                    rows.append([_s(act, 24), _s(k, 900), _s(v, 600)])
            elif isinstance(item, str) and item not in seen:
                seen.add(item)
                rows.append(["set", _s(item, 1200), ""])

    s = summary if isinstance(summary, dict) else {}
    for block_name, act in (
        ("registry_keys_set", "set"),
        ("registry_keys_deleted", "delete"),
        ("registry_keys_monitored", "monitored"),
    ):
        for item in _as_list(s.get(block_name)):
            if isinstance(item, dict):
                k = str(item.get("key") or item.get("path") or item.get("name") or "")
                v = str(item.get("value") or item.get("data") or "")
                line = f"{act}|{k}|{v}"
                if k and line not in seen:
                    seen.add(line)
                    rows.append([_s(act, 24), _s(k, 900), _s(v, 600)])
            elif isinstance(item, str) and item not in seen:
                seen.add(item)
                rows.append([act, _s(item, 1200), ""])

    for p in _as_list(s.get("processes")):
        if not isinstance(p, dict):
            continue
        pid = str(p.get("pid") or "")
        for key, act in (("registry_keys_set", "set"), ("registry_keys_deleted", "delete")):
            for rk in _as_list(p.get(key)):
                if isinstance(rk, str):
                    line = f"{act}|{rk}|{pid}"
                    if line not in seen:
                        seen.add(line)
                        rows.append([_s(act, 24), _s(rk, 900), f"pid={pid}"])
                elif isinstance(rk, dict):
                    k = str(rk.get("key") or rk.get("path") or rk.get("name") or "")
                    v = str(rk.get("value") or rk.get("data") or "")
                    line = f"{act}|{k}|{v}|{pid}"
                    if k and line not in seen:
                        seen.add(line)
                        rows.append([_s(act, 24), _s(k, 900), _s(v, 600)])
    return rows[:800]


def _collect_network_rows(root: dict[str, Any]) -> tuple[list[list[str]], list[list[str]], list[list[str]]]:
    dns_r: list[list[str]] = []
    http_r: list[list[str]] = []
    ip_r: list[list[str]] = []
    seen_d: set[str] = set()
    seen_h: set[str] = set()
    seen_i: set[str] = set()

    net = root.get("network")
    if not isinstance(net, dict):
        net = {}
    beh = root.get("behavior")
    if isinstance(beh, dict) and isinstance(beh.get("network"), dict):
        # merge keys from behavior.network
        for k, v in beh["network"].items():
            if k not in net or net.get(k) in (None, [], {}):
                net[k] = v

    for fl in _as_list(net.get("flows") or net.get("connections") or net.get("packets")):
        if not isinstance(fl, dict):
            continue
        proto = str(fl.get("protocol") or fl.get("transport") or "")
        dom = str(fl.get("domain") or fl.get("host") or "")
        ip = str(fl.get("ip") or fl.get("dst_ip") or fl.get("destination_ip") or "")
        port = str(fl.get("dport") or fl.get("port") or "")
        uri = str(fl.get("uri") or fl.get("url") or "")
        if dom and f"dns|{dom}" not in seen_d:
            seen_d.add(f"dns|{dom}")
            dns_r.append([proto, dom, ip, port, _s(fl.get("request") or "", 400)])
        if uri and f"http|{uri}" not in seen_h:
            seen_h.add(f"http|{uri}")
            http_r.append([proto, _s(uri, 1500), ip, port])
        if ip and re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip) and ip not in seen_i:
            seen_i.add(ip)
            ip_r.append([ip, port, proto, dom])

    return dns_r[:400], http_r[:400], ip_r[:300]


def _collect_mutex_service(
    root: dict[str, Any], summary: dict[str, Any] | None = None
) -> tuple[list[list[str]], list[list[str]]]:
    mutex: list[list[str]] = []
    svc: list[list[str]] = []
    beh = root.get("behavior")
    if not isinstance(beh, dict):
        beh = {}
    for m in _as_list(beh.get("mutexes_spawned") or beh.get("mutexes") or root.get("mutexes")):
        if isinstance(m, dict):
            mutex.append([_s(m.get("name") or m.get("mutex") or m, 500)])
        elif isinstance(m, str):
            mutex.append([_s(m, 500)])
    for item in _as_list(beh.get("services_created") or beh.get("services") or root.get("services")):
        if isinstance(item, dict):
            svc.append([_s(item.get("name"), 200), _s(item.get("path") or item.get("image"), 800), _s(item.get("action"), 80)])
        elif isinstance(item, str):
            svc.append([_s(item, 400), "", ""])
    for item in _as_list(beh.get("tasks") or beh.get("scheduled_tasks") or root.get("tasks")):
        if isinstance(item, dict):
            svc.append([_s(item.get("name") or item.get("task"), 200), _s(item.get("command") or item.get("path"), 800), "task"])

    s = summary if isinstance(summary, dict) else {}
    for m in _as_list(s.get("mutexes")):
        if isinstance(m, dict):
            mutex.append([_s(m.get("name") or m.get("mutex") or m, 500)])
        elif isinstance(m, str):
            mutex.append([_s(m, 500)])
    for p in _as_list(s.get("processes")):
        if not isinstance(p, dict):
            continue
        for m in _as_list(p.get("mutants") or p.get("mutexes")):
            if isinstance(m, dict):
                mutex.append([_s(m.get("name") or m.get("mutex") or m, 500)])
            elif isinstance(m, str):
                mutex.append([_s(m, 500)])
    return mutex[:200], svc[:250]


def _collect_signatures_mitre(
    root: dict[str, Any], summary: dict[str, Any] | None = None
) -> tuple[list[list[str]], list[list[str]]]:
    sigs: list[list[str]] = []
    mitre: list[list[str]] = []
    for sig in _as_list(root.get("signatures") or root.get("classification") or _dig(root, "behavior", "signatures")):
        if isinstance(sig, dict):
            sigs.append(
                [
                    _s(sig.get("threat") or sig.get("name") or sig.get("identifier"), 200),
                    _s(sig.get("category") or sig.get("origin"), 120),
                    _s(sig.get("description") or sig.get("detail"), 1200),
                ]
            )
        elif isinstance(sig, str):
            sigs.append([_s(sig, 400), "", ""])
    for m in _as_list(root.get("mitre_attcks") or root.get("mitre_attacks") or root.get("mitre")):
        if isinstance(m, dict):
            mitre.append([_s(m.get("tactic"), 120), _s(m.get("technique"), 120), _s(m.get("identifier") or m.get("id"), 80), _s(m.get("description"), 800)])
        elif isinstance(m, str):
            mitre.append(["", "", _s(m, 80), ""])

    s = summary if isinstance(summary, dict) else {}
    if not sigs:
        for sig in _as_list(s.get("signatures")):
            if isinstance(sig, dict):
                sigs.append(
                    [
                        _s(sig.get("threat") or sig.get("name") or sig.get("identifier"), 200),
                        _s(sig.get("category") or sig.get("origin"), 120),
                        _s(sig.get("description") or sig.get("detail"), 1200),
                    ]
                )
            elif isinstance(sig, str):
                sigs.append([_s(sig, 400), "", ""])
    if not mitre:
        for m in _as_list(s.get("mitre_attcks") or s.get("mitre_attacks") or s.get("mitre")):
            if isinstance(m, dict):
                mitre.append(
                    [_s(m.get("tactic"), 120), _s(m.get("technique"), 120), _s(m.get("identifier") or m.get("id"), 80), _s(m.get("description"), 800)]
                )
            elif isinstance(m, str):
                mitre.append(["", "", _s(m, 80), ""])
    return sigs[:350], mitre[:120]


def _collect_timeline(root: dict[str, Any], summary: dict[str, Any] | None = None) -> list[list[str]]:
    rows: list[list[str]] = []
    beh = root.get("behavior")
    if isinstance(beh, dict):
        for ev in _as_list(beh.get("processes")):
            if isinstance(ev, dict) and (ev.get("time") or ev.get("timestamp")):
                rows.append([_s(ev.get("time") or ev.get("timestamp"), 40), "process", _s(ev.get("path") or ev.get("action"), 1200)])
    for ev in _as_list(root.get("timeline")):
        if isinstance(ev, dict):
            rows.append([_s(ev.get("time") or ev.get("timestamp"), 40), _s(ev.get("type") or "event", 40), _s(ev.get("message") or ev.get("action") or ev, 1200)])
    s = summary if isinstance(summary, dict) else {}
    for ev in _as_list(s.get("processes")):
        if isinstance(ev, dict) and (ev.get("time") or ev.get("timestamp")):
            rows.append(
                [
                    _s(ev.get("time") or ev.get("timestamp"), 40),
                    "process",
                    _s(ev.get("path") or ev.get("process_name") or ev.get("name") or ev.get("action"), 1200),
                ]
            )
    return rows[:500]


def _collect_interesting_strings(root: dict[str, Any], summary: dict[str, Any]) -> list[str]:
    out: list[str] = []
    for block in (summary.get("interesting"), root.get("interesting_strings"), _dig(root, "static", "interesting_strings")):
        for x in _as_list(block):
            if isinstance(x, str):
                out.append(x)
            elif isinstance(x, dict):
                out.append(_s(x.get("string") or x.get("value") or x, 500))
    return _uniq(out, 400)


def _screenshot_rows(supplemental: dict[str, Any]) -> list[list[str]]:
    rows: list[list[str]] = []
    raw = supplemental.get("screenshots")
    if isinstance(raw, list):
        for i, item in enumerate(raw):
            if isinstance(item, dict):
                img = item.get("image") or item.get("Image")
                ref = item.get("screenshot") or item.get("url") or item.get("path") or ""
                if isinstance(img, str) and img.strip():
                    ref = f"base64 image ({len(img)} chars)"
                rows.append(
                    [
                        str(i + 1),
                        _s(item.get("name") or item.get("file") or item.get("id"), 200),
                        _s(ref, 800),
                    ]
                )
            else:
                rows.append([str(i + 1), _s(item, 400), ""])
    elif isinstance(raw, dict):
        for k, v in list(raw.items())[:80]:
            rows.append([_s(k, 40), _s(v, 1200), ""])
    return rows[:120]


def _api_dropped_table(supplemental: dict[str, Any]) -> list[list[str]]:
    rows: list[list[str]] = []
    raw = supplemental.get("dropped_files_v2")
    items: list[Any] = []
    if isinstance(raw, list):
        items = raw
    elif isinstance(raw, dict):
        items = _as_list(raw.get("files") or raw.get("dropped_files") or raw.get("items"))
    for item in items[:500]:
        if isinstance(item, dict):
            rows.append(
                [
                    _s(item.get("sha256") or item.get("hash"), 80),
                    _s(item.get("path") or item.get("name"), 700),
                    _s(item.get("type") or item.get("size"), 120),
                ]
            )
    return rows


def _children_rows(supplemental: dict[str, Any]) -> list[list[str]]:
    rows: list[list[str]] = []
    raw = supplemental.get("children")
    if isinstance(raw, list):
        for item in raw:
            if isinstance(item, dict):
                rows.append(
                    [
                        _s(item.get("job_id") or item.get("id"), 80),
                        _s(item.get("state") or item.get("status"), 40),
                        _s(item.get("sha256") or item.get("type"), 80),
                        _s(item.get("environment_description") or item.get("environment_id"), 120),
                    ]
                )
    return rows[:80]


def _memory_rows(supplemental: dict[str, Any]) -> list[list[str]]:
    rows: list[list[str]] = []
    raw = supplemental.get("memory_strings")
    if isinstance(raw, dict):
        strings = raw.get("strings") or raw.get("memory_strings") or raw.get("data")
    else:
        strings = raw
    for i, s in enumerate(_as_list(strings)[:400]):
        if isinstance(s, dict):
            rows.append([str(i + 1), _s(s.get("string") or s.get("value") or s, 1400)])
        else:
            rows.append([str(i + 1), _s(s, 1400)])
    return rows


def _appendix_lines(root: dict[str, Any], summary: dict[str, Any], max_lines: int = 700) -> list[str]:
    """High-signal flattened paths for analyst appendix."""
    lines: list[str] = []

    def walk(obj: Any, prefix: str, depth: int) -> None:
        if len(lines) >= max_lines or depth > 14:
            return
        if isinstance(obj, dict):
            for k in sorted(obj.keys(), key=str):
                if k in ("screenshots", "memory_dump", "pcap"):
                    lines.append(f"{prefix}.{k}: <binary/large object omitted>")
                    continue
                v = obj[k]
                nk = f"{prefix}.{k}" if prefix else str(k)
                if isinstance(v, (dict, list)) and len(json.dumps(v, default=str)) > 400:
                    walk(v, nk, depth + 1)
                else:
                    lines.append(f"{nk}: {_s(v, 380)}")
        elif isinstance(obj, list):
            for i, it in enumerate(obj[:25]):
                walk(it, f"{prefix}[{i}]", depth + 1)
            if len(obj) > 25:
                lines.append(f"{prefix}: … ({len(obj)} total items, truncated)")

    walk(summary, "summary", 0)
    if isinstance(root, dict):
        skip_roots = {"processes", "network", "behavior", "signatures", "mitre_attcks", "mitre_attacks"}
        for top in sorted(root.keys(), key=str):
            if top in skip_roots:
                lines.append(f"report.{top}: <large branch; see dedicated sections>")
                continue
            if top in ("classification", "static", "interesting", "debug", "target_url", "summary", "url_analysis"):
                walk(root[top], f"report.{top}", 0)
            elif len(lines) < max_lines - 40:
                walk(root.get(top), f"report.{top}", 0)
    return lines[:max_lines]


def build_forensic_digest(
    full_report: dict[str, Any] | list[Any],
    summary: dict[str, Any],
    supplemental: dict[str, Any],
    milestones: list[tuple[float, str]],
) -> ForensicDigest:
    root: dict[str, Any] = full_report if isinstance(full_report, dict) else {}
    root = _enrich_root_from_summary(root, summary)

    digest = ForensicDigest()
    digest.process_rows = _collect_process_rows(root)
    digest.file_activity_rows = _collect_file_rows(root, supplemental, summary)
    digest.registry_rows = _collect_registry_rows(root, summary)
    dns, http, ips = _collect_network_rows(root)
    digest.network_dns_rows = dns
    digest.network_http_rows = http
    digest.network_ip_rows = ips
    digest.mutex_rows, digest.service_task_rows = _collect_mutex_service(root, summary)
    digest.signature_rows, digest.mitre_rows = _collect_signatures_mitre(root, summary)
    digest.timeline_rows = _collect_timeline(root, summary)
    digest.interesting_strings = _collect_interesting_strings(root, summary)
    digest.screenshot_index = _screenshot_rows(supplemental)
    digest.dropped_file_rows = _api_dropped_table(supplemental)
    digest.child_report_rows = _children_rows(supplemental)
    digest.memory_string_rows = _memory_rows(supplemental)
    digest.classification_rows = _flatten_summary_kv(summary)
    digest.appendix_telemetry_lines = _appendix_lines(root, summary)

    digest.exec_flow_narrative = [
        "This section reconstructs the analytical workflow from the operator workstation through the Falcon Sandbox.",
        "Step 1 — Sample was hashed locally and transmitted only via the Hybrid Analysis API (no local execution on this host).",
        "Step 2 — The submission was accepted and assigned a job identifier for asynchronous sandbox execution.",
        "Step 3 — The remote environment executed the specimen while kernel and user-mode monitors recorded behavioral telemetry.",
        "Step 4 — Telemetry was aggregated into the JSON report, summary verdicts, and optional supplemental artifacts.",
        "Step 5 — MlwAnalystX normalized the payload into the tables in this document for analyst review.",
        "",
        "Client-side milestone log:",
    ]
    for sec, label in milestones[:80]:
        digest.exec_flow_narrative.append(f"  T+{sec:8.2f}s — {label}")

    return digest
