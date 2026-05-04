from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any


SUSPICIOUS_TLDS = re.compile(
    r"\.(tk|ml|ga|cf|gq|xyz|top|click|download|loan|zip|review|buzz|icu|cfd|bar|cyou|quest|autos|beauty|hair|skin|makeup|boats|homes|motorcycles|sbs|rest|cfd)$",
    re.I,
)


@dataclass
class BehavioralProfile:
    created_files: list[str] = field(default_factory=list)
    persistence_indicators: list[str] = field(default_factory=list)
    processes: list[str] = field(default_factory=list)
    process_chains: list[str] = field(default_factory=list)
    ips: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    dns_calls: list[str] = field(default_factory=list)
    http_urls: list[str] = field(default_factory=list)
    signatures: list[str] = field(default_factory=list)
    timeline: list[tuple[str, str]] = field(default_factory=list)
    raw_highlights: dict[str, Any] = field(default_factory=dict)


def _as_list(x: Any) -> list[Any]:
    if x is None:
        return []
    if isinstance(x, list):
        return x
    if isinstance(x, dict):
        return [x]
    return []


def _walk_process_tree(node: Any, depth: int = 0, acc: list[str] | None = None) -> list[str]:
    if acc is None:
        acc = []
    if not isinstance(node, dict):
        return acc
    name = node.get("process_name") or node.get("name") or node.get("path") or "unknown"
    pid = node.get("pid") or node.get("process_id")
    parent = node.get("parent", {})
    parent_name = (
        parent.get("process_name") or parent.get("name") or parent.get("path") if isinstance(parent, dict) else None
    )
    chain = f"{'  ' * depth}[{pid}] {name}"
    if parent_name:
        chain += f"  ← parent: {parent_name}"
    acc.append(chain)
    for child in _as_list(node.get("children")):
        _walk_process_tree(child, depth + 1, acc)
    return acc


def extract_from_ha_report(full_report: dict[str, Any] | list[Any], summary: dict[str, Any]) -> BehavioralProfile:
    """Best-effort extraction across common Falcon Sandbox JSON shapes."""
    prof = BehavioralProfile()
    root: dict[str, Any] = full_report if isinstance(full_report, dict) else {}
    beh = root.get("behavior")
    beh_d: dict[str, Any] = beh if isinstance(beh, dict) else {}

    # Summary-backed fields (always useful)
    for d in _as_list(summary.get("domains")):
        if isinstance(d, str) and d:
            prof.domains.append(d)
    for h in _as_list(summary.get("hosts")):
        if isinstance(h, str) and h:
            if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", h):
                prof.ips.append(h)
            else:
                prof.dns_calls.append(h)
    for ch in _as_list(summary.get("compromised_hosts")):
        if isinstance(ch, str) and ch:
            prof.ips.append(ch)

    # Processes
    proc_block = root.get("process_tree") or beh_d.get("process_tree")
    if isinstance(proc_block, dict):
        prof.process_chains = _walk_process_tree(proc_block)
    procs = root.get("processes") or beh_d.get("processes")
    for p in _as_list(procs):
        if not isinstance(p, dict):
            continue
        line = p.get("path") or p.get("name") or p.get("process_name")
        if line:
            prof.processes.append(str(line))
    for p in _as_list(summary.get("processes")):
        if not isinstance(p, dict):
            continue
        line = p.get("path") or p.get("name") or p.get("process_name") or p.get("normalized_path")
        if line:
            prof.processes.append(str(line))

    # Network
    net = root.get("network") or beh_d.get("network")
    if isinstance(net, dict):
        for ip in _as_list(net.get("hosts") or net.get("ips")):
            if isinstance(ip, str):
                prof.ips.append(ip)
        for dom in _as_list(net.get("domains")):
            if isinstance(dom, str):
                prof.domains.append(dom)
        for fl in _as_list(net.get("flows") or net.get("connections")):
            if not isinstance(fl, dict):
                continue
            if fl.get("transport") == "DNS" or "dns" in str(fl.get("protocol", "")).lower():
                prof.dns_calls.append(str(fl.get("domain") or fl.get("request") or fl))
            if fl.get("url"):
                prof.http_urls.append(str(fl["url"]))

    # Files / dropped
    for key in ("extracted_files", "dropped_files", "files_created", "file_created"):
        block = root.get(key) or beh_d.get(key)
        for item in _as_list(block):
            if isinstance(item, dict):
                path = item.get("path") or item.get("name") or item.get("sha256")
                if path:
                    prof.created_files.append(str(path))
            elif isinstance(item, str):
                prof.created_files.append(item)

    # Signatures / mitre-style tags
    for sig in _as_list(root.get("signatures") or root.get("mitre_attcks")):
        if isinstance(sig, dict):
            t = sig.get("threat") or sig.get("name") or sig.get("identifier")
            if t:
                prof.signatures.append(str(t))
        elif isinstance(sig, str):
            prof.signatures.append(sig)

    # Persistence heuristics from signatures + paths
    persist_kw = (
        "runkey",
        "registry",
        "startup",
        "schtasks",
        "service",
        "com hijack",
        "persistence",
        "bits job",
        "wmipersistence",
    )
    for s in prof.signatures:
        low = s.lower()
        if any(k in low for k in persist_kw):
            prof.persistence_indicators.append(s)
    for path in prof.processes + prof.created_files:
        low = path.lower()
        if any(k in low for k in ("\\startup\\", "runonce", "currentversion\\run", "schtasks", "services\\")):
            prof.persistence_indicators.append(path)

    # Dedupe preserve order
    def uniq(seq: list[str]) -> list[str]:
        seen: set[str] = set()
        out: list[str] = []
        for x in seq:
            if x not in seen:
                seen.add(x)
                out.append(x)
        return out

    prof.created_files = uniq(prof.created_files)[:200]
    prof.processes = uniq(prof.processes)[:200]
    prof.ips = uniq(prof.ips)[:200]
    prof.domains = uniq(prof.domains)[:200]
    prof.dns_calls = uniq(prof.dns_calls)[:200]
    prof.http_urls = uniq(prof.http_urls)[:200]
    prof.signatures = uniq(prof.signatures)[:200]
    prof.persistence_indicators = uniq(prof.persistence_indicators)[:100]

    suspicious_domains = [d for d in prof.domains if SUSPICIOUS_TLDS.search(d)]
    prof.raw_highlights["suspicious_domain_hits"] = suspicious_domains

    # Timeline from process events if present
    evs = beh_d.get("processtree")
    events = beh_d.get("processes")
    timeline_src = root.get("timeline") or events or evs
    for ev in _as_list(timeline_src)[:80]:
        if isinstance(ev, dict):
            ts = str(ev.get("time") or ev.get("timestamp") or ev.get("tick") or "?")
            msg = str(ev.get("event") or ev.get("action") or ev.get("path") or ev)
            prof.timeline.append((ts, msg))

    return prof
