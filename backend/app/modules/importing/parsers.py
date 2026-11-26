"""Parse imported scanner reports (Phase 12): Tenable .nessus v2 and
Greenbone/OpenVAS XML. Pure: bytes in, dataclasses out, no DB/network.

The file is untrusted. It is parsed with defusedxml with any DTD refused,
so XXE, external entities and entity-expansion bombs never get a chance;
counts are capped; every reject raises ImportFormatError and the caller
writes nothing.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from xml.etree.ElementTree import Element

from defusedxml import DefusedXmlException
from defusedxml.ElementTree import ParseError, fromstring

MAX_HOSTS = 1_000
MAX_RESULTS = 100_000

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$")
_NESSUS_SEVERITY = {1: "LOW", 2: "MEDIUM", 3: "HIGH", 4: "CRITICAL"}


class ImportFormatError(ValueError):
    """The file can't be imported; the message says why (shown to the user)."""


@dataclass
class ParsedResult:
    port: int
    protocol: str
    cve_ids: list[str]
    severity: str
    cvss: float | None
    cvss_vector: str | None
    plugin_id: str
    name: str
    description: str | None
    scanner_severity: str
    qod: float | None = None


@dataclass
class ParsedHost:
    names: list[str]  # IP first, then report name / FQDN / hostname
    scan_start: datetime
    ports: dict[tuple[int, str], str | None] = field(default_factory=dict)
    results: list[ParsedResult] = field(default_factory=list)


@dataclass
class ParsedReport:
    format: str  # "nessus" | "openvas"
    hosts: list[ParsedHost]
    skipped_no_cve: int = 0
    skipped_info: int = 0
    dropped_bad_cve: int = 0


def parse_report(raw: bytes) -> ParsedReport:
    try:
        root = fromstring(raw, forbid_dtd=True, forbid_entities=True, forbid_external=True)
    except DefusedXmlException as exc:
        raise ImportFormatError(f"Refused: the file declares a DTD or entities ({exc})") from exc
    except (ParseError, LookupError, ValueError) as exc:
        # LookupError / ValueError: an unknown or unsupported declared encoding.
        raise ImportFormatError(f"Malformed XML: {exc}") from exc
    if root.tag == "NessusClientData_v2":
        return _parse_nessus(root)
    if root.tag == "get_reports_response":
        inner = root.find("report")
        if inner is None:
            raise ImportFormatError("get_reports_response contains no <report>")
        root = inner
    if root.tag == "report":
        # A GMP export nests the real report in report/report.
        inner = root.find("report")
        return _parse_openvas(inner if inner is not None else root)
    raise ImportFormatError(
        f"Unknown report format (root element <{root.tag[:50]}>); "
        "expected a .nessus v2 or an OpenVAS/Greenbone XML report"
    )


# --- helpers -------------------------------------------------------------------


def _text(el: Element | None) -> str | None:
    if el is None or el.text is None:
        return None
    value = el.text.strip()
    return value or None


def _float(value: str | None) -> float | None:
    try:
        number = float(value) if value is not None else None
    except ValueError:
        return None
    return number if number is not None and 0.0 <= number <= 10.0 else None


def _port(value: str | None) -> int:
    try:
        port = int(value or "")
    except ValueError as exc:
        raise ImportFormatError(f"Invalid port {value!r}") from exc
    if not 0 <= port <= 65535:
        raise ImportFormatError(f"Port out of range: {port}")
    return port


def _severity_from_score(score: float | None) -> str:
    """CVSS v3 qualitative bands."""
    if score is None or score == 0:
        return "NONE"
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"


def _clean_cves(candidates: list[str], report: ParsedReport) -> list[str]:
    out: list[str] = []
    for cve in candidates:
        cve = cve.strip().upper()
        if not cve or cve == "NOCVE":
            continue
        if _CVE_RE.match(cve):
            if cve not in out:
                out.append(cve)
        else:
            report.dropped_bad_cve += 1
    return out


def _check_result_count(n: int) -> None:
    if n > MAX_RESULTS:
        raise ImportFormatError(f"Too many results (over {MAX_RESULTS:,})")


# --- Nessus ----------------------------------------------------------------------


def _nessus_time(tags: dict[str, str]) -> datetime | None:
    if ts := tags.get("HOST_START_TIMESTAMP"):
        try:
            return datetime.fromtimestamp(int(ts), UTC)
        except (ValueError, OverflowError, OSError):
            pass
    if text := tags.get("HOST_START"):
        try:
            return datetime.strptime(text, "%a %b %d %H:%M:%S %Y").replace(tzinfo=UTC)
        except ValueError:
            pass
    return None


def _parse_nessus(root: Element) -> ParsedReport:
    report = ParsedReport(format="nessus", hosts=[])
    report_hosts = root.findall("./Report/ReportHost")
    if len(report_hosts) > MAX_HOSTS:
        raise ImportFormatError(f"Too many hosts (over {MAX_HOSTS:,})")
    n_results = 0
    for rh in report_hosts:
        tags = {
            t.get("name", ""): (t.text or "").strip() for t in rh.findall("./HostProperties/tag")
        }
        name = (rh.get("name") or "").strip()
        scan_start = _nessus_time(tags)
        if scan_start is None:
            raise ImportFormatError(f"Host {name[:100]!r} has no scan time (HOST_START)")
        names = [n for n in (tags.get("host-ip"), name, tags.get("host-fqdn")) if n]
        host = ParsedHost(names=names, scan_start=scan_start)
        for item in rh.findall("ReportItem"):
            n_results += 1
            _check_result_count(n_results)
            port = _port(item.get("port"))
            protocol = (item.get("protocol") or "tcp").lower()[:10]
            host.ports.setdefault((port, protocol), item.get("svc_name"))
            try:
                sev_num = int(item.get("severity") or "0")
            except ValueError:
                sev_num = 0
            if sev_num <= 0:
                report.skipped_info += 1
                continue
            cves = _clean_cves([c.text or "" for c in item.findall("cve")], report)
            if not cves:
                report.skipped_no_cve += 1
                continue
            plugin_id = (item.get("pluginID") or "")[:64]
            cvss3 = _float(_text(item.find("cvss3_base_score")))
            cvss = cvss3 if cvss3 is not None else _float(_text(item.find("cvss_base_score")))
            vector = _text(item.find("cvss3_vector")) or _text(item.find("cvss_vector"))
            host.results.append(
                ParsedResult(
                    port=port,
                    protocol=protocol,
                    cve_ids=cves,
                    severity=_NESSUS_SEVERITY.get(sev_num, "CRITICAL"),
                    cvss=cvss,
                    cvss_vector=vector,
                    plugin_id=plugin_id,
                    name=(item.get("pluginName") or "")[:500],
                    description=_text(item.find("synopsis")) or _text(item.find("description")),
                    scanner_severity=str(sev_num),
                )
            )
        report.hosts.append(host)
    return report


# --- OpenVAS / Greenbone -----------------------------------------------------------


def _iso(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _openvas_port(value: str | None) -> tuple[int, str]:
    """'80/tcp' -> (80, 'tcp'); 'general/tcp' -> (0, 'tcp')."""
    number, _, protocol = (value or "").strip().partition("/")
    protocol = (protocol or "tcp").lower()[:10]
    return (0 if number in ("", "general", "package") else _port(number)), protocol


def _parse_openvas(report_el: Element) -> ParsedReport:
    report = ParsedReport(format="openvas", hosts=[])
    default_start = _iso(_text(report_el.find("scan_start")))
    host_starts = {
        (_text(h.find("ip")) or ""): _iso(_text(h.find("start"))) for h in report_el.findall("host")
    }
    hosts: dict[str, ParsedHost] = {}
    results = report_el.findall("./results/result")
    _check_result_count(len(results))
    for result in results:
        host_el = result.find("host")
        ip = (_text(host_el) or "") if host_el is not None else ""
        if not ip:
            continue
        host = hosts.get(ip)
        if host is None:
            if len(hosts) >= MAX_HOSTS:
                raise ImportFormatError(f"Too many hosts (over {MAX_HOSTS:,})")
            scan_start = host_starts.get(ip) or default_start
            if scan_start is None:
                raise ImportFormatError(f"Host {ip[:100]!r} has no scan time (scan_start)")
            hostname = _text(host_el.find("hostname")) if host_el is not None else None
            host = ParsedHost(names=[n for n in (ip, hostname) if n], scan_start=scan_start)
            hosts[ip] = host
        port, protocol = _openvas_port(_text(result.find("port")))
        host.ports.setdefault((port, protocol), None)
        score = _float(_text(result.find("severity")))
        threat = (_text(result.find("threat")) or "").lower()
        if threat in ("log", "debug", "false positive") or not score:
            report.skipped_info += 1
            continue
        nvt = result.find("nvt")
        refs = [r.get("id") or "" for r in result.findall("./nvt/refs/ref[@type='cve']")]
        legacy = (_text(nvt.find("cve")) or "") if nvt is not None else ""
        cves = _clean_cves(refs + legacy.split(","), report)
        if not cves:
            report.skipped_no_cve += 1
            continue
        qod = _float_qod(_text(result.find("./qod/value")))
        host.results.append(
            ParsedResult(
                port=port,
                protocol=protocol,
                cve_ids=cves,
                severity=_severity_from_score(score),
                cvss=score,
                cvss_vector=None,
                plugin_id=((nvt.get("oid") if nvt is not None else None) or "")[:64],
                name=((_text(nvt.find("name")) if nvt is not None else None) or "")[:500],
                description=_text(result.find("description")),
                scanner_severity=threat or str(score),
                qod=qod,
            )
        )
    report.hosts = list(hosts.values())
    return report


def _float_qod(value: str | None) -> float | None:
    try:
        qod = float(value) if value is not None else None
    except ValueError:
        return None
    return qod if qod is not None and 0.0 <= qod <= 100.0 else None
