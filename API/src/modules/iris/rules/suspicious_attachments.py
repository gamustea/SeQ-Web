"""
Suspicious Attachment Extension rule — flags emails whose Content-Type
or Content-Disposition headers reference file extensions commonly used
to deliver malware.

Attackers often attach executables (.exe, .scr), scripts (.js, .vbs,
.ps1), macro-enabled documents (.docm, .xlsm), or disk images (.iso,
.img) that bypass security scanners.
"""

import re

from .registry import iris_rules, RuleResult

DANGEROUS_EXTENSIONS = {
    # Executables
    ".exe", ".dll", ".scr", ".bat", ".cmd", ".com", ".msi",
    ".msp", ".mst", ".cpl", ".pif", ".gadget",
    # Scripts
    ".js", ".jse", ".vbs", ".vbe", ".ps1", ".psm1", ".psd1",
    ".ps1xml", ".wsf", ".wsh", ".wsc", ".sct", ".hta",
    ".py", ".rb", ".pl", ".sh", ".bash", ".zsh",
    # Macro-bearing documents
    ".docm", ".xlsm", ".pptm", ".dotm", ".xlam", ".xla",
    ".ppa", ".ppam", ".sldm",
    # LNK and shortcuts
    ".lnk", ".url", ".website",
    # Disk / archive that can carry executables
    ".iso", ".img", ".vhd", ".vhdx", ".vmdk", ".ova", ".ovf",
    ".jar",
    # Registry
    ".reg",
    # Other dangerous
    ".appref-ms", ".settingcontent-ms", ".searchconnector-ms",
    ".application", ".xps",
}

SUSPICIOUS_MIME_TYPES = [
    "application/x-msdownload",
    "application/x-msdos-program",
    "application/x-msi",
    "application/x-javascript",
    "application/javascript",
    "application/x-vb",
    "application/x-vbs",
    "application/x-powershell",
    "application/x-sh",
    "application/x-bat",
    "application/x-ms-shortcut",
    "application/x-iso9660-image",
    "application/java-archive",
    "application/octet-stream",
]


def _extract_filename(content_disposition: str) -> str | None:
    match = re.search(r'filename\s*=\s*["\']?([^"\';\n]+)["\']?', content_disposition, re.IGNORECASE)
    if match:
        return match.group(1).strip()
    match = re.search(r'filename\*\s*=\s*["\']?([^"\';\n]+)["\']?', content_disposition, re.IGNORECASE)
    if match:
        return match.group(1).strip()
    return None


def _get_extension(filename: str) -> str:
    _, _, ext = filename.rpartition(".")
    return "." + ext.lower() if ext else ""


def _has_double_extension(filename: str) -> bool:
    parts = filename.lower().split(".")
    if len(parts) >= 3:
        last = parts[-1]
        second_last = parts[-2]
        if len(last) <= 4 and last.isalpha() and len(second_last) <= 4 and second_last.isalpha():
            return True
    return False


@iris_rules.register(name="Suspicious Attachments", category="header_analysis",
                     description="Detecta si el correo adjunta archivos con extensiones peligrosas (.exe, .js, .vbs, .iso, etc.)")
def check_suspicious_attachments(headers: dict) -> RuleResult:
    content_type = headers.get("content-type", "")
    content_disposition = headers.get("content-disposition", "")
    combined = (content_type + " " + content_disposition).lower()

    if "multipart" in combined:
        return RuleResult(
            score=0, verdict="neutral",
            details={"reason": "multipart email — individual parts not inspected at header level"},
            recommendation=None,
        )

    filename = _extract_filename(content_disposition)
    findings: list[dict] = []

    if filename:
        ext = _get_extension(filename)
        if ext in DANGEROUS_EXTENSIONS:
            findings.append({
                "filename": filename,
                "extension": ext,
                "double_extension": _has_double_extension(filename),
                "source": "content-disposition",
            })
        elif _has_double_extension(filename):
            findings.append({
                "filename": filename,
                "extension": ext or "(none)",
                "double_extension": True,
                "source": "content-disposition",
            })

    for mime in SUSPICIOUS_MIME_TYPES:
        if mime in content_type.lower():
            findings.append({
                "mime_type": mime,
                "filename": filename or "unknown",
                "source": "content-type",
            })

    if not findings:
        return RuleResult(
            score=0, verdict="pass",
            details={"content_type": content_type, "content_disposition": content_disposition},
            recommendation=None,
        )

    score = 0
    ext_descriptions: list[str] = []
    for f in findings:
        if "extension" in f:
            ext_descriptions.append(f["extension"])
            if f.get("double_extension"):
                score -= 2  # extra penalty for double extensions
            score -= 6
        if "mime_type" in f:
            ext_descriptions.append(f["mime_type"])
            score -= 5

    score = max(score, -20)

    return RuleResult(
        score=score, verdict="fail",
        details={
            "content_type": content_type,
            "content_disposition": content_disposition,
            "findings": findings,
        },
        recommendation=(
            f"El correo incluye archivos adjuntos con extensiones potencialmente peligrosas: "
            f"{', '.join(ext_descriptions)}. "
            "Estas extensiones son utilizadas frecuentemente para distribuir malware. "
            "No abras estos archivos a menos que estés absolutamente seguro de su procedencia."
        ),
    )
