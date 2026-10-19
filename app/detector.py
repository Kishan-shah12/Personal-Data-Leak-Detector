import re
from typing import Any, Dict, List, Optional


def luhn_checksum(card_number: str) -> bool:
    """Validate numeric string using Luhn algorithm."""
    digits = [int(c) for c in card_number if c.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    checksum = 0
    reverse_digits = digits[::-1]
    for i, digit in enumerate(reverse_digits):
        if i % 2 == 1:
            doubled = digit * 2
            checksum += doubled - 9 if doubled > 9 else doubled
        else:
            checksum += digit
    return checksum % 10 == 0


def mask_sensitive(value: str, keep_start: int = 2, keep_end: int = 2) -> str:
    """Mask string contents keeping boundary characters visible."""
    if len(value) <= (keep_start + keep_end):
        return "*" * len(value)
    return value[:keep_start] + ("*" * (len(value) - keep_start - keep_end)) + value[-keep_end:]


PATTERNS: Dict[str, Dict[str, Any]] = {
    "Credit Card": {
        "pattern": re.compile(r"\b(?:\d{4}[-\s]?){3}\d{4}\b"),
        "severity": "Critical",
        "validator": lambda val: luhn_checksum(re.sub(r"[-\s]", "", val)),
        "description": "Exposed payment card number passing Luhn checksum.",
        "recommendation": "High financial fraud risk under PCI-DSS. Immediately tokenize or redact.",
    },
    "Private Key": {
        "pattern": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
        "severity": "Critical",
        "description": "Cryptographic private key block found unencrypted.",
        "recommendation": "Rotate certificate/key immediately and remove from public/shared storage.",
    },
    "API Key / Secret Token": {
        "pattern": re.compile(
            r"(?i)\b(?:ghp_[a-zA-Z0-9]{36}|akpa_[a-zA-Z0-9]{36}|AKIA[0-9A-Z]{16}|bearer\s+[a-zA-Z0-9_\-\.]{20,})\b"
        ),
        "severity": "Critical",
        "description": "Cloud or service authentication credential exposed in payload.",
        "recommendation": "Revoke active token credentials in the service provider dashboard.",
    },
    "JWT Authentication Token": {
        "pattern": re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
        "severity": "Critical",
        "description": "Live JSON Web Token (JWT) session credential found.",
        "recommendation": "Ensure tokens are short-lived, never written to static files, and properly invalidated.",
    },
    "SSN": {
        "pattern": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
        "severity": "High",
        "description": "US Social Security Number format detected.",
        "recommendation": "Severe PII compliance violation. Mask or remove before sharing.",
    },
    "Exposed Password / Secret": {
        "pattern": re.compile(
            r"(?i)\b(?:password|passwd|secret_key|api_secret)\s*[:=]\s*[\"']?([^\s\"';]{6,})[\"']?"
        ),
        "severity": "High",
        "description": "Plaintext credential or password assignment detected.",
        "recommendation": "Store passwords only in secure vault solutions; never save in clear text.",
    },
    "Email Address": {
        "pattern": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
        "severity": "Medium",
        "description": "Identifiable personal/corporate email address.",
        "recommendation": "Subject to GDPR/CCPA privacy compliance regulations.",
    },
    "Phone Number": {
        "pattern": re.compile(r"(?:\+?\d{1,3}[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)?\d{3}[-.\s]?\d{4}\b"),
        "severity": "Medium",
        "description": "Direct telephone contact number.",
        "recommendation": "Verify consent before storing or transmitting contact information.",
    },
    "IPv4 Address": {
        "pattern": re.compile(
            r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
        ),
        "severity": "Low",
        "description": "Exposed internal or public network IP address.",
        "recommendation": "Review network topology disclosure to avoid reconnaissance risks.",
    },
}


def find_document_location(text: str, start: int) -> str:
    """Finds section, page, or line location of match within document text."""
    prefix = text[:start]
    # Check for page markers like --- [Page 2] ---
    pages = re.findall(r"---\s*\[(Page\s*\d+|Sheet:\s*[^\]]+|Table\s*\d+)\]\s*---", prefix)
    current_location = pages[-1] if pages else ""

    # Line number
    line_number = prefix.count("\n") + 1

    if current_location:
        return f"{current_location} (Line {line_number})"
    return f"Line {line_number}"


def extract_context_snippet(text: str, start: int, end: int, window: int = 35) -> str:
    """Extracts text around match, keeping context readable while masking match."""
    s = max(0, start - window)
    e = min(len(text), end + window)
    pre = ("..." if s > 0 else "") + text[s:start].replace("\r", " ").replace("\n", " ")
    post = text[end:e].replace("\r", " ").replace("\n", " ") + ("..." if e < len(text) else "")
    match_val = text[start:end]
    return f"{pre}「{mask_sensitive(match_val)}」{post}".strip()


def scan_text(text: str) -> List[Dict[str, Any]]:
    """
    Scans raw text against regex patterns and validation rules to detect leaks.
    """
    findings: List[Dict[str, Any]] = []

    for category, config in PATTERNS.items():
        regex: re.Pattern = config["pattern"]
        validator = config.get("validator")
        severity = config["severity"]
        description = config.get("description", "")
        recommendation = config.get("recommendation", "")

        for match in regex.finditer(text):
            val = match.group(0).strip()
            if validator and not validator(val):
                continue

            loc = find_document_location(text, match.start())
            snippet = extract_context_snippet(text, match.start(), match.end())

            findings.append(
                {
                    "category": category,
                    "severity": severity,
                    "detected_value": mask_sensitive(val),
                    "start": match.start(),
                    "end": match.end(),
                    "location": loc,
                    "snippet": snippet,
                    "description": description,
                    "recommendation": recommendation,
                }
            )

    # Sort findings by severity (Critical -> High -> Medium -> Low)
    severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    findings.sort(key=lambda x: severity_order.get(x["severity"], 4))

    return findings
