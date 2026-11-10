from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse

from app.database import check_db_connection, leaks_collection
from app.detector import scan_text
from app.extractor import extract_document_text
from app.malware_scanner import scan_for_malware_and_invisible_code

BASE_DIR = Path(__file__).resolve().parent.parent
TEMPLATES_DIR = BASE_DIR / "templates"

app = FastAPI(
    title="SENTINEL CORE // Personal Data Leak & Malware Detection Matrix",
    version="2.0.0",
)


@app.get("/", response_class=FileResponse)
def index() -> FileResponse:
    index_file = TEMPLATES_DIR / "index.html"
    if not index_file.exists():
        raise HTTPException(status_code=404, detail="Template index.html not found")
    return FileResponse(index_file)


@app.post("/api/scan")
async def scan_payload(
    text: Optional[str] = Form(None),
    file: Optional[UploadFile] = File(None),
) -> Dict[str, Any]:
    content = ""
    source = "direct_input"
    doc_type = "Direct Text Input"
    filename = None
    raw_bytes = b""

    if isinstance(file, UploadFile) and file.filename:
        filename = file.filename
        source = f"file:{filename}"
        raw_bytes = await file.read()

        if not raw_bytes:
            raise HTTPException(
                status_code=400,
                detail=f"The uploaded file '{filename}' is empty (0 bytes).",
            )

        # Extract text within isolated parser sandbox
        try:
            content, doc_type, _ = extract_document_text(filename, raw_bytes)
        except Exception as e:
            content = ""
            doc_type = f"Protected/Binary Container ({str(e)[:40]})"

    elif text is not None and text.strip():
        content = text
        raw_bytes = text.encode("utf-8", errors="ignore")
    else:
        raise HTTPException(
            status_code=400,
            detail="Please provide either text logs or an uploaded document/file to audit.",
        )

    # 1. Execute Safe In-Memory Malware & Invisible Code Scanner
    malware_res = scan_for_malware_and_invisible_code(
        filename=filename,
        raw_bytes=raw_bytes,
        extracted_text=content,
    )

    malware_findings: List[Dict[str, Any]] = malware_res.get("findings", [])
    malware_summary: Dict[str, int] = malware_res.get("severity_summary", {
        "critical": 0, "high": 0, "medium": 0, "low": 0
    })

    # 2. Execute Sensitive Data Leak Scanner
    leak_findings: List[Dict[str, Any]] = scan_text(content) if content.strip() else []

    leak_crit = sum(1 for f in leak_findings if f.get("severity") == "Critical")
    leak_high = sum(1 for f in leak_findings if f.get("severity") == "High")
    leak_med = sum(1 for f in leak_findings if f.get("severity") == "Medium")
    leak_low = sum(1 for f in leak_findings if f.get("severity") == "Low")

    # Combine metrics across malware and data leak matrices
    total_crit = malware_summary.get("critical", 0) + leak_crit
    total_high = malware_summary.get("high", 0) + leak_high
    total_med = malware_summary.get("medium", 0) + leak_med
    total_low = malware_summary.get("low", 0) + leak_low

    if total_crit > 0:
        overall_risk_level = "CRITICAL"
    elif total_high > 0:
        overall_risk_level = "HIGH"
    elif total_med > 0:
        overall_risk_level = "MEDIUM"
    elif total_low > 0:
        overall_risk_level = "LOW"
    else:
        overall_risk_level = "NOMINAL"

    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source": source,
        "filename": filename,
        "document_type": doc_type,
        "content_length": len(content),
        "raw_bytes_size": len(raw_bytes),
        "leak_count": len(leak_findings),
        "malware_threat_count": len(malware_findings),
        "malware_status": malware_res.get("threat_status", "CLEAN"),
        "malware_score": malware_res.get("malware_score", 0),
        "risk_level": overall_risk_level,
        "severity_summary": {
            "critical": total_crit,
            "high": total_high,
            "medium": total_med,
            "low": total_low,
        },
        "malware_summary": malware_summary,
        "leak_summary": {
            "critical": leak_crit,
            "high": leak_high,
            "medium": leak_med,
            "low": leak_low,
        },
        "malware_findings": malware_findings,
        "leak_findings": leak_findings,
        "findings": leak_findings,
        "entropy": malware_res.get("entropy", 0.0),
        "safety_sandbox": malware_res.get("quarantine_guarantee", {}),
    }

    if check_db_connection():
        try:
            leaks_collection.insert_one(record)
        except Exception:
            pass

    return {
        "status": "success",
        "source": source,
        "filename": filename,
        "document_type": doc_type,
        "extracted_chars": len(content),
        "raw_bytes_size": len(raw_bytes),
        "leak_count": len(leak_findings),
        "malware_threat_count": len(malware_findings),
        "malware_status": malware_res.get("threat_status", "CLEAN"),
        "malware_score": malware_res.get("malware_score", 0),
        "risk_level": overall_risk_level,
        "severity_summary": {
            "critical": total_crit,
            "high": total_high,
            "medium": total_med,
            "low": total_low,
        },
        "malware_summary": malware_summary,
        "leak_summary": {
            "critical": leak_crit,
            "high": leak_high,
            "medium": leak_med,
            "low": leak_low,
        },
        "malware_findings": malware_findings,
        "leak_findings": leak_findings,
        "findings": leak_findings,  # backward compatibility for index.html
        "entropy": malware_res.get("entropy", 0.0),
        "safety_sandbox": malware_res.get("quarantine_guarantee", {
            "in_memory_sandbox": True,
            "zero_execution_guarantee": True,
            "host_isolation": "ACTIVE",
        }),
        "note": (
            "No extractable text or plain text content was recovered from this document."
            if not content.strip() and not malware_findings else None
        ),
    }


@app.get("/api/health")
def health() -> Dict[str, Any]:
    return {
        "status": "online",
        "engine": "SENTINEL CORE v2.0 (Dual Leak & Malware Defense)",
        "mongodb_connected": check_db_connection(),
        "safety_guarantee": {
            "in_memory_quarantine": "ENABLED",
            "zero_execution_policy": "ACTIVE",
            "zip_bomb_shield": "ACTIVE (Max 60MB, Max 100:1 ratio)",
            "max_upload_size_mb": 25,
        },
        "malware_detection_capabilities": [
            "Invisible Zero-Width Steganography (ZWSP, ZWNJ, ZWJ, WJ, Invisible Ops)",
            "Trojan Source Inversion Attacks (CVE-2021-42574 Bidi Overrides)",
            "Disguised Executable Masquerading (PE, ELF, Mach-O Magic Header Inspection)",
            "Double Extension Social Engineering (.pdf.exe, .docx.vbs, etc.)",
            "Embedded Office VBA Macros & Auto-Execution Hooks (vbaProject.bin, Shell, WScript)",
            "Remote Template Injection (CVE-2022-30190 Follina vector)",
            "PDF Active Exploits (/JavaScript, /OpenAction, /Launch, /EmbeddedFiles)",
            "RTF Embedded OLE Objects (CVE-2017-11882 Equation Editor vector)",
            "Interactive Reverse Shells & Remote Command Execution Payloads",
            "Obfuscated PowerShell Downloaders & Memory Droppers",
            "Ransomware Shadow Copy Deletion (vssadmin, bcdedit, wmic)",
            "Destructive Wiper Payloads & Fork Bombs",
            "EICAR Anti-Virus Standard Test Signatures",
            "Decompression Bomb / Zip Bomb Memory Exhaustion Defense",
        ],
        "supported_formats": [
            "PDF (.pdf)",
            "Word (.docx, .doc, .docm, .dotx)",
            "Excel (.xlsx, .xlsm, .csv, .tsv)",
            "Rich Text (.rtf)",
            "Text / Source Code / Configs (.txt, .py, .js, .sh, .json, .yaml, .xml, .env, .log, etc.)",
            "Any Binary / Document Payload (Safe in-memory quarantine inspection)",
        ],
    }
