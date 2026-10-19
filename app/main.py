from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse

from app.database import check_db_connection, leaks_collection
from app.detector import scan_text
from app.extractor import extract_document_text

BASE_DIR = Path(__file__).resolve().parent.parent
TEMPLATES_DIR = BASE_DIR / "templates"

app = FastAPI(title="Personal Data Leak Detector", version="1.1.0")


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

    if file and file.filename:
        filename = file.filename
        source = f"file:{filename}"
        raw_bytes = await file.read()

        if not raw_bytes:
            raise HTTPException(status_code=400, detail=f"The uploaded file '{filename}' is empty (0 bytes).")

        content, doc_type, _ = extract_document_text(filename, raw_bytes)
        if not content.strip():
            # Return clean report indicating file was scanned but had no extractable text
            return {
                "status": "success",
                "source": source,
                "filename": filename,
                "doc_type": doc_type,
                "extracted_chars": 0,
                "leak_count": 0,
                "risk_level": "NOMINAL",
                "findings": [],
                "note": "No text content was found in this document (e.g., scanned image PDF without OCR, or empty document).",
            }
    elif text:
        content = text
    else:
        raise HTTPException(status_code=400, detail="Please provide either 'text' or an uploaded document file.")

    findings: List[Dict[str, Any]] = scan_text(content)

    # Calculate severity counts and risk level
    crit_count = sum(1 for f in findings if f.get("severity") == "Critical")
    high_count = sum(1 for f in findings if f.get("severity") == "High")
    med_count = sum(1 for f in findings if f.get("severity") == "Medium")
    low_count = sum(1 for f in findings if f.get("severity") == "Low")

    if crit_count > 0:
        risk_level = "CRITICAL"
    elif high_count > 0:
        risk_level = "HIGH"
    elif med_count > 0:
        risk_level = "MEDIUM"
    elif low_count > 0:
        risk_level = "LOW"
    else:
        risk_level = "NOMINAL"

    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source": source,
        "filename": filename,
        "document_type": doc_type,
        "content_length": len(content),
        "leak_count": len(findings),
        "risk_level": risk_level,
        "severity_summary": {
            "critical": crit_count,
            "high": high_count,
            "medium": med_count,
            "low": low_count,
        },
        "findings": findings,
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
        "leak_count": len(findings),
        "risk_level": risk_level,
        "severity_summary": {
            "critical": crit_count,
            "high": high_count,
            "medium": med_count,
            "low": low_count,
        },
        "findings": findings,
    }


@app.get("/api/health")
def health() -> Dict[str, Any]:
    return {
        "status": "online",
        "mongodb_connected": check_db_connection(),
        "supported_formats": [
            "PDF (.pdf)",
            "Word (.docx, .doc)",
            "Excel (.xlsx, .xlsm)",
            "Rich Text (.rtf)",
            "Text / Code / Logs (.txt, .log, .json, .csv, .env, .md, .xml, .yaml, .py, etc.)",
        ],
    }
