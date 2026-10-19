# 🛡️ Personal Data Leak Detector (SENTINEL CORE)

> **A real-time data leak detection engine with deep multi-format document extraction and a ray-traced 3D holographic defense matrix.**

---

## 🌟 Key Features

- **Multi-Format Document Extraction**:
  - **PDF (`.pdf`)**: Page-by-page text parsing with boundary detection via `pypdf`.
  - **Word (`.docx`, `.doc`)**: Heading, paragraph, and multi-column table extraction using `python-docx` (with OLE binary string recovery fallback for legacy `.doc`).
  - **Excel (`.xlsx`, `.xlsm`, `.csv`, `.tsv`)**: Scans all workbook sheets, rows, and cells using `openpyxl`.
  - **Rich Text Format (`.rtf`)**: Strips RTF control codes to extract readable document text.
  - **Text, Config & Code**: Analyzes `.env`, `.log`, `.json`, `.csv`, `.yaml`, `.xml`, `.py`, `.js`, etc. with multi-encoding fallback (UTF-8, Latin-1, CP1252).
- **Comprehensive Leak Detection Matrices**:
  - Credit Card numbers (with Luhn checksum validation)
  - Cryptographic Private Keys (`-----BEGIN RSA/EC/OPENSSH PRIVATE KEY-----`)
  - Cloud API Secrets & Tokens (AWS, GitHub Personal Access Tokens, Bearer auth)
  - JWT Session Credentials
  - Social Security Numbers (SSN)
  - Plaintext Passwords & Credential assignments
  - Personal Email Addresses & Phone Numbers
  - IPv4 Network Addresses
- **Location Tracking & Surrounding Context**:
  - Pinpoints the exact document location (`[Page 2] (Line 14)`, `[Sheet: Clients] (Line 3)`).
  - Context snippets with masked exposure highlighting (`... 「AK****************LE」 ...`).
  - Detailed security risk descriptions and compliance mitigation advice (GDPR, PCI-DSS).
- **Interactive 3D Holographic Matrix (Three.js)**:
  - Ray-traced wireframe shield with orbiting 1,500-particle constellation.
  - Dynamically changes defense state based on threat level (Nominal vs. Compromised).
  - Full touch-rotation controls for mobile screens and mouse controls for desktop.
- **100% Mobile Responsive UI**:
  - Optimized for **Portrait view** (320px–430px) and **Landscape short viewports** (320px–500px height).
  - Safe-area insets (`env(safe-area-inset-top)`, etc.) for notches and home indicators.
  - Dynamic viewport units (`100dvh`).

---

## 🚀 Quick Start

### 1. Clone the Repository
```bash
git clone https://github.com/Kishan-shah12/Personal-Data-Leak-Detector.git
cd Personal-Data-Leak-Detector
```

### 2. Set Up Virtual Environment & Dependencies
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 3. Run the Development Server
```bash
uvicorn app.main:app --reload
```

Open your browser at:
👉 **http://127.0.0.1:8000** (or API interactive docs at http://127.0.0.1:8000/docs)

---

## 📁 Project Architecture

```
├── app/
│   ├── database.py       # MongoDB optional telemetry persistence
│   ├── detector.py       # Regex matrices, Luhn validator, snippet extraction
│   ├── extractor.py      # Multi-format document text extractor (PDF, DOCX, XLSX, etc.)
│   └── main.py           # FastAPI routes, file streaming & scan endpoints
├── templates/
│   └── index.html        # Futuristic Three.js UI, responsive workbench & telemetry dashboard
├── requirements.txt      # Project dependencies
└── README.md             # Project documentation
```

---

## 🔒 Security & Privacy

Uploaded documents and stream payloads are processed in-memory for extraction and audit purposes. Sensitive findings are masked automatically in all returned payloads and telemetry logs.
