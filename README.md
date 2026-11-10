# 🛡️ SENTINEL CORE // Data Leak & Malware Detection Matrix

> **A real-time cybersecurity engine combining deep document data leak detection with safe in-memory malware & invisible malicious code inspection, backed by a ray-traced 3D holographic defense matrix.**

---

## 🌟 Key Capabilities

### 1. 👁️ Malicious Invisible Code & Steganography Detection
- **Zero-Width Unicode Steganography**:
  - Scans for concealed zero-width characters: `ZWSP (\u200B)`, `ZWNJ (\u200C)`, `ZWJ (\u200D)`, `WJ (\u2060)`, invisible mathematical operators, and embedded BOMs.
  - Automatically attempts binary steganography decoding to reconstruct concealed ASCII payloads.
- **Trojan Source Attacks (CVE-2021-42574)**:
  - Detects Bidirectional (Bidi) Unicode overrides (`\u202A`–`\u202E`, `\u2066`–`\u2069`) that visually invert displayed code to hide malicious execution paths from human reviewers.
- **Whitespace Steganography**:
  - Detects anomalous trailing whitespace combinations (SNOW steganography pattern).
- **Homoglyph & Confusable Identifiers**:
  - Flags mixed Cyrillic/Greek lookalikes concealing malicious URLs or mimicking critical system functions.

---

### 2. ☣️ Malware & Dangerous Payload Inspection
- **Disguised Executable Masquerading (Extension Spoofing)**:
  - Inspects byte-level magic headers (`MZ` Windows PE, `\x7fELF` Linux binaries, Mach-O macOS executables) hidden inside benign document extensions (`.pdf`, `.docx`, `.jpg`, `.txt`).
  - Detects double extension social engineering attacks (e.g., `invoice.pdf.exe`, `report.docx.vbs`).
- **Embedded Document Exploits & Malicious Macros**:
  - Safely inspects Office OpenXML packages (`.docx`, `.xlsx`, `.xlsm`, `.docm`) for `vbaProject.bin`.
  - Flags auto-execution triggers (`AutoOpen`, `Workbook_Open`, `Document_Open`) and dangerous system APIs (`Shell`, `WScript.Shell`, `WinExec`, `PowerShell`, `cmd.exe`).
  - Detects Remote Template Injection (Follina / CVE-2022-30190 vectors).
  - Inspects PDF object dictionaries for active `/JavaScript`, `/OpenAction` auto-executors, and `/Launch` external binary triggers.
  - Detects RTF embedded OLE objects (CVE-2017-11882 Microsoft Equation Editor memory corruption vector).
- **Interactive Reverse Shells & Remote Access Payloads**:
  - Detects Netcat, Bash `/dev/tcp/`, Socat, Python, PHP, and Ruby reverse shells.
  - Detects obfuscated Base64 PowerShell execution (`-enc`, `-w hidden`, `IEX`, WebClient downloaders).
- **Ransomware & Destructive System Commands**:
  - Detects volume shadow copy destruction (`vssadmin delete shadows`, `wmic shadowcopy delete`, `bcdedit ignoreallfailures`).
  - Destructive wipers (`rm -rf /`, `format C: /y`) and fork bombs (`:(){ :|:& };:`).
- **Industry Standard Anti-Virus Test Signatures**:
  - Full EICAR Standard Anti-Virus Test File verification.

---

### 3. 🔒 Safe In-Memory Quarantine & Host System Safety Guarantee
To ensure the host scanning system is **never compromised or harmed** while inspecting untrusted or malicious files:
- **Zero-Execution Policy**: Uploaded files and payloads are **never executed**, invoked via shell, or evaluated (`no eval/exec/subprocess`).
- **In-Memory Streaming**: Inspection occurs entirely within isolated memory byte streams (`io.BytesIO`). Untrusted binaries are never saved to disk with execution permissions.
- **Decompression Bomb (Zip Bomb) Defense**: Enforces strict expansion quotas (maximum 60 MB uncompressed, maximum 100:1 compression ratio, and entry count limits) to prevent CPU and memory exhaustion / DoS attacks.
- **Upload Quota Defense**: Strict 25 MB file size boundary.
- **Path Traversal Sanitization**: All incoming filenames are normalized, stripping null bytes (`\x00`), directory traversal markers (`../`, `..\`), and shell metacharacters.
- **Parser Fault Isolation**: Every document and container parser operates in an isolated exception barrier, preventing malformed file exploits from crashing the server.

---

### 4. 🔑 Sensitive Data Leak Detection Matrices
- Credit Card numbers (with Luhn algorithm checksum validation)
- Cryptographic Private Keys (`-----BEGIN RSA/EC/OPENSSH/DSA PRIVATE KEY-----`)
- Cloud API Secrets & Access Tokens (AWS AKIA, GitHub PAT, Bearer auth)
- JSON Web Tokens (JWT session credentials)
- US Social Security Numbers (SSN)
- Plaintext Passwords & Credential assignments
- Personal Email Addresses & Phone Numbers (with E.164 verification)
- IPv4 Network Addresses

---

### 5. 🎮 Interactive 3D Holographic Matrix (Three.js WebGL)
- Real-time ray-traced wireframe shield with orbiting 1,500-particle constellation.
- Dynamically pulses **Crimson Red** upon detecting active malware, invisible Trojan Source code, or high-entropy credentials, and **Cyan/Emerald** when fortified and nominal.
- Full drag-to-rotate touch controls on mobile and mouse orbit on desktop.

---

## 🚀 Quick Start

### 1. Set Up Environment & Dependencies
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 2. Run the Development Server
```bash
uvicorn app.main:app --reload
```

Open your browser at:
👉 **http://127.0.0.1:8000** (or API interactive Swagger docs at http://127.0.0.1:8000/docs)

---

## 📁 Project Architecture

```
├── app/
│   ├── database.py       # MongoDB optional telemetry persistence
│   ├── detector.py       # Sensitive data leak regex matrices & Luhn validator
│   ├── extractor.py      # Multi-format document text extractor (PDF, DOCX, XLSX, RTF)
│   ├── malware_scanner.py# Safe in-memory malware & invisible code inspection engine
│   └── main.py           # FastAPI endpoints, quarantine orchestration & safe ingestion
├── templates/
│   └── index.html        # Futuristic Three.js UI, dual telemetry workbench & enclave HUD
├── requirements.txt      # Project dependencies
└── README.md             # Project documentation
```
