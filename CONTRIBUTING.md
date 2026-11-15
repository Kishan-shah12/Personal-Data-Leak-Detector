# 🛡️ Contributing to SENTINEL CORE

Thank you for your interest in contributing to **SENTINEL CORE (Personal Data Leak & Malware Quarantine Matrix)**! 

This project was founded and architected by **[Kishan Sah](https://www.linkedin.com/in/kishan-sah-b97a73315/)** to provide individuals and organizations with a lightweight, high-performance security inspection tool operating under an uncompromising **Zero-Execution In-Memory Quarantine** model.

To preserve the security, integrity, and intellectual property of the project, all contributors must read and adhere to these guidelines.

---

## 📑 Table of Contents

1. [Contributor Rights & Intellectual Property](#-contributor-rights--intellectual-property)
2. [Developer Certificate of Origin (DCO)](#-developer-certificate-of-origin-dco)
3. [Zero-Execution Security Invariants](#-zero-execution-security-invariants-non-negotiable)
4. [Development & Setup Workflow](#-development--setup-workflow)
5. [Pull Request Process & Quality Standards](#-pull-request-process--quality-standards)
6. [Responsible Security Vulnerability Disclosure](#-responsible-security-vulnerability-disclosure)
7. [Code of Conduct](#-code-of-conduct)

---

## ⚖️ Contributor Rights & Intellectual Property

To protect the project from unauthorized relicensing, fragmentation, or misuse of rights:

1. **Project Ownership & Copyright**:
   - The foundational architecture, design, and core codebase are **Copyright (c) 2026 Kishan Sah**.
   - The project is officially released under the [MIT License](LICENSE).
   - Any external fork, redistribution, or derivative work must retain the original copyright notice and permission terms naming **Kishan Sah**.

2. **Contributor Attribution & Recognition**:
   - Every accepted contributor will be permanently honored and listed in [`CONTRIBUTORS.md`](CONTRIBUTORS.md).
   - Contributors retain personal copyright over their specific original contributions while granting the project an irrevocable, royalty-free, perpetual license to distribute their code under the project's MIT License.

3. **Protection Against Rights Misuse**:
   - No contributor or downstream distributor may relicense the project under proprietary terms, strip existing author attribution, or assert patent claims against the maintainers or users of Sentinel Core.

---

## ✍️ Developer Certificate of Origin (DCO)

By submitting a Pull Request, issue, or patch to Sentinel Core, you certify the following under the standard Developer Certificate of Origin:

```
By making a contribution to this project, I certify that:

(a) The contribution was created in whole or in part by me and I have the right
    to submit it under the MIT License; or
(b) The contribution is based upon previous work that, to the best of my knowledge,
    is covered under an appropriate open-source license and I have the right under
    that license to submit that work with modifications; or
(c) The contribution was provided directly to me by some other person who certified
    (a) or (b) and I have not modified it.
(d) I understand and agree that this project and the contribution are public and that
    a record of the contribution (including all personal information I submit with
    it) is maintained indefinitely and may be redistributed consistent with this
    project or the open source license(s) involved.
```

To sign off on your commits, use git's `-s` flag:
```bash
git commit -s -m "feat(detection): add new token entropy heuristic"
```

---

## 🛑 Zero-Execution Security Invariants (Non-Negotiable)

Because Sentinel Core analyzes untrusted, hostile payloads and malware samples, all code submitted to `app/` must strictly observe these four safety invariants:

| Invariant | Requirement | Violation Severity |
| :--- | :--- | :--- |
| **No Dynamic Execution** | Never invoke `eval()`, `exec()`, `os.system()`, `subprocess.Popen()`, or `ctypes` on untrusted file bytes or user strings. | **Instant Rejection** |
| **In-Memory Quarantine** | Files must be analyzed in memory buffers (`io.BytesIO`). Do not persist unquarantined payloads to temporary disk paths. | **Instant Rejection** |
| **Bounded Decompression** | Any archive parsing must enforce max expansion caps (60 MB) and compression ratio thresholds (< 100:1) to prevent Zip Bombs. | **Instant Rejection** |
| **Path Traversal Shield** | User-supplied filenames must always pass through path normalization stripping `../`, directory separators, and control bytes. | **Instant Rejection** |

---

## 🛠️ Development & Setup Workflow

### 1. Fork & Clone
```bash
git clone https://github.com/Kishan-shah12/Personal-Data-Leak-Detector.git
cd Personal-Data-Leak-Detector
git checkout -b feature/your-feature-name
```

### 2. Virtual Environment & Dependencies
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 3. Run the Development Server
```bash
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```
Navigate to `http://127.0.0.1:8000` to inspect the UI and 3D WebGL Holographic Shield.

### 4. Run Automated Test Suites
Every PR must pass all existing and new unit tests before review:
```bash
python3 -m unittest discover -s tests -v
```

---

## 📋 Pull Request Process & Quality Standards

When opening a Pull Request:
1. **Branch Naming**:
   - `feature/description` for new features or detection rules.
   - `fix/description` for bug fixes or false-positive corrections.
   - `docs/description` for documentation and guide improvements.
2. **Commit Message Format**:
   - Use conventional commit messages: `feat(...)`, `fix(...)`, `docs(...)`, `test(...)`.
   - Always sign off commits (`git commit -s`).
3. **Automated Testing**:
   - Add corresponding test cases in `tests/test_scanner.py` for any new detection rules or parsers.
   - Ensure 100% test pass rate.
4. **No Real Secrets**:
   - Never commit live API keys, private keys, or actual malware droppers. Use recognized test surrogates (e.g., EICAR standard string, mock tokens, synthetic regex strings).

---

## 🚨 Responsible Security Vulnerability Disclosure

If you discover a zero-day vulnerability, parser bypass, or security flaw within Sentinel Core:
- **Do NOT open a public GitHub issue.**
- Report the vulnerability privately to the project architect:
  - **Kishan Sah**: [LinkedIn Direct Message](https://www.linkedin.com/in/kishan-sah-b97a73315/)
- Please provide:
  1. Description of the issue and attack vector.
  2. Proof of concept (PoC) payload.
  3. Impact assessment and recommended mitigation.
- Security disclosures will be acknowledged within 48 hours and credited upon patch release.

---

## 🤝 Code of Conduct

We are committed to maintaining an open, welcoming, and harassment-free environment for all contributors.
- Treat every community member with respect and professional courtesy.
- Focus on constructive technical feedback.
- Support ethical security research and responsible disclosure practices.

---

<div align="center">
  <sub>Maintained by <strong>Kishan Sah</strong> &amp; Open Source Community Contributors.</sub>
</div>
