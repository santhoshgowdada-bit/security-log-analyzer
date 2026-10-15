"""
Comprehensive test suite for Security Log Analyzer.
Tests parser, detector, database and integration workflows.
"""

import sys
import unittest
import sqlite3
from pathlib import Path

# Ensure src and project root are on path
PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))
sys.path.insert(0, str(PROJECT_ROOT))
LOGS_DIR = PROJECT_ROOT / "data" / "logs"

from src.parser import parse_logs, parse_windows_csv, parse_windows_event_log
from src.detector import detect_bruteforce, detect_multiple_accounts




class TestPipeDelimitedLogs(unittest.TestCase):
    """Tests for pipe-delimited standard auth log format."""

    def test_failed_logins(self):
        content = (LOGS_DIR / "failed_logins.log").read_text(encoding="utf-8")
        logs = parse_logs(content)
        self.assertEqual(len(logs), 5)
        self.assertTrue(all(l["status"] == "FAILED" for l in logs))
        self.assertTrue(all(l["ip"] == "192.168.1.150" for l in logs))

    def test_mixed_logins(self):
        content = (LOGS_DIR / "mixed_login.log").read_text(encoding="utf-8")
        logs = parse_logs(content)
        self.assertEqual(len(logs), 7)
        success = [l for l in logs if l["status"] == "SUCCESS"]
        failed = [l for l in logs if l["status"] == "FAILED"]
        self.assertEqual(len(success), 5)
        self.assertEqual(len(failed), 2)

    def test_bruteforce_demo(self):
        content = (LOGS_DIR / "bruteforce_demo.log").read_text(encoding="utf-8")
        logs = parse_logs(content)
        self.assertEqual(len(logs), 7)
        failed = [l for l in logs if l["status"] == "FAILED"]
        self.assertEqual(len(failed), 6)
        # Brute-force detection should trigger
        alerts = detect_bruteforce(logs, threshold=3)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["ip"], "198.51.100.42")
        self.assertEqual(alerts[0]["failed_attempts"], 6)

    def test_multiple_account_detection(self):
        content = (LOGS_DIR / "failed_logins.log").read_text(encoding="utf-8")
        logs = parse_logs(content)
        alerts = detect_multiple_accounts(logs, threshold=3)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["ip"], "192.168.1.150")
        self.assertGreaterEqual(alerts[0]["failed_attempts"], 3)


class TestSSHLogs(unittest.TestCase):
    """Tests for Linux/Kali SSH syslog format."""

    def test_ssh_parsing(self):
        content = (LOGS_DIR / "ssh.log").read_text(encoding="utf-8")
        logs = parse_logs(content)
        self.assertGreater(len(logs), 0)
        self.assertEqual(logs[0]["username"], "wronguser")
        self.assertEqual(logs[0]["ip"], "::1")  # IPv6
        self.assertEqual(logs[0]["status"], "FAILED")

    def test_ssh_bruteforce_detection(self):
        content = (LOGS_DIR / "ssh.log").read_text(encoding="utf-8")
        logs = parse_logs(content)
        alerts = detect_bruteforce(logs, threshold=3)
        self.assertTrue(any(a["alert_type"] == "Possible Brute-Force Attack" for a in alerts))


class TestWindowsCSV(unittest.TestCase):
    """Tests for Windows Security CSV format."""

    def test_windows_compact_csv(self):
        content = (LOGS_DIR / "windows_security_compact.csv").read_text(encoding="utf-8")
        logs = parse_logs(content)
        self.assertEqual(len(logs), 200)
        self.assertEqual(logs[0]["status"], "SUCCESS")
        self.assertEqual(logs[0]["event_id"], "4624")
        self.assertEqual(logs[0]["source"], "Windows")
        self.assertIsNone(logs[0]["ip_address"])  # Dash is cleaned to None

    def test_windows_attack_sample(self):
        content = (LOGS_DIR / "windows_attack_sample.csv").read_text(encoding="utf-8-sig")
        logs = parse_logs(content)
        self.assertEqual(len(logs), 12)
        failed = [l for l in logs if l["status"] == "FAILED"]
        success = [l for l in logs if l["status"] == "SUCCESS"]
        self.assertEqual(len(failed), 9)
        self.assertEqual(len(success), 3)

    def test_windows_attack_detection(self):
        content = (LOGS_DIR / "windows_attack_sample.csv").read_text(encoding="utf-8-sig")
        logs = parse_logs(content)
        bf = detect_bruteforce(logs, threshold=3)
        ma = detect_multiple_accounts(logs, threshold=3)
        self.assertGreaterEqual(len(bf), 2)
        self.assertGreaterEqual(len(ma), 1)

    def test_ipv6_preserved(self):
        csv_content = (
            '"Timestamp","EventID","Username","LogonType","SourceIP","SourcePort"\n'
            '"2026-10-06 10:00:00","4625","user1","3","::1","54321"\n'
            '"2026-10-06 10:00:01","4625","user2","3","::1","54322"\n'
        )
        logs = parse_logs(csv_content)
        self.assertEqual(len(logs), 2)
        self.assertEqual(logs[0]["ip_address"], "::1")
        self.assertEqual(logs[0]["ip"], "::1")

    def test_dash_ip_cleaned(self):
        csv_content = (
            '"Timestamp","EventID","Username","LogonType","SourceIP","SourcePort"\n'
            '"2026-10-06 10:00:03","4625","SYSTEM","5","-","-"\n'
        )
        logs = parse_logs(csv_content)
        self.assertEqual(len(logs), 1)
        self.assertIsNone(logs[0]["ip_address"])
        self.assertIsNone(logs[0]["ip"])


class TestWindowsEventLog(unittest.TestCase):
    """Tests for Windows Event Viewer text format."""

    def test_event_viewer_parsing(self):
        content = (LOGS_DIR / "windows_security.log").read_text(encoding="utf-8-sig", errors="ignore")
        logs = parse_logs(content)
        self.assertEqual(len(logs), 100)
        self.assertEqual(logs[0]["status"], "SUCCESS")
        self.assertEqual(logs[0]["event_id"], "4624")
        self.assertEqual(logs[0]["source"], "Windows")


class TestEmptyAndInvalidInputs(unittest.TestCase):
    """Tests for edge cases and error handling."""

    def test_empty_string(self):
        logs = parse_logs("")
        self.assertEqual(logs, [])

    def test_none_input(self):
        logs = parse_logs(None)
        self.assertEqual(logs, [])

    def test_whitespace_only(self):
        logs = parse_logs("   \n  \n   ")
        self.assertEqual(logs, [])

    def test_unrecognized_format(self):
        content = "This is random text\nIt has no log format\nJust plain English."
        logs = parse_logs(content)
        self.assertEqual(logs, [])

    def test_bruteforce_no_logs(self):
        alerts = detect_bruteforce([], threshold=3)
        self.assertEqual(alerts, [])

    def test_multiple_accounts_no_logs(self):
        alerts = detect_multiple_accounts([], threshold=3)
        self.assertEqual(alerts, [])

    def test_bruteforce_below_threshold(self):
        logs = [
            {"ip": "1.2.3.4", "status": "FAILED"},
            {"ip": "1.2.3.4", "status": "FAILED"},
        ]
        alerts = detect_bruteforce(logs, threshold=3)
        self.assertEqual(len(alerts), 0)

    def test_missing_ip_in_detection(self):
        """Events with missing IP should not crash detection."""
        logs = [
            {"ip": None, "status": "FAILED", "username": "admin"},
            {"ip": "-", "status": "FAILED", "username": "admin"},
            {"ip": "", "status": "FAILED", "username": "admin"},
        ]
        alerts = detect_bruteforce(logs, threshold=3)
        self.assertEqual(len(alerts), 0)  # None/empty IPs are filtered

    def test_partial_parse(self):
        """Mix of valid and invalid lines should parse valid ones."""
        content = (
            "2026-10-08 10:00:01 | LOGIN | admin | 192.168.1.1 | FAILED\n"
            "this line is garbage\n"
            "another invalid line\n"
            "2026-10-08 10:00:02 | LOGIN | bob | 192.168.1.2 | SUCCESS\n"
        )
        logs = parse_logs(content)
        self.assertEqual(len(logs), 2)
        self.assertEqual(logs[0]["username"], "admin")
        self.assertEqual(logs[1]["username"], "bob")


class TestDetectionRules(unittest.TestCase):
    """Tests for detection rule logic."""

    def test_bruteforce_exact_threshold(self):
        logs = [
            {"ip": "10.0.0.1", "ip_address": "10.0.0.1", "status": "FAILED"},
            {"ip": "10.0.0.1", "ip_address": "10.0.0.1", "status": "FAILED"},
            {"ip": "10.0.0.1", "ip_address": "10.0.0.1", "status": "FAILED"},
        ]
        alerts = detect_bruteforce(logs, threshold=3)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["severity"], "HIGH")
        self.assertEqual(alerts[0]["risk_score"], 70)

    def test_bruteforce_multiple_ips(self):
        logs = [
            {"ip": "10.0.0.1", "status": "FAILED"},
            {"ip": "10.0.0.1", "status": "FAILED"},
            {"ip": "10.0.0.1", "status": "FAILED"},
            {"ip": "10.0.0.2", "status": "FAILED"},
            {"ip": "10.0.0.2", "status": "FAILED"},
            {"ip": "10.0.0.2", "status": "FAILED"},
            {"ip": "10.0.0.2", "status": "FAILED"},
        ]
        alerts = detect_bruteforce(logs, threshold=3)
        self.assertEqual(len(alerts), 2)

    def test_multiple_accounts_exact_threshold(self):
        logs = [
            {"ip": "10.0.0.1", "ip_address": "10.0.0.1", "status": "FAILED", "username": "alice"},
            {"ip": "10.0.0.1", "ip_address": "10.0.0.1", "status": "FAILED", "username": "bob"},
            {"ip": "10.0.0.1", "ip_address": "10.0.0.1", "status": "FAILED", "username": "charlie"},
        ]
        alerts = detect_multiple_accounts(logs, threshold=3)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["severity"], "MEDIUM")
        self.assertEqual(alerts[0]["risk_score"], 50)

    def test_success_events_ignored_by_detection(self):
        logs = [
            {"ip": "10.0.0.1", "status": "SUCCESS", "username": "admin"},
            {"ip": "10.0.0.1", "status": "SUCCESS", "username": "admin"},
            {"ip": "10.0.0.1", "status": "SUCCESS", "username": "admin"},
        ]
        bf = detect_bruteforce(logs, threshold=3)
        ma = detect_multiple_accounts(logs, threshold=3)
        self.assertEqual(len(bf), 0)
        self.assertEqual(len(ma), 0)


class TestDatabaseIntegration(unittest.TestCase):
    """Tests for database operations."""

    def test_db_exists(self):
        db_path = PROJECT_ROOT / "security_alerts.db"
        self.assertTrue(db_path.exists())

    def test_db_schema(self):
        conn = sqlite3.connect(PROJECT_ROOT / "security_alerts.db")
        cur = conn.cursor()
        cur.execute("PRAGMA table_info(alerts)")
        columns = {row[1] for row in cur.fetchall()}
        conn.close()
        self.assertIn("alert_type", columns)
        self.assertIn("ip_address", columns)
        self.assertIn("count", columns)
        self.assertIn("severity", columns)
        self.assertIn("risk_score", columns)

    def test_existing_records_preserved(self):
        conn = sqlite3.connect(PROJECT_ROOT / "security_alerts.db")
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM alerts")
        count = cur.fetchone()[0]
        conn.close()
        self.assertGreater(count, 0, "Existing alert records should be preserved")


if __name__ == "__main__":
    unittest.main()
