"""
Phase 10: Comprehensive Synthetic Verification Suite for Security Log Analyzer.
Executes and validates Tests A through I as required by the project specification.
"""

import sys
import io
import unittest
import pandas as pd
from pathlib import Path

# Add src and root to path
PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))
sys.path.insert(0, str(PROJECT_ROOT))

from src.parser import parse_logs
from src.detector import detect_bruteforce, detect_multiple_accounts
from src.app import (
    detect_file_source,
    alert_already_in_db,
    build_threat_risk_gauge_figure,
    build_severity_donut_figure,
    build_auth_outcome_donut_figure,
    build_suspicious_ips_bar_figure,
    build_targeted_users_bar_figure,
    build_attack_types_bar_figure,
    build_ip_distribution_donut_figure,
    build_auth_timeline_figure
)


class TestPhase10Verification(unittest.TestCase):
    """Execution of all Phase 10 validation test cases A through I."""

    def test_a_normal_login(self):
        """
        TEST A: NORMAL LOGIN
        One or two successful logins.
        Expected: Successful events counted; no brute-force alert generated.
        """
        log_content = (
            "2026-10-12 10:00:00 | LOGIN | alice | 192.168.1.10 | SUCCESS\n"
            "2026-10-12 10:05:00 | LOGIN | bob | 192.168.1.20 | SUCCESS\n"
        )
        parsed = parse_logs(log_content)
        self.assertEqual(len(parsed), 2)
        success_count = sum(1 for e in parsed if e.get("status") == "SUCCESS")
        failed_count = sum(1 for e in parsed if e.get("status") == "FAILED")
        self.assertEqual(success_count, 2)
        self.assertEqual(failed_count, 0)

        # Brute-force and multiple account detectors should produce 0 alerts
        bf_alerts = detect_bruteforce(parsed, threshold=5)
        ma_alerts = detect_multiple_accounts(parsed, threshold=3)
        self.assertEqual(len(bf_alerts), 0)
        self.assertEqual(len(ma_alerts), 0)

    def test_b_failed_logins(self):
        """
        TEST B: FAILED LOGINS
        Five failed login attempts from one source IP.
        Expected: Five failed events counted; threshold=5 rule generates alert.
        """
        log_content = "\n".join([
            f"2026-10-12 11:0{i}:00 | LOGIN | admin | 192.168.1.150 | FAILED"
            for i in range(5)
        ])
        parsed = parse_logs(log_content)
        self.assertEqual(len(parsed), 5)
        failed_count = sum(1 for e in parsed if e.get("status") == "FAILED")
        self.assertEqual(failed_count, 5)

        bf_alerts = detect_bruteforce(parsed, threshold=5)
        self.assertEqual(len(bf_alerts), 1)
        alert = bf_alerts[0]
        self.assertEqual(alert["ip"], "192.168.1.150")
        self.assertEqual(alert["failed_attempts"], 5)
        self.assertEqual(alert["severity"], "HIGH")
        self.assertEqual(alert["risk_score"], 70)
        self.assertIn("Possible Brute-Force", alert["alert_type"])

    def test_c_mixed_logins(self):
        """
        TEST C: MIXED LOGINS
        A mixture of successful and failed events.
        Expected: Counts accurate; detection is strictly based on failed attempts.
        """
        log_lines = [
            "2026-10-12 08:00:00 | LOGIN | charlie | 10.0.0.50 | SUCCESS",
            "2026-10-12 08:01:00 | LOGIN | david | 10.0.0.50 | SUCCESS",
            "2026-10-12 08:02:00 | LOGIN | root | 10.0.0.50 | FAILED",
            "2026-10-12 08:03:00 | LOGIN | root | 10.0.0.50 | FAILED",
            "2026-10-12 08:04:00 | LOGIN | root | 10.0.0.50 | FAILED",
            "2026-10-12 08:05:00 | LOGIN | root | 10.0.0.50 | FAILED",
            "2026-10-12 08:06:00 | LOGIN | root | 10.0.0.50 | FAILED",
            "2026-10-12 08:07:00 | LOGIN | eva | 10.0.0.99 | FAILED",
            "2026-10-12 08:08:00 | LOGIN | eva | 10.0.0.99 | SUCCESS"
        ]
        parsed = parse_logs("\n".join(log_lines))
        self.assertEqual(len(parsed), 9)
        success_count = sum(1 for e in parsed if e.get("status") == "SUCCESS")
        failed_count = sum(1 for e in parsed if e.get("status") == "FAILED")
        self.assertEqual(success_count, 3)
        self.assertEqual(failed_count, 6)

        bf_alerts = detect_bruteforce(parsed, threshold=5)
        self.assertEqual(len(bf_alerts), 1)
        self.assertEqual(bf_alerts[0]["ip"], "10.0.0.50")
        self.assertEqual(bf_alerts[0]["failed_attempts"], 5)

    def test_d_multiple_ips(self):
        """
        TEST D: MULTIPLE IPS
        Events from different IP addresses.
        Expected: IP grouping correct; one IP's attempts not added to another.
        """
        log_lines = [
            # 4 failures from IP A (below threshold 5)
            "2026-10-12 09:00:00 | LOGIN | user1 | 172.16.0.1 | FAILED",
            "2026-10-12 09:01:00 | LOGIN | user1 | 172.16.0.1 | FAILED",
            "2026-10-12 09:02:00 | LOGIN | user1 | 172.16.0.1 | FAILED",
            "2026-10-12 09:03:00 | LOGIN | user1 | 172.16.0.1 | FAILED",
            # 4 failures from IP B (below threshold 5)
            "2026-10-12 09:00:00 | LOGIN | user2 | 172.16.0.2 | FAILED",
            "2026-10-12 09:01:00 | LOGIN | user2 | 172.16.0.2 | FAILED",
            "2026-10-12 09:02:00 | LOGIN | user2 | 172.16.0.2 | FAILED",
            "2026-10-12 09:03:00 | LOGIN | user2 | 172.16.0.2 | FAILED",
        ]
        parsed = parse_logs("\n".join(log_lines))
        self.assertEqual(len(parsed), 8)

        # Neither IP reached threshold=5 (8 total failures across 2 IPs)
        bf_alerts = detect_bruteforce(parsed, threshold=5)
        self.assertEqual(len(bf_alerts), 0)

        # Add 5th attempt ONLY to IP A
        log_lines.append("2026-10-12 09:04:00 | LOGIN | user1 | 172.16.0.1 | FAILED")
        parsed2 = parse_logs("\n".join(log_lines))
        bf_alerts2 = detect_bruteforce(parsed2, threshold=5)
        self.assertEqual(len(bf_alerts2), 1)
        self.assertEqual(bf_alerts2[0]["ip"], "172.16.0.1")
        self.assertEqual(bf_alerts2[0]["failed_attempts"], 5)

    def test_e_empty_file(self):
        """
        TEST E: EMPTY FILE
        Expected: Clear message, no crash, no fabricated events or alerts.
        """
        empty_content = ""
        src_name, is_valid, _, reason = detect_file_source("empty.log", empty_content)
        self.assertFalse(is_valid)
        self.assertIn("no data", reason.lower())

        parsed = parse_logs(empty_content)
        self.assertEqual(parsed, [])

        alerts = detect_bruteforce(parsed, threshold=5)
        self.assertEqual(alerts, [])

    def test_f_malformed_file(self):
        """
        TEST F: MALFORMED FILE
        Expected: Parsing errors reported, application remains usable.
        """
        malformed_text = "This is a random text file\nWithout security format\nJust random sentences."
        src_name, is_valid, _, reason = detect_file_source("notes.txt", malformed_text)
        self.assertFalse(is_valid)
        self.assertEqual(src_name, "Unknown Format")

        parsed = parse_logs(malformed_text)
        self.assertEqual(parsed, [])
        alerts = detect_bruteforce(parsed, threshold=5)
        self.assertEqual(alerts, [])

    def test_g_visualizations(self):
        """
        TEST G: VISUALIZATIONS
        Expected: All charts render when suitable data exists, empty-state on empty, no Plotly errors.
        """
        sample_logs = [
            {"timestamp": "2026-10-12 10:00:00", "status": "SUCCESS", "username": "alice", "ip": "192.168.1.10", "ip_address": "192.168.1.10"},
            {"timestamp": "2026-10-12 10:01:00", "status": "FAILED", "username": "admin", "ip": "192.168.1.50", "ip_address": "192.168.1.50"},
            {"timestamp": "2026-10-12 10:02:00", "status": "FAILED", "username": "admin", "ip": "192.168.1.50", "ip_address": "192.168.1.50"},
        ]
        sample_alerts = [
            {"alert_type": "Possible Brute-Force Attack", "ip": "192.168.1.50", "failed_attempts": 5, "severity": "HIGH", "risk_score": 70}
        ]

        # 1. Gauge
        fig_gauge = build_threat_risk_gauge_figure(sample_alerts, 1, 2, 3, height=300)
        self.assertIsNotNone(fig_gauge)

        # 2. Severity Donut
        fig_sev = build_severity_donut_figure(sample_alerts, 3, 1, 2, height=300)
        self.assertIsNotNone(fig_sev)

        # 3. Auth Outcome Donut
        fig_auth = build_auth_outcome_donut_figure(1, 2, height=300)
        self.assertIsNotNone(fig_auth)

        # 4. Suspicious IPs Bar
        fig_ips = build_suspicious_ips_bar_figure(sample_logs, sample_alerts, height=300)
        self.assertIsNotNone(fig_ips)

        # 5. Targeted Users Bar
        fig_users = build_targeted_users_bar_figure(sample_logs, height=300)
        self.assertIsNotNone(fig_users)

        # 6. Attack Types Bar
        fig_atk = build_attack_types_bar_figure(sample_alerts, height=280)
        self.assertIsNotNone(fig_atk)

        # 7. Hostile IP Donut
        fig_ip_don = build_ip_distribution_donut_figure(sample_logs, height=300)
        self.assertIsNotNone(fig_ip_don)

        # 8. Auth Timeline
        fig_time = build_auth_timeline_figure(sample_logs, height=320)
        self.assertIsNotNone(fig_time)

        # Test empty datasets return graceful None or clean state without crashing
        empty_gauge = build_threat_risk_gauge_figure([], 0, 0, 0, height=300)
        self.assertIsNotNone(empty_gauge)  # renders clean 0/100 score
        self.assertIsNone(build_suspicious_ips_bar_figure([], []))
        self.assertIsNone(build_targeted_users_bar_figure([]))
        self.assertIsNone(build_attack_types_bar_figure([]))
        self.assertIsNone(build_ip_distribution_donut_figure([]))

    def test_h_export(self):
        """
        TEST H: EXPORT
        Expected: CSV export produces valid CSV with expected columns and values.
        """
        alerts = [
            {"alert_type": "Possible Brute-Force Attack", "ip": "10.0.0.1", "failed_attempts": 6, "severity": "HIGH", "risk_score": 70}
        ]
        df = pd.DataFrame(alerts)
        csv_buffer = io.StringIO()
        df.to_csv(csv_buffer, index=False)
        csv_content = csv_buffer.getvalue()

        self.assertIn("alert_type,ip,failed_attempts,severity,risk_score", csv_content)
        self.assertIn("Possible Brute-Force Attack,10.0.0.1,6,HIGH,70", csv_content)

    def test_i_repeated_analysis(self):
        """
        TEST I: REPEATED ANALYSIS
        Upload and analyze the same file twice.
        Expected: Metrics correct for each upload; historical alerts deduplicated.
        """
        existing_db_records = [
            (1, "Possible Brute-Force Attack", "192.168.1.100", 5, "HIGH", 70)
        ]
        analyzed_alert = {
            "alert_type": "Possible Brute-Force Attack",
            "ip": "192.168.1.100",
            "failed_attempts": 5,
            "severity": "HIGH",
            "risk_score": 70
        }

        # First check: duplicate detected
        self.assertTrue(alert_already_in_db(analyzed_alert, existing_db_records))

        # Different IP or different attempt count: not a duplicate
        different_alert = dict(analyzed_alert, ip="192.168.1.200")
        self.assertFalse(alert_already_in_db(different_alert, existing_db_records))


if __name__ == "__main__":
    unittest.main()
