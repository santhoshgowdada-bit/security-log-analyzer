"""
Tests for Security Log Analyzer dashboard logic, file source auto-detection,
and database deduplication.
"""

import sys
import time
import unittest
from pathlib import Path
import streamlit as st

# Add src and project root to path
PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))
sys.path.insert(0, str(PROJECT_ROOT))
LOGS_DIR = PROJECT_ROOT / "data" / "logs"

from src import app
from src.app import detect_file_source, alert_already_in_db, severity_badge_html




class TestFileSourceDetection(unittest.TestCase):
    """Test automatic recognition of log source formats."""

    def test_windows_csv_detection(self):
        sample = (LOGS_DIR / "windows_attack_sample.csv").read_text(encoding="utf-8-sig")
        src_name, is_valid, _, reason = detect_file_source("windows_attack_sample.csv", sample)
        self.assertEqual(src_name, "Windows Security CSV")
        self.assertTrue(is_valid)
        self.assertIsNone(reason)

    def test_windows_event_log_detection(self):
        sample = (LOGS_DIR / "windows_security.log").read_text(encoding="utf-8-sig", errors="ignore")
        src_name, is_valid, _, reason = detect_file_source("windows_security.log", sample)
        self.assertEqual(src_name, "Windows Event Viewer Log")
        self.assertTrue(is_valid)
        self.assertIsNone(reason)

    def test_ssh_syslog_detection(self):
        sample = (LOGS_DIR / "ssh.log").read_text(encoding="utf-8")
        src_name, is_valid, _, reason = detect_file_source("ssh.log", sample)
        self.assertEqual(src_name, "Linux SSH Log (Syslog)")
        self.assertTrue(is_valid)
        self.assertIsNone(reason)

    def test_pipe_delimited_detection(self):
        sample = (LOGS_DIR / "failed_logins.log").read_text(encoding="utf-8")
        src_name, is_valid, _, reason = detect_file_source("failed_logins.log", sample)
        self.assertEqual(src_name, "Standard Auth Log (Pipe-delimited)")
        self.assertTrue(is_valid)
        self.assertIsNone(reason)

    def test_empty_content_detection(self):
        src_name, is_valid, _, reason = detect_file_source("empty.log", "")
        self.assertEqual(src_name, "Empty File")
        self.assertFalse(is_valid)
        self.assertIsNotNone(reason)

    def test_unrecognized_format_detection(self):
        src_name, is_valid, _, reason = detect_file_source("notes.txt", "Just a plain memo without security logs")
        self.assertEqual(src_name, "Unknown Format")
        self.assertFalse(is_valid)
        self.assertIsNotNone(reason)


class TestDatabaseDeduplication(unittest.TestCase):
    """Test deduplication logic to prevent duplicating identical alerts."""

    def test_alert_duplicate_check(self):
        existing_rows = [
            (1, "Possible Brute-Force Attack", "192.168.1.100", 5, "HIGH", 70),
            (2, "Possible Multiple-Account Attack", "10.0.0.5", 3, "MEDIUM", 50)
        ]
        duplicate_alert = {
            "alert_type": "Possible Brute-Force Attack",
            "ip": "192.168.1.100",
            "failed_attempts": 5,
            "severity": "HIGH",
            "risk_score": 70
        }
        new_alert = {
            "alert_type": "Possible Brute-Force Attack",
            "ip": "192.168.1.200",
            "failed_attempts": 6,
            "severity": "HIGH",
            "risk_score": 70
        }
        self.assertTrue(alert_already_in_db(duplicate_alert, existing_rows))
        self.assertFalse(alert_already_in_db(new_alert, existing_rows))


class TestSeverityBadges(unittest.TestCase):
    """Test HTML severity badge rendering."""

    def test_high_badge(self):
        html = severity_badge_html("HIGH")
        self.assertIn("sev-high", html)
        self.assertIn("HIGH", html)

    def test_medium_badge(self):
        html = severity_badge_html("MEDIUM")
        self.assertIn("sev-medium", html)
        self.assertIn("MEDIUM", html)

    def test_low_badge(self):
        html = severity_badge_html("LOW")
        self.assertIn("sev-low", html)
        self.assertIn("LOW", html)


class MockUIContainer:
    def __init__(self):
        self.markdowns = []

    def markdown(self, text, unsafe_allow_html=False):
        self.markdowns.append(text)


class TestAnalysisWorkflow(unittest.TestCase):
    """Test 7-stage workflow execution, timing bounds, and metric integrity."""

    def test_workflow_success_metrics(self):
        sample_path = str(LOGS_DIR / "bruteforce_demo.log")
        wrapper = app.LocalFileWrapper("bruteforce_demo.log", sample_path)
        mock_ui = MockUIContainer()

        start_t = time.time()
        success = app.execute_analysis_workflow([wrapper], mock_ui)
        elapsed = time.time() - start_t

        self.assertTrue(success)
        # Verify minimum visible duration of ~5 seconds was honored
        self.assertGreaterEqual(elapsed, 4.9)

        # Check all 7 stages were rendered
        all_text = " ".join(mock_ui.markdowns)
        self.assertIn("Stage 1: Initializing Analysis", all_text)
        self.assertIn("Stage 7: Analysis Completed", all_text)

        # Check real metrics recorded
        metrics = st.session_state.get("analysis_metrics")
        self.assertIsNotNone(metrics)
        self.assertEqual(metrics["files_analyzed"], 1)
        self.assertEqual(metrics["total_events"], 7)
        self.assertEqual(metrics["failed_logins"], 6)
        self.assertEqual(metrics["successful_logins"], 1)
        self.assertEqual(metrics["total_alerts"], 1)
        self.assertEqual(metrics["high_alerts"], 1)
        self.assertEqual(metrics["unrecognized_lines"], 0)

    def test_workflow_invalid_file_honest_error(self):
        class DummyInvalid:
            name = "notes.txt"
            def read(self, *args):
                return b"Random plain notes without security events."
            def seek(self, pos):
                pass

        mock_ui = MockUIContainer()
        success = app.execute_analysis_workflow([DummyInvalid()], mock_ui)
        self.assertFalse(success)

        all_text = " ".join(mock_ui.markdowns)
        self.assertIn("Analysis Failed: No Supported Security Logs", all_text)
        self.assertIn("notes.txt", all_text)
        self.assertNotIn("Stage 7 of 7", all_text)
        self.assertNotIn("All processing completed", all_text)

    def test_quick_load_workflow(self):
        """Verify quick-load workflow with LocalFileWrapper executes cleanly."""
        sample_path = str(LOGS_DIR / "windows_attack_sample.csv")
        wrapper = app.LocalFileWrapper("windows_attack_sample.csv", sample_path)
        mock_ui = MockUIContainer()
        success = app.execute_analysis_workflow(
            [wrapper], mock_ui, min_visible_duration=0.1, demo_mode=False
        )
        self.assertTrue(success)
        metrics = st.session_state.get("analysis_metrics")
        self.assertIsNotNone(metrics)
        self.assertGreater(metrics["total_events"], 0)


class TestAppTestUIWorkflow(unittest.TestCase):
    """End-to-end Streamlit UI interaction tests using AppTest."""

    def test_scroll_dashboard_anchors(self):
        from streamlit.testing.v1 import AppTest
        app_file = str(PROJECT_ROOT / "src" / "app.py")
        at = AppTest.from_file(app_file)
        at.run(timeout=30)
        self.assertFalse(at.exception, f"App raised exception: {at.exception}")

        # Check default navigation is Scroll View
        self.assertGreaterEqual(len(at.radio), 1)
        self.assertIn("Scroll View", at.radio[0].value)

        # Check all required section anchors
        markdown_text = " ".join([m.value for m in at.markdown])
        expected_anchors = [
            "sec-overview", "sec-kpis", "sec-upload", "sec-alerts",
            "sec-timeline", "sec-gauge", "sec-severity", "sec-auth-ratio",
            "sec-suspicious-ips", "sec-events", "sec-reports", "sec-rules"
        ]
        for anchor in expected_anchors:
            self.assertIn(anchor, markdown_text, f"Missing section anchor: {anchor}")

    def test_attack_and_clean_demo_buttons(self):
        from streamlit.testing.v1 import AppTest
        app_file = str(PROJECT_ROOT / "src" / "app.py")
        at = AppTest.from_file(app_file)
        at.session_state["demo_mode"] = False
        at.run(timeout=30)
        self.assertFalse(at.exception)

        # Click Attack button
        attack_btn = next((b for b in at.button if "Attack" in b.label), None)
        self.assertIsNotNone(attack_btn, "Attack demo button missing")
        attack_btn.click().run(timeout=30)
        self.assertFalse(at.exception)
        self.assertTrue(at.session_state["analysis_done"])
        self.assertGreater(len(at.session_state["alerts"]), 0)

        # Click Clean button
        clean_btn = next((b for b in at.button if "Clean" in b.label), None)
        self.assertIsNotNone(clean_btn, "Clean demo button missing")
        clean_btn.click().run(timeout=30)
        self.assertFalse(at.exception)
        self.assertTrue(at.session_state["analysis_done"])
        self.assertEqual(len(at.session_state["alerts"]), 0)


if __name__ == "__main__":
    unittest.main()


