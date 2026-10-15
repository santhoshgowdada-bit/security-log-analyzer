import sqlite3


import os

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "security_alerts.db")

def init_db():
    connection = sqlite3.connect(DB_PATH)
    cursor = connection.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        alert_type TEXT,
        ip_address TEXT,
        count INTEGER,
        severity TEXT,
        risk_score INTEGER
    )
    """)
    connection.commit()
    connection.close()

init_db()

def save_alert(alert):
    connection = sqlite3.connect(DB_PATH)
    cursor = connection.cursor()

    ip_val = alert.get("ip") or alert.get("ip_address") or "N/A"
    alert_type = alert.get("alert_type", "Security Alert")
    count_val = alert.get("failed_attempts") if alert.get("failed_attempts") is not None else alert.get("count", 0)
    sev_val = alert.get("severity", "MEDIUM")
    risk_val = alert.get("risk_score", 50)

    cursor.execute(
        """
        INSERT INTO alerts
        (alert_type, ip_address, count, severity, risk_score)
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            alert_type,
            ip_val,
            count_val,
            sev_val,
            risk_val
        )
    )

    connection.commit()
    connection.close()