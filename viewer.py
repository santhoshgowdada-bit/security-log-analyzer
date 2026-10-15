import os
import sqlite3

# Connect to the root database regardless of CWD
DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "security_alerts.db")
connection = sqlite3.connect(DB_PATH)

cursor = connection.cursor()

# Get all alerts
cursor.execute("SELECT * FROM alerts")

alerts = cursor.fetchall()

print("\n===== STORED SECURITY ALERTS =====\n")

if alerts:
    for alert in alerts:
        print(f"ID: {alert[0]}")
        print(f"Alert Type: {alert[1]}")
        print(f"IP Address: {alert[2]}")
        print(f"Failed Attempts: {alert[3]}")
        print(f"Severity: {alert[4]}")
        print(f"Risk Score: {alert[5]}")
        print("-" * 35)
else:
    print("No alerts found.")

# Close the database
connection.close()