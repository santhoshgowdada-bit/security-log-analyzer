def detect_bruteforce(logs, threshold=5):

    failed_attempts = {}

    for log in logs:

        ip = log.get("ip") or log.get("ip_address")

        if log.get("status") == "FAILED" and ip and ip != "-":

            failed_attempts[ip] = failed_attempts.get(ip, 0) + 1

    alerts = []

    for ip, count in failed_attempts.items():

        if count >= threshold:

            alerts.append({
                "ip": ip,
                "failed_attempts": count,
                "alert_type": "Possible Brute-Force Attack",
                "severity": "HIGH",
                "risk_score": 70,
                "details": f"{count} failed login attempts from IP {ip} exceeding threshold ({threshold})"
            })

    return alerts


def detect_multiple_accounts(logs, threshold=3):

    ip_users = {}

    for log in logs:

        ip = log.get("ip") or log.get("ip_address")
        username = log.get("username")

        if log.get("status") == "FAILED" and ip and ip != "-" and username and username != "UNKNOWN":

            if ip not in ip_users:
                ip_users[ip] = set()

            ip_users[ip].add(username)

    alerts = []

    for ip, usernames in ip_users.items():

        if len(usernames) >= threshold:

            alerts.append({
                "ip": ip,
                "failed_attempts": len(usernames),
                "alert_type": "Possible Multiple-Account Attack",
                "severity": "MEDIUM",
                "risk_score": 50,
                "details": f"{len(usernames)} distinct usernames targeted from IP {ip} exceeding threshold ({threshold})"
            })

    return alerts