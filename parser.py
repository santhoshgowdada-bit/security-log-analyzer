import csv
import io
import re


def _clean_ip(ip_val):
    if not ip_val:
        return None
    ip_str = str(ip_val).strip()
    if ip_str in ("-", "", "none", "null", "None", "NULL"):
        return None
    return ip_str


def _clean_port(port_val):
    if not port_val:
        return None
    port_str = str(port_val).strip()
    if port_str in ("-", "", "none", "null", "None", "NULL"):
        return None
    return port_str


def _extract_ip(message):
    ip_match = re.search(
        r"(?:\b(?:\d{1,3}\.){3}\d{1,3}\b|::1)",
        message
    )
    return ip_match.group(0) if ip_match else "UNKNOWN"


def _extract_username(message):
    patterns = [
        r"invalid user\s+([A-Za-z0-9_.-]+)",
        r"for(?: invalid)? user\s+([A-Za-z0-9_.-]+)",
        r"for\s+([A-Za-z0-9_.-]+)\s+from",
        r"ruser=\s*([A-Za-z0-9_.-]+)",
        r"user=\s*([A-Za-z0-9_.-]+)",
        r"username=\s*([A-Za-z0-9_.-]+)",
    ]

    for pattern in patterns:
        match = re.search(pattern, message, re.IGNORECASE)
        if match:
            return match.group(1)

    return "UNKNOWN"


def _extract_status(message):
    lower_message = message.lower()

    if any(token in lower_message for token in [
        "failed password",
        "authentication failure",
        "invalid user",
        "connection closed by invalid user",
    ]):
        return "FAILED"

    if any(token in lower_message for token in [
        "accepted password",
        "session opened",
        "successful login",
        "session opened for user",
    ]):
        return "SUCCESS"

    return "UNKNOWN"


def parse_windows_csv(content):
    logs = []
    clean_content = content.lstrip("\ufeff").strip()
    if not clean_content:
        return logs

    reader = csv.DictReader(io.StringIO(clean_content))
    if not reader.fieldnames:
        return logs

    for row in reader:
        norm_row = {
            (k.strip().strip('"').lower() if k else ""): (v.strip().strip('"') if v else "")
            for k, v in row.items()
        }

        timestamp = norm_row.get("timestamp", "")
        raw_event_id = norm_row.get("eventid") or norm_row.get("event_id") or ""
        username = norm_row.get("username", "")
        logon_type = norm_row.get("logontype") or norm_row.get("logon_type") or "-"
        raw_ip = norm_row.get("sourceip") or norm_row.get("source_ip") or norm_row.get("ip_address")
        raw_port = norm_row.get("sourceport") or norm_row.get("source_port")

        event_id_str = str(raw_event_id).strip()
        status = "UNKNOWN"
        if event_id_str == "4624":
            status = "SUCCESS"
        elif event_id_str == "4625":
            status = "FAILED"
        elif norm_row.get("status"):
            st_val = norm_row.get("status").strip().upper()
            if "SUCCESS" in st_val:
                status = "SUCCESS"
            elif "FAIL" in st_val:
                status = "FAILED"

        ip_clean = _clean_ip(raw_ip)
        port_clean = _clean_port(raw_port)

        log = {
            "timestamp": timestamp,
            "event_id": event_id_str,
            "event": f"EVENT_{event_id_str}" if event_id_str else "WINDOWS_LOGON",
            "username": username,
            "ip_address": ip_clean,
            "ip": ip_clean,
            "source_port": port_clean,
            "logon_type": logon_type,
            "status": status,
            "source": "Windows",
            "source_type": "Windows",
        }
        logs.append(log)

    return logs


def parse_windows_event_log(content):
    logs = []
    clean_content = content.lstrip("\ufeff").strip()
    if not clean_content:
        return logs

    blocks = [b.strip() for b in re.split(r"\n(?=TimeCreated\s*:)", clean_content) if b.strip()]

    for block in blocks:
        tc_match = re.search(r"TimeCreated\s*:\s*(.+)", block)
        if not tc_match:
            continue
        timestamp = tc_match.group(1).strip()

        id_match = re.search(r"Id\s*:\s*(\d+)", block)
        event_id_str = id_match.group(1).strip() if id_match else ""

        new_logon = re.search(r"New Logon:.*?Account Name:\s*([^\r\n]+)", block, re.DOTALL)
        subject = re.search(r"Subject:.*?Account Name:\s*([^\r\n]+)", block, re.DOTALL)
        if new_logon and new_logon.group(1).strip() not in ("-", ""):
            username = new_logon.group(1).strip()
        elif subject and subject.group(1).strip() not in ("-", ""):
            username = subject.group(1).strip()
        else:
            username = "UNKNOWN"

        logon_type_match = re.search(r"Logon Type:\s*([^\r\n]+)", block)
        logon_type = logon_type_match.group(1).strip() if logon_type_match else "-"

        src_ip_match = re.search(r"Source Network Address:\s*([^\r\n]+)", block)
        raw_ip = src_ip_match.group(1).strip() if src_ip_match else None

        src_port_match = re.search(r"Source Port:\s*([^\r\n]+)", block)
        raw_port = src_port_match.group(1).strip() if src_port_match else None

        status = "UNKNOWN"
        if event_id_str == "4624":
            status = "SUCCESS"
        elif event_id_str == "4625":
            status = "FAILED"

        ip_clean = _clean_ip(raw_ip)
        port_clean = _clean_port(raw_port)

        log = {
            "timestamp": timestamp,
            "event_id": event_id_str,
            "event": f"EVENT_{event_id_str}" if event_id_str else "WINDOWS_LOGON",
            "username": username,
            "ip_address": ip_clean,
            "ip": ip_clean,
            "source_port": port_clean,
            "logon_type": logon_type,
            "status": status,
            "source": "Windows",
            "source_type": "Windows",
        }
        logs.append(log)

    return logs


def parse_logs(content):
    if not content or not content.strip():
        return []

    clean_content = content.lstrip("\ufeff").strip()

    first_non_empty = ""
    for line in clean_content.splitlines():
        line_s = line.strip()
        if line_s:
            first_non_empty = line_s
            break

    first_lower = first_non_empty.lower()
    if ("," in first_lower) and ("eventid" in first_lower or "sourceip" in first_lower or "logontype" in first_lower):
        return parse_windows_csv(clean_content)

    if "TimeCreated" in clean_content and re.search(r"Id\s*:\s*\d+", clean_content):
        return parse_windows_event_log(clean_content)

    logs = []

    for line in clean_content.splitlines():
        line = line.strip()
        if not line:
            continue

        if "|" in line:
            parts = [part.strip() for part in line.split("|")]
            if len(parts) >= 5:
                ip_clean = _clean_ip(parts[3])
                log = {
                    "timestamp": parts[0],
                    "event": parts[1].upper(),
                    "username": parts[2],
                    "ip": ip_clean,
                    "ip_address": ip_clean,
                    "status": parts[4].upper()
                }
                logs.append(log)
                continue

        match = re.match(
            r"^(?P<timestamp>[A-Za-z]{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+\S+\s+(?P<event>[A-Za-z0-9_.:-]+(?:\[[^\]]+\])?):\s*(?P<message>.*)$",
            line
        )

        if not match:
            continue

        message = match.group("message")
        username = _extract_username(message)
        ip = _extract_ip(message)
        status = _extract_status(message)

        log = {
            "timestamp": match.group("timestamp"),
            "event": match.group("event").replace("-", "_").upper(),
            "username": username,
            "ip": ip,
            "ip_address": ip,
            "status": status,
        }

        if log["status"] != "UNKNOWN":
            logs.append(log)

    return logs