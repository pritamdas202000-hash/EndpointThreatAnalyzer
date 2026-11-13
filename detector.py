"""Procedural heuristic detections for normalized endpoint events."""

import re
from datetime import datetime, timedelta, timezone


FAILED_LOGON_ID = 4625
SUCCESSFUL_LOGON_ID = 4624
PROCESS_CREATE_ID = 1
PRIVILEGED_EVENT_IDS = {4672, 4720, 4728, 4732, 4756}
ADMIN_NAMES = {"administrator", "admin", "root", "guest", "defaultaccount", "wdagutilityaccount"}
SUSPICIOUS_PATHS = ("\\appdata\\local\\temp\\", "c:\\users\\public\\")


def _event_id(event):
    try:
        return int(event.get("event_id"))
    except (TypeError, ValueError):
        return None


def _parse_timestamp(value):
    if not value:
        return None
    text = str(value).strip().replace("Z", "+00:00")
    try:
        timestamp = datetime.fromisoformat(text)
        if timestamp.tzinfo is not None:
            return timestamp.astimezone(timezone.utc).replace(tzinfo=None)
        return timestamp
    except ValueError:
        for pattern in ("%b %d %H:%M:%S", "%b  %d %H:%M:%S"):
            try:
                return datetime.strptime(text, pattern).replace(year=datetime.now().year)
            except ValueError:
                continue
    return None


def _alert(title, severity, reason, mitigation, event, related_events=None):
    return {
        "Alert Title": title,
        "Severity": severity,
        "Reason for Detection": reason,
        "Actionable Mitigation Steps": mitigation,
        "timestamp": event.get("timestamp"),
        "hostname": event.get("hostname"),
        "event_id": event.get("event_id"),
        "username": event.get("username"),
        "process_name": event.get("process_name"),
        "source_ip": event.get("source_ip"),
        "raw_message": event.get("raw_message", ""),
        "related_events": related_events or [event],
    }


def _brute_force_alerts(events, threshold=5, window_minutes=5):
    groups = {}
    for event in events:
        if _event_id(event) != FAILED_LOGON_ID:
            continue
        timestamp = _parse_timestamp(event.get("timestamp"))
        if timestamp is None:
            continue
        key = (
            str(event.get("username") or "unknown").lower(),
            event.get("source_ip") or "unknown",
            event.get("hostname") or "unknown",
        )
        groups.setdefault(key, []).append((timestamp, event))

    alerts = []
    for (username, source_ip, hostname), failures in groups.items():
        failures.sort(key=lambda item: item[0])
        start = 0
        for end, (timestamp, event) in enumerate(failures):
            while timestamp - failures[start][0] > timedelta(minutes=window_minutes):
                start += 1
            window = failures[start : end + 1]
            if len(window) == threshold:
                alerts.append(
                    _alert(
                        "Possible Brute Force Attack",
                        "High",
                        f"{len(window)} failed logons for {username} from {source_ip} on {hostname} within {window_minutes} minutes.",
                        [
                            "Validate whether the source IP is expected.",
                            "Temporarily block or rate-limit the source if unauthorized.",
                            "Reset affected credentials and review nearby successful logons.",
                        ],
                        event,
                        [item[1] for item in window],
                    )
                )
    return alerts


def _process_alerts(events):
    alerts = []
    for event in events:
        process = str(event.get("process_name") or "")
        command = str(event.get("command_line") or "")
        raw_message = str(event.get("raw_message", ""))
        searchable = f"{process} {command} {raw_message}".lower().replace("/", "\\")
        if _event_id(event) == PROCESS_CREATE_ID and any(path in searchable for path in SUSPICIOUS_PATHS):
            alerts.append(
                _alert(
                    "Suspicious Process Executed From Writable Location",
                    "High",
                    f"Sysmon process creation ran from a commonly abused writable path: {process or command or 'path in event details'}.",
                    [
                        "Verify the executable's signature, hash, parent process, and user context.",
                        "Isolate the host if execution is confirmed malicious.",
                        "Quarantine the file and inspect persistence and child-process activity.",
                    ],
                    event,
                )
            )

        if re.search(r"(?i)(?:^|\s)-(?:enc|encodedcommand)(?:\s|$)", f"{process} {command} {raw_message}"):
            alerts.append(
                _alert(
                    "Encoded PowerShell Command",
                    "High",
                    "The command line contains a PowerShell encoded-command flag, which can conceal script content.",
                    [
                        "Recover and decode the command in an isolated analysis environment.",
                        "Review PowerShell and process-creation telemetry around this event.",
                        "Contain the host and rotate exposed credentials if execution is unauthorized.",
                    ],
                    event,
                )
            )
    return alerts


def _admin_usage_alerts(events):
    alerts = []
    for event in events:
        event_id = _event_id(event)
        username = str(event.get("username") or "").lower()
        normalized_user = username.replace("/", "\\").split("\\")[-1].rstrip("$")
        is_admin_account = normalized_user in ADMIN_NAMES or username.endswith("-500")
        logon_type = str(event.get("logon_type") or "")
        unusual_condition = event_id in PRIVILEGED_EVENT_IDS or (
            event_id == SUCCESSFUL_LOGON_ID and logon_type in {"3", "10"}
        )
        if is_admin_account and unusual_condition:
            alerts.append(
                _alert(
                    "Administrative Account Used Under Unusual Conditions",
                    "Medium" if event_id == SUCCESSFUL_LOGON_ID else "High",
                    f"Administrative or built-in account {username} was involved in event {event_id} (logon type {logon_type or 'unknown'}). Confirm the activity is authorized.",
                    [
                        "Confirm the account owner, source, and business purpose.",
                        "Review adjacent logons, privilege changes, and process activity.",
                        "Disable or rotate the account credentials if the activity is unrecognized.",
                    ],
                    event,
                )
            )
    return alerts


def run_detection_rules(events, brute_force_threshold=5, brute_force_window_minutes=5):
    """Run all rules and return alert dictionaries without mutating input events."""
    alerts = _brute_force_alerts(events, brute_force_threshold, brute_force_window_minutes)
    alerts.extend(_process_alerts(events))
    alerts.extend(_admin_usage_alerts(events))
    return alerts