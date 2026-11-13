"""Time-based correlation for normalized events and detection alerts."""

from datetime import timedelta

from detector import SUCCESSFUL_LOGON_ID, _alert, _event_id, _parse_timestamp


def correlate_events(events, alerts=None, window_minutes=10):
    """Correlate failed-to-successful logons and high-severity alerts by host."""
    correlations = []
    timed_events = []
    for event in events:
        timestamp = _parse_timestamp(event.get("timestamp"))
        if timestamp is not None:
            timed_events.append((timestamp, event))
    timed_events.sort(key=lambda item: item[0])

    failures = [item for item in timed_events if _event_id(item[1]) == 4625]
    for success_time, success in timed_events:
        if _event_id(success) != SUCCESSFUL_LOGON_ID:
            continue
        username = str(success.get("username") or "").lower()
        source_ip = success.get("source_ip")
        related = []
        for failure_time, failure in failures:
            same_user = str(failure.get("username") or "").lower() == username
            same_ip = not source_ip or not failure.get("source_ip") or failure.get("source_ip") == source_ip
            if same_user and same_ip and timedelta(0) <= success_time - failure_time <= timedelta(minutes=window_minutes):
                related.append(failure)
        if len(related) >= 2:
            related.append(success)
            correlations.append(
                _alert(
                    "Failed Logons Followed by Successful Logon",
                    "Critical",
                    f"{len(related) - 1} failed logons for {username or 'unknown user'} were followed by a successful logon within {window_minutes} minutes.",
                    [
                        "Verify the successful sign-in with the user and identity provider.",
                        "Revoke active sessions and reset credentials if unauthorized.",
                        "Investigate the source IP and review endpoint activity after the login.",
                    ],
                    success,
                    related,
                )
            )

    high_alerts = [
        alert
        for alert in (alerts or [])
        if str(alert.get("Severity", "")).lower() in {"high", "critical"} and alert.get("hostname")
    ]
    by_host = {}
    for alert in high_alerts:
        by_host.setdefault(str(alert["hostname"]).lower(), []).append(alert)
    for hostname, host_alerts in by_host.items():
        if len(host_alerts) < 2:
            continue
        event = host_alerts[-1]
        correlations.append(
            _alert(
                "Multiple High-Severity Alerts on One Host",
                "Critical",
                f"{len(host_alerts)} high-severity or critical alerts were detected on host {hostname}.",
                [
                    "Prioritize host containment and preserve relevant telemetry.",
                    "Build a timeline from the related alerts and inspect process ancestry.",
                    "Escalate for incident response and scope other affected systems.",
                ],
                event,
                host_alerts,
            )
        )
    return correlations