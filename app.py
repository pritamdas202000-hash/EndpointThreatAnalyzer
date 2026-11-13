"""Streamlit dashboard for uploaded endpoint and system logs."""

import pandas as pd
import streamlit as st

from correlator import correlate_events
from detector import run_detection_rules
from parser import parse_log_file


st.set_page_config(page_title="Endpoint Threat Detection - Log Analyzer", page_icon="🔎", layout="wide")
st.title("Endpoint Threat Detection - Log Analyzer")
st.caption("Upload endpoint or system logs to parse events, apply heuristic detections, and correlate activity.")
st.warning(
    "This app accepts uploads from its visitors. Uploaded logs are sent to the server for processing; "
    "do not upload sensitive, personal, or production logs."
)

uploads = st.file_uploader(
    "Log files",
    type=["json", "jsonl", "ndjson", "log", "txt", "evtx"],
    accept_multiple_files=True,
)

if not uploads:
    st.info("Upload one or more JSON, text/syslog, or EVTX files to begin analysis.")
    st.stop()

events = []
parse_errors = []
for upload in uploads:
    try:
        events.extend(parse_log_file(upload.name, upload.getvalue()))
    except Exception as error:
        parse_errors.append(f"{upload.name}: {error}")

if parse_errors:
    for message in parse_errors:
        st.error(message)

alerts = run_detection_rules(events)
correlations = correlate_events(events, alerts)
all_alerts = alerts + correlations

severity_counts = {
    severity: sum(1 for alert in all_alerts if alert.get("Severity") == severity)
    for severity in ("Critical", "High", "Medium", "Low")
}
metric_columns = st.columns(6)
metric_columns[0].metric("Logs parsed", len(events))
metric_columns[1].metric("Alerts", len(all_alerts))
metric_columns[2].metric("Critical", severity_counts["Critical"])
metric_columns[3].metric("High", severity_counts["High"])
metric_columns[4].metric("Medium", severity_counts["Medium"])
metric_columns[5].metric("Low", severity_counts["Low"])

st.subheader("Flagged activity")
if not all_alerts:
    st.success("No configured detection rules were triggered for these logs.")
else:
    severity_filter = st.multiselect(
        "Severity filter",
        options=["Critical", "High", "Medium", "Low"],
        default=["Critical", "High", "Medium", "Low"],
    )
    visible_alerts = [alert for alert in all_alerts if alert.get("Severity") in severity_filter]
    table_rows = []
    for alert in visible_alerts:
        table_rows.append(
            {
                "Severity": alert.get("Severity"),
                "Alert Title": alert.get("Alert Title"),
                "Timestamp": alert.get("timestamp"),
                "Host": alert.get("hostname"),
                "User": alert.get("username"),
                "Event ID": alert.get("event_id"),
                "Process": alert.get("process_name"),
                "Source IP": alert.get("source_ip"),
                "Reason for Detection": alert.get("Reason for Detection"),
                "Actionable Mitigation Steps": "\n".join(alert.get("Actionable Mitigation Steps", [])),
                "Event Details": alert.get("raw_message", ""),
            }
        )
    st.dataframe(pd.DataFrame(table_rows), use_container_width=True, hide_index=True)

with st.expander("Detection notes"):
    st.write(
        "Rules are heuristic triage signals, not proof of compromise. Review source telemetry and tune thresholds "
        "for your environment before using alerts for automated response. EVTX support requires python-evtx."
    )