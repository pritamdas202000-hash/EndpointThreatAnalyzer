# Endpoint Threat Detection - Log Analyzer

A lightweight, Python-based Security Operations (SOC) triage tool built with Streamlit. It ingests raw endpoint and system logs, normalizes events, runs heuristic threat detection rules, and correlates multi-event attack patterns for rapid investigation.

## Architecture & Project Structure

The pipeline separates ingestion, detection, and correlation into distinct modules:

```text
Endpoint-Threat-Detection-Log-Analyzer/
├── app.py              # Streamlit web interface, file upload handler, and triage dashboard
├── parser.py           # Log ingestion, format validation, and event normalization
├── detector.py         # Heuristic detection engine and suspicious pattern matching
├── correlator.py       # Multi-event correlation logic to group related alerts and timelines
├── requirements.txt    # Python dependencies
└── README.md           # Project documentation
