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
```

## Core Workflow

1. **Log Parsing (`parser.py`)**
   - Ingests uploaded endpoint/system log files and extracts key fields (timestamps, event IDs, processes, source/destination details, user accounts).
   - Standardizes raw entries into a structured format for downstream analysis.

2. **Heuristic Detection (`detector.py`)**
   - Scans normalized events against custom detection rules to flag suspicious behavior, anomalies, and potential Indicators of Compromise (IoCs).
   - Assigns severity levels and detection context to matched events.

3. **Activity Correlation (`correlator.py`)**
   - Links isolated alerts across common attributes (such as host, user, process lineage, or time windows) to surface broader incident chains and reduce alert fatigue.

4. **Triage Interface (`app.py`)**
   - Provides an interactive dashboard to upload logs, inspect flagged detections, review correlated activity, and filter events during investigation.

## Local Setup & Execution

1. **Clone the repository:**
   ```bash
   git clone https://github.com/pritamdas202000-hash/Endpoint-Threat-Detection-Log-Analyzer.git
   cd Endpoint-Threat-Detection-Log-Analyzer
   ```

2. **Create and activate a virtual environment:**
   - **Windows (PowerShell):**
     ```powershell
     python -m venv .venv
     .\.venv\Scripts\Activate.ps1
     ```
   - **Linux / macOS:**
     ```bash
     python3 -m venv .venv
     source .venv/bin/activate
     ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Run the application:**
   ```bash
   streamlit run app.py
   ```
   Open `http://localhost:8501` in your browser to access the dashboard.

## Data Privacy Note
Uploaded log files are processed in-memory during the active session and are not saved to persistent storage.
