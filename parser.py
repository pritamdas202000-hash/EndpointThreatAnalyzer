"""Procedural parsers for common Windows and system log formats."""

import json
import re
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path


SYSLOG_PATTERN = re.compile(
    r"^(?P<timestamp>(?:<\d+>)?(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)"
    r"\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<hostname>\S+)\s+"
    r"(?P<process>[^:\[]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<message>.*)$",
    re.IGNORECASE,
)
ISO_TIMESTAMP_PATTERN = re.compile(
    r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b"
)
FIELD_PATTERN = re.compile(
    r"(?i)\b(?P<key>TargetUserName|SubjectUserName|UserName|AccountName|"
    r"IpAddress|SourceAddress|SourceIP|ClientAddress|LogonType|EventID|"
    r"ProcessName|Image|NewProcessName|CommandLine)\s*[:=]\s*"
    r"(?:\"(?P<quoted>[^\"]*)\"|'(?P<single>[^']*)'|(?P<plain>[^,;\s]+))"
)
EVENT_ID_PATTERN = re.compile(r"(?i)\b(?:event\s*id|eventid)\s*[:=#]?\s*(\d+)\b")
IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def _key_name(value):
    return re.sub(r"[^a-z0-9]", "", str(value).lower())


def _flatten_mapping(value, output):
    if isinstance(value, dict):
        for key, child in value.items():
            if isinstance(child, (dict, list)):
                _flatten_mapping(child, output)
            else:
                output[_key_name(key)] = child
    elif isinstance(value, list):
        for child in value:
            if isinstance(child, dict) and "#text" in child:
                name = child.get("@Name") or child.get("Name")
                if name:
                    output[_key_name(name)] = child["#text"]
                else:
                    _flatten_mapping(child, output)
            else:
                _flatten_mapping(child, output)


def _first_value(flattened, aliases):
    for alias in aliases:
        value = flattened.get(_key_name(alias))
        if value not in (None, ""):
            return value
    return None


def normalize_event(record, raw_message=None):
    """Return a consistent event dictionary from a structured record."""
    if not isinstance(record, dict):
        record = {"raw_message": str(record)}

    flattened = {}
    _flatten_mapping(record, flattened)
    event_id = _first_value(flattened, ("event_id", "eventid", "id"))
    if event_id is not None and str(event_id).isdigit():
        event_id = int(event_id)

    message = raw_message or _first_value(flattened, ("raw_message", "message", "description"))
    if message is None:
        message = json.dumps(record, ensure_ascii=False, default=str)

    return {
        "timestamp": _first_value(flattened, ("timestamp", "timecreated", "systemtime", "datetime", "time")),
        "hostname": _first_value(flattened, ("hostname", "computer", "host", "machinename")),
        "event_id": event_id,
        "username": _first_value(flattened, ("username", "targetusername", "subjectusername", "accountname", "user")),
        "process_name": _first_value(flattened, ("process_name", "processname", "image", "newprocessname", "application")),
        "command_line": _first_value(flattened, ("commandline", "processcommandline", "command")),
        "source_ip": _first_value(flattened, ("source_ip", "ipaddress", "sourceaddress", "sourceip", "clientaddress", "ip")),
        "logon_type": _first_value(flattened, ("logontype",)),
        "event_data": record,
        "raw_message": str(message),
    }


def parse_json_content(content):
    """Parse a JSON document or JSON-lines payload into normalized events."""
    text = content.decode("utf-8-sig", errors="replace") if isinstance(content, bytes) else str(content)
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        records = []
        for line in text.splitlines():
            if not line.strip():
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        payload = records

    if isinstance(payload, dict):
        for key in ("events", "records", "items"):
            if isinstance(payload.get(key), list):
                payload = payload[key]
                break
        else:
            payload = [payload]
    if not isinstance(payload, list):
        payload = [payload]
    return [normalize_event(item) for item in payload if isinstance(item, (dict, str, int, float))]


def parse_text_line(line):
    """Parse one syslog or key/value-like Windows text line."""
    original = line.rstrip("\r\n")
    fields = {}
    syslog_match = SYSLOG_PATTERN.match(original)
    if syslog_match:
        fields.update(
            timestamp=syslog_match.group("timestamp"),
            hostname=syslog_match.group("hostname"),
            process_name=syslog_match.group("process").strip(),
            raw_message=syslog_match.group("message"),
        )
    else:
        timestamp_match = ISO_TIMESTAMP_PATTERN.search(original)
        if timestamp_match:
            fields["timestamp"] = timestamp_match.group(0)
        fields["raw_message"] = original

    for match in FIELD_PATTERN.finditer(original):
        value = next((match.group(name) for name in ("quoted", "single", "plain") if match.group(name) is not None), "")
        fields[match.group("key")] = value
    event_id_match = EVENT_ID_PATTERN.search(original)
    if event_id_match and "EventID" not in fields:
        fields["EventID"] = event_id_match.group(1)
    if not any(key in fields for key in ("IpAddress", "SourceAddress", "SourceIP", "ClientAddress")):
        ip_match = IP_PATTERN.search(original)
        if ip_match:
            fields["SourceIP"] = ip_match.group(0)
    return normalize_event(fields, raw_message=fields.get("raw_message", original))


def parse_text_content(content):
    text = content.decode("utf-8-sig", errors="replace") if isinstance(content, bytes) else str(content)
    return [parse_text_line(line) for line in text.splitlines() if line.strip()]


def _local_name(tag):
    return tag.rsplit("}", 1)[-1]


def _evtx_xml_to_record(xml_text):
    root = ET.fromstring(xml_text)
    system = {}
    event_data = {}
    for element in root.iter():
        name = _local_name(element.tag)
        if name == "Provider" and element.attrib.get("Name"):
            system["provider"] = element.attrib["Name"]
        elif name == "EventID" and element.text:
            system["event_id"] = element.text
        elif name == "Computer" and element.text:
            system["computer"] = element.text
        elif name == "TimeCreated" and element.attrib.get("SystemTime"):
            system["timestamp"] = element.attrib["SystemTime"]
        elif name == "Data" and element.text:
            data_name = element.attrib.get("Name")
            if data_name:
                event_data[data_name] = element.text
    return {"System": system, "EventData": event_data}


def parse_evtx_content(content):
    """Read EVTX bytes using python-evtx, or accept an EVTX XML dump."""
    data = content if isinstance(content, bytes) else str(content).encode("utf-8")
    if data.lstrip().startswith(b"<"):
        xml_text = data.decode("utf-8-sig", errors="replace")
        roots = re.findall(r"<Event\b.*?</Event>", xml_text, flags=re.DOTALL)
        return [normalize_event(_evtx_xml_to_record(item), raw_message=item) for item in roots]

    try:
        from Evtx import Evtx
    except ImportError as error:
        raise RuntimeError("EVTX parsing requires the 'python-evtx' package.") from error

    temp_path = None
    try:
        with tempfile.NamedTemporaryFile(suffix=".evtx", delete=False) as temp_file:
            temp_file.write(data)
            temp_path = temp_file.name
        records = []
        with Evtx.Evtx(temp_path) as log:
            for record in log.records():
                xml_text = record.xml()
                records.append(normalize_event(_evtx_xml_to_record(xml_text), raw_message=xml_text))
        return records
    finally:
        if temp_path:
            Path(temp_path).unlink(missing_ok=True)


def parse_log_file(file_name, content):
    """Route uploaded/file contents by extension and return normalized events."""
    suffix = Path(file_name).suffix.lower()
    if suffix == ".evtx":
        return parse_evtx_content(content)
    if suffix in (".json", ".jsonl", ".ndjson"):
        return parse_json_content(content)
    text = content.decode("utf-8-sig", errors="replace") if isinstance(content, bytes) else str(content)
    if text.lstrip().startswith(("{", "[")):
        try:
            return parse_json_content(text)
        except (ValueError, TypeError):
            pass
    return parse_text_content(text)