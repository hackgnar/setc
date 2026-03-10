"""Schema dictionaries and converter for Falco JSON events to CIM/ECS/OCSF/CEF/UDM."""
from __future__ import annotations

import io
import json
import logging
import re
import tarfile
import time
from typing import Any

import docker.models.containers

from modules.docker_process_logger import apply_schema, format_cef_line

logger = logging.getLogger(__name__)

# ===================================================================
# Priority mapping + MITRE tag extraction (for alert schemas)
# ===================================================================

_FALCO_PRIORITY_MAP = {
    "Emergency":     {"cim": "critical", "ecs": 4, "ocsf": "5", "cef": "10", "udm": "CRITICAL"},
    "Alert":         {"cim": "critical", "ecs": 4, "ocsf": "5", "cef": "9",  "udm": "CRITICAL"},
    "Critical":      {"cim": "critical", "ecs": 4, "ocsf": "5", "cef": "9",  "udm": "CRITICAL"},
    "Error":         {"cim": "high",     "ecs": 3, "ocsf": "4", "cef": "7",  "udm": "HIGH"},
    "Warning":       {"cim": "high",     "ecs": 3, "ocsf": "4", "cef": "7",  "udm": "HIGH"},
    "Notice":        {"cim": "medium",   "ecs": 2, "ocsf": "3", "cef": "5",  "udm": "MEDIUM"},
    "Informational": {"cim": "low",      "ecs": 1, "ocsf": "2", "cef": "3",  "udm": "LOW"},
    "Debug":         {"cim": "low",      "ecs": 1, "ocsf": "1", "cef": "1",  "udm": "LOW"},
}


def _extract_mitre_tags(tags):
    """Return (tactic_name, [technique_ids]) from Falco tags list."""
    tactic = None
    technique_ids = []
    for tag in (tags or []):
        if tag.startswith("mitre_"):
            tactic = tag[len("mitre_"):].replace("_", " ").title()
        elif re.match(r"^T\d{4}", tag):
            technique_ids.append(tag)
    return tactic, technique_ids

# ===================================================================
# Process event schemas
# ===================================================================

falco_cim_process = {
    "timestamp": lambda x: x.get("time", time.time()),
    "action": lambda x: "allowed",
    "process_name": lambda x: x.get("proc.name"),
    "process_id": lambda x: x.get("proc.pid"),
    "parent_process_id": lambda x: x.get("proc.ppid"),
    "process_exec": lambda x: x.get("proc.exepath"),
    "process": lambda x: x.get("proc.cmdline"),
    "user": lambda x: x.get("user.name"),
    "dest": lambda x: x.get("container.name"),
}

falco_ecs_process = {
    "@timestamp": lambda x: x.get("time", time.time()),
    "ecs.version": lambda x: "8.17",
    "event.kind": lambda x: "event",
    "event.category": lambda x: "process",
    "event.type": lambda x: "start",
    "event.action": lambda x: x.get("evt.type"),
    "process.name": lambda x: x.get("proc.name"),
    "process.pid": lambda x: x.get("proc.pid"),
    "process.parent.pid": lambda x: x.get("proc.ppid"),
    "process.command_line": lambda x: x.get("proc.cmdline"),
    "process.executable": lambda x: x.get("proc.exepath"),
    "container.name": lambda x: x.get("container.name"),
    "container.id": lambda x: x.get("container.id"),
    "user.name": lambda x: x.get("user.name"),
}

falco_ocsf_process = {
    "time": lambda x: x.get("time", time.time()),
    "activity_name": lambda x: "Launch",
    "activity_id": lambda x: "1",
    "category_uid": lambda x: "1",
    "category_name": lambda x: "System Activity",
    "class_uid": lambda x: "1007",
    "class_name": lambda x: "Process Activity",
    "severity": lambda x: "Informational",
    "severity_id": lambda x: "1",
    "type_uid": lambda x: "100701",
    "type_name": lambda x: "Process Activity: Launch",
    "process": {
        "name": lambda x: x.get("proc.name"),
        "pid": lambda x: x.get("proc.pid"),
        "cmd_line": lambda x: x.get("proc.cmdline"),
        "file": {
            "path": lambda x: x.get("proc.exepath"),
        },
        "parent_process": {
            "pid": lambda x: x.get("proc.ppid"),
        },
    },
    "actor": {
        "user": {
            "name": lambda x: x.get("user.name"),
        },
    },
    "metadata": {
        "version": lambda x: "1.4.0",
        "product": {
            "name": lambda x: "Falco",
            "vendor_name": lambda x: "SETC",
        },
    },
}

falco_cef_process = {
    "rt": lambda x: x.get("time", time.time()),
    "sproc": lambda x: x.get("proc.name"),
    "spid": lambda x: x.get("proc.pid"),
    "dpid": lambda x: x.get("proc.ppid"),
    "suser": lambda x: x.get("user.name"),
    "act": lambda x: x.get("evt.type"),
    "cat": lambda x: "process",
    "cs1Label": lambda x: "commandLine",
    "cs1": lambda x: x.get("proc.cmdline"),
    "cs4Label": lambda x: "containerName",
    "cs4": lambda x: x.get("container.name"),
}

falco_udm_process = {
    "metadata": {
        "event_timestamp": lambda x: x.get("time", time.time()),
        "event_type": lambda x: "PROCESS_LAUNCH",
        "vendor_name": lambda x: "SETC",
        "product_name": lambda x: "Falco",
        "product_version": lambda x: "0.43.0",
    },
    "principal": {
        "user": {
            "userid": lambda x: x.get("user.name"),
        },
    },
    "target": {
        "process": {
            "pid": lambda x: x.get("proc.pid"),
            "parentProcess": {
                "pid": lambda x: x.get("proc.ppid"),
            },
            "commandLine": lambda x: x.get("proc.cmdline"),
            "file": {
                "full_path": lambda x: x.get("proc.exepath"),
            },
        },
    },
    "security_result": {
        "action": lambda x: "ALLOW",
    },
}

# ===================================================================
# Network event schemas
# ===================================================================

falco_cim_network = {
    "timestamp": lambda x: x.get("time", time.time()),
    "action": lambda x: "allowed",
    "src": lambda x: x.get("fd.sip"),
    "dest": lambda x: x.get("fd.cip"),
    "src_port": lambda x: x.get("fd.sport"),
    "dest_port": lambda x: x.get("fd.cport"),
    "transport": lambda x: "tcp",
    "process_name": lambda x: x.get("proc.name"),
    "user": lambda x: x.get("user.name"),
}

falco_ecs_network = {
    "@timestamp": lambda x: x.get("time", time.time()),
    "ecs.version": lambda x: "8.17",
    "event.kind": lambda x: "event",
    "event.category": lambda x: "network",
    "event.type": lambda x: "connection",
    "event.action": lambda x: x.get("evt.type"),
    "source.ip": lambda x: x.get("fd.sip"),
    "destination.ip": lambda x: x.get("fd.cip"),
    "source.port": lambda x: x.get("fd.sport"),
    "destination.port": lambda x: x.get("fd.cport"),
    "process.name": lambda x: x.get("proc.name"),
    "container.name": lambda x: x.get("container.name"),
    "container.id": lambda x: x.get("container.id"),
    "user.name": lambda x: x.get("user.name"),
}

falco_ocsf_network = {
    "time": lambda x: x.get("time", time.time()),
    "activity_name": lambda x: "Traffic",
    "activity_id": lambda x: "6",
    "category_uid": lambda x: "4",
    "category_name": lambda x: "Network Activity",
    "class_uid": lambda x: "4001",
    "class_name": lambda x: "Network Activity",
    "severity": lambda x: "Informational",
    "severity_id": lambda x: "1",
    "type_uid": lambda x: "400106",
    "type_name": lambda x: "Network Activity: Traffic",
    "src_endpoint": {
        "ip": lambda x: x.get("fd.sip"),
        "port": lambda x: x.get("fd.sport"),
    },
    "dst_endpoint": {
        "ip": lambda x: x.get("fd.cip"),
        "port": lambda x: x.get("fd.cport"),
    },
    "metadata": {
        "version": lambda x: "1.4.0",
        "product": {
            "name": lambda x: "Falco",
            "vendor_name": lambda x: "SETC",
        },
    },
}

falco_cef_network = {
    "rt": lambda x: x.get("time", time.time()),
    "src": lambda x: x.get("fd.sip"),
    "dst": lambda x: x.get("fd.cip"),
    "spt": lambda x: x.get("fd.sport"),
    "dpt": lambda x: x.get("fd.cport"),
    "proto": lambda x: "tcp",
    "sproc": lambda x: x.get("proc.name"),
    "suser": lambda x: x.get("user.name"),
    "act": lambda x: x.get("evt.type"),
    "cat": lambda x: "network",
    "cs4Label": lambda x: "containerName",
    "cs4": lambda x: x.get("container.name"),
}

falco_udm_network = {
    "metadata": {
        "event_timestamp": lambda x: x.get("time", time.time()),
        "event_type": lambda x: "NETWORK_CONNECTION",
        "vendor_name": lambda x: "SETC",
        "product_name": lambda x: "Falco",
        "product_version": lambda x: "0.43.0",
    },
    "principal": {
        "ip": lambda x: [x.get("fd.sip")] if x.get("fd.sip") else None,
        "port": lambda x: x.get("fd.sport"),
    },
    "target": {
        "ip": lambda x: [x.get("fd.cip")] if x.get("fd.cip") else None,
        "port": lambda x: x.get("fd.cport"),
    },
    "network": {
        "ipProtocol": lambda x: "TCP",
    },
    "security_result": {
        "action": lambda x: "ALLOW",
    },
}

# ===================================================================
# File event schemas
# ===================================================================

falco_cim_file = {
    "timestamp": lambda x: x.get("time", time.time()),
    "action": lambda x: "modified",
    "file_path": lambda x: x.get("fd.name"),
    "process_name": lambda x: x.get("proc.name"),
    "user": lambda x: x.get("user.name"),
    "dest": lambda x: x.get("container.name"),
}

falco_ecs_file = {
    "@timestamp": lambda x: x.get("time", time.time()),
    "ecs.version": lambda x: "8.17",
    "event.kind": lambda x: "event",
    "event.category": lambda x: "file",
    "event.type": lambda x: "change",
    "event.action": lambda x: x.get("evt.type"),
    "file.path": lambda x: x.get("fd.name"),
    "process.name": lambda x: x.get("proc.name"),
    "process.command_line": lambda x: x.get("proc.cmdline"),
    "container.name": lambda x: x.get("container.name"),
    "container.id": lambda x: x.get("container.id"),
    "user.name": lambda x: x.get("user.name"),
}

falco_ocsf_file = {
    "time": lambda x: x.get("time", time.time()),
    "activity_name": lambda x: "Update",
    "activity_id": lambda x: "3",
    "category_uid": lambda x: "1",
    "category_name": lambda x: "System Activity",
    "class_uid": lambda x: "1001",
    "class_name": lambda x: "File System Activity",
    "severity": lambda x: "Informational",
    "severity_id": lambda x: "1",
    "type_uid": lambda x: "100103",
    "type_name": lambda x: "File System Activity: Update",
    "file": {
        "name": lambda x: x.get("fd.name"),
        "type": lambda x: "Regular File",
        "type_id": lambda x: "1",
    },
    "actor": {
        "process": {
            "name": lambda x: x.get("proc.name"),
            "cmd_line": lambda x: x.get("proc.cmdline"),
        },
        "user": {
            "name": lambda x: x.get("user.name"),
        },
    },
    "metadata": {
        "version": lambda x: "1.4.0",
        "product": {
            "name": lambda x: "Falco",
            "vendor_name": lambda x: "SETC",
        },
    },
}

falco_cef_file = {
    "rt": lambda x: x.get("time", time.time()),
    "fname": lambda x: x.get("fd.name"),
    "sproc": lambda x: x.get("proc.name"),
    "suser": lambda x: x.get("user.name"),
    "act": lambda x: x.get("evt.type"),
    "cat": lambda x: "file",
    "cs1Label": lambda x: "commandLine",
    "cs1": lambda x: x.get("proc.cmdline"),
    "cs4Label": lambda x: "containerName",
    "cs4": lambda x: x.get("container.name"),
}

falco_udm_file = {
    "metadata": {
        "event_timestamp": lambda x: x.get("time", time.time()),
        "event_type": lambda x: "FILE_MODIFICATION",
        "vendor_name": lambda x: "SETC",
        "product_name": lambda x: "Falco",
        "product_version": lambda x: "0.43.0",
    },
    "principal": {
        "user": {
            "userid": lambda x: x.get("user.name"),
        },
        "process": {
            "commandLine": lambda x: x.get("proc.cmdline"),
        },
    },
    "target": {
        "file": {
            "full_path": lambda x: x.get("fd.name"),
        },
    },
    "security_result": {
        "action": lambda x: "ALLOW",
    },
}

# ===================================================================
# Alert schemas (for built-in Falco detection rules)
# ===================================================================

falco_cim_alert = {
    "timestamp": lambda x: x.get("time", time.time()),
    "action": lambda x: "detected",
    "severity": lambda x: _FALCO_PRIORITY_MAP.get(x.get("_priority", "Notice"), {}).get("cim", "medium"),
    "signature": lambda x: x.get("_rule"),
    "description": lambda x: x.get("_output"),
    "process_name": lambda x: x.get("proc.name"),
    "process_id": lambda x: x.get("proc.pid"),
    "user": lambda x: x.get("user.name"),
    "dest": lambda x: x.get("container.name"),
}

falco_ecs_alert = {
    "@timestamp": lambda x: x.get("time", time.time()),
    "ecs.version": lambda x: "8.17",
    "event.kind": lambda x: "alert",
    "event.category": lambda x: "intrusion_detection",
    "event.type": lambda x: "info",
    "event.severity": lambda x: _FALCO_PRIORITY_MAP.get(x.get("_priority", "Notice"), {}).get("ecs", 2),
    "event.action": lambda x: x.get("evt.type"),
    "rule.name": lambda x: x.get("_rule"),
    "rule.description": lambda x: x.get("_output"),
    "threat.framework": lambda x: "MITRE ATT&CK" if _extract_mitre_tags(x.get("_tags"))[0] else None,
    "threat.tactic.name": lambda x: _extract_mitre_tags(x.get("_tags"))[0],
    "threat.technique.id": lambda x: _extract_mitre_tags(x.get("_tags"))[1] or None,
    "process.name": lambda x: x.get("proc.name"),
    "process.pid": lambda x: x.get("proc.pid"),
    "process.command_line": lambda x: x.get("proc.cmdline"),
    "container.name": lambda x: x.get("container.name"),
    "container.id": lambda x: x.get("container.id"),
    "user.name": lambda x: x.get("user.name"),
}

falco_ocsf_alert = {
    "time": lambda x: x.get("time", time.time()),
    "activity_name": lambda x: "Create",
    "activity_id": lambda x: "1",
    "category_uid": lambda x: "2",
    "category_name": lambda x: "Findings",
    "class_uid": lambda x: "2004",
    "class_name": lambda x: "Detection Finding",
    "severity_id": lambda x: _FALCO_PRIORITY_MAP.get(x.get("_priority", "Notice"), {}).get("ocsf", "3"),
    "finding_info": {
        "title": lambda x: x.get("_rule"),
        "desc": lambda x: x.get("_output"),
    },
    "attacks": lambda x: [{
        "tactic": {"name": _extract_mitre_tags(x.get("_tags"))[0]},
        "technique": {"uid": tid for tid in _extract_mitre_tags(x.get("_tags"))[1]},
        "version": "14.1",
    }] if _extract_mitre_tags(x.get("_tags"))[0] else None,
    "process": {
        "name": lambda x: x.get("proc.name"),
        "pid": lambda x: x.get("proc.pid"),
        "cmd_line": lambda x: x.get("proc.cmdline"),
    },
    "metadata": {
        "version": lambda x: "1.4.0",
        "product": {
            "name": lambda x: "Falco",
            "vendor_name": lambda x: "SETC",
        },
    },
}

falco_cef_alert = {
    "rt": lambda x: x.get("time", time.time()),
    "msg": lambda x: x.get("_output"),
    "sproc": lambda x: x.get("proc.name"),
    "spid": lambda x: x.get("proc.pid"),
    "suser": lambda x: x.get("user.name"),
    "cs2Label": lambda x: "ruleName",
    "cs2": lambda x: x.get("_rule"),
    "cs3Label": lambda x: "tags",
    "cs3": lambda x: ",".join(x.get("_tags", [])),
    "cs4Label": lambda x: "containerName",
    "cs4": lambda x: x.get("container.name"),
}

falco_udm_alert = {
    "metadata": {
        "event_timestamp": lambda x: x.get("time", time.time()),
        "event_type": lambda x: "GENERIC_EVENT",
        "vendor_name": lambda x: "SETC",
        "product_name": lambda x: "Falco",
        "product_version": lambda x: "0.43.0",
    },
    "security_result": {
        "alert_state": lambda x: "ALERTING",
        "severity": lambda x: _FALCO_PRIORITY_MAP.get(x.get("_priority", "Notice"), {}).get("udm", "MEDIUM"),
        "rule_name": lambda x: x.get("_rule"),
        "description": lambda x: x.get("_output"),
    },
    "target": {
        "process": {
            "pid": lambda x: x.get("proc.pid"),
            "commandLine": lambda x: x.get("proc.cmdline"),
        },
    },
    "principal": {
        "user": {
            "userid": lambda x: x.get("user.name"),
        },
    },
}

# ===================================================================
# Rule → schema mapping
# ===================================================================

_RULE_SCHEMAS = {
    "SETC Process Execution": {
        "cim": falco_cim_process,
        "ecs": falco_ecs_process,
        "ocsf": falco_ocsf_process,
        "cef": falco_cef_process,
        "udm": falco_udm_process,
        "cef_header": ("SETC", "Falco", "0.43.0",
                       "SETC-FALCO-PROC", "Process Activity: Execution", "5"),
    },
    "SETC Network Connection": {
        "cim": falco_cim_network,
        "ecs": falco_ecs_network,
        "ocsf": falco_ocsf_network,
        "cef": falco_cef_network,
        "udm": falco_udm_network,
        "cef_header": ("SETC", "Falco", "0.43.0",
                       "SETC-FALCO-NET", "Network Activity: Connection", "5"),
    },
    "SETC File Write": {
        "cim": falco_cim_file,
        "ecs": falco_ecs_file,
        "ocsf": falco_ocsf_file,
        "cef": falco_cef_file,
        "udm": falco_udm_file,
        "cef_header": ("SETC", "Falco", "0.43.0",
                       "SETC-FALCO-FILE", "File Activity: Write", "5"),
    },
}


def convert_falco_events(events: list[dict[str, Any]],
                         write_container: docker.models.containers.Container,
                         vuln_name: str) -> None:
    """Convert Falco events to all log formats and write to the shared volume.

    Args:
        events: List of parsed Falco JSON events (with output_fields flattened).
        write_container: Container with the shared volume mounted at /data.
        vuln_name: CVE/vuln name used as the subdirectory.
    """
    cim_all: list[dict] = []
    ecs_all: list[dict] = []
    ocsf_all: list[dict] = []
    cef_all: list[str] = []
    udm_all: list[dict] = []

    cim_alerts: list[dict] = []
    ecs_alerts: list[dict] = []
    ocsf_alerts: list[dict] = []
    cef_alerts: list[str] = []
    udm_alerts: list[dict] = []

    for event in events:
        rule = event.get("rule", "")
        fields = event.get("output_fields", {})
        fields["time"] = event.get("time", time.time())
        schemas = _RULE_SCHEMAS.get(rule)

        if schemas:
            # SETC telemetry rule → observational event
            cim_all.append(apply_schema(fields, schemas["cim"]))
            ecs_all.append(apply_schema(fields, schemas["ecs"]))
            ocsf_all.append(apply_schema(fields, schemas["ocsf"]))
            udm_all.append(apply_schema(fields, schemas["udm"]))

            cef_extensions = apply_schema(fields, schemas["cef"])
            cef_all.append(format_cef_line(schemas["cef_header"], cef_extensions))
        else:
            # Built-in Falco detection rule → alert event
            fields["_rule"] = rule
            fields["_priority"] = event.get("priority", "Notice")
            fields["_output"] = event.get("output", "")
            fields["_tags"] = event.get("tags", [])

            cim_alerts.append(apply_schema(fields, falco_cim_alert))
            ecs_alerts.append(apply_schema(fields, falco_ecs_alert))
            ocsf_alerts.append(apply_schema(fields, falco_ocsf_alert))
            udm_alerts.append(apply_schema(fields, falco_udm_alert))

            priority = event.get("priority", "Notice")
            cef_sev = _FALCO_PRIORITY_MAP.get(priority, {}).get("cef", "5")
            header = ("SETC", "Falco", "0.43.0", "FALCO-DETECT",
                      f"Falco Detection: {rule}", str(cef_sev))
            cef_alerts.append(format_cef_line(header, apply_schema(fields, falco_cef_alert)))

    telemetry_count = len(cim_all)
    alert_count = len(cim_alerts)
    logger.info("Falco conversion: %d telemetry events, %d alert events for %s",
                telemetry_count, alert_count, vuln_name)

    # Write telemetry (SETC rules)
    for log_type, data in [("cim", cim_all), ("ecs", ecs_all),
                           ("ocsf", ocsf_all), ("udm", udm_all),
                           ("cef", cef_all)]:
        if not data:
            continue
        _write_to_volume(write_container, log_type, data, vuln_name, suffix="falco")

    # Write alerts (built-in Falco detection rules)
    for log_type, data in [("cim", cim_alerts), ("ecs", ecs_alerts),
                           ("ocsf", ocsf_alerts), ("udm", udm_alerts),
                           ("cef", cef_alerts)]:
        if not data:
            continue
        _write_to_volume(write_container, log_type, data, vuln_name, suffix="falco_alert")


def _write_to_volume(write_container: docker.models.containers.Container,
                     log_type: str, data: list, directory: str,
                     suffix: str = "falco") -> None:
    """Write converted logs to the shared Docker volume as a tar archive."""
    tar_fileobj = io.BytesIO()
    with tarfile.open(fileobj=tar_fileobj, mode="w|") as tar:
        if isinstance(data, list) and data and isinstance(data[0], str):
            my_content = ("\n".join(data) + "\n").encode('utf-8')
        else:
            my_content = json.dumps(data).encode('utf-8')
        tf = tarfile.TarInfo("%s_%s_%s.log" % (log_type, suffix, str(time.time())))
        tf.size = len(my_content)
        tar.addfile(tf, io.BytesIO(my_content))
    tar_fileobj.flush()
    tar_fileobj.seek(0)
    try:
        write_container.put_archive("/data/%s/%s" % (directory, log_type), tar_fileobj)
    except Exception as e:
        logger.warning("Failed to write %s falco logs to volume: %s", log_type, e)
