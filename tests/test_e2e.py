"""End-to-end test: run a real exploit and verify success via Docker volume logs."""

import json
from pathlib import Path


# ---------------------------------------------------------------------------
# Log artifact existence
# ---------------------------------------------------------------------------

def test_pcap_generated(cve_log_dir, cve_name):
    """PCAP capture file exists and is non-empty."""
    pcap = cve_log_dir / "pcap" / f"{cve_name}.pcap"
    assert pcap.exists(), f"PCAP not found: {pcap}"
    assert pcap.stat().st_size > 0, "PCAP file is empty"


def test_zeek_logs_generated(cve_log_dir):
    """Zeek produced a conn.log from the PCAP."""
    conn_log = cve_log_dir / "zeek" / "conn.log"
    assert conn_log.exists(), f"conn.log not found: {conn_log}"
    assert conn_log.stat().st_size > 0, "conn.log is empty"


def test_log_standards_generated(cve_log_dir):
    """CIM, ECS, and OCSF log directories contain at least one file each."""
    for standard in ("cim", "ecs", "ocsf"):
        log_dir = cve_log_dir / standard
        assert log_dir.exists(), f"{standard} directory missing: {log_dir}"
        files = list(log_dir.iterdir())
        assert files, f"{standard} directory is empty: {log_dir}"


# ---------------------------------------------------------------------------
# Exploit success: reverse shell on port 4444
# ---------------------------------------------------------------------------

def _parse_conn_log(cve_log_dir):
    """Return parsed JSON entries from Zeek conn.log."""
    conn_log = cve_log_dir / "zeek" / "conn.log"
    entries = []
    for line in conn_log.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            entries.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return entries


def test_exploit_creates_reverse_shell(cve_log_dir):
    """Zeek conn.log contains at least one connection on port 4444 (reverse shell)."""
    entries = _parse_conn_log(cve_log_dir)
    assert entries, "conn.log has no parseable entries"

    has_4444 = any(
        e.get("id.resp_p") == 4444 or e.get("id.orig_p") == 4444
        for e in entries
    )
    assert has_4444, (
        "No port 4444 connection found in conn.log — reverse shell not established. "
        f"Ports seen: {sorted({e.get('id.resp_p') for e in entries} | {e.get('id.orig_p') for e in entries})}"
    )


def test_network_logs_contain_exploit_traffic(cve_log_dir):
    """CIM/ECS/OCSF network log files reference port 4444."""
    found_in = []
    for standard in ("cim", "ecs", "ocsf"):
        log_dir = cve_log_dir / standard
        if not log_dir.exists():
            continue
        for f in log_dir.iterdir():
            if not f.is_file():
                continue
            content = f.read_text()
            if "4444" in content:
                found_in.append(str(f.relative_to(cve_log_dir)))

    assert found_in, (
        "No CIM/ECS/OCSF network log references port 4444. "
        "Expected exploit traffic in standardised logs."
    )
