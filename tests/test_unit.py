"""Unit tests for pure functions — no Docker required."""
from __future__ import annotations

import os
import sys
import pytest
from typing import Any

# ---------------------------------------------------------------------------
# Path setup so we can import from setc/ and docker_images/log_format/
# ---------------------------------------------------------------------------
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "setc"))

sys.path.insert(0, os.path.join(ROOT, "docker_images", "log_format"))
import log_format_conversion as lfc  # noqa: E402

from setc import validate_config  # noqa: E402
from modules.docker_process_logger import (  # noqa: E402
    ParsedCommand,
    parse_command,
    apply_schema as process_apply_schema,
    cim_endpoint_process,
    ecs_process,
    ocsf_process,
    cef_process,
    udm_process,
    format_cef_line as process_format_cef_line,
)
from utils import prefixed_name  # noqa: E402
from modules.postgres import TABLES, FORMAT_TABLE  # noqa: E402
from modules.elasticsearch import INDEX_MAP  # noqa: E402
from modules.falco_log_converter import (  # noqa: E402
    falco_cim_process, falco_ecs_process, falco_ocsf_process,
    falco_cef_process, falco_udm_process,
    falco_cim_network, falco_ecs_network, falco_ocsf_network,
    falco_cim_file, falco_ecs_file, falco_ocsf_file,
    falco_cim_alert, falco_ecs_alert, falco_ocsf_alert,
    falco_cef_alert, falco_udm_alert,
    _FALCO_PRIORITY_MAP, _extract_mitre_tags,
)

# ---------------------------------------------------------------------------
# Sample data
# ---------------------------------------------------------------------------
SAMPLE_ZEEK_HTTP: dict[str, Any] = {
    "ts": 1700000000.0,
    "uid": "CTest1234",
    "id.orig_h": "10.0.0.1",
    "id.orig_p": 54321,
    "id.resp_h": "10.0.0.2",
    "id.resp_p": 80,
    "method": "GET",
    "host": "example.com",
    "uri": "/index.html?q=1",
    "referrer": "http://example.com/home",
    "user_agent": "TestAgent/1.0",
    "request_body_len": 0,
    "response_body_len": 512,
    "status_code": 200,
    "orig_mime_types": "text/html",
}

SAMPLE_ZEEK_CONN: dict[str, Any] = {
    "ts": 1700000000.0,
    "uid": "CConn5678",
    "id.orig_h": "10.0.0.1",
    "id.orig_p": 54321,
    "id.resp_h": "10.0.0.2",
    "id.resp_p": 443,
    "proto": "tcp",
    "service": "ssl",
    "orig_bytes": 100,
    "resp_bytes": 200,
    "orig_pkts": 5,
    "resp_pkts": 8,
}

SAMPLE_PROCESS: dict[str, Any] = {
    "USER": "root",
    "PID": "1",
    "PPID": "0",
    "PGID": "1",
    "SESS": "1",
    "JOBC": "0",
    "STAT": "Ss",
    "TT": "?",
    "TIME": "00:00:01",
    "ELAPSED": "01:00:00",
    "LOGNAME": "root",
    "%CPU": "0.1",
    "%MEM": "0.5",
    "COMMAND": "/usr/bin/python3 script.py arg1",
}


# ===================================================================
# 1. validate_config()
# ===================================================================
class TestValidateConfig:
    """Tests for setc.validate_config()."""

    def _minimal_docker(self, **overrides: Any) -> list[dict]:
        entry: dict[str, Any] = {
            "name": "test-vuln",
            "settings": {
                "description": "A test vuln",
                "exploit": "exploit/test",
                "target_image": "vuln:latest",
            },
        }
        entry.update(overrides)
        return [entry]

    def _minimal_compose(self, **overrides: Any) -> list[dict]:
        entry: dict[str, Any] = {
            "name": "test-compose",
            "settings": {
                "description": "A compose vuln",
                "exploit": "exploit/test",
                "yml_file": "docker-compose.yml",
                "target_name": "web",
            },
        }
        entry.update(overrides)
        return [entry]

    def test_valid_docker_config(self):
        assert validate_config(self._minimal_docker()) == []

    def test_valid_compose_config(self):
        assert validate_config(self._minimal_compose()) == []

    def test_empty_list(self):
        errors = validate_config([])
        assert len(errors) == 1
        assert "non-empty" in errors[0]

    def test_not_a_list(self):
        errors = validate_config({"name": "x"})
        assert len(errors) == 1

    def test_non_object_entry(self):
        errors = validate_config(["not a dict"])
        assert len(errors) == 1
        assert "JSON object" in errors[0]

    def test_missing_name(self):
        cfg = [{"settings": {"description": "d", "exploit": "e", "target_image": "i"}}]
        errors = validate_config(cfg)
        assert any("'name'" in e for e in errors)

    def test_missing_settings(self):
        cfg = [{"name": "x"}]
        errors = validate_config(cfg)
        assert any("'settings'" in e for e in errors)

    def test_missing_description(self):
        cfg = self._minimal_docker()
        del cfg[0]["settings"]["description"]
        errors = validate_config(cfg)
        assert any("'description'" in e for e in errors)

    def test_valid_config_without_exploit(self):
        """Config without exploit field = manual mode, should be valid."""
        cfg = self._minimal_docker()
        del cfg[0]["settings"]["exploit"]
        assert validate_config(cfg) == []

    def test_valid_config_with_empty_exploit(self):
        """Config with empty exploit string = manual mode, should be valid."""
        cfg = self._minimal_docker()
        cfg[0]["settings"]["exploit"] = ""
        assert validate_config(cfg) == []

    def test_exploit_wrong_type(self):
        """exploit field must be a string if present."""
        cfg = self._minimal_docker()
        cfg[0]["settings"]["exploit"] = 123
        errors = validate_config(cfg)
        assert any("'exploit'" in e for e in errors)

    def test_both_target_image_and_yml_file(self):
        cfg = self._minimal_docker()
        cfg[0]["settings"]["yml_file"] = "compose.yml"
        errors = validate_config(cfg)
        assert any("not both" in e for e in errors)

    def test_neither_target_image_nor_yml_file(self):
        cfg = self._minimal_docker()
        del cfg[0]["settings"]["target_image"]
        errors = validate_config(cfg)
        assert any("either" in e for e in errors)

    def test_name_not_string(self):
        cfg = self._minimal_docker()
        cfg[0]["name"] = 123
        errors = validate_config(cfg)
        assert any("'name' must be a string" in e for e in errors)

    def test_target_delay_non_numeric(self):
        cfg = self._minimal_docker()
        cfg[0]["settings"]["target_delay"] = "abc"
        errors = validate_config(cfg)
        assert any("target_delay" in e for e in errors)

    def test_target_delay_numeric_string(self):
        cfg = self._minimal_docker()
        cfg[0]["settings"]["target_delay"] = "5"
        assert validate_config(cfg) == []

    def test_exploit_options_wrong_type(self):
        cfg = self._minimal_docker()
        cfg[0]["settings"]["exploit_options"] = 42
        errors = validate_config(cfg)
        assert any("exploit_options" in e for e in errors)

    def test_exploit_success_pattern_wrong_type(self):
        cfg = self._minimal_docker()
        cfg[0]["settings"]["exploit_success_pattern"] = []
        errors = validate_config(cfg)
        assert any("exploit_success_pattern" in e for e in errors)

    def test_yml_file_missing_target_name(self):
        cfg = self._minimal_compose()
        del cfg[0]["settings"]["target_name"]
        errors = validate_config(cfg)
        assert any("target_name" in e for e in errors)

    @pytest.mark.parametrize("field", [
        "exploit_retries", "exploit_check_delay", "exploit_check_count",
        "ready_delay", "ready_retries",
    ])
    def test_retry_field_valid(self, field: str):
        cfg = self._minimal_docker()
        cfg[0]["settings"][field] = 10
        assert validate_config(cfg) == []

    @pytest.mark.parametrize("field", [
        "exploit_retries", "exploit_check_delay", "exploit_check_count",
        "ready_delay", "ready_retries",
    ])
    def test_retry_field_non_numeric(self, field: str):
        cfg = self._minimal_docker()
        cfg[0]["settings"][field] = "abc"
        errors = validate_config(cfg)
        assert any(field in e for e in errors)


# ===================================================================
# 2. apply_schema() from log_format_conversion
# ===================================================================
class TestApplySchema:
    """Tests for the generic apply_schema() function."""

    def test_flat_schema(self):
        schema = {
            "upper": lambda x: x.get("val", "").upper(),
            "length": lambda x: len(x.get("val", "")),
        }
        result = lfc.apply_schema({"val": "hello"}, schema)
        assert result == {"upper": "HELLO", "length": 5}

    def test_nested_schema(self):
        schema = {
            "outer": {
                "inner": lambda x: x.get("v"),
            }
        }
        result = lfc.apply_schema({"v": 42}, schema)
        assert result == {"outer": {"inner": 42}}

    def test_none_excluded(self):
        schema = {
            "present": lambda x: "yes",
            "absent": lambda x: None,
        }
        result = lfc.apply_schema({}, schema)
        assert "absent" not in result
        assert result["present"] == "yes"

    def test_empty_log_empty_schema(self):
        assert lfc.apply_schema({}, {}) == {}


# ===================================================================
# 3. Schema conversions from log_format_conversion
# ===================================================================
class TestOcsfActivityId:
    """Tests for ocsf_activity_id()."""

    @pytest.mark.parametrize("method,expected", [
        ("CONNECT", 1), ("DELETE", 2), ("GET", 3), ("HEAD", 4),
        ("OPTIONS", 5), ("POST", 6), ("PUT", 7), ("TRACE", 8),
        ("OTHER", 99), ("UNKNOWN", 0), ("PATCH", 0),
    ])
    def test_methods(self, method: str, expected: int):
        assert lfc.ocsf_activity_id(method) == expected


class TestZeekHttpConversions:
    """Tests for zeek HTTP log → CIM / ECS / OCSF."""

    def test_zeek_to_cim_key_fields(self):
        result = lfc.zeek_to_cim(SAMPLE_ZEEK_HTTP)
        assert result["src"] == "10.0.0.1"
        assert result["dest"] == "10.0.0.2"
        assert result["dest_port"] == 80
        assert result["http_method"] == "GET"
        assert result["status"] == 200
        assert result["bytes_in"] == 0
        assert result["bytes_out"] == 512
        assert result["bytes"] == 512
        assert result["url"] == "/index.html?q=1"
        assert result["http_user_agent"] == "TestAgent/1.0"

    def test_zeek_to_ecs_key_fields(self):
        result = lfc.zeek_to_ecs(SAMPLE_ZEEK_HTTP)
        assert result["source.ip"] == "10.0.0.1"
        assert result["destination.ip"] == "10.0.0.2"
        assert result["http.request.method"] == "GET"
        assert result["http.response.status_code"] == 200
        assert result["http.response.body.bytes"] == 512

    def test_zeek_to_ocsf_nested_structure(self):
        result = lfc.zeek_to_ocsf(SAMPLE_ZEEK_HTTP)
        assert result["activity_id"] == 3  # GET
        assert result["category_name"] == "Network Activity"
        assert "http_request" in result
        assert result["http_request"]["http_method"] == "GET"
        assert result["http_request"]["url"]["path"] == "/index.html"
        assert "http_response" in result
        assert result["http_response"]["code"] == 200
        assert "src_endpoint" in result
        assert result["src_endpoint"]["ip"] == "10.0.0.1"


class TestZeekNetworkConversions:
    """Tests for zeek conn log → CIM / ECS / OCSF."""

    def test_zeek_to_network_cim(self):
        result = lfc.zeek_to_network_cim(SAMPLE_ZEEK_CONN)
        assert result["src"] == "10.0.0.1"
        assert result["dest"] == "10.0.0.2"
        assert result["dest_port"] == 443
        assert result["transport"] == "tcp"
        assert result["bytes"] == 300
        assert result["packets"] == 13

    def test_zeek_to_network_ecs(self):
        result = lfc.zeek_to_network_ecs(SAMPLE_ZEEK_CONN)
        assert result["source.ip"] == "10.0.0.1"
        assert result["destination.ip"] == "10.0.0.2"
        assert result["destination.port"] == 443
        assert result["network.protocol"] == "tcp"
        assert result["network.bytes"] == 300
        assert result["network.packets"] == 13

    def test_zeek_to_network_ocsf(self):
        result = lfc.zeek_to_network_ocsf(SAMPLE_ZEEK_CONN)
        assert result["category_name"] == "Network Activity"
        assert "dst_endpoint" in result
        assert result["dst_endpoint"]["ip"] == "10.0.0.2"
        assert result["dst_endpoint"]["port"] == 443
        assert "src_endpoint" in result
        assert result["src_endpoint"]["ip"] == "10.0.0.1"
        assert "metadata" in result
        assert result["metadata"]["version"] == "1.4.0"


# ===================================================================
# 4. parse_command()
# ===================================================================
class TestParseCommand:
    """Tests for docker_process_logger.parse_command()."""

    def test_returns_named_tuple(self):
        result = parse_command("/usr/bin/python3 script.py arg1")
        assert isinstance(result, ParsedCommand)

    def test_normal_command(self):
        result = parse_command("/usr/bin/python3 script.py arg1")
        assert result.filename == "python3"
        assert result.args == ["script.py"]
        assert "python3" in result.fullcmd
        assert "arg1" in result.fullcmd

    def test_rosetta_prefix(self):
        result = parse_command("/usr/libexec/rosetta /usr/bin/python3 script.py")
        assert result.filename == "python3"
        assert result.abspath == "/usr/bin/python3"

    def test_qemu_prefix(self):
        result = parse_command("/usr/bin/qemu-i386 /usr/local/bin/app --flag")
        assert result.filename == "app"
        assert result.abspath == "/usr/local/bin/app"

    def test_tuple_unpacking_compat(self):
        path, filename, abspath, args, fullcmd = parse_command("/usr/bin/python3 script.py")
        assert filename == "python3"


# ===================================================================
# 5. Process schema conversions
# ===================================================================
class TestProcessSchemas:
    """Tests for process log schema conversions."""

    def test_cim_endpoint_process(self):
        result = process_apply_schema(SAMPLE_PROCESS, cim_endpoint_process)
        assert result["process_name"] == "python3"
        assert result["process_id"] == "1"
        assert result["parent_process_id"] == "0"
        assert result["user"] == "root"
        assert result["action"] == "allowed"

    def test_ecs_process(self):
        result = process_apply_schema(SAMPLE_PROCESS, ecs_process)
        assert result["process.name"] == "python3"
        assert result["process.pid"] == "1"
        assert result["event.category"] == "process"
        assert result["user"] == "root"
        assert isinstance(result["process.args"], list)
        assert "python3" in result["process.args"][0]
        assert "script.py" in result["process.args"]
        assert result["process.interactive"] is False  # TT == "?"

    def test_ocsf_process_nested(self):
        result = process_apply_schema(SAMPLE_PROCESS, ocsf_process)
        assert result["category_name"] == "Discovery"
        assert "process" in result
        assert result["process"]["name"] == "python3"
        assert result["process"]["pid"] == "1"
        assert "file" in result["process"]
        assert result["process"]["file"]["name"] == "python3"
        assert "user" in result["process"]
        assert result["process"]["user"]["name"] == "root"
        assert "metadata" in result


# ===================================================================
# 6. prefixed_name()
# ===================================================================
class TestPrefixedName:
    """Tests for utils.prefixed_name()."""

    def test_with_prefix(self):
        assert prefixed_name("setc", "zeek") == "setc-zeek"

    def test_empty_prefix(self):
        assert prefixed_name("", "zeek") == "zeek"


# ===================================================================
# 7. CEF conversions
# ===================================================================
class TestCefEscapeHelpers:
    """Tests for CEF escape functions."""

    def test_cef_escape_header_pipe(self):
        assert lfc.cef_escape_header("a|b") == "a\\|b"

    def test_cef_escape_header_backslash(self):
        assert lfc.cef_escape_header("a\\b") == "a\\\\b"

    def test_cef_escape_header_both(self):
        assert lfc.cef_escape_header("a\\|b") == "a\\\\\\|b"

    def test_cef_escape_extension_equals(self):
        assert lfc.cef_escape_extension("key=val") == "key\\=val"

    def test_cef_escape_extension_backslash(self):
        assert lfc.cef_escape_extension("a\\b") == "a\\\\b"


class TestFormatCefLine:
    """Tests for format_cef_line()."""

    def test_basic_format(self):
        header = ("Vendor", "Product", "1.0", "100", "Test Event", "5")
        extensions = {"src": "10.0.0.1", "dst": "10.0.0.2"}
        result = lfc.format_cef_line(header, extensions)
        assert result.startswith("CEF:0|Vendor|Product|1.0|100|Test Event|5|")
        assert "src=10.0.0.1" in result
        assert "dst=10.0.0.2" in result

    def test_none_values_excluded(self):
        header = ("V", "P", "1", "1", "E", "1")
        extensions = {"src": "10.0.0.1", "empty": None}
        result = lfc.format_cef_line(header, extensions)
        assert "src=10.0.0.1" in result
        assert "empty" not in result

    def test_header_escaping(self):
        header = ("Ven|dor", "Pro\\duct", "1.0", "100", "Test", "5")
        result = lfc.format_cef_line(header, {})
        assert "Ven\\|dor" in result
        assert "Pro\\\\duct" in result


class TestZeekCefConversions:
    """Tests for zeek log → CEF conversions."""

    def test_zeek_to_cef_http(self):
        result = lfc.zeek_to_cef(SAMPLE_ZEEK_HTTP)
        assert isinstance(result, str)
        assert result.startswith("CEF:0|SETC|setc|1.0|SETC-HTTP-GET|HTTP Activity: GET|3|")
        assert "src=10.0.0.1" in result
        assert "dst=10.0.0.2" in result
        assert "requestMethod=GET" in result
        assert "dhost=example.com" in result
        assert "request=/index.html?q\\=1" in result  # equals escaped in extension

    def test_zeek_to_network_cef(self):
        result = lfc.zeek_to_network_cef(SAMPLE_ZEEK_CONN)
        assert isinstance(result, str)
        assert result.startswith("CEF:0|SETC|setc|1.0|SETC-NET-CONN|Network Activity: Traffic|3|")
        assert "src=10.0.0.1" in result
        assert "dst=10.0.0.2" in result
        assert "proto=tcp" in result
        assert "act=allowed" in result


class TestCefProcessSchema:
    """Tests for CEF process schema conversion."""

    def test_cef_process_output(self):
        extensions = process_apply_schema(SAMPLE_PROCESS, cef_process)
        line = process_format_cef_line(
            ("SETC", "setc", "1.0", "SETC-PROC-SNAP", "Process Activity: Snapshot", "3"),
            extensions)
        assert isinstance(line, str)
        assert line.startswith("CEF:0|SETC|")
        assert "sproc=python3" in line
        assert "spid=1" in line
        assert "suser=root" in line
        assert "act=allowed" in line
        assert "cat=process" in line


# ===================================================================
# 8. UDM conversions
# ===================================================================
class TestZeekUdmConversions:
    """Tests for zeek log → UDM conversions."""

    def test_zeek_to_udm_http(self):
        result = lfc.zeek_to_udm(SAMPLE_ZEEK_HTTP)
        assert result["metadata"]["event_type"] == "NETWORK_HTTP"
        assert result["metadata"]["vendor_name"] == "SETC"
        assert result["principal"]["ip"] == ["10.0.0.1"]
        assert result["principal"]["port"] == 54321
        assert result["target"]["ip"] == ["10.0.0.2"]
        assert result["target"]["port"] == 80
        assert result["target"]["hostname"] == "example.com"
        assert result["network"]["http"]["method"] == "GET"
        assert result["network"]["http"]["responseCode"] == 200
        assert result["network"]["http"]["userAgent"] == "TestAgent/1.0"
        assert result["network"]["receivedBytes"] == 512
        assert result["network"]["sentBytes"] == 0
        assert result["network"]["applicationProtocol"] == "HTTP"
        assert result["security_result"]["action"] == "ALLOW"

    def test_zeek_to_network_udm(self):
        result = lfc.zeek_to_network_udm(SAMPLE_ZEEK_CONN)
        assert result["metadata"]["event_type"] == "NETWORK_CONNECTION"
        assert result["metadata"]["vendor_name"] == "SETC"
        assert result["principal"]["ip"] == ["10.0.0.1"]
        assert result["target"]["ip"] == ["10.0.0.2"]
        assert result["target"]["port"] == 443
        assert result["network"]["ipProtocol"] == "TCP"
        assert result["network"]["applicationProtocol"] == "ssl"
        assert result["network"]["sentBytes"] == 100
        assert result["network"]["receivedBytes"] == 200
        assert result["security_result"]["action"] == "ALLOW"


class TestUdmProcessSchema:
    """Tests for UDM process schema conversion."""

    def test_udm_process_output(self):
        result = process_apply_schema(SAMPLE_PROCESS, udm_process)
        assert result["metadata"]["event_type"] == "PROCESS_LAUNCH"
        assert result["metadata"]["vendor_name"] == "SETC"
        assert result["principal"]["user"]["userid"] == "root"
        assert result["target"]["process"]["pid"] == "1"
        assert result["target"]["process"]["parentProcess"]["pid"] == "0"
        assert "python3" in result["target"]["process"]["commandLine"]
        assert result["target"]["process"]["file"]["full_path"] is not None
        assert result["security_result"]["action"] == "ALLOW"


# ===================================================================
# 9. PostgresModule constants
# ===================================================================
class TestPostgresModule:
    """Tests for PostgresModule table/format constants."""

    def test_tables_has_all_formats(self):
        expected = {"zeek_logs", "cim_logs", "ecs_logs", "ocsf_logs", "cef_logs", "udm_logs", "falco_logs"}
        assert set(TABLES.keys()) == expected

    def test_cef_uses_text_column(self):
        assert TABLES["cef_logs"] == "event TEXT"
        for table_name, col_def in TABLES.items():
            if table_name != "cef_logs":
                assert col_def == "event JSONB", f"{table_name} should use JSONB"

    def test_format_table_mapping(self):
        expected_dirs = {"zeek", "cim", "ecs", "ocsf", "cef", "udm", "falco"}
        assert set(FORMAT_TABLE.keys()) == expected_dirs
        # CEF is non-JSON, all others are JSON
        for fmt_dir, (table_name, is_json) in FORMAT_TABLE.items():
            if fmt_dir == "cef":
                assert is_json is False
                assert table_name == "cef_logs"
            else:
                assert is_json is True
                assert table_name == f"{fmt_dir}_logs"


# ===================================================================
# 10. ElasticsearchModule constants
# ===================================================================
class TestElasticsearchModule:
    """Tests for ElasticsearchModule index/format constants."""

    def test_index_map_has_all_formats(self):
        expected = {"zeek", "cim", "ecs", "ocsf", "cef", "udm", "falco"}
        assert set(INDEX_MAP.keys()) == expected

    def test_cef_is_non_json(self):
        _, is_json = INDEX_MAP["cef"]
        assert is_json is False
        for fmt_dir, (index_name, is_json) in INDEX_MAP.items():
            if fmt_dir != "cef":
                assert is_json is True, f"{fmt_dir} should be JSON"


# ===================================================================
# 11. exploit_mode validation
# ===================================================================
class TestExploitModeValidation:
    """Tests for exploit_mode config validation."""

    def _minimal_docker(self, **settings_overrides: Any) -> list[dict]:
        settings: dict[str, Any] = {
            "description": "A test vuln",
            "exploit": "exploit/test",
            "target_image": "vuln:latest",
        }
        settings.update(settings_overrides)
        return [{"name": "test-vuln", "settings": settings}]

    def test_exploit_mode_cli(self):
        assert validate_config(self._minimal_docker(exploit_mode="cli")) == []

    def test_exploit_mode_rpc(self):
        assert validate_config(self._minimal_docker(exploit_mode="rpc")) == []

    def test_exploit_mode_invalid(self):
        errors = validate_config(self._minimal_docker(exploit_mode="foo"))
        assert any("exploit_mode" in e for e in errors)

    def test_exploit_mode_wrong_type(self):
        errors = validate_config(self._minimal_docker(exploit_mode=123))
        assert any("exploit_mode" in e for e in errors)


# ===================================================================
# 12. _parse_msf_options()
# ===================================================================
from runners.base import BaseRunner  # noqa: E402


class TestParseMsfOptions:
    """Tests for BaseRunner._parse_msf_options()."""

    def test_parse_basic(self):
        assert BaseRunner._parse_msf_options("set RPORT 9080;") == {"RPORT": "9080"}

    def test_parse_multiple(self):
        result = BaseRunner._parse_msf_options("set PAYLOAD cmd/unix/reverse_bash;set RPORT 9080;")
        assert result == {"PAYLOAD": "cmd/unix/reverse_bash", "RPORT": "9080"}

    def test_parse_empty(self):
        assert BaseRunner._parse_msf_options("") == {}

    def test_parse_no_trailing_semicolon(self):
        assert BaseRunner._parse_msf_options("set RPORT 9080") == {"RPORT": "9080"}

    def test_parse_ignores_non_set(self):
        assert BaseRunner._parse_msf_options("exploit;set RPORT 80;") == {"RPORT": "80"}


# ===================================================================
# 13. Falco schema conversions
# ===================================================================

SAMPLE_FALCO_PROCESS: dict[str, Any] = {
    "container.id": "abc123",
    "container.name": "setc-target",
    "proc.name": "bash",
    "proc.pid": 12345,
    "proc.ppid": 1234,
    "proc.cmdline": "bash -c whoami",
    "proc.exepath": "/usr/bin/bash",
    "user.name": "root",
    "evt.type": "execve",
    "time": 1700000000.0,
}

SAMPLE_FALCO_NETWORK: dict[str, Any] = {
    "container.id": "abc123",
    "container.name": "setc-target",
    "proc.name": "nc",
    "fd.name": "10.0.0.1:4444->10.0.0.2:54321",
    "fd.sip": "10.0.0.1",
    "fd.cip": "10.0.0.2",
    "fd.sport": 4444,
    "fd.cport": 54321,
    "evt.type": "connect",
    "user.name": "root",
    "time": 1700000000.0,
}

SAMPLE_FALCO_FILE: dict[str, Any] = {
    "container.id": "abc123",
    "container.name": "setc-target",
    "proc.name": "bash",
    "fd.name": "/etc/shadow",
    "user.name": "root",
    "evt.type": "write",
    "proc.cmdline": "bash -c cat /etc/shadow",
    "time": 1700000000.0,
}


class TestFalcoSchemaConversions:
    """Tests for Falco event schema conversions."""

    def test_falco_process_to_cim(self):
        result = process_apply_schema(SAMPLE_FALCO_PROCESS, falco_cim_process)
        assert result["process_name"] == "bash"
        assert result["process_id"] == 12345
        assert result["parent_process_id"] == 1234
        assert result["user"] == "root"
        assert result["action"] == "allowed"
        assert result["process_exec"] == "/usr/bin/bash"
        assert result["dest"] == "setc-target"

    def test_falco_process_to_ecs(self):
        result = process_apply_schema(SAMPLE_FALCO_PROCESS, falco_ecs_process)
        assert result["process.name"] == "bash"
        assert result["process.pid"] == 12345
        assert result["process.parent.pid"] == 1234
        assert result["process.command_line"] == "bash -c whoami"
        assert result["process.executable"] == "/usr/bin/bash"
        assert result["event.category"] == "process"
        assert result["container.name"] == "setc-target"
        assert result["container.id"] == "abc123"
        assert result["user.name"] == "root"

    def test_falco_process_to_ocsf(self):
        result = process_apply_schema(SAMPLE_FALCO_PROCESS, falco_ocsf_process)
        assert result["class_uid"] == "1007"
        assert result["class_name"] == "Process Activity"
        assert result["category_name"] == "System Activity"
        assert "process" in result
        assert result["process"]["name"] == "bash"
        assert result["process"]["pid"] == 12345
        assert result["process"]["cmd_line"] == "bash -c whoami"
        assert result["process"]["parent_process"]["pid"] == 1234
        assert "actor" in result
        assert result["actor"]["user"]["name"] == "root"
        assert "metadata" in result
        assert result["metadata"]["product"]["name"] == "Falco"

    def test_falco_process_to_cef(self):
        extensions = process_apply_schema(SAMPLE_FALCO_PROCESS, falco_cef_process)
        line = process_format_cef_line(
            ("SETC", "Falco", "0.43.0", "SETC-FALCO-PROC", "Process Activity: Execution", "5"),
            extensions)
        assert isinstance(line, str)
        assert line.startswith("CEF:0|SETC|Falco|")
        assert "sproc=bash" in line
        assert "spid=12345" in line
        assert "suser=root" in line
        assert "act=execve" in line
        assert "cat=process" in line

    def test_falco_process_to_udm(self):
        result = process_apply_schema(SAMPLE_FALCO_PROCESS, falco_udm_process)
        assert result["metadata"]["event_type"] == "PROCESS_LAUNCH"
        assert result["metadata"]["vendor_name"] == "SETC"
        assert result["metadata"]["product_name"] == "Falco"
        assert result["principal"]["user"]["userid"] == "root"
        assert result["target"]["process"]["pid"] == 12345
        assert result["target"]["process"]["parentProcess"]["pid"] == 1234
        assert result["target"]["process"]["commandLine"] == "bash -c whoami"
        assert result["security_result"]["action"] == "ALLOW"

    def test_falco_network_to_cim(self):
        result = process_apply_schema(SAMPLE_FALCO_NETWORK, falco_cim_network)
        assert result["src"] == "10.0.0.1"
        assert result["dest"] == "10.0.0.2"
        assert result["src_port"] == 4444
        assert result["dest_port"] == 54321
        assert result["transport"] == "tcp"
        assert result["transport"] == "tcp"
        assert result["process_name"] == "nc"
        assert result["user"] == "root"

    def test_falco_network_to_ecs(self):
        result = process_apply_schema(SAMPLE_FALCO_NETWORK, falco_ecs_network)
        assert result["source.ip"] == "10.0.0.1"
        assert result["destination.ip"] == "10.0.0.2"
        assert result["source.port"] == 4444
        assert result["destination.port"] == 54321
        assert result["event.category"] == "network"
        assert result["event.category"] == "network"
        assert result["container.name"] == "setc-target"

    def test_falco_network_to_ocsf(self):
        result = process_apply_schema(SAMPLE_FALCO_NETWORK, falco_ocsf_network)
        assert result["category_name"] == "Network Activity"
        assert result["src_endpoint"]["ip"] == "10.0.0.1"
        assert result["src_endpoint"]["port"] == 4444
        assert result["dst_endpoint"]["ip"] == "10.0.0.2"
        assert result["dst_endpoint"]["port"] == 54321
        assert result["metadata"]["product"]["name"] == "Falco"

    def test_falco_file_to_ecs(self):
        result = process_apply_schema(SAMPLE_FALCO_FILE, falco_ecs_file)
        assert result["event.category"] == "file"
        assert result["event.type"] == "change"
        assert result["file.path"] == "/etc/shadow"
        assert result["process.name"] == "bash"
        assert result["user.name"] == "root"
        assert result["container.name"] == "setc-target"

    def test_falco_file_to_ocsf(self):
        result = process_apply_schema(SAMPLE_FALCO_FILE, falco_ocsf_file)
        assert result["class_name"] == "File System Activity"
        assert result["file"]["name"] == "/etc/shadow"
        assert result["actor"]["process"]["name"] == "bash"
        assert result["actor"]["user"]["name"] == "root"


# ===================================================================
# 14. Falco alert schema conversions
# ===================================================================

SAMPLE_FALCO_ALERT: dict[str, Any] = {
    "_rule": "Terminal shell in container",
    "_priority": "Notice",
    "_output": "A shell was spawned in a container (container=setc-target proc=bash)",
    "_tags": ["maturity_stable", "container", "shell", "mitre_execution", "T1059.004"],
    "container.id": "abc123",
    "container.name": "setc-target",
    "proc.name": "bash",
    "proc.pid": 12345,
    "proc.cmdline": "bash",
    "user.name": "root",
    "evt.type": "execve",
    "time": 1700000000.0,
}


class TestFalcoAlertSchemas:
    """Tests for Falco built-in detection rule → alert schema conversions."""

    def test_falco_alert_to_cim(self):
        result = process_apply_schema(SAMPLE_FALCO_ALERT, falco_cim_alert)
        assert result["action"] == "detected"
        assert result["severity"] == "medium"
        assert result["signature"] == "Terminal shell in container"
        assert result["description"] == SAMPLE_FALCO_ALERT["_output"]
        assert result["process_name"] == "bash"
        assert result["process_id"] == 12345
        assert result["user"] == "root"
        assert result["dest"] == "setc-target"

    def test_falco_alert_to_ecs(self):
        result = process_apply_schema(SAMPLE_FALCO_ALERT, falco_ecs_alert)
        assert result["event.kind"] == "alert"
        assert result["event.category"] == "intrusion_detection"
        assert result["event.severity"] == 2
        assert result["rule.name"] == "Terminal shell in container"
        assert result["rule.description"] == SAMPLE_FALCO_ALERT["_output"]
        assert result["threat.framework"] == "MITRE ATT&CK"
        assert result["threat.tactic.name"] == "Execution"
        assert result["threat.technique.id"] == ["T1059.004"]
        assert result["process.name"] == "bash"
        assert result["process.pid"] == 12345
        assert result["container.name"] == "setc-target"
        assert result["container.id"] == "abc123"
        assert result["user.name"] == "root"

    def test_falco_alert_to_ocsf(self):
        result = process_apply_schema(SAMPLE_FALCO_ALERT, falco_ocsf_alert)
        assert result["class_uid"] == "2004"
        assert result["class_name"] == "Detection Finding"
        assert result["category_uid"] == "2"
        assert result["category_name"] == "Findings"
        assert result["severity_id"] == "3"
        assert result["finding_info"]["title"] == "Terminal shell in container"
        assert result["finding_info"]["desc"] == SAMPLE_FALCO_ALERT["_output"]
        assert result["attacks"] is not None
        assert result["attacks"][0]["tactic"]["name"] == "Execution"
        assert result["process"]["name"] == "bash"
        assert result["process"]["pid"] == 12345
        assert result["metadata"]["product"]["name"] == "Falco"

    def test_falco_alert_to_cef(self):
        extensions = process_apply_schema(SAMPLE_FALCO_ALERT, falco_cef_alert)
        header = ("SETC", "Falco", "0.43.0", "FALCO-DETECT",
                  "Falco Detection: Terminal shell in container", "5")
        line = process_format_cef_line(header, extensions)
        assert isinstance(line, str)
        assert "CEF:0|SETC|Falco|0.43.0|FALCO-DETECT|" in line
        assert "sproc=bash" in line
        assert "spid=12345" in line
        assert "suser=root" in line
        assert "cs2=Terminal shell in container" in line
        assert "msg=" in line

    def test_falco_alert_to_udm(self):
        result = process_apply_schema(SAMPLE_FALCO_ALERT, falco_udm_alert)
        assert result["metadata"]["event_type"] == "GENERIC_EVENT"
        assert result["metadata"]["vendor_name"] == "SETC"
        assert result["metadata"]["product_name"] == "Falco"
        assert result["security_result"]["alert_state"] == "ALERTING"
        assert result["security_result"]["severity"] == "MEDIUM"
        assert result["security_result"]["rule_name"] == "Terminal shell in container"
        assert result["security_result"]["description"] == SAMPLE_FALCO_ALERT["_output"]
        assert result["target"]["process"]["pid"] == 12345
        assert result["principal"]["user"]["userid"] == "root"

    def test_extract_mitre_tags(self):
        tags = ["maturity_stable", "container", "mitre_execution", "T1059.004", "T1059"]
        tactic, techniques = _extract_mitre_tags(tags)
        assert tactic == "Execution"
        assert techniques == ["T1059.004", "T1059"]

    def test_extract_mitre_tags_none(self):
        tactic, techniques = _extract_mitre_tags(None)
        assert tactic is None
        assert techniques == []

    def test_extract_mitre_tags_no_mitre(self):
        tactic, techniques = _extract_mitre_tags(["container", "shell"])
        assert tactic is None
        assert techniques == []

    @pytest.mark.parametrize("priority,expected_cim,expected_ecs,expected_ocsf,expected_cef,expected_udm", [
        ("Emergency",     "critical", 4, "5", "10", "CRITICAL"),
        ("Alert",         "critical", 4, "5", "9",  "CRITICAL"),
        ("Critical",      "critical", 4, "5", "9",  "CRITICAL"),
        ("Error",         "high",     3, "4", "7",  "HIGH"),
        ("Warning",       "high",     3, "4", "7",  "HIGH"),
        ("Notice",        "medium",   2, "3", "5",  "MEDIUM"),
        ("Informational", "low",      1, "2", "3",  "LOW"),
        ("Debug",         "low",      1, "1", "1",  "LOW"),
    ])
    def test_priority_mapping(self, priority, expected_cim, expected_ecs,
                              expected_ocsf, expected_cef, expected_udm):
        mapping = _FALCO_PRIORITY_MAP[priority]
        assert mapping["cim"] == expected_cim
        assert mapping["ecs"] == expected_ecs
        assert mapping["ocsf"] == expected_ocsf
        assert mapping["cef"] == expected_cef
        assert mapping["udm"] == expected_udm
