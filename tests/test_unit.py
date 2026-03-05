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

# log_format_conversion.py reads sys.argv[1] and sys.argv[2] at module level,
# so we must patch argv before importing it.
_original_argv = sys.argv[:]
sys.argv = ["test", "/tmp", "/tmp"]
sys.path.insert(0, os.path.join(ROOT, "docker_images", "log_format"))
import log_format_conversion as lfc  # noqa: E402
sys.argv = _original_argv

from setc import validate_config  # noqa: E402
from modules.docker_process_logger import (  # noqa: E402
    parse_command,
    apply_schema as process_apply_schema,
    cim_endpoint_process,
    ecs_process,
    ocsf_process,
)
from utils import prefixed_name  # noqa: E402

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

    def test_missing_exploit(self):
        cfg = self._minimal_docker()
        del cfg[0]["settings"]["exploit"]
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
        assert result["metadata"]["version"] == "1.3.0"


# ===================================================================
# 4. parse_command()
# ===================================================================
class TestParseCommand:
    """Tests for docker_process_logger.parse_command()."""

    def test_normal_command(self):
        path, filename, abspath, args, fullcmd = parse_command("/usr/bin/python3 script.py arg1")
        assert filename == "python3"
        assert args == ["script.py"]
        assert "python3" in fullcmd
        assert "arg1" in fullcmd

    def test_rosetta_prefix(self):
        path, filename, abspath, args, fullcmd = parse_command(
            "/usr/libexec/rosetta /usr/bin/python3 script.py"
        )
        assert filename == "python3"
        assert abspath == "/usr/bin/python3"

    def test_qemu_prefix(self):
        path, filename, abspath, args, fullcmd = parse_command(
            "/usr/bin/qemu-i386 /usr/local/bin/app --flag"
        )
        assert filename == "app"
        assert abspath == "/usr/local/bin/app"


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
