import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
CONFIG_PATH = PROJECT_ROOT / "example_configurations" / "docker_small.json"
VOLUME_NAME = "set_logs"


@pytest.fixture(scope="session")
def cve_name():
    with open(CONFIG_PATH) as f:
        config = json.load(f)
    return config[0]["name"]


@pytest.fixture(scope="session")
def volume_base(run_setc):
    """Copy volume data to a temp directory using Docker (no sudo needed)."""
    tmp = Path(tempfile.mkdtemp(prefix="setc_test_"))
    subprocess.run(
        [
            "docker", "run", "--rm",
            "-v", f"{VOLUME_NAME}:/src:ro",
            "-v", f"{tmp}:/dst",
            "alpine",
            "cp", "-a", "/src/.", "/dst/",
        ],
        check=True,
        capture_output=True,
        timeout=60,
    )
    yield tmp
    shutil.rmtree(tmp, ignore_errors=True)


@pytest.fixture(scope="session")
def cve_log_dir(volume_base, cve_name):
    return volume_base / cve_name


@pytest.fixture(scope="session", autouse=True)
def run_setc():
    """Run SETC once for the entire test session, then yield for assertions."""
    cmd = [
        sys.executable,
        str(PROJECT_ROOT / "setc" / "setc.py"),
        str(CONFIG_PATH),
        "--cleanup_volume",
        "--cleanup_network",
    ]
    result = subprocess.run(
        cmd,
        cwd=str(PROJECT_ROOT),
        capture_output=True,
        text=True,
        timeout=600,
    )
    if result.returncode != 0:
        pytest.fail(
            f"SETC failed (exit {result.returncode}):\n"
            f"STDOUT:\n{result.stdout}\n"
            f"STDERR:\n{result.stderr}"
        )
    yield result
