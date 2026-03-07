"""Falco runtime security module for continuous syscall monitoring during exploitation."""
from __future__ import annotations

import io
import json
import logging
import os
import tarfile
import time
from typing import Any

import docker
import docker.models.containers

from utils import prefixed_name, safe_stop_remove
from modules.falco_log_converter import convert_falco_events

logger = logging.getLogger(__name__)

# Resolve paths to Falco config files relative to this module
_MODULE_DIR = os.path.dirname(os.path.abspath(__file__))
_FALCO_DIR = os.path.join(os.path.dirname(_MODULE_DIR), "..", "docker_images", "falco")
_FALCO_YAML = os.path.abspath(os.path.join(_FALCO_DIR, "falco.yaml"))
_FALCO_RULES = os.path.abspath(os.path.join(_FALCO_DIR, "falco_rules.local.yaml"))


class FalcoModule:
    """Optional module that runs Falco as a privileged container for runtime syscall monitoring."""

    FALCO_IMAGE = "falcosecurity/falco:0.43.0"
    def __init__(self, docker_client: docker.DockerClient, volume_name: str = "set_logs",
                 network_name: str = "set_framework_net", prefix: str = "") -> None:
        """Initialize Falco module with Docker client and shared resource names."""
        self.client = docker_client
        self.volume = volume_name
        self.network = network_name
        self.prefix = prefix
        self.falco = None
        self._file_offset = 0

    def _prefixed(self, name: str) -> str:
        """Return the session-prefixed version of a container name."""
        return prefixed_name(self.prefix, name)

    def _find_existing(self) -> docker.models.containers.Container | None:
        """Find a running Falco container already mounted to our volume."""
        for container in self.client.containers.list(all=True,
                                                      filters={"ancestor": self.FALCO_IMAGE}):
            mounts = container.attrs.get("Mounts", [])
            for m in mounts:
                if m.get("Name") == self.volume:
                    if container.status != "running":
                        logger.info("Starting stopped Falco container: %s", container.name)
                        container.start()
                    return container
        return None

    def setup(self) -> None:
        """Start the Falco container with modern eBPF, or reuse one already running."""
        existing = self._find_existing()
        if existing:
            logger.info("Reusing existing Falco container: %s", existing.name)
            self.falco = existing
            return

        logger.info("Starting Falco container for runtime monitoring")
        self.falco = self.client.containers.run(
            self.FALCO_IMAGE,
            command=["falco"],
            detach=True,
            name=self._prefixed("falco"),
            privileged=True,
            pid_mode="host",
            volumes={
                self.volume: {"bind": "/falco_output", "mode": "rw"},
                "/sys/kernel/tracing": {"bind": "/sys/kernel/tracing", "mode": "ro"},
                "/var/run/docker.sock": {"bind": "/host/var/run/docker.sock", "mode": "ro"},
                "/proc": {"bind": "/host/proc", "mode": "ro"},
                "/etc": {"bind": "/host/etc", "mode": "ro"},
                _FALCO_YAML: {"bind": "/etc/falco/falco.yaml", "mode": "ro"},
                _FALCO_RULES: {"bind": "/etc/falco/falco_rules.local.yaml", "mode": "ro"},
            },
            network=self.network,
        )
        logger.info("Falco container started: %s", self.falco.name)

    def is_ready(self) -> bool:
        """Return True if the Falco container is running."""
        if not self.falco:
            return False
        try:
            self.falco.reload()
            return self.falco.status == "running"
        except (docker.errors.NotFound, docker.errors.APIError):
            return False

    def create_log_directories(self, name: str, write_container: docker.models.containers.Container) -> None:
        """Create the falco subdirectory for a CVE on the volume."""
        cmd = ["mkdir", "-p", "/data/%s/falco" % name]
        try:
            result = write_container.exec_run(cmd=cmd)
            if result.exit_code != 0:
                logger.warning("Failed to create falco directory for %s: %s", name, result.output)
        except (docker.errors.NotFound, docker.errors.APIError) as e:
            logger.warning("Could not create falco log directory: %s", e)

    def extract_events(self, vuln_name: str, container_names: list[str],
                       write_container: docker.models.containers.Container) -> None:
        """Extract Falco events for a specific CVE, filter by container, and convert to log formats.

        Args:
            vuln_name: CVE/vuln name for organizing output.
            container_names: Container names to filter events for.
            write_container: Container with the shared volume mounted at /data.
        """
        if not self.falco:
            return

        try:
            # Get current file size
            result = self.falco.exec_run(
                cmd=["wc", "-c", "/falco_output/falco_events.jsonl"],
                demux=True)
            if result.exit_code != 0:
                logger.warning("Falco events file not found yet")
                return
            stdout = result.output[0] if result.output[0] else b""
            current_size = int(stdout.strip().split()[0])

            if current_size <= self._file_offset:
                logger.debug("No new Falco events since last extraction")
                return

            # Read new content since last offset
            result = self.falco.exec_run(
                cmd=["tail", "-c", "+%d" % (self._file_offset + 1),
                     "/falco_output/falco_events.jsonl"],
                demux=True)
            if result.exit_code != 0:
                logger.warning("Failed to read Falco events")
                return

            self._file_offset = current_size
            raw_output = result.output[0] if result.output[0] else b""
            raw_text = raw_output.decode("utf-8", errors="replace")

            # Parse NDJSON and filter by container name
            all_events = []
            filtered_events = []
            for line in raw_text.strip().split("\n"):
                if not line.strip():
                    continue
                try:
                    event = json.loads(line)
                    all_events.append(event)
                    output_fields = event.get("output_fields", {})
                    cname = output_fields.get("container.name", "")
                    if cname in container_names:
                        filtered_events.append(event)
                except json.JSONDecodeError:
                    continue

            logger.info("Falco: %d total events, %d matched target containers for %s",
                        len(all_events), len(filtered_events), vuln_name)

            if not filtered_events:
                return

            # Create falco directory
            self.create_log_directories(vuln_name, write_container)

            # Write raw filtered events to falco subdirectory
            raw_content = "\n".join(json.dumps(e) for e in filtered_events) + "\n"
            tar_fileobj = io.BytesIO()
            with tarfile.open(fileobj=tar_fileobj, mode="w|") as tar:
                data = raw_content.encode("utf-8")
                tf = tarfile.TarInfo("falco_events.log")
                tf.size = len(data)
                tar.addfile(tf, io.BytesIO(data))
            tar_fileobj.flush()
            tar_fileobj.seek(0)
            write_container.put_archive("/data/%s/falco" % vuln_name, tar_fileobj)

            # Convert to all log formats
            convert_falco_events(filtered_events, write_container, vuln_name)
            logger.info("Falco events converted and written for %s", vuln_name)

        except (docker.errors.NotFound, docker.errors.APIError) as e:
            logger.warning("Falco event extraction failed: %s", e)

    def cleanup(self) -> None:
        """Stop and remove the Falco container."""
        if self.falco:
            safe_stop_remove(self.falco, label=self._prefixed("falco"))
            logger.info("Falco container removed")
