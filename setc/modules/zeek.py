from __future__ import annotations

import logging

import docker
from utils import prefixed_name, safe_stop_remove

logger = logging.getLogger(__name__)


class ZeekModule:
    """IDS module that runs a persistent Zeek container to parse PCAPs into structured logs."""

    def __init__(self, docker_client: docker.DockerClient, volume_name: str = "set_logs",
                 network_name: str = "set_framework_net", prefix: str = "") -> None:
        """Initialize Zeek module with Docker client and shared resource names."""
        self.client=docker_client
        self.volume=volume_name
        self.network=network_name
        self.prefix=prefix
        self.zeek = None

    def _prefixed(self, name: str) -> str:
        """Return the session-prefixed version of a container name."""
        return prefixed_name(self.prefix, name)

    def setup(self) -> None:
        """Start the persistent Zeek container on the shared volume and network."""
        dk_zeek = self.client.containers.run("zeek/zeek:8.1.1", command="/bin/bash",
                                        detach=True, name=self._prefixed("zeek"),tty=True,
                                        network=self.network,
                                        volumes={self.volume:{'bind':'/data', 'mode':'rw'}})
        self.zeek = dk_zeek

    def create_log_directories(self, name: str) -> None:
        """Create the pcap/zeek/cim/ocsf/ecs subdirectories for a CVE on the volume."""
        #cmd = ["mkdir","-p","/data/%s/\\{pcap, zeek, cim, ocsf, cef\\}" % name]
        #self.zeek.exec_run(cmd=cmd)
        for subdir in ["pcap", "zeek", "cim", "ocsf", "ecs", "cef"]:
            cmd = ["mkdir", "-p", "/data/%s/%s" % (name, subdir)]
            try:
                result = self.zeek.exec_run(cmd=cmd)
                if result.exit_code != 0:
                    logger.warning("Failed to create directory /data/%s/%s: %s", name, subdir, result.output)
            except (docker.errors.NotFound, docker.errors.APIError) as e:
                logger.warning("Could not create log directory: %s", e)

    def pcap_parse(self, name: str) -> None:
        """Run Zeek against the captured PCAP to produce JSON logs."""
        cmd = ["/usr/local/zeek/bin/zeek", "-C", "-r",
               f"/data/{name}/pcap/{name}.pcap",
               f"Log::default_logdir=/data/{name}/zeek",
               "LogAscii::use_json=T"]
        try:
            result = self.zeek.exec_run(cmd=cmd, tty=True)
            if result.exit_code != 0:
                logger.warning("Zeek pcap parsing failed for %s: %s", name, result.output)
        except (docker.errors.NotFound, docker.errors.APIError) as e:
            logger.warning("Could not parse pcap: %s", e)

    def cleanup(self) -> None:
        """Stop and remove the Zeek container."""
        safe_stop_remove(self.zeek, label=self._prefixed("zeek"))

    def to_logstandard(self, name: str) -> None:
        """Convert Zeek JSON logs to CIM, ECS, and OCSF using the logformat container."""
        cmd = [f"/data/{name}/zeek", f"/data/{name}"]
        try:
            dk_logformat = self.client.containers.run("logformat", detach=True,
                                                 command=cmd, name=self._prefixed("logformat"),
                                                 volumes={self.volume:{'bind':'/data', 'mode':'rw'}})
            safe_stop_remove(dk_logformat, label=self._prefixed("logformat"))
        except docker.errors.APIError as e:
            logger.warning("Log format conversion failed for %s: %s", name, e)
