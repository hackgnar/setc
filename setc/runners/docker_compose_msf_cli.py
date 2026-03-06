from __future__ import annotations

import logging
import os

import docker
import docker.models.containers
from python_on_whales import DockerClient
from python_on_whales.exceptions import DockerException
from runners.base import BaseRunner
from utils import safe_stop_remove

logger = logging.getLogger(__name__)
"""
A config will have the following:
- client - for interacting with network and volume
- yml file
- target name
- msf_exploit
- msf_options
"""


class DockerComposeMsfCli(BaseRunner):
    """Runner for exploiting multi-container targets defined by docker-compose files."""

    def __init__(self, docker_client: docker.DockerClient, vuln_name: str = "", target_name: str = "target",
                 network_name: str = "set_framework_net", volume_name: str = "set_logs",
                 target_yml: str = "", msf_exploit: str = "", msf_options: str = "", delay: int = 0,
                 msf_image: str = "metasploitframework/metasploit-framework:6.2.33",
                 prefix: str = "") -> None:
        """Initialize with compose file path, target service name, and exploit config."""
        super().__init__(docker_client, network_name, volume_name, prefix=prefix)
        self.vuln_name = vuln_name
        self.target_yml = self._expand_and_validate(target_yml, "yml_file")
        self.target_name=target_name
        self.msf_exploit=msf_exploit
        self.msf_options=msf_options
        self.delay=delay
        self.msf_image=msf_image
        self.compose_project = self.prefix if self.prefix else "setc"

        self.setc_yml = self._expand_and_validate(
            "$SETC_PATH/example_configurations/setc-net_docker-compose.yml", "SETC_PATH")
        self.wdocker = None
        self.tcpdump_instances = []
        self.attack=None

 
    @staticmethod
    def _expand_and_validate(path: str, label: str) -> str:
        """Expand environment variables in a path and verify it exists.

        Raises:
            EnvironmentError: If any env vars remain unexpanded.
            FileNotFoundError: If the expanded path does not exist.
        """
        expanded = os.path.expandvars(path)
        if "$" in expanded:
            unset = [tok for tok in expanded.split(os.sep) if tok.startswith("$")]
            raise EnvironmentError(
                f"Environment variable(s) not set for {label}: {', '.join(unset)}. "
                f"Path after expansion: {expanded}"
            )
        if not os.path.exists(expanded):
            raise FileNotFoundError(
                f"Path does not exist for {label}: {expanded}"
            )
        return expanded

    def target_setup(self) -> None:
        """Build and start the docker-compose services."""
        wdocker = DockerClient(compose_project_name=self.compose_project, compose_files=[self.target_yml, self.setc_yml])
        wdocker.compose.build()
        wdocker.compose.up(detach=True)
        self.wdocker = wdocker
        # Resolve actual container name for the target service under the new project prefix
        if self.prefix:
            self.target_name = self.target_name.replace("setc-", f"{self.compose_project}-", 1)

    def target_cleanup(self) -> None:
        """Stop and remove all compose services and tcpdump sidecars."""
        if self.tcpdump_instances:
            self.tcpdump_cleanup()
        try:
            self.wdocker.compose.stop()
            self.wdocker.compose.rm()
        except DockerException as e:
            logger.warning("Failed to stop/remove compose services: %s", e)

    def tcpdump_setup(self) -> None:
        """Start a tcpdump container for the target compose service."""
        tcpdump_instances = []
        for i in self.wdocker.compose.ps():
            #TODO: parse pcaps for all compose instances. For now, we are only parsing the target instance
            if i.name == self.target_name:
                dk_tcpdump = self._run_tcpdump_container(self.vuln_name, self.target_name)
                tcpdump_instances.append(dk_tcpdump)
        self.tcpdump_instances = tcpdump_instances

    def tcpdump_cleanup(self) -> None:
        """Stop and remove all tcpdump sidecar containers."""
        for instance in self.tcpdump_instances:
            safe_stop_remove(instance, label="tcpdump")

    def _get_target_container(self) -> docker.models.containers.Container:
        """Look up and return the target container by name from the Docker API."""
        return self.client.containers.get(self.target_name)
