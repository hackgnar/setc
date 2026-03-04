import logging
import os
import time

from python_on_whales import DockerClient
from python_on_whales.exceptions import DockerException
import docker
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
    def __init__(self, docker_client, vuln_name="", target_name="target", 
                 network_name="set_framework_net", volume_name="set_logs", 
                 target_yml="", msf_exploit="", msf_options="", delay=0,
                 msf_image="metasploitframework/metasploit-framework:6.2.33"):
        super().__init__(docker_client, network_name, volume_name)
        self.vuln_name = vuln_name
        self.target_yml = self._expand_and_validate(target_yml, "yml_file")
        self.target_name=target_name
        self.msf_exploit=msf_exploit
        self.msf_options=msf_options
        self.delay=delay
        self.msf_image=msf_image

        self.setc_yml = self._expand_and_validate(
            "$SETC_PATH/example_configurations/setc-net_docker-compose.yml", "SETC_PATH")
        self.wdocker = None
        self.tcpdump_instances = []
        self.attack=None
        self.target_logs=None

 
    @staticmethod
    def _expand_and_validate(path, label):
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

    def target_setup(self):
        wdocker = DockerClient(compose_project_name="setc", compose_files=[self.target_yml, self.setc_yml])
        wdocker.compose.build()
        wdocker.compose.up(detach=True)
        self.wdocker = wdocker

    def target_cleanup(self):
        if self.tcpdump_instances:
            self.tcpdump_cleanup()
        try:
            self.wdocker.compose.stop()
            self.wdocker.compose.rm()
        except DockerException as e:
            logger.warning("Failed to stop/remove compose services: %s", e)

    def tcpdump_setup(self):
        tcpdump_instances = []
        for i in self.wdocker.compose.ps():
            #TODO: parse pcaps for all compose instances. For now, we are only parsing the target instance
            if i.name == self.target_name:
                #TODO: fix this with named arguments
                cmd = ["-U", "-v", "-w", f"/data/{self.vuln_name}/pcap/{self.vuln_name}.pcap"]
                dk_tcpdump = self.client.containers.run("tcpdump",command=cmd, detach=True,
                                  name="%s-tcpdump" % self.target_name, privileged=True,
                                  network="container:%s" % self.target_name, #TODO: this should be derived from self.target.name
                                  volumes={self.volume:{"bind":"/data","mode":'rw'}})
                tcpdump_instances.append(dk_tcpdump)
        self.tcpdump_instances = tcpdump_instances

    def tcpdump_cleanup(self):
        for instance in self.tcpdump_instances:
            safe_stop_remove(instance, label="tcpdump")

    def ready_to_exploit(self):
         #TODO: add a delay and retries argument similar to exploit_intil_success
        if self.target_logs == None:
            logger.debug("Checking if target %s is setup", self.target_name)
        else:
            self._progress_dot()
        #temp solution
        try:
            target = self.client.containers.get(self.target_name)
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
