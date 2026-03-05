from __future__ import annotations

import logging
import time

import docker
import docker.models.containers
from runners.base import BaseRunner
from utils import safe_stop_remove

logger = logging.getLogger(__name__)

class DockerMsfCli(BaseRunner):
    def __init__(self, docker_client: docker.DockerClient, name: str = "target",
                 network_name: str = "set_framework_net", volume_name: str = "set_logs",
                 target_image: str = "", msf_exploit: str = "", msf_options: str = "", delay: int = 0,
                 msf_image: str = "metasploitframework/metasploit-framework:6.2.33") -> None:
        super().__init__(docker_client, network_name, volume_name)
        self.target=None
        self.attack=None
        self.tcpdump=None
        #these should be setup on init.  However, should they be cleaned first???
        self.name=name
        self.target_name=name
        self.target_image=target_image
        self.msf_exploit=msf_exploit
        self.delay=delay
        self.msf_options=msf_options
        self.msf_image= msf_image 
        
    def target_setup(self) -> None:
        logger.debug("Starting vulnerable target %s", self.name)
        #tcpdump setup should happen automaticly after target setup
        dk_target = self.client.containers.run(self.target_image,
                                  detach=True, name=self.name,
                                  network=self.network)
        self.target=dk_target
        time.sleep(self.delay)

    def target_cleanup(self) -> None:
        if self.tcpdump:
            self.tcpdump_cleanup()
        safe_stop_remove(self.target, label=self.name)

    def tcpdump_setup(self) -> None:
        self.tcpdump = self._run_tcpdump_container(self.name, self.name)

    def tcpdump_cleanup(self) -> None:
        safe_stop_remove(self.tcpdump, label="%s-tcpdump" % self.name)

    def _get_target_container(self) -> docker.models.containers.Container:
        return self.target
