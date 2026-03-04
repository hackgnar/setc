import logging
import time
import docker
from runners.base import BaseRunner
from utils import safe_stop_remove

logger = logging.getLogger(__name__)

class DockerMsfCli(BaseRunner):
    def __init__(self, docker_client, name="target", 
                 network_name="set_framework_net", volume_name="set_logs", 
                 target_image="", msf_exploit="", msf_options="", delay=0,
                 msf_image="metasploitframework/metasploit-framework:6.2.33"):
        super().__init__(docker_client, network_name, volume_name)
        self.target=None
        self.attack=None
        self.tcpdump=None
        #these should be setup on init.  However, should they be cleaned first???
        self.name=name
        self.target_name=name
        self.target_image=target_image
        self.msf_exploit=msf_exploit
        self.target_logs=None
        self.delay=delay
        self.msf_options=msf_options
        self.msf_image= msf_image 
        
    def target_setup(self):
        logger.debug("Starting vulnerable target %s", self.name)
        #tcpdump setup should happen automaticly after target setup
        dk_target = self.client.containers.run(self.target_image,
                                  detach=True, name=self.name,
                                  network=self.network)
        self.target=dk_target
        time.sleep(self.delay)

    def target_cleanup(self):
        if self.tcpdump:
            self.tcpdump_cleanup()
        safe_stop_remove(self.target, label=self.name)

    def tcpdump_setup(self):
        cmd = ["-U", "-v", "-w", f"/data/{self.name}/pcap/{self.name}.pcap"]
        dk_tcpdump = self.client.containers.run("tcpdump",command=cmd, detach=True,
                                  name="%s-tcpdump" % self.name, privileged=True,
                                  network="container:%s" % self.name, #TODO: this should be derived from self.target.name
                                  volumes={self.volume:{"bind":"/data","mode":'rw'}})
        self.tcpdump=dk_tcpdump

    def tcpdump_cleanup(self):
        safe_stop_remove(self.tcpdump, label="%s-tcpdump" % self.name)

    def ready_to_exploit(self):
        #TODO: add a delay and retries argument similar to exploit_intil_success
        if self.target_logs == None:
            logger.debug("Checking if target %s is setup", self.name)
        else:
            self._progress_dot()
        #temp solution
        try:
            logs = self.target.logs()
        except (docker.errors.NotFound, docker.errors.APIError) as e:
            self._progress_end()
            logger.warning("Could not get target logs: %s", e)
            return False
        if self.target_logs == logs:
            self._progress_end()
            logger.info("Target %s is ready for exploit", self.name)
            return True
        else:
            self.target_logs = logs
            time.sleep(5)
        return False
