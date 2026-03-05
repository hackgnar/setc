from __future__ import annotations

import logging

import docker
from utils import safe_stop_remove

logger = logging.getLogger(__name__)


class ZeekModule:
    def __init__(self, docker_client: docker.DockerClient, volume_name: str = "set_logs",
                 network_name: str = "set_framework_net") -> None:
        self.client=docker_client
        self.volume=volume_name
        self.network=network_name
        self.zeek = None

    def setup(self) -> None:
        dk_zeek = self.client.containers.run("zeek/zeek", command="/bin/bash",
                                        detach=True, name="zeek",tty=True,
                                        network=self.network,
                                        volumes={self.volume:{'bind':'/data', 'mode':'rw'}})
        self.zeek = dk_zeek

    def create_log_directories(self, name: str) -> None:
        #cmd = ["mkdir","-p","/data/%s/\\{pcap, zeek, cim, ocsf, cef\\}" % name]
        #self.zeek.exec_run(cmd=cmd)
        for subdir in ["pcap", "zeek", "cim", "ocsf", "ecs"]:
            cmd = ["mkdir", "-p", "/data/%s/%s" % (name, subdir)]
            try:
                result = self.zeek.exec_run(cmd=cmd)
                if result.exit_code != 0:
                    logger.warning("Failed to create directory /data/%s/%s: %s", name, subdir, result.output)
            except (docker.errors.NotFound, docker.errors.APIError) as e:
                logger.warning("Could not create log directory: %s", e)

    def pcap_parse(self, name: str) -> None:
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
        safe_stop_remove(self.zeek, label="zeek")

    def to_logstandard(self, name: str) -> None:
        cmd = [f"/data/{name}/zeek", f"/data/{name}"]
        try:
            dk_logformat = self.client.containers.run("logformat", detach=True,
                                                 command=cmd, name="logformat",
                                                 volumes={"set_logs":{'bind':'/data', 'mode':'rw'}})
            safe_stop_remove(dk_logformat, label="logformat")
        except docker.errors.APIError as e:
            logger.warning("Log format conversion failed for %s: %s", name, e)
