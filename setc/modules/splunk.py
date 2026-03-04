import logging

import docker
from utils import safe_stop_remove

logger = logging.getLogger(__name__)


class SplunkModule:
    def __init__(self, docker_client, volume_name="set_logs",
                 network_name="set_framework_net", splunk_password="password1234"):
        self.client=docker_client
        self.volume=volume_name
        self.network=network_name
        self.splunk = None
        self.finished = "Ansible playbook complete, will begin streaming splunkd_stderr.log"
        self.password=splunk_password
        self.setup_complete=False

    def setup(self):
        dk_splunk = self.client.containers.run("splunk/splunk", detach=True,
                                          name="splunk",
                                          volumes={"set_logs":{'bind':'/data', 'mode':'rw'}},
                                          ports={8000:8000}, tty=True,
                                          environment=["SPLUNK_START_ARGS=--accept-license",
                                                       "SPLUNK_PASSWORD={}".format(self.password)],
                                          platform="linux/amd64")
        self.splunk = dk_splunk

    def is_ready(self):
        return self.finished in str(self.splunk.logs())

    def post_setup(self):
        auth = f"admin:{self.password}"
        commands = [
            ["./bin/splunk", "add", "index", "zeek", "-auth", auth],
            ["./bin/splunk", "add", "index", "cim", "-auth", auth],
            ["./bin/splunk", "add", "index", "ecs", "-auth", auth],
            ["./bin/splunk", "add", "index", "ocsf", "-auth", auth],
            ["./bin/splunk", "add", "monitor", "/data/*/zeek/*", "-index", "zeek", "-auth", auth, "-sourcetype", "_json"],
            ["./bin/splunk", "add", "monitor", "/data/*/cim/*", "-index", "cim", "-auth", auth, "-sourcetype", "_json"],
            ["./bin/splunk", "add", "monitor", "/data/*/ocsf/*", "-index", "ocsf", "-auth", auth, "-sourcetype", "_json"],
            ["./bin/splunk", "add", "monitor", "/data/*/ecs/*", "-index", "ecs", "-auth", auth, "-sourcetype", "_json"],
        ]
        for cmd in commands:
            try:
                result = self.splunk.exec_run(cmd=cmd, user="splunk", tty=True, detach=False)
                if result.exit_code != 0:
                    logger.warning("Splunk command failed: %s", " ".join(cmd).split("-auth")[0].strip())
            except (docker.errors.NotFound, docker.errors.APIError) as e:
                logger.warning("Splunk exec failed: %s", e)
        self.setup_complete=True

    def cleanup(self):
        if self.splunk:
            safe_stop_remove(self.splunk, label="splunk")
