import docker
from utils import safe_stop_remove

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
        commands = [
            "./bin/splunk add index zeek -auth 'admin:{}'".format(self.password),
            "./bin/splunk add index cim -auth 'admin:{}'".format(self.password),
            "./bin/splunk add index ecs -auth 'admin:{}'".format(self.password),
            "./bin/splunk add index ocsf -auth 'admin:{}'".format(self.password),
            """./bin/splunk add monitor "/data/*/zeek/*" -index zeek -auth admin:{} -sourcetype _json""".format(self.password),
            """./bin/splunk add monitor "/data/*/cim/*" -index cim -auth admin:{} -sourcetype _json""".format(self.password),
            """./bin/splunk add monitor "/data/*/ocsf/*" -index ocsf -auth admin:{} -sourcetype _json""".format(self.password),
            """./bin/splunk add monitor "/data/*/ecs/*" -index ecs -auth admin:{} -sourcetype _json""".format(self.password),
        ]
        for cmd in commands:
            try:
                result = self.splunk.exec_run(cmd=cmd, user="splunk", tty=True, detach=False)
                if result.exit_code != 0:
                    print("[!] Warning: splunk command failed: %s" % cmd.split("-auth")[0].strip())
            except (docker.errors.NotFound, docker.errors.APIError) as e:
                print(f"[!] Warning: splunk exec failed: {e}")
        self.setup_complete=True

    def cleanup(self):
        if self.splunk:
            safe_stop_remove(self.splunk, label="splunk")
