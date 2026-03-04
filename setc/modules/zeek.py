import docker
from utils import safe_stop_remove

class ZeekModule:
    def __init__(self, docker_client, volume_name="set_logs",
                 network_name="set_framework_net"):
        self.client=docker_client
        self.volume=volume_name
        self.network=network_name
        self.zeek = None

    def setup(self):
        dk_zeek = self.client.containers.run("zeek/zeek", command="/bin/bash",
                                        detach=True, name="zeek",tty=True,
                                        network=self.network,
                                        volumes={self.volume:{'bind':'/data', 'mode':'rw'}})
        self.zeek = dk_zeek

    def create_log_directories(self, name):
        #cmd = ["mkdir","-p","/data/%s/\\{pcap, zeek, cim, ocsf, cef\\}" % name]
        #self.zeek.exec_run(cmd=cmd)
        for subdir in ["pcap", "zeek", "cim", "ocsf", "ecs"]:
            cmd = ["mkdir", "-p", "/data/%s/%s" % (name, subdir)]
            try:
                result = self.zeek.exec_run(cmd=cmd)
                if result.exit_code != 0:
                    print("[!] Warning: failed to create directory /data/%s/%s: %s" % (name, subdir, result.output))
            except (docker.errors.NotFound, docker.errors.APIError) as e:
                print(f"[!] Warning: could not create log directory: {e}")

    def pcap_parse(self, name):
        bash_cmd = """
        /usr/local/zeek/bin/zeek -C -r \
        /data/{0}/pcap/{0}.pcap \
        Log::default_logdir=/data/{0}/zeek \
        LogAscii::use_json=T"""
        bash_cmd = bash_cmd.format(name)
        cmd = ["/bin/bash", "-c", bash_cmd]
        try:
            result = self.zeek.exec_run(cmd=cmd, tty=True)
            if result.exit_code != 0:
                print("[!] Warning: zeek pcap parsing failed for %s: %s" % (name, result.output))
        except (docker.errors.NotFound, docker.errors.APIError) as e:
            print(f"[!] Warning: could not parse pcap: {e}")

    def cleanup(self):
        safe_stop_remove(self.zeek, label="zeek")

    def to_logstandard(self, name):
        cmd = "/data/{0}/zeek /data/{0}"
        cmd = cmd.format(name)
        try:
            dk_logformat = self.client.containers.run("logformat", detach=True,
                                                 command=cmd, name="logformat",
                                                 volumes={"set_logs":{'bind':'/data', 'mode':'rw'}})
            safe_stop_remove(dk_logformat, label="logformat")
        except docker.errors.APIError as e:
            print(f"[!] Warning: log format conversion failed for {name}: {e}")
