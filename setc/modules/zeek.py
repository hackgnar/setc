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
        cmd = ["mkdir","-p", "/data/%s/pcap" % name]
        self.zeek.exec_run(cmd=cmd)
        cmd = ["mkdir","-p", "/data/%s/zeek" % name]
        self.zeek.exec_run(cmd=cmd)
        cmd = ["mkdir","-p","/data/%s/cim" % name]
        self.zeek.exec_run(cmd=cmd)
        cmd = ["mkdir","-p", "/data/%s/ocsf" % name]
        self.zeek.exec_run(cmd=cmd)
        cmd = ["mkdir","-p", "/data/%s/ecs" % name]
        self.zeek.exec_run(cmd=cmd)

    def pcap_parse(self, name):
        bash_cmd = """
        /usr/local/zeek/bin/zeek -C -r \
        /data/{0}/pcap/{0}.pcap \
        Log::default_logdir=/data/{0}/zeek \
        LogAscii::use_json=T"""
        bash_cmd = bash_cmd.format(name)
        cmd = ["/bin/bash", "-c", bash_cmd] 
        self.zeek.exec_run(cmd=cmd, tty=True)
    
    def cleanup(self):
        self.zeek.stop()
        self.zeek.remove()

    def to_logstandard(self, name):
        cmd = "/data/{0}/zeek /data/{0}"
        cmd = cmd.format(name)
        dk_logformat = self.client.containers.run("logformat", detach=True, 
                                             command=cmd, name="logformat",
                                             volumes={"set_logs":{'bind':'/data', 'mode':'rw'}})
        dk_logformat.stop()
        dk_logformat.remove()
