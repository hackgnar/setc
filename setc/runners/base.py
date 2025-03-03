import time

class BaseRunner:
    def __init__(self, docker_client, network_name="set_framework_net", volume_name="set_logs"):
        self.client=docker_client
        self.network=network_name
        self.volume=volume_name

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
        pass

    def attack_cleanup(self):
        pass

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
        pass

    def exploit_success(self):
        pass

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
