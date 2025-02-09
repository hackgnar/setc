import docker
import json
import time
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("config", type=str, 
                    help="The SETC configuration file to use")
parser.add_argument("-p", "--password", 
                    help="The password to use for SIEM services",
                    default="password1234")
args = parser.parse_args()

# SETTINGS
#config_file = "sample_config.json"
config_file = args.config

# Helper functions
def msf_attack_target(atk_system, config):
    cmd = "/usr/src/metasploit-framework/msfconsole"
    flag = "-x"
    args = """use %s; %s \
            set RHOSTS %s; \
            set LHOST %s; \
            set ForceExploit true; \
            set AutoCheck false; \
            set ExitOnSession false; \
            exploit"""
    if "exploit_options" in config["settings"]:
        custom_args = config["settings"]["exploit_options"]
        args = args % (config["settings"]["exploit"], custom_args,
                       "target_"+config["name"], "attack_"+config["name"])
    else:
        args = args % (config["settings"]["exploit"], "", 
                       "target_"+config["name"], "attack_"+config["name"])
    print("[*] Exploiting target system: %s - %s" % (config["name"], config["settings"]["description"]))
    res = atk_system.exec_run(cmd=[cmd, flag, args], tty=True, detach=True)
    time.sleep(90)

# framework setup
client = docker.from_env()
#TODO: run pcap file cleanup if needed
networks = client.networks.list()
networks = [i.name for i in networks]
if "set_framework_net" in networks:
    net = client.networks.get("set_framework_net")
    net.remove()
net = client.networks.create("set_framework_net", driver="bridge")

vol = None
vols = [v.name for v in client.volumes.list()]
if "set_logs" in vols:
    vol = client.volumes.get("set_logs")
else:
    vol = client.volumes.create(name="set_logs")

fconfig = open(config_file, "r")
config = json.load(fconfig)
fconfig.close()

# Core system setup
#nifi
#siem
#monitor/controller (could be built into nifi)

# splunk parsing
print("[*] Starting up Splunk server for log analysis")
dk_splunk = client.containers.run("splunk/splunk", detach=True, name="splunk", 
                                   volumes={"set_logs":{'bind':'/data', 'mode':'rw'}},
                                   ports={'8000/tcp':8000}, tty=True, 
                                   environment=["SPLUNK_START_ARGS=--accept-license",
                                                "SPLUNK_PASSWORD={}".format(args.password)],
                                   platform="linux/amd64")
finished = "Ansible playbook complete, will begin streaming splunkd_stderr.log"

print("[*] Starting up Zeek server for PCAP processing")
dk_zeek = client.containers.run("zeek/zeek", command="/bin/bash", detach=True, name="zeek",
                                tty=True, network="set_framework_net",
                                volumes={"set_logs":{'bind':'/data', 'mode':'rw'}})
dk_zeek.exec_run(cmd = ["mkdir","-p","/data/zeek/latest/"])
dk_zeek.exec_run(cmd = ["mkdir","-p","/data/pcap/"])
dk_zeek.exec_run(cmd = ["mkdir","-p","/data/logs/"])

print("[*] Splunk loading", end='')
while finished not in str(dk_splunk.logs()):
    time.sleep(5)
    print(".",flush=True, end='')
print("")

cmd = "./bin/splunk add index zeek -auth 'admin:{}'".format(args.password)
dk_splunk.exec_run(cmd = cmd , user="splunk", tty=True, detach=False)
cmd = "./bin/splunk add index cim -auth 'admin:{}'".format(args.password)
dk_splunk.exec_run(cmd = cmd , user="splunk", tty=True, detach=False)
cmd = "./bin/splunk add index ecs -auth 'admin:{}'".format(args.password)
dk_splunk.exec_run(cmd = cmd , user="splunk", tty=True, detach=False)
cmd = "./bin/splunk add index ocsf -auth 'admin:{}'".format(args.password)
dk_splunk.exec_run(cmd = cmd , user="splunk", tty=True, detach=False)
cmd = """./bin/splunk add monitor "/data/zeek/*/*" -index zeek -auth admin:{} -sourcetype _json"""
cmd = cmd.format(args.password)
dk_splunk.exec_run(cmd = cmd , user="splunk", tty=True, detach=False)
cmd = """./bin/splunk add monitor "/data/logs/cim*" -index cim -auth admin:{} -sourcetype _json"""
cmd = cmd.format(args.password)
dk_splunk.exec_run(cmd = cmd , user="splunk", tty=True, detach=False)
cmd = """./bin/splunk add monitor "/data/logs/ocsf*" -index ocsf -auth admin:{} -sourcetype _json"""
cmd = cmd.format(args.password)
dk_splunk.exec_run(cmd = cmd , user="splunk", tty=True, detach=False)
cmd = """./bin/splunk add monitor "/data/logs/ecs*" -index ecs -auth admin:{} -sourcetype _json"""
cmd = cmd.format(args.password)
dk_splunk.exec_run(cmd = cmd , user="splunk", tty=True, detach=False)

running_containers = []
# attack/target Setup systems
for system_config in config:
    containers = []
    print("[*] Starting vulnerable server: %s - %s" % (system_config["name"], system_config["settings"]["description"]))
    target_name = "target_" + system_config["name"]
    dk_trg = client.containers.run(system_config["settings"]["target_image"], 
                                   detach=True, name=target_name,
                                   network="set_framework_net")
    containers.append(dk_trg)
    
    #metasploit exploit shortcut
    atk_img = "metasploitframework/metasploit-framework:6.2.33"
    if system_config["settings"]["attack_src"] != "msf":
        pass

    dk_atk = client.containers.run(atk_img, 
                                   detach=True, name="attack_"+system_config["name"],
                                   network="set_framework_net", tty=True)
    containers.append(dk_atk)
    
    net_tcpdump = "container:%s" % (target_name)
    tcpdump_name = "tcpdump_" + system_config["name"]
    cmd = '-U -v -w /data/%s/pcap/%s.pcap' % (system_config["name"], system_config["name"])
    dk_tcpdump = client.containers.run("tcpdump", command=cmd, detach=True, 
                                       name=tcpdump_name, privileged=True,
                                       network=net_tcpdump,
                                       volumes={"set_logs":{'bind':'/data', 'mode':'rw'}})
    containers.append(dk_tcpdump)
    
    running_containers.append(containers)
    #if "startup_delay" in system_config["settings"]:
    time.sleep(90)
    
    # exploitation call
    msf_attack_target(dk_atk, system_config)
    
    # zeek parsing
    print("[*] Flushing log pipeline")
    bash_cmd = """cd /data/pcap; \
    mkdir /data/zeek/%s; \
    /usr/local/zeek/bin/zeek -C -r \
    /data/pcap/%s \
    Log::default_logdir=/data/zeek/%s \
    LogAscii::use_json=T
    """
    tmp = system_config["name"]
    bash_cmd = bash_cmd % (tmp, tmp+".pcap", tmp)
    cmd = ["/bin/bash", "-c", bash_cmd] 
    dk_zeek.exec_run(cmd=cmd, tty=True)
    
    # container cleanup
    for container_group in running_containers:
        for node in container_group:
            node.stop()
            node.remove()
    running_containers = []

print("[*] Converting logs to logging standards")
dk_logformat = client.containers.run("logformat", detach=True, name="logformat",
                                     volumes={"set_logs":{'bind':'/data', 'mode':'rw'}})
dk_zeek.stop()
dk_zeek.remove()
dk_logformat.stop()
dk_logformat.remove()

net.remove()
