import docker
import argparse
import time
import json
from runners.docker_msf_cli import DockerMsfCli
from runners.docker_compose_msf_cli import DockerComposeMsfCli
from modules.zeek import ZeekModule
from modules.splunk import SplunkModule
from modules.docker_process_logger import DockerProcessLogs

parser = argparse.ArgumentParser()
parser.add_argument("config", type=str, 
                    help="The SETC configuration file to use. Example configuration files are provided in the projects sample_configuration directory.")
parser.add_argument("-p", "--password", 
                    help="The password to use for SIEM services. If not provided, a default password of password1234 will be used",
                    default="password1234")
#arg for vol name
parser.add_argument("--volume", 
                    help="The Docker volume to use for storing and manulpulating SETC log files. If not provided, the volume set_logs will be used",
                    default="set_logs")
#arg for net name
parser.add_argument("--network", 
                    help="The Docker network to be used for container network connections. If not provided, the network set_framework_net will be used.",
                    default="set_framework_net")
#arg to spin up splunk
parser.add_argument("--splunk",
                    help="Create a Splunk instance and populate it with SETC logs. The Splunk instance will remain up by default after the completion of a SETC run. The instance must be cleaned up manually.",
                    action='store_true')
#arg to blow out volumes before
parser.add_argument("--cleanup_network",
                    help="Delete the SETC docker network before running.",
                    action='store_true')
#arg to blow out networks before
parser.add_argument("--cleanup_volume",
                    help="Delete the SETC docker log volume before running.",
                    action='store_true')
#verbose argument
parser.add_argument("-v", "--verbose",
                    help="Enable SETC debug logging.",
                    action='store_true')

parser.add_argument("--zeek",
                    help="SETC parses pcap logs with zeek by default. Use this flag to DISABLE zeek.",
                    action='store_false')

parser.add_argument("--msf", 
                    help="Override the default metasploit framework image. This is useful if you would like to use custom built or bleeding edge msf image to get access to the latest or custom msf exploits",
                    default="metasploitframework/metasploit-framework:6.2.33")
args = parser.parse_args()

# SETTINGS
#config_file = "sample_config.json"
config_file = args.config
fconfig = open(config_file, "r")
config = json.load(fconfig)
fconfig.close()

# framework setup
client = docker.from_env()

########################################
###        PRE UP Core Runners       ###
########################################

# Volume & Network cleanup.  Should this be universal or per instance???
if args.cleanup_network:
    if args.verbose:
        print("[i] Cleaning up old SETC networks")
    networks = [i.name for i in client.networks.list()]
    if args.network in networks:
        net = client.networks.get(args.network)
        net.remove()

if args.cleanup_volume:
    if args.verbose:
        print("[i] Cleaning up old SETC volumes")
    vols = [i.name for i in client.volumes.list()]
    if args.volume in vols:
        vol = client.volumes.get(args.volume)
        vol.remove()


networks = [i.name for i in client.networks.list()]
if args.network not in networks:
    client.networks.create(args.network, driver="bridge")


vols = [i.name for i in client.volumes.list()]
if args.volume not in vols:
    client.volumes.create(args.volume)
# Core system setup

########################################
###       PRE UP Core Modules        ###
########################################
if args.zeek:
    zeek = ZeekModule(client)
    zeek.setup()
    for system_config in config:
        zeek.create_log_directories(system_config["name"])

tp = DockerProcessLogs(zeek.zeek)

splunk = None
if args.splunk:
    splunk = SplunkModule(client, splunk_password=args.password)
    splunk.setup()


########################################
###      Post UP Core Modules       ###
########################################

########################################
###       Post UP Core Modules       ###
########################################

# IF this is a docker based system
# attack/target Setup systems
for system_config in config:
    status_str = "[*] Starting servers for : %s - %s"
    print(status_str % (system_config["name"], 
                        system_config["settings"]["description"]))
    #TODO: if zeek is disabled, the docker class should not generate pcaps

    #TODO: is there a generic way to add optional config fields???
    delay=0
    if "target_delay" in system_config["settings"]:
        delay=int(system_config["settings"]["target_delay"])
    msf_options=""
    if "exploit_options" in system_config["settings"]:
        msf_options=system_config["settings"]["exploit_options"]
    setc = None
    setc_type = None
    if "yml_file" in system_config["settings"]:
        setc = DockerComposeMsfCli(client,
                                   vuln_name=system_config["name"],
                                   target_name=system_config["settings"]["target_name"],
                                   target_yml=system_config["settings"]["yml_file"],
                                   msf_exploit=system_config["settings"]["exploit"],
                                   msf_options=msf_options,
                                   delay=delay,
                                   msf_image=args.msf)
        setc_type="compose"
    else:
        setc = DockerMsfCli(client,
                            name = system_config["name"],
                            target_image=system_config["settings"]["target_image"],
                            msf_exploit=system_config["settings"]["exploit"],
                            msf_options=msf_options,
                            delay=delay,
                            msf_image=args.msf)
        setc_type="docker"
 
    ########################################
    ###          Pre UP Runners         ###
    ########################################

    ########################################
    ###          Pre UP Modules         ###
    ########################################
   
    setc.setup_all()

    ########################################
    ###          Post UP Runners         ###
    ########################################

    ########################################
    ###          Post UP Modules         ###
    ########################################
    if setc_type == "docker":
        tp.post_up(setc.target, setc.target.name)
    else:
        #TODO: user docker client to pull the instance by name
        target = client.containers.get(system_config["settings"]["target_name"])
        tp.post_up(target, system_config["name"])

    tries = 0
    while not setc.ready_to_exploit():
        if tries > 5:
            break
        tries += 1
    setc.exploit_until_success()

    ########################################
    ###          Pre Down Runners        ###
    ########################################

    ########################################
    ###          Pre Down Modules        ###
    ########################################
    if setc_type == "docker":
        tp.pre_down(setc.target, setc.target.name)
    else:
        #TODO: user docker client to pull the instance by name
        target = client.containers.get(system_config["settings"]["target_name"])
        tp.pre_down(target, system_config["name"])


    if args.zeek:
        zeek.pcap_parse(system_config["name"])
        zeek.to_logstandard(system_config["name"])

    setc.cleanup_all()

    ########################################
    ###          Post Down Runners       ###
    ########################################

    ########################################
    ###          Post Down Modules       ###
    ########################################

    if splunk and splunk.is_ready() and not splunk.setup_complete:
        print("[*] Creating Splunk indexes and parsing data")
        splunk.post_setup()

########################################
###       Pre Down Core Runners      ###
########################################

########################################
###       Pre Down Core Modules      ###
########################################

########################################
###       Post Down Core Runners     ###
########################################

########################################
###       Post Down Core Modules     ###
########################################

if args.zeek:
    zeek.cleanup()
