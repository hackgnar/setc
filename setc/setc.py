import docker
import argparse
import logging
import time
import json
from runners.docker_msf_cli import DockerMsfCli
from runners.docker_compose_msf_cli import DockerComposeMsfCli
from modules.zeek import ZeekModule
from modules.splunk import SplunkModule
from modules.docker_process_logger import DockerProcessLogs


def validate_config(config):
    errors = []

    if not isinstance(config, list) or len(config) == 0:
        return ["Config must be a non-empty JSON array of objects."]

    for i, entry in enumerate(config):
        prefix = f"Entry {i + 1}"

        if not isinstance(entry, dict):
            errors.append(f"{prefix}: must be a JSON object, got {type(entry).__name__}.")
            continue

        if "name" not in entry:
            errors.append(f"{prefix}: missing required field 'name'.")
        elif not isinstance(entry["name"], str):
            errors.append(f"{prefix}: 'name' must be a string.")
        else:
            prefix = f"Entry {i + 1} ('{entry['name']}')"

        if "settings" not in entry:
            errors.append(f"{prefix}: missing required field 'settings'.")
            continue
        if not isinstance(entry["settings"], dict):
            errors.append(f"{prefix}: 'settings' must be a JSON object.")
            continue

        s = entry["settings"]

        # Required string fields
        for field in ("description", "exploit"):
            if field not in s:
                errors.append(f"{prefix}: missing required setting '{field}'.")
            elif not isinstance(s[field], str):
                errors.append(f"{prefix}: setting '{field}' must be a string.")

        # Exactly one of target_image or yml_file
        has_image = "target_image" in s
        has_yml = "yml_file" in s
        if has_image and has_yml:
            errors.append(f"{prefix}: specify only one of 'target_image' or 'yml_file', not both.")
        elif not has_image and not has_yml:
            errors.append(f"{prefix}: must specify either 'target_image' or 'yml_file'.")
        else:
            if has_image and not isinstance(s["target_image"], str):
                errors.append(f"{prefix}: 'target_image' must be a string.")
            if has_yml:
                if not isinstance(s["yml_file"], str):
                    errors.append(f"{prefix}: 'yml_file' must be a string.")
                if "target_name" not in s:
                    errors.append(f"{prefix}: 'target_name' is required when 'yml_file' is used.")
                elif not isinstance(s["target_name"], str):
                    errors.append(f"{prefix}: 'target_name' must be a string.")

        # Optional fields — type-check only if present
        if "target_delay" in s:
            try:
                int(s["target_delay"])
            except (ValueError, TypeError):
                errors.append(f"{prefix}: 'target_delay' must be convertible to an integer.")

        for field in ("exploit_options", "exploit_success_pattern"):
            if field in s and not isinstance(s[field], str):
                errors.append(f"{prefix}: '{field}' must be a string.")

    return errors


def parse_args():
    parser = argparse.ArgumentParser(
        prog="setc",
        description="Security Event Traffic Creator - generate realistic attack traffic and logs for security testing.",
    )

    parser.add_argument("config", type=str,
                        help="The SETC configuration file to use. Example configuration files are provided in the projects sample_configuration directory.")
    parser.add_argument("-v", "--verbose",
                        help="Enable SETC debug logging.",
                        action='store_true')

    docker_group = parser.add_argument_group("Docker settings")
    docker_group.add_argument("-p", "--password",
                              help="The password to use for SIEM services. If not provided, a default password of password1234 will be used",
                              default="password1234")
    docker_group.add_argument("--volume",
                              help="The Docker volume to use for storing and manipulating SETC log files. If not provided, the volume set_logs will be used",
                              default="set_logs")
    docker_group.add_argument("--network",
                              help="The Docker network to be used for container network connections. If not provided, the network set_framework_net will be used.",
                              default="set_framework_net")
    docker_group.add_argument("--msf",
                              help="Override the default metasploit framework image. This is useful if you would like to use custom built or bleeding edge msf image to get access to the latest or custom msf exploits",
                              default="metasploitframework/metasploit-framework:6.2.33")

    module_group = parser.add_argument_group("Module options")
    module_group.add_argument("--splunk",
                              help="Create a Splunk instance and populate it with SETC logs. The Splunk instance will remain up by default after the completion of a SETC run. The instance must be cleaned up manually.",
                              action='store_true')
    module_group.add_argument("--no-zeek",
                              help="Disable zeek pcap log parsing (enabled by default).",
                              action='store_true')

    cleanup_group = parser.add_argument_group("Cleanup options")
    cleanup_group.add_argument("--cleanup_network",
                               help="Delete the SETC docker network before running.",
                               action='store_true')
    cleanup_group.add_argument("--cleanup_volume",
                               help="Delete the SETC docker log volume before running.",
                               action='store_true')

    args = parser.parse_args()

    try:
        with open(args.config, "r") as f:
            config = json.load(f)
    except FileNotFoundError:
        parser.error(f"Configuration file not found: {args.config}")
    except json.JSONDecodeError as e:
        parser.error(f"Invalid JSON in configuration file: {e}")

    config_errors = validate_config(config)
    if config_errors:
        parser.error("Configuration validation failed:\n  " + "\n  ".join(config_errors))

    return args, config


BANNER = r"""
   _____ ________________
  / ___// ____/_  __/ ____/
  \__ \/ __/   / / / /
 ___/ / /___  / / / /___
/____/_____/ /_/  \____/

  Security Event Traffic Creator
  [ exploit . capture . detect ]
"""


logger = logging.getLogger(__name__)


class _ColorFormatter(logging.Formatter):
    COLORS = {
        logging.DEBUG:    "\033[36m🔍 DEBUG\033[0m",    # cyan
        logging.INFO:     "\033[32m✅ INFO\033[0m",      # green
        logging.WARNING:  "\033[33m⚠️  WARN\033[0m",     # yellow
        logging.ERROR:    "\033[31m❌ ERROR\033[0m",     # red
        logging.CRITICAL: "\033[1;31m💀 CRIT\033[0m",   # bold red
    }

    def format(self, record):
        label = self.COLORS.get(record.levelno, record.levelname)
        ts = self.formatTime(record, self.datefmt)
        return f"\033[2m{ts}\033[0m {label}  {record.getMessage()}"


def main():
    args, config = parse_args()

    handler = logging.StreamHandler()
    handler.setFormatter(_ColorFormatter())
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        handlers=[handler],
    )
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("docker").setLevel(logging.WARNING)

    print(BANNER)

    # framework setup
    try:
        client = docker.from_env(timeout=300)
    except docker.errors.DockerException as e:
        logger.error("Failed to connect to Docker. Is Docker running?")
        logger.error("Error: %s", e)
        return

    zeek = None
    splunk = None

    try:
        ########################################
        ###        PRE UP Core Runners       ###
        ########################################

        # Volume & Network cleanup
        if args.cleanup_network:
            logger.debug("Cleaning up old SETC networks")
            networks = [i.name for i in client.networks.list()]
            if args.network in networks:
                net = client.networks.get(args.network)
                net.remove()

        if args.cleanup_volume:
            logger.debug("Cleaning up old SETC volumes")
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
        if not args.no_zeek:
            zeek = ZeekModule(client)
            zeek.setup()
            for system_config in config:
                zeek.create_log_directories(system_config["name"])

        tp = None
        if zeek:
            tp = DockerProcessLogs(zeek.zeek)

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
            try:
                logger.info("Starting servers for: %s - %s",
                            system_config["name"],
                            system_config["settings"]["description"])
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
                #Note: Trying the pattern match passing a different way to cut down on class arguments
                if "exploit_success_pattern" in system_config["settings"]:
                    setc.exploit_success_pattern=system_config["settings"]["exploit_success_pattern"]

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
                if tp:
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
                if tp:
                    if setc_type == "docker":
                        tp.pre_down(setc.target, setc.target.name)
                    else:
                        #TODO: user docker client to pull the instance by name
                        target = client.containers.get(system_config["settings"]["target_name"])
                        tp.pre_down(target, system_config["name"])


                if not args.no_zeek:
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
                    logger.info("Creating Splunk indexes and parsing data")
                    splunk.post_setup()

            except Exception as e:
                logger.error("Error processing system %s: %s", system_config['name'], e)
                logger.warning("Continuing to next system...")
                try:
                    if setc:
                        setc.cleanup_all()
                except Exception:
                    pass

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

    finally:
        if zeek:
            zeek.cleanup()
        if splunk:
            splunk.cleanup()


if __name__ == "__main__":
    main()
