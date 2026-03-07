from __future__ import annotations

import logging

import docker
import docker.models.containers
from utils import prefixed_name

logger = logging.getLogger(__name__)


class SplunkModule:
    """Optional SIEM module that runs a Splunk container and indexes SETC logs."""

    def __init__(self, docker_client: docker.DockerClient, volume_name: str = "set_logs",
                 network_name: str = "set_framework_net", splunk_password: str = "password1234",
                 prefix: str = "") -> None:
        """Initialize Splunk module with Docker client and connection settings."""
        self.client=docker_client
        self.volume=volume_name
        self.network=network_name
        self.prefix=prefix
        self.splunk = None
        self.finished = "Ansible playbook complete, will begin streaming splunkd_stderr.log"
        self.password=splunk_password
        self.setup_complete=False

    def _prefixed(self, name: str) -> str:
        """Return the session-prefixed version of a container name."""
        return prefixed_name(self.prefix, name)

    def _find_existing(self) -> docker.models.containers.Container | None:
        """Find a running Splunk container already mounted to our volume."""
        for container in self.client.containers.list(all=True,
                                                      filters={"ancestor": "splunk/splunk:10.2.1"}):
            mounts = container.attrs.get("Mounts", [])
            for m in mounts:
                if m.get("Name") == self.volume:
                    if container.status != "running":
                        logger.info("Starting stopped Splunk container: %s", container.name)
                        container.start()
                    return container
        return None

    def setup(self) -> None:
        """Start a Splunk container, or reuse one already mounted to our volume."""
        existing = self._find_existing()
        if existing:
            logger.info("Reusing existing Splunk container: %s", existing.name)
            self.splunk = existing
            self.setup_complete = True
            return
        dk_splunk = self.client.containers.run("splunk/splunk:10.2.1", detach=True,
                                          name=self._prefixed("splunk"),
                                          volumes={self.volume:{'bind':'/data', 'mode':'rw'}},
                                          ports={'8000/tcp':8000}, tty=True,
                                          environment=["SPLUNK_START_ARGS=--accept-license",
                                                       "SPLUNK_GENERAL_TERMS=--accept-sgt-current-at-splunk-com",
                                                       "SPLUNK_PASSWORD={}".format(self.password)],
                                          platform="linux/amd64")
        self.splunk = dk_splunk

    def is_ready(self) -> bool:
        """Return True if the Splunk container has finished its startup playbook."""
        return self.finished in str(self.splunk.logs())

    def post_setup(self) -> None:
        """Create Splunk indexes (zeek, cim, ecs, ocsf) and add data monitors."""
        auth = f"admin:{self.password}"
        commands = [
            ["./bin/splunk", "add", "index", "zeek", "-auth", auth],
            ["./bin/splunk", "add", "index", "cim", "-auth", auth],
            ["./bin/splunk", "add", "index", "ecs", "-auth", auth],
            ["./bin/splunk", "add", "index", "ocsf", "-auth", auth],
            ["./bin/splunk", "add", "monitor", "/data/*/zeek/*", "-index", "zeek", "-auth", auth, "-sourcetype", "_json"],
            ["./bin/splunk", "add", "monitor", "/data/*/cim/*", "-index", "cim", "-auth", auth, "-sourcetype", "_json"],
            ["./bin/splunk", "add", "monitor", "/data/*/ocsf/*", "-index", "ocsf", "-auth", auth, "-sourcetype", "_json"],
            ["./bin/splunk", "add", "monitor", "/data/*/ecs/*", "-index", "ecs", "-auth", auth, "-sourcetype", "_json"],
            ["./bin/splunk", "add", "index", "cef", "-auth", auth],
            ["./bin/splunk", "add", "monitor", "/data/*/cef/*", "-index", "cef", "-auth", auth, "-sourcetype", "cef"],
            ["./bin/splunk", "add", "index", "udm", "-auth", auth],
            ["./bin/splunk", "add", "monitor", "/data/*/udm/*", "-index", "udm", "-auth", auth, "-sourcetype", "_json"],
            ["./bin/splunk", "add", "index", "falco", "-auth", auth],
            ["./bin/splunk", "add", "monitor", "/data/*/falco/*", "-index", "falco", "-auth", auth, "-sourcetype", "_json"],
        ]
        for cmd in commands:
            try:
                result = self.splunk.exec_run(cmd=cmd, user="splunk", tty=True, detach=False)
                if result.exit_code != 0:
                    logger.warning("Splunk command failed: %s", " ".join(cmd).split("-auth")[0].strip())
            except (docker.errors.NotFound, docker.errors.APIError) as e:
                logger.warning("Splunk exec failed: %s", e)
        self.setup_complete=True

    def cleanup(self, remove: bool = False) -> None:
        """Optionally stop and remove the Splunk container, or leave it running."""
        if self.splunk:
            if remove:
                try:
                    self.splunk.stop()
                    self.splunk.remove()
                    logger.info("Splunk container removed")
                except (docker.errors.NotFound, docker.errors.APIError) as e:
                    logger.warning("Could not remove Splunk container: %s", e)
            else:
                logger.info("Splunk available at http://localhost:8000 (user: admin)")
