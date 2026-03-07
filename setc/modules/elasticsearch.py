from __future__ import annotations

import json
import logging
import time
import urllib.request
import urllib.error

import docker
import docker.models.containers
from utils import prefixed_name

logger = logging.getLogger(__name__)

# Maps format directory names (as written under /data/<cve>/) to (index_name, is_json).
INDEX_MAP = {
    "zeek": ("zeek", True),
    "cim":  ("cim",  True),
    "ecs":  ("ecs",  True),
    "ocsf": ("ocsf", True),
    "cef":  ("cef",  False),
    "udm":  ("udm",  True),
}


class ElasticsearchModule:
    """Optional SIEM module that runs an Elasticsearch container and indexes SETC logs."""

    def __init__(self, docker_client: docker.DockerClient, volume_name: str = "set_logs",
                 network_name: str = "set_framework_net", elasticsearch_password: str = "password1234",
                 prefix: str = "") -> None:
        """Initialize Elasticsearch module with Docker client and connection settings."""
        self.client = docker_client
        self.volume = volume_name
        self.network = network_name
        self.prefix = prefix
        self.password = elasticsearch_password
        self.es_container = None
        self.kibana_container = None
        self._es_client = None
        self.setup_complete = False
        self._data_views_created = False

    def _prefixed(self, name: str) -> str:
        """Return the session-prefixed version of a container name."""
        return prefixed_name(self.prefix, name)

    def _find_existing(self, image: str) -> docker.models.containers.Container | None:
        """Find a running container for *image* already attached to our network."""
        for container in self.client.containers.list(all=True,
                                                      filters={"ancestor": image}):
            mounts = container.attrs.get("Mounts", [])
            for m in mounts:
                if m.get("Name") == self.volume:
                    if container.status != "running":
                        logger.info("Starting stopped container: %s", container.name)
                        container.start()
                    return container
            # Kibana has no volume mount — match by network instead
            nets = container.attrs.get("NetworkSettings", {}).get("Networks", {})
            if self.network in nets:
                if container.status != "running":
                    logger.info("Starting stopped container: %s", container.name)
                    container.start()
                return container
        return None

    def setup(self) -> None:
        """Start Elasticsearch and Kibana containers, or reuse existing ones."""
        existing_es = self._find_existing("docker.elastic.co/elasticsearch/elasticsearch:9.0.0")
        if existing_es:
            logger.info("Reusing existing Elasticsearch container: %s", existing_es.name)
            self.es_container = existing_es
            self.setup_complete = True
        else:
            self.es_container = self.client.containers.run(
                "docker.elastic.co/elasticsearch/elasticsearch:9.0.0", detach=True,
                name=self._prefixed("elasticsearch"),
                volumes={self.volume: {"bind": "/data", "mode": "ro"}},
                ports={"9200/tcp": 9200},
                environment=[
                    "discovery.type=single-node",
                    "xpack.security.enabled=true",
                    f"ELASTIC_PASSWORD={self.password}",
                    "xpack.security.http.ssl.enabled=false",
                    "ES_JAVA_OPTS=-Xms512m -Xmx512m",
                ],
                network=self.network,
            )

        existing_kb = self._find_existing("docker.elastic.co/kibana/kibana:9.0.0")
        if existing_kb:
            logger.info("Reusing existing Kibana container: %s", existing_kb.name)
            self.kibana_container = existing_kb
        else:
            es_name = self.es_container.name
            self.kibana_container = self.client.containers.run(
                "docker.elastic.co/kibana/kibana:9.0.0", detach=True,
                name=self._prefixed("kibana"),
                ports={"5601/tcp": 5601},
                environment=[
                    f"ELASTICSEARCH_HOSTS=http://{es_name}:9200",
                    "ELASTICSEARCH_USERNAME=kibana_system",
                    f"ELASTICSEARCH_PASSWORD={self.password}",
                    "NODE_OPTIONS=--max-old-space-size=512",
                ],
                network=self.network,
            )

    def is_ready(self) -> bool:
        """Return True if the Elasticsearch container is accepting connections."""
        if not self.es_container:
            return False
        try:
            result = self.es_container.exec_run(
                ["curl", "-s", "-u", f"elastic:{self.password}", "http://localhost:9200/_cluster/health"],
                demux=False,
            )
            return result.exit_code == 0
        except (docker.errors.NotFound, docker.errors.APIError):
            return False

    def _get_client(self):
        """Return an Elasticsearch client, creating one lazily."""
        if self._es_client is None:
            from elasticsearch import Elasticsearch
            self._es_client = Elasticsearch(
                "http://127.0.0.1:9200",
                basic_auth=("elastic", self.password),
            )
        return self._es_client

    def post_setup(self) -> None:
        """Set up the kibana_system user password and create indices for all log formats."""
        # Set the kibana_system password so Kibana can authenticate to Elasticsearch
        self.es_container.exec_run([
            "curl", "-s", "-X", "POST",
            "-u", f"elastic:{self.password}",
            "-H", "Content-Type: application/json",
            f"http://localhost:9200/_security/user/kibana_system/_password",
            "-d", json.dumps({"password": self.password}),
        ])
        es = self._get_client()
        for index_name, _ in INDEX_MAP.values():
            es.indices.create(index=index_name, ignore=400)
        self.setup_complete = True
        logger.info("Elasticsearch indices created")

    def _create_kibana_data_views(self) -> None:
        """Create a Kibana data view for each index so logs are visible in Discover."""
        import base64
        auth = base64.b64encode(f"elastic:{self.password}".encode()).decode()
        headers = {
            "kbn-xsrf": "true",
            "Content-Type": "application/json",
            "Authorization": f"Basic {auth}",
        }
        for index_name, _ in INDEX_MAP.values():
            body = json.dumps({
                "data_view": {
                    "title": index_name,
                    "name": index_name,
                },
            }).encode()
            req = urllib.request.Request(
                "http://127.0.0.1:5601/api/data_views/data_view",
                data=body, headers=headers, method="POST",
            )
            try:
                urllib.request.urlopen(req)
                logger.debug("Created Kibana data view: %s", index_name)
            except urllib.error.HTTPError as e:
                if e.code == 409:
                    logger.debug("Kibana data view already exists: %s", index_name)
                else:
                    logger.warning("Failed to create Kibana data view %s: %s", index_name, e)

    def ingest_logs(self, cve_name: str) -> None:
        """Read log files from the volume and index them into Elasticsearch."""
        es = self._get_client()

        for fmt_dir, (index_name, is_json) in INDEX_MAP.items():
            # List files in /data/<cve_name>/<format>/
            base_path = f"/data/{cve_name}/{fmt_dir}"
            try:
                ls_result = self.es_container.exec_run(["ls", base_path], demux=False)
                if ls_result.exit_code != 0:
                    continue
                filenames = ls_result.output.decode().strip().split("\n")
            except (docker.errors.NotFound, docker.errors.APIError):
                continue

            for filename in filenames:
                if not filename.strip():
                    continue
                filepath = f"{base_path}/{filename.strip()}"
                try:
                    cat_result = self.es_container.exec_run(["cat", filepath], demux=False)
                    if cat_result.exit_code != 0:
                        continue
                    content = cat_result.output.decode()
                except (docker.errors.NotFound, docker.errors.APIError):
                    continue

                # Derive log_type from filename (e.g. "cim_http.log" -> "http")
                log_type = filename.strip().rsplit(".", 1)[0]  # remove .log extension
                # Strip format prefix if present (e.g. "cim_http" -> "http")
                for pfx in ("cim_", "ecs_", "ocsf_", "cef_", "udm_", "zeek_"):
                    if log_type.startswith(pfx):
                        log_type = log_type[len(pfx):]
                        break

                if is_json:
                    self._ingest_json(es, index_name, cve_name, log_type, content)
                else:
                    self._ingest_text(es, index_name, cve_name, log_type, content)

        logger.info("Elasticsearch ingest complete for %s", cve_name)

        if not self._data_views_created and self.kibana_container:
            self._create_kibana_data_views()
            self._data_views_created = True

    def _ingest_json(self, es, index_name: str, cve_name: str, log_type: str,
                     content: str) -> None:
        """Parse JSON content and bulk-index each event."""
        from elasticsearch import helpers
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            logger.debug("Skipping non-JSON content in %s", index_name)
            return
        events = data if isinstance(data, list) else [data]
        actions = []
        for event in events:
            doc = {"cve_name": cve_name, "log_type": log_type}
            doc.update(event)
            actions.append({"_index": index_name, "_source": doc})
        if actions:
            helpers.bulk(es, actions)

    def _ingest_text(self, es, index_name: str, cve_name: str, log_type: str,
                     content: str) -> None:
        """Index each non-empty line as a text event (used for CEF)."""
        from elasticsearch import helpers
        actions = []
        for line in content.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            actions.append({
                "_index": index_name,
                "_source": {"cve_name": cve_name, "log_type": log_type, "event": line},
            })
        if actions:
            helpers.bulk(es, actions)

    def cleanup(self, remove: bool = False) -> None:
        """Optionally stop and remove the Elasticsearch and Kibana containers, or leave them running."""
        if self._es_client:
            try:
                self._es_client.close()
            except Exception:
                pass
        for container, label in [(self.kibana_container, "Kibana"),
                                  (self.es_container, "Elasticsearch")]:
            if not container:
                continue
            if remove:
                try:
                    container.stop()
                    container.remove()
                    logger.info("%s container removed", label)
                except (docker.errors.NotFound, docker.errors.APIError) as e:
                    logger.warning("Could not remove %s container: %s", label, e)
        if not remove:
            if self.es_container:
                logger.info("Elasticsearch available at http://localhost:9200 (user: elastic)")
            if self.kibana_container:
                logger.info("Kibana available at http://localhost:5601 (user: elastic)")
