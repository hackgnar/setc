from __future__ import annotations

import json
import logging
import time

import docker
import docker.models.containers
from psycopg2.extras import Json
from utils import prefixed_name

logger = logging.getLogger(__name__)

# Table definitions — keyed by table name, value is the SQL column type for the event column.
TABLES = {
    "zeek_logs": "event JSONB",
    "cim_logs": "event JSONB",
    "ecs_logs": "event JSONB",
    "ocsf_logs": "event JSONB",
    "cef_logs": "event TEXT",
    "udm_logs": "event JSONB",
    "falco_logs": "event JSONB",
}

# Maps format directory names (as written under /data/<cve>/) to (table_name, is_json).
FORMAT_TABLE = {
    "zeek": ("zeek_logs", True),
    "cim": ("cim_logs", True),
    "ecs": ("ecs_logs", True),
    "ocsf": ("ocsf_logs", True),
    "cef": ("cef_logs", False),
    "udm": ("udm_logs", True),
    "falco": ("falco_logs", True),
}


class PostgresModule:
    """Optional SIEM module that runs a PostgreSQL container and indexes SETC logs."""

    def __init__(self, docker_client: docker.DockerClient, volume_name: str = "set_logs",
                 network_name: str = "set_framework_net", postgres_password: str = "password1234",
                 prefix: str = "") -> None:
        """Initialize Postgres module with Docker client and connection settings."""
        self.client = docker_client
        self.volume = volume_name
        self.network = network_name
        self.prefix = prefix
        self.password = postgres_password
        self.postgres = None
        self._conn = None
        self.setup_complete = False

    def _prefixed(self, name: str) -> str:
        """Return the session-prefixed version of a container name."""
        return prefixed_name(self.prefix, name)

    def _find_existing(self) -> docker.models.containers.Container | None:
        """Find a running postgres:17 container already mounted to our volume."""
        for container in self.client.containers.list(all=True,
                                                      filters={"ancestor": "postgres:17"}):
            mounts = container.attrs.get("Mounts", [])
            for m in mounts:
                if m.get("Name") == self.volume:
                    if container.status != "running":
                        logger.info("Starting stopped Postgres container: %s", container.name)
                        container.start()
                    return container
        return None

    def setup(self) -> None:
        """Start a Postgres container, or reuse one already mounted to our volume."""
        existing = self._find_existing()
        if existing:
            logger.info("Reusing existing Postgres container: %s", existing.name)
            self.postgres = existing
            self.setup_complete = True
            return
        self.postgres = self.client.containers.run(
            "postgres:17", detach=True,
            name=self._prefixed("postgres"),
            volumes={self.volume: {"bind": "/data", "mode": "ro"}},
            ports={"5432/tcp": 5432},
            environment=[
                "POSTGRES_USER=setc",
                f"POSTGRES_PASSWORD={self.password}",
                "POSTGRES_DB=setc",
            ],
            network=self.network,
        )

    def is_ready(self) -> bool:
        """Return True if the Postgres container is accepting connections."""
        if not self.postgres:
            return False
        try:
            result = self.postgres.exec_run(
                ["pg_isready", "-U", "setc", "-d", "setc"],
                demux=False,
            )
            return result.exit_code == 0
        except (docker.errors.NotFound, docker.errors.APIError):
            return False

    def _get_connection(self):
        """Return a psycopg2 connection, creating one lazily."""
        if self._conn is None or self._conn.closed:
            import psycopg2
            self._conn = psycopg2.connect(
                host="127.0.0.1", port=5432,
                user="setc", password=self.password, dbname="setc",
            )
            self._conn.autocommit = True
        return self._conn

    def post_setup(self) -> None:
        """Create tables for all log formats."""
        conn = self._get_connection()
        cur = conn.cursor()
        for table_name, event_col in TABLES.items():
            cur.execute(f"""
                CREATE TABLE IF NOT EXISTS {table_name} (
                    id SERIAL PRIMARY KEY,
                    cve_name TEXT NOT NULL,
                    log_type TEXT NOT NULL,
                    {event_col} NOT NULL,
                    created_at TIMESTAMPTZ DEFAULT NOW()
                );
            """)
        cur.close()
        self.setup_complete = True
        logger.info("PostgreSQL tables created")

    def ingest_logs(self, cve_name: str) -> None:
        """Read log files from the volume and INSERT rows into Postgres."""
        conn = self._get_connection()
        cur = conn.cursor()

        for fmt_dir, (table_name, is_json) in FORMAT_TABLE.items():
            # List files in /data/<cve_name>/<format>/
            base_path = f"/data/{cve_name}/{fmt_dir}"
            try:
                ls_result = self.postgres.exec_run(["ls", base_path], demux=False)
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
                    cat_result = self.postgres.exec_run(["cat", filepath], demux=False)
                    if cat_result.exit_code != 0:
                        continue
                    content = cat_result.output.decode()
                except (docker.errors.NotFound, docker.errors.APIError):
                    continue

                # Derive log_type from filename (e.g. "cim_http.log" → "http")
                log_type = filename.strip().rsplit(".", 1)[0]  # remove .log extension
                # Strip format prefix if present (e.g. "cim_http" → "http")
                for prefix in ("cim_", "ecs_", "ocsf_", "cef_", "udm_", "zeek_"):
                    if log_type.startswith(prefix):
                        log_type = log_type[len(prefix):]
                        break

                if is_json:
                    self._ingest_json(cur, table_name, cve_name, log_type, content)
                else:
                    self._ingest_text(cur, table_name, cve_name, log_type, content)

        cur.close()
        logger.info("PostgreSQL ingest complete for %s", cve_name)

    def _ingest_json(self, cur, table_name: str, cve_name: str, log_type: str,
                     content: str) -> None:
        """Parse JSON content and insert each event as a JSONB row."""
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            logger.debug("Skipping non-JSON content in %s", table_name)
            return
        events = data if isinstance(data, list) else [data]
        for event in events:
            cur.execute(
                f"INSERT INTO {table_name} (cve_name, log_type, event) VALUES (%s, %s, %s)",
                (cve_name, log_type, Json(event)),
            )

    def _ingest_text(self, cur, table_name: str, cve_name: str, log_type: str,
                     content: str) -> None:
        """Insert each non-empty line as a TEXT row (used for CEF)."""
        for line in content.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            cur.execute(
                f"INSERT INTO {table_name} (cve_name, log_type, event) VALUES (%s, %s, %s)",
                (cve_name, log_type, line),
            )

    def cleanup(self, remove: bool = False) -> None:
        """Optionally stop and remove the Postgres container, or leave it running."""
        if self._conn and not self._conn.closed:
            self._conn.close()
        if self.postgres:
            if remove:
                try:
                    self.postgres.stop()
                    self.postgres.remove()
                    logger.info("PostgreSQL container removed")
                except (docker.errors.NotFound, docker.errors.APIError) as e:
                    logger.warning("Could not remove PostgreSQL container: %s", e)
            else:
                logger.info("PostgreSQL available at localhost:5432 (user: setc, db: setc)")
