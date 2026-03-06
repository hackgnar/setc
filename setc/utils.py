from __future__ import annotations

import logging

import docker
import docker.models.containers

logger = logging.getLogger(__name__)


def prefixed_name(prefix: str, name: str) -> str:
    """Return '{prefix}-{name}' if a prefix is set, otherwise just name."""
    return f"{prefix}-{name}" if prefix else name


def safe_stop_remove(container: docker.models.containers.Container, label: str = "container") -> None:
    """Stop and remove a container, ignoring errors if already gone."""
    try:
        container.stop()
    except docker.errors.NotFound:
        pass
    except docker.errors.APIError as e:
        logger.warning("Failed to stop %s: %s", label, e)
    try:
        container.remove()
    except docker.errors.NotFound:
        pass
    except docker.errors.APIError as e:
        logger.warning("Failed to remove %s: %s", label, e)
