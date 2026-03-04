import logging

import docker

logger = logging.getLogger(__name__)


def safe_stop_remove(container, label="container"):
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
