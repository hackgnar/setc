import docker


def safe_stop_remove(container, label="container"):
    """Stop and remove a container, ignoring errors if already gone."""
    try:
        container.stop()
    except docker.errors.NotFound:
        pass
    except docker.errors.APIError as e:
        print(f"[!] Warning: failed to stop {label}: {e}")
    try:
        container.remove()
    except docker.errors.NotFound:
        pass
    except docker.errors.APIError as e:
        print(f"[!] Warning: failed to remove {label}: {e}")
