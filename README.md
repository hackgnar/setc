# SETC: Security Exploit Telemetry Collection

SETC automates vulnerability exploitation in Docker containers, captures network traffic and system telemetry, and converts logs to standard formats (CIM, OCSF, ECS). It produces repeatable, on-demand exploit telemetry for security research, tooling development, and dataset generation.

For the full research background, see the [arXiv preprint](https://arxiv.org/pdf/2406.05942), the published [IEEE CARS 2024 paper](https://ieeexplore.ieee.org/document/10778761), and the [doctoral dissertation](https://scholar.dsu.edu/theses/501/).

## Quickstart

```bash
# Clone and install
git clone https://github.com/your-org/setc.git
cd setc
pip install -r requirements.txt

# Build required system containers
cd docker_images/tcpdump && docker build -t tcpdump . && cd ../..
cd docker_images/log_format && docker build -t logformat . && cd ../..
docker pull metasploitframework/metasploit-framework:6.2.33

# Run a single-exploit example
python3 setc/setc.py example_configurations/docker_small.json --cleanup_volume --cleanup_network
```

## How It Works

```
Config JSON
  |
  v
1. Parse config entries (one per CVE / exploit)
  |
  v
2. Start target container(s) + tcpdump on a private Docker network
  |
  v
3. Launch Metasploit, run exploit, retry until success
  |
  v
4. Capture process tables (pre/post exploit)
  |
  v
5. Zeek parses captured PCAPs into structured logs
  |
  v
6. Convert logs to CIM, ECS, and OCSF formats
  |
  v
7. Output to Docker volume (and optionally Splunk)
```

## Configuration

Each config is a JSON array of exploit entries. SETC supports two target modes:

**Single container** -- provide a Docker image directly:
```json
[
    {
        "name": "CVE-2018-11776",
        "settings": {
            "description": "Struts2 OGNL injection RCE",
            "target_image": "vulhub/struts2:2.5.25",
            "exploit": "multi/http/struts2_multi_eval_ognl"
        }
    }
]
```

**Docker Compose** -- for multi-container targets (uses `$VULN_PATH` and `$SETC_PATH` env vars):
```json
[
    {
        "name": "CVE-2014-6271",
        "settings": {
            "description": "Apache CGI shellshock using user agent",
            "yml_file": "$VULN_PATH/bash/CVE-2014-6271/docker-compose.yml",
            "target_name": "setc-web-1",
            "exploit": "multi/http/apache_mod_cgi_bash_env_exec",
            "exploit_options": "set TARGETURI /victim.cgi;"
        }
    }
]
```

### Config fields

| Field | Required | Description |
|-------|----------|-------------|
| `name` | Yes | CVE or exploit identifier |
| `description` | Yes | Human-readable description |
| `exploit` | Yes | Metasploit module path |
| `target_image` | One of these | Docker image for single-container targets |
| `yml_file` + `target_name` | One of these | Docker Compose file + target container name |
| `exploit_options` | No | Additional MSF console commands (semicolon-separated) |
| `exploit_success_pattern` | No | Regex pattern to detect success (default: checks for port 4444) |
| `target_delay` | No | Seconds to wait after starting the target (default: 0) |
| `exploit_retries` | No | Retry count before giving up (default: 4) |
| `exploit_check_delay` | No | Seconds between status checks (default: 3) |
| `exploit_check_count` | No | Status checks per attempt (default: 7) |
| `ready_delay` | No | Seconds between readiness checks (default: 5) |
| `ready_retries` | No | Readiness checks before giving up (default: 5) |

See `setc_config_schema.json` for the full JSON Schema. Validate configs with:
```bash
check-jsonschema --schemafile setc_config_schema.json example_configurations/docker_small.json
```

## Output

SETC writes all telemetry to a Docker volume (`set_logs` by default). Each CVE gets its own directory:

```
set_logs/
  CVE-2018-11776/
    pcap/                     # Raw packet capture
    zeek/                     # Zeek-parsed logs (conn.log, http.log, ...)
    cim/
      cim_http.log            # Splunk CIM web format
      cim_network.log         # Splunk CIM network format
      cim_process_*.log       # CIM endpoint process logs
    ecs/
      ecs_http.log            # Elastic Common Schema
      ecs_network.log
      ecs_process_*.log
    ocsf/
      ocsf_http.log           # OCSF 1.4.0 HTTP Activity
      ocsf_network.log        # OCSF 1.4.0 Network Activity
      ocsf_process_*.log      # OCSF Process Query
```

## CLI Reference

```
usage: setc [-h] [-v] [-p PASSWORD] [--volume VOLUME] [--network NETWORK]
            [--msf MSF] [--prefix PREFIX] [--splunk] [--no-zeek]
            [--cleanup_network] [--cleanup_volume] [--cleanup_splunk]
            config
```

| Flag | Description |
|------|-------------|
| `config` | Path to a SETC configuration JSON file |
| `-v, --verbose` | Enable debug logging |
| `-p, --password` | SIEM password (default: `password1234`) |
| `--volume` | Docker volume name (default: `set_logs`) |
| `--network` | Docker network name (default: `set_framework_net`) |
| `--msf` | Override the Metasploit Docker image |
| `--prefix` | Session prefix for container names (auto-generated if omitted) |
| `--splunk` | Launch a Splunk instance and ingest logs |
| `--no-zeek` | Disable Zeek PCAP parsing |
| `--cleanup_network` | Delete the Docker network before running |
| `--cleanup_volume` | Delete the log volume before running |
| `--cleanup_splunk` | Remove Splunk container after completion |

### Example runs

```bash
# Single-container config
python3 setc/setc.py example_configurations/docker_small.json --cleanup_volume

# Docker Compose targets (set env vars first)
export VULN_PATH=/path/to/vulhub
export SETC_PATH=/path/to/setc
python3 setc/setc.py example_configurations/compose_small.json --cleanup_volume --cleanup_network

# With Splunk integration
python3 setc/setc.py example_configurations/docker_large.json --splunk --cleanup_volume
```

## Setup

### Prerequisites
- Python 3.10+
- Docker (native or Docker Desktop)

### System containers

These three containers are required for SETC to run:

```bash
# Network monitoring (tcpdump sidecar)
cd docker_images/tcpdump && docker build -t tcpdump .

# Log format conversion
cd docker_images/log_format && docker build -t logformat .

# Metasploit (pinned for Docker hostname resolution compatibility)
docker pull metasploitframework/metasploit-framework:6.2.33
```

### Sample target images

The example configs reference these vulnerable images. Build or pull whichever you need:

```bash
# Metasploitable2 (used by docker_large.json)
cd docker_images/metasploitable2 && docker build -t metasploitable2 .

# Apache HTTPD CVEs (used by docker_large.json)
cd docker_images/httpd/CVE-2021-41773 && docker build -t cve-2021-41773 .
cd docker_images/httpd/CVE-2021-42013 && docker build -t cve-2021-42013 .

# Vulhub images are pulled automatically by Docker
```

For Docker Compose configs, clone [vulhub](https://github.com/vulhub/vulhub) and set `VULN_PATH` to point to it.

## Development

```bash
pip install -r requirements-dev.txt

# Run unit tests (no Docker required)
python -m pytest tests/test_unit.py -v

# Run e2e tests (requires Docker and built images)
python -m pytest tests/test_e2e.py -v
```

Unit tests run automatically via GitHub Actions on pushes to `main`/`dev` and on pull requests.

## Demo

Note: This video shows an earlier version of SETC. The core workflow is the same but the CLI options have changed.

[![SETC Demo Video](https://img.youtube.com/vi/v09yiL_8USM/0.jpg)](https://www.youtube.com/watch?v=v09yiL_8USM)

## Citation

If you use SETC in your research, please cite:

**IEEE CARS 2024 paper:**
```bibtex
@INPROCEEDINGS{10778761,
  author={Holeman, Ryan and Hastings, John D. and Mathew Vaidyan, Varghese},
  booktitle={2024 Cyber Awareness and Research Symposium (CARS)},
  title={SETC: A Vulnerability Telemetry Collection Framework},
  year={2024},
  pages={1-7},
  doi={10.1109/CARS61786.2024.10778761}
}
```

**Dissertation:**
```bibtex
@phdthesis{holeman2024setc,
  author={Holeman, Ryan},
  title={SETC: A Vulnerability Telemetry Collection Framework},
  school={Dakota State University},
  year={2024},
  url={https://scholar.dsu.edu/theses/501/}
}
```
