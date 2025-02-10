# SETC: Security Exploit Telemetry Framework
The SETC framework enables automated, reproducible vulnerability exploitation data collection at scale. Currently, security researchers face three significant limitations when collecting vulnerability data:
* First, when data comes from real-world incidents or security competitions, it's not repeatable - if researchers need additional data points, there's no way to recreate the exact scenario.
* Second, researchers are restricted to events outside their control - they can't study specific vulnerabilities or attack techniques on demand.
* Finally, manual attack simulation is extremely time and resource-intensive, requiring significant setup and execution effort for each scenario.
SETC addresses these challenges through a novel framework architecture. More about the project can be found on the [arxiv pre-release paper](https://arxiv.org/pdf/2406.05942) here or in the official [IEEE paper being released at CARS](https://ieee-cars.org/).

## Overview
The SETC framework provides a means for recording deep security telemetry of attacks against vulnerable services. The framework achieves the collection of security telemetry by hosting and exploiting vulnerable services in a controlled container environment. Vulnerable services, exploits, and telemetry collection are modular and defined in framework configuration files.
 

The data produced by the framework aims to advance security research, security tooling, and security telemetry collection. Users can generate attack telemetry through a modular configuration system for various vulnerability classes, services, or time frames. The modular configuration system also allows users to share configuration files for collaboration and validation of research. The SET framework is a unique tool that produces high-caliber mass exploitation telemetry in controlled security environments.

## Current Capabilities
* Modular configurations
* Vulnerable instance hosting
* Vulnerability exploitation
* Network monitoring
* System log telemetry
* IDS parsing
* Logging pipeline
* Logging standard support for CIM & OCSF
* SIEM support

## How it Works
So how does it work under the hood? Upon initiating the framework, the core framework runner will parse and read a configuration file that dictates how a particular execution of the framework will behave. Each entry in the configuration file instructs what vulnerable service should be hosted and what exploit should be run against it. These groups of entries may define classes of vulnerabilities, vulnerabilities associated with specific software, or vulnerabilities from particular date ranges.

 
Once a configuration is parsed, the framework will initialize the vulnerable service instance containers in a private network. In parallel, the framework will also initiate the telemetry collection modules for each vulnerable instance. The collection modules are a mix of proxy container services and container sidecars with various security metric collection capabilities. Once the framework has validated vulnerable services and collection modules are fully running, the framework will transition into the exploitation phase.
 

At the start of each exploitation phase, the framework will create containers capable of running end-to-end exploits specific to a vulnerable instance. Once an exploit is initiated, the framework will monitor the exploit containers for signs of successful or failed exploitation. In the event of a failed exploit attempt, the framework will reinitiate an attack and repeat until a successful exploit is achieved. After completing an exploit, The framework will transition into a clean-up and telemetry collection phase.
 

During the telemetry collection phase, data is sent to a logging pipeline. The logging pipeline of the framework serves two core purposes. The first purpose is to function as a data transposition layer for log events in the logging pipeline. Telemetry files can be converted into various logging standard formats. These include standards such as OCSF, CIM, and UDM. After data transposition, the logging pipeline phase routes data to its final destination. These destinations are configurable and include sinks such as simple file storage or SIEM ingestion and analysis.

## Setup
The current Alpha verison of SETC uses python3 and Docker. Both applications are required to run the framework. Docker support works for both Docker native and Docker Desktop.

### Libraries
* Python Docker API - The core SETC framework dynamicly controls Docker instances though the [Python Docker API library](https://docker-py.readthedocs.io/en/stable/). Python Docker can be installed with pip `pip install docker`

### SETC System Containers

* Network Monitoring - This container is needed for network based monitoring of target and attack containers.  To install:
```
cd docker_images/tcpdump
docker build -t tcpdump .
```

* Log Standard Formatting - This container is currently used to transpose log formats to supported logging standards. This will be replace by Nifi in the upcoming SETC beta version.
```
cd docker_images/logformat
docker build -t logformat .
```

* Metasploit - SETC provides many deployment and configuration shortcut if attack exploits are deployed with Metasploit. Due to Docker host lookup compatability, make sure to install the correct version. Newer versions are unable to do Docker hostname resolution from within MSF console.
```
docker pull metasploitframework/metasploit-framework:6.2.33
```

### Optional Sample Containers
SETC provides sample configuration files with the following vulnerable Docker images. If you would like to use the included sample configuration files, you will have to install the following vulnerable Docker images.

* Metasploitable
```
cd docker_images/metasploitable2
docker build -t metasploitable2 .
```

* Vulhub JBoss
```
docker pull vulhub/jboss:as-6.1.0
```

* Vulhub Laravel
```
docker pull vulhub/laravel:8.4.2
```

* CVE-2021-41773
```
cd docker_images/http/CVE-2021-41773
docker build -t cve-2021-41773

```

* CVE-2021-42013
```
cd docker_images/http/CVE-2021-42013
docker build -t cve-2021-42013

```

## Usage
SETC is fairly straight forward to run. The only required argument is a configuration file. The following shows the current supported arguments for the framework:


```
% python3 setc.py --help
usage: setc.py [-h] [-p PASSWORD] [--volume VOLUME] [--network NETWORK] [--splunk] [--cleanup_network] [--cleanup_volume]
               [-v] [--zeek]
               config

positional arguments:
  config                The SETC configuration file to use. Example configuration files are provided in the projects
                        sample_configuration directory.

options:
  -h, --help            show this help message and exit
  -p PASSWORD, --password PASSWORD
                        The password to use for SIEM services. If not provided, a default password of password1234 will be
                        used
  --volume VOLUME       The Docker volume to use for storing and manulpulating SETC log files. If not provided, the volume
                        set_logs will be used
  --network NETWORK     The Docker network to be used for container network connections. If not provided, the network
                        set_framework_net will be used.
  --splunk              Create a Splunk instance and populate it with SETC logs. The Splunk instance will remain up by
                        default after the completion of a SETC run. The instance must be cleaned up manually.
  --cleanup_network     Delete the SETC docker network before running.
  --cleanup_volume      Delete the SETC docker log volume before running.
  -v, --verbose         Enable SETC debug logging.
  --zeek                SETC parses pcap logs with zeek by default. Use this flag to DISABLE zeek.
```

### SETC Demo Video
Note: The demo video uses SETC v1. 
[![SETC Demo Video](https://img.youtube.com/vi/v09yiL_8USM/0.jpg)](https://www.youtube.com/watch?v=v09yiL_8USM)

## Roadmap
SETC is currently considered an Alpha version of the project. While the alpha version is fully functional, many corners were cut to develop a working prototype rapidly. Completing the following roadmap features will make the project more usable, modular, and fit for community contribution.

| Feature    | Description |
| -------- | ------- |
| Conversion from Docker to Kubernetes | Ultimately, the project needs to be converted from a Docker engine to a Kubernetes engine to support advanced sidecar patterns and complex multi-system vulnerability systems. The completion of this milestone will transition the project into a beta version.|
| Endpoint agent support | Docker sidecar patterns do not support application monitoring. This needs to be added as a “docker in docker” design or the framework needs to support Kubernetes as a backend.|
| Nifi as the log pipeline | Due to time constrains Nifi was dropped as a log pipeline in the alpha release. Nifi is still planned to be included in later iterations of the project.|
| File audit telemetry | Docker sidecar patterns do not support file  monitoring. This needs to be added as a “docker in docker” design or the framework needs to support Kubernetes as a backend.|
| Modular IDS support | Zeek is currently the only supported IDS in the framework. It is also implemented in a very monolithic design.|
| Modular log standard conversion | Log file transposition is not currently configurable. All supported standards are created on each run.|
| Modular SIEM support | The framework currently only supports Splunk.|
| SIEM auto configuration | SIEM modules have no configuration stage. SIEMs are instantiated and data accessable to them, but configuration is a manual process during each run.|
| Run time parralelization | A configuration entity takes about 3 minutes to run from start to finish (start services, exploit, & cleanup). While this feature is not needed, it would make demos look really “cool”.|
| Scanning support | Scanning functionality on attack containers was not MVP for the alpha version. This could allow for auto exploit detection and other framework features.|
| Exploit validation checks	| Due to time constrains, exploit validation checks were removed from MVP. These are needed to validate an exploit completed without inspection of log telemetry.|
| Vulnerable server service health check | Currently, the framework just waits 1-2 minutes to make sure a service container has started. Having a validity check for service status would increase run speeds and reliability.|
| Support for docker-compose | Some vulnerable services require multiple containers. The current alpha version only supports vulnerable services contained in a single image.|
| HTTP proxy module | The current version derives HTTP logs from pcap files. Having HTTP proxy modules would allow for more standardized web events, fields, etc.|
|Consolidate telemetry and attack modules | To keep the design simple, telemetry and attack modules are duplicated for each configuration entity. Reusing containers would speed up runtime.| 
