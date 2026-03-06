from __future__ import annotations

import json
import logging
import os
import time
import io
import tarfile
import shlex
from typing import Any, NamedTuple

import docker
import docker.models.containers

logger = logging.getLogger(__name__)

class ParsedCommand(NamedTuple):
	path: str
	filename: str
	abspath: str
	args: list[str]
	fullcmd: str

def apply_schema(log: dict[str, Any], schema: dict[str, Any]) -> dict[str, Any]:
	result = {}
	for field_name, mapping in schema.items():
		if isinstance(mapping, dict):
			value = apply_schema(log, mapping)
		else:
			value = mapping(log)
		if value is not None:
			result[field_name] = value
	return result

#TODO: add hostnames to each log model
#TODO: add a pre/post exploit field to each log model

def parse_command(cmd: str) -> ParsedCommand:
	tmp = shlex.split(cmd)
	abspath = ""
	if os.path.basename(tmp[0]) == "rosetta" or os.path.basename(tmp[0]) == "qemu-i386" :
		abspath = tmp[1]
		tmp = tmp[2:]
	else:
		abspath = os.path.abspath(tmp[0])
	filename = os.path.basename(abspath)
	path = os.path.dirname(abspath)
	args = tmp[1:-1]
	fullcmd = ' '.join(tmp)
	return ParsedCommand(path=path, filename=filename, abspath=abspath, args=args, fullcmd=fullcmd)

cim_endpoint_process = {
	"timestamp": lambda x: x.get("ts", time.time()), #required
	"action": lambda x: "allowed", #required
	"cpu_load_percent":lambda x: x.get("%CPU"),
	"dest":lambda x: "unknown", #required
	"mem_used":lambda x: x.get("%MEM"),
	"original_file_name": lambda x: parse_command(x.get("COMMAND")).filename,
	"parent_process":lambda x: "unknown", #required
	"parent_process_id":lambda x: x.get("PPID"), #required
	"parent_process_name":lambda x: "unknown", #required
	"parent_process_path":lambda x: "unknown", #required
	"process":lambda x: parse_command(x.get("COMMAND")).fullcmd, #required
	"process_exec": lambda x: parse_command(x.get("COMMAND")).abspath,
	"process_id": lambda x: x.get("PID"),
	"process_name": lambda x: parse_command(x.get("COMMAND")).filename,
	"process_path": lambda x: parse_command(x.get("COMMAND")).path, #TODO
	"user": lambda x: x.get("USER"),
}

ecs_process = {
	"@timestamp":lambda x: x.get("ts", time.time()),
	"ecs.version":lambda x:"8.17",
	"event.kind":lambda x:"event",
	"event.category":lambda x:"process",
	"event.type":lambda x:"info",
	"process.args": lambda x: str(shlex.split(parse_command(x.get("COMMAND")).fullcmd)),
	"process.args_count":lambda x: len(shlex.split(parse_command(x.get("COMMAND")).fullcmd)),
	"process.command_line": lambda x:parse_command(x.get("COMMAND")).fullcmd,
	"process.executable": lambda x: parse_command(x.get("COMMAND")).abspath,
	"process.interactive": lambda x: parse_command(x.get("COMMAND")).abspath,
	"process.name": lambda x: parse_command(x.get("COMMAND")).filename,
	"process.pgid": lambda x: x.get("PGID"),
	"process.pid": lambda x: x.get("PID"),
	"process.start": lambda x: x.get("TIME"),
	"process.tty": lambda x: x.get("TT"),
	"process.uptime": lambda x: x.get("ELAPSED"),
	"user": lambda x: x.get("USER"),
}

ocsf_process = {
	"time": lambda x: x.get("ts", time.time()),
	"activity_name": lambda x: "query",
	"activity_id": lambda x:"1",
	"category_uid": lambda x: "5",
	"category_name": lambda x: "Discovery",
	"class_uid": lambda x: "5015",
	"class_name": lambda x: "Process Query",
	"query_result": lambda x: "Exists",
	"query_result_id": lambda x: "1",
	"severity": lambda x: "Informational",
	"severity_id": lambda x: "1",
	"type_uid": lambda x: "501599",
	"type_name": lambda x: "Process Query: Other",	
	"process": {
		"name": lambda x: parse_command(x.get("COMMAND")).filename,
		"pid": lambda x: x.get("PID"),
		"session": {
			"terminal": lambda x: x.get("TT"),
		},
		"file": {
			"name": lambda x: parse_command(x.get("COMMAND")).filename,
			"type": lambda x: "process",
			"path": lambda x: parse_command(x.get("COMMAND")).abspath,
			"type_id": lambda x: "99",
			"parent_folder": lambda x: parse_command(x.get("COMMAND")).path,
		},
		"user": {
			"name": lambda x: x.get("USER")
		},
		"cmd_line": lambda x:parse_command(x.get("COMMAND")).fullcmd,
		"created_time":lambda x: x.get("TIME")
  },
  "metadata": {
	"version": lambda x: "1.4.0",
	"product": {
	  "name": lambda x: "docker process logs",
	},
  },
}

class DockerProcessLogs:
	def __init__(self, write_container: docker.models.containers.Container, volume_name: str = "set_logs") -> None:
		self.write_container=write_container
		self.read_container=None
		self.raw_logs = None
		self.docker_logs = None
		self.ocsf = None
		self.ecs=None
		self.cim=None

	def post_up(self, read_container: docker.models.containers.Container, vuln_name: str) -> None:
		self.read_container=read_container
		self.get_process_logs(read_container)
		self.convert_to_cim()
		self.convert_to_ecs()
		self.convert_to_ocsf()
		self.write_to_volume("cim", vuln_name)
		self.write_to_volume("ecs", vuln_name)
		self.write_to_volume("ocsf", vuln_name)

	def pre_down(self, read_container: docker.models.containers.Container, vuln_name: str) -> None:
		self.read_container=read_container
		self.get_process_logs(read_container)
		self.convert_to_cim()
		self.convert_to_ecs()
		self.convert_to_ocsf()
		self.write_to_volume("cim", vuln_name)
		self.write_to_volume("ecs", vuln_name)
		self.write_to_volume("ocsf", vuln_name)

	def get_process_logs(self, read_container: docker.models.containers.Container) -> None:
		args = "o user,pid,ppid,pgid,sess,jobc,state,tt,time,etime,logname,%cpu,%mem,args"
		try:
			raw_logs = read_container.top(ps_args=args)
		except (docker.errors.NotFound, docker.errors.APIError) as e:
			logger.warning("Could not get process logs: %s", e)
			self.raw_logs = None
			self.docker_logs = []
			return
		self.raw_logs=raw_logs
		self.docker_logs=[dict(zip(raw_logs["Titles"],i)) for i in raw_logs["Processes"]]

	def convert_to_ocsf(self) -> None:
		self.ocsf = [apply_schema(log, ocsf_process) for log in self.docker_logs]

	def convert_to_ecs(self) -> None:
		self.ecs = [apply_schema(log, ecs_process) for log in self.docker_logs]

	def convert_to_cim(self) -> None:
		self.cim = [apply_schema(log, cim_endpoint_process) for log in self.docker_logs]

	def write_to_volume(self, log_type: str, directory: str) -> None:
		tar_fileobj = io.BytesIO()
		with tarfile.open(fileobj=tar_fileobj, mode="w|") as tar:
			my_content = json.dumps(getattr(self,log_type)).encode('utf-8')
			tf = tarfile.TarInfo("%s_process_%s.log" % (log_type, str(time.time())))
			tf.size = len(my_content)
			tar.addfile(tf, io.BytesIO(my_content))
		tar_fileobj.flush()
		tar_fileobj.seek(0)
		try:
			self.write_container.put_archive("/data/%s/%s" % (directory, log_type), tar_fileobj)
		except (docker.errors.NotFound, docker.errors.APIError) as e:
			logger.warning("Failed to write %s logs to volume: %s", log_type, e)
