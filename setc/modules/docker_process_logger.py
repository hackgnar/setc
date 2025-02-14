import json
import os
import time
import io
import tarfile
import shlex

#TODO: add hostnames to each log model
#TODO: add a pre/post exploit field to each log model

def parse_command(cmd):
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
	return (path, filename, abspath, args, fullcmd)

cim_endpoint_process = {
	"timestamp": lambda x: x.get("ts", time.time()), #required
	"action": lambda x: "allowed", #required
	"cpu_load_percent":lambda x: x.get("%CPU"),
	"dest":lambda x: "unknown", #required
	"mem_used":lambda x: x.get("%MEM"),
	"original_file_name": lambda x: parse_command(x.get("COMMAND"))[1],
	"parent_process":lambda x: "unknown", #required
	"parent_process_id":lambda x: x.get("PPID"), #required
	"parent_process_name":lambda x: "unknown", #required
	"parent_process_path":lambda x: "unknown", #required
	"process":lambda x: parse_command(x.get("COMMAND"))[4], #required
	"process_exec": lambda x: parse_command(x.get("COMMAND"))[2],
	"process_id": lambda x: x.get("PID"),
	"process_name": lambda x: parse_command(x.get("COMMAND"))[1],
	"process_path": lambda x: parse_command(x.get("COMMAND"))[0], #TODO
	"user": lambda x: x.get("USER"),
}

ecs_process = {
	"@timestamp":lambda x: x.get("ts", time.time()),
	"ecs.version":lambda x:"8.17",
	"event.kind":lambda x:"event",
	"event.category":lambda x:"process",
	"event.type":lambda x:"info",
	"process.args": lambda x: str(shlex.split(parse_command(x.get("COMMAND"))[4])), 
	"process.args_count":lambda x: len(shlex.split(parse_command(x.get("COMMAND"))[4])),
	"process.command_line": lambda x:parse_command(x.get("COMMAND"))[4],
	"process.executable": lambda x: parse_command(x.get("COMMAND"))[2],
	"process.interactive": lambda x: parse_command(x.get("COMMAND"))[2],
	"process.name": lambda x: parse_command(x.get("COMMAND"))[1],
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
		"name": lambda x: parse_command(x.get("COMMAND"))[1],
		"pid": lambda x: x.get("PID"),
		"session": {
			"terminal": lambda x: x.get("TT"),
		},
		"file": {
			"name": lambda x: parse_command(x.get("COMMAND"))[1],
			"type": lambda x: "process",
			"path": lambda x: parse_command(x.get("COMMAND"))[2],
			"type_id": lambda x: "99",
			"parent_folder": lambda x: parse_command(x.get("COMMAND"))[0],
		},
		"user": {
			"name": lambda x: x.get("USER")
		},
		"cmd_line": lambda x:parse_command(x.get("COMMAND"))[4],
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
	def __init__(self, write_container, volume_name="set_logs"):
		self.write_container=write_container
		self.read_container=None
		self.raw_logs = None
		self.docker_logs = None
		self.ocsf = None
		self.ecs=None
		self.cim=None

	def post_up(self, read_container):
		self.read_container=read_container
		self.get_process_logs(read_container)
		self.convert_to_cim()
		self.convert_to_ecs()
		self.convert_to_ocsf()
		self.write_to_volume("cim")
		self.write_to_volume("ecs")
		self.write_to_volume("ocsf")

	def pre_down(self, read_container):
		self.read_container=read_container
		self.get_process_logs(read_container)
		self.convert_to_cim()
		self.convert_to_ecs()
		self.convert_to_ocsf()
		self.write_to_volume("cim")
		self.write_to_volume("ecs")
		self.write_to_volume("ocsf")

	def get_process_logs(self, read_container):
		args = "o user,pid,ppid,pgid,sess,jobc,state,tt,time,etime,logname,%cpu,%mem,args"
		raw_logs = read_container.top(ps_args=args)
		self.raw_logs=raw_logs
		self.docker_logs=[dict(zip(raw_logs["Titles"],i)) for i in raw_logs["Processes"]]

	def __procs_docker_to_ocsf(self, log, schema=ocsf_process):
		flog = {}
		for k, v in schema.items():
			if type(v) == dict:
				ocsf_value = self.__procs_docker_to_ocsf(log, schema=v)
			else:
				ocsf_value = v(log)
			if ocsf_value != None:
				flog[k] = ocsf_value
		return flog

	def convert_to_ocsf(self):
		ocsf_logs = []
		for log in self.docker_logs:
			ocsf_logs.append(self.__procs_docker_to_ocsf(log))
		self.ocsf = ocsf_logs

	def convert_to_ecs(self):
		processes = []
		for log in self.docker_logs:
			flog = {}
			for k, v in ecs_process.items():
				ecs_value = v(log)
				if ecs_value != None:
					flog[k] = ecs_value
			processes.append(flog)
		self.ecs=processes

	def convert_to_cim(self):
		processes = []
		for log in self.docker_logs:
			flog = {}
			for k, v in cim_endpoint_process.items():
				cim_value = v(log)
				if cim_value != None:
					flog[k] = cim_value
			processes.append(flog)
		self.cim=processes

	def write_to_volume(self, log_type):
		tar_fileobj = io.BytesIO()	 
		with tarfile.open(fileobj=tar_fileobj, mode="w|") as tar:
			my_content = json.dumps(getattr(self,log_type)).encode('utf-8')
			tf = tarfile.TarInfo("%s_process_%s.log" % (log_type, str(time.time())))
			tf.size = len(my_content)
			tar.addfile(tf, io.BytesIO(my_content))  
		tar_fileobj.flush()
		tar_fileobj.seek(0)
		self.write_container.put_archive("/data/%s/%s" % (self.read_container.name, log_type), tar_fileobj)
