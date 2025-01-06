import json
import time
import urllib3
import os
import sys

base_dir=sys.argv[1]
output_dir=sys.argv[2]

cim_http_from_zeek = {
    "timestamp": lambda x: x.get("ts", time.time()),
    "action": lambda x: "http", # required
    "app": lambda x: None, 
    "bytes": lambda x: x.get("request_body_len", 0) + x.get("response_body_len", 0), # required
    "bytes_in": lambda x: x.get("request_body_len", 0), # required
    "bytes_out": lambda x: x.get("response_body_len", 0), # required
    "cached": lambda x: None,
    "category": lambda x: "-", # required
    "cookie": lambda x: x.get("cookie_vars", None),
    "dest": lambda x: x.get("id.resp_h", "-"), # required
    "dest_port": lambda x: x.get("id.resp_p", "-"), # required
    "duration": lambda x: None, 
    "http_content_type": lambda x: x.get("orig_mime_types", "-"), # recomended
    "http_method": lambda x: x.get("method", "-"), # recomended
    "http_referrer": lambda x: x.get("referrer", "-"), # recomended
    "http_referrer_domain": lambda x: urllib3.util.parse_url(x.get("referrer", "-")).host, # recomended
    "http_user_agent": lambda x: x.get("user_agent", "-"), # required
    "http_user_agent_length": lambda x: len(x.get("user_agent", "-")), # required
    "host":lambda x: x.get("host", "-"),
    "response_time": lambda x: None, 
    "site": lambda x: None, 
    "src": lambda x: x.get("id.orig_h", "-"), # required
    "status": lambda x: x.get("status_code", "-"), # required
    "uri_path": lambda x: urllib3.util.parse_url(x.get("uri", "-")).path, # recomended
    "uri_query": lambda x: urllib3.util.parse_url(x.get("uri", "-")).query, # recomended
    "url": lambda x: x.get("uri", "-"), # required
    "url_domain": lambda x: urllib3.util.parse_url(x.get("uri", "-")).host, # recomended
    "url_length": lambda x: len(x.get("uri", "-")), # required
    "user": lambda x: None, 
    "vendor_product": lambda x: None, 
    "error_code": lambda x: None, 
    "operation": lambda x: None, 
    "storage_name": lambda x: None 
}

def ocsf_activity_id(method):
    if method.lower() == "connect":
        return 1
    if method.lower() == "delete":
        return 2
    if method.lower() == "get":
        return 3
    if method.lower() == "head":
        return 4
    if method.lower() == "options":
        return 5
    if method.lower() == "post":
        return 6
    if method.lower() == "put":
        return 7
    if method.lower() == "trace":
        return 8
    if method.lower() == "other":
        return 99
    return 0
    

ocsf_http_from_zeek = {
    "activity": lambda x: x.get("method", "Unknown"),
    "activity_id": lambda x: ocsf_activity_id(x.get("method", "Unknown")), # Required
    "category_name": lambda x: "Network Activity",
    "category_uid": lambda x: "4", # Required
    "class_name": lambda x: "HTTP Activity", # Optional
    "class_uid": lambda x: "4002", # Required
    "time": lambda x: x.get("ts", time.time()),
    "http_request": {
        "http_method": lambda x: x.get("method", "Unknown"),
        "url": {
            "hostname": lambda x: urllib3.util.parse_url(x.get("uri", "-")).host,
            "path": lambda x: urllib3.util.parse_url(x.get("uri", "-")).path,
            "port": lambda x: x.get("id.resp_p", "-"),
            "scheme": lambda x: "http",
            "text": lambda x: x.get("uri", "-")
        },
        "user_agent": lambda x: x.get("user_agent", "-"),
        "version": lambda x: "HTTP/1.1"
    },
    "http_response": {
        "code": lambda x: x.get("status_code", "-")
    },
    "message": lambda x: "",
    "metadata": {
        "version": lambda x: "1.3.0",
        "product": {
            "vendor_name": lambda x: "Unknown"
        }
    },
    "severity": lambda x: "Informational",
    "severity_id": lambda x: "1",
    "src_endpoint": {
        "ip": lambda x: x.get("id.orig_h", "-"),
        "port": lambda x: x.get("id.orig_p", "-")
    },
    "start_time": lambda x: x.get("ts", time.time()),
    "type_uid": lambda x: "40020"+str(ocsf_activity_id(x.get("method", "Unknown"))), # Required
    "type_name": lambda x: "HTTP Activity: "+x.get("method", "Unknown")
}

def zeek_to_ocsf(log, schema=ocsf_http_from_zeek):
    ocsf_log = {}
    for field_name, mapping in schema.items():
        if type(mapping) == dict:
            ocsf_value = zeek_to_ocsf(log, schema=mapping)
        else:
            ocsf_value = mapping(log)
        if ocsf_value != None:
            ocsf_log[field_name] = ocsf_value
    return ocsf_log

ecs_http_from_zeek = {
    "@timestamp":lambda x: x.get("ts", time.time()),
    "ecs.version":lambda x:"8.17",
    "event.kind":lambda x:"event",
    "event.category":lambda x:"web",
    "event.type":lambda x:"protocol",
    "http.request.method":lambda x: x.get("method", "-"),
    "http.response.body.bytes":lambda x: x.get("response_body_len", "-"),
    "http.response.status_code":lambda x: x.get("status_code", "-"),
    "http.version":lambda x:"1.1",
    "http.hostname":lambda x: urllib3.util.parse_url(x.get("uri", "-")).host,
    "user_agent.original":lambda x: x.get("user_agent", "-"),
    "source.ip":lambda x: x.get("id.orig_h", "-"),
    "destination.ip":lambda x: x.get("id.resp_h", "-"),
    "url.path":lambda x: urllib3.util.parse_url(x.get("uri", "-")).path,
    "url.domain":lambda x: urllib3.util.parse_url(x.get("uri", "-")).host
}

# https://docs.splunk.com/Documentation/CIM/6.0.1/User/NetworkTraffic
cim_network_from_zeek = {
    "timestamp": lambda x: x.get("ts", time.time()),
    "action": lambda x: "allowed", 
    "app": lambda x: x.get("service", "-"), #Required
    "bytes": lambda x: x.get("orig_bytes", 0)+x.get("resp_bytes", 0),
    "bytes_in": lambda x: x.get("orig_bytes", 0),
    "bytes_out": lambda x: x.get("resp_bytes", 0),
    "dest": lambda x: x.get("id.resp_h", 0),
    "dest_ip": lambda x: x.get("id.resp_h", 0),
    "dest_port": lambda x: x.get("id.resp_p", 0),
    "packets": lambda x: x.get("orig_pkts", 0)+x.get("resp_pkts", 0),
    "packets_in": lambda x: x.get("orig_pkts", 0),
    "packets_out": lambda x: x.get("resp_pkts", 0),
    "src": lambda x: x.get("id.orig_h", 0),
    "src_ip": lambda x: x.get("id.orig_h", 0),
    "src_port": lambda x: x.get("id.orig_p", 0),
    "transport": lambda x: x.get("proto", "-")
}

#https://www.elastic.co/guide/en/ecs/current/ecs-network.html
#https://www.elastic.co/guide/en/ecs/current/ecs-source.html
#https://www.elastic.co/guide/en/ecs/current/ecs-destination.html
ecs_network_from_zeek = {
    "@timestamp": lambda x: x.get("ts", time.time()),
    "network.application": lambda x: x.get("service", "-"), #Required
    "network.bytes": lambda x: x.get("orig_bytes", 0)+x.get("resp_bytes", 0),
    "source.bytes": lambda x: x.get("orig_bytes", 0),
    "destination.bytes": lambda x: x.get("resp_bytes", 0),
    "destination.ip": lambda x: x.get("id.resp_h", 0),
    "destination.port": lambda x: x.get("id.resp_p", 0),
    "network.packets": lambda x: x.get("orig_pkts", 0)+x.get("resp_pkts", 0),
    "source.packets": lambda x: x.get("orig_pkts", 0),
    "destination.packets": lambda x: x.get("resp_pkts", 0),
    "source.ip": lambda x: x.get("id.orig_h", 0),
    "destination.ip": lambda x: x.get("id.orig_p", 0),
    "network.protocol": lambda x: x.get("proto", "-")
}

#https://schema.ocsf.io/1.3.0/classes/network_activity?extensions=
#interestingly there is now packets, bytes, protocol, direction, etc????
ocsf_network_from_zeek = {
  "time": lambda x: x.get("ts", time.time()), #Required
  "category_uid": lambda x: "4", #Required
  "category_name": lambda x: "Network Activity",
  "activity_id": lambda x: "6", #Required
  "type_uid": lambda x: "400106", #Required
  "type_name": lambda x: "Network Activity: Traffic",
  "class_uid": lambda x: "4001", #Required
  "class_name": lambda x: "Network Activity",
  "activity_name": lambda x: "Traffic",
  "severity_id": lambda x: "1", #Required
  "severity": lambda x: "Informational",
  "metadata": { #Required
    "version": lambda x: "1.3.0", #Required
    "product": { #Required
      "vendor_name": lambda x: "Unknown" #Required
    }
  },
  "dst_endpoint": { #Required
    "port": lambda x: x.get("id.resp_p", 0),
    "ip": lambda x: x.get("id.resp_h", 0)
  },
  "src_endpoint": { #Recomended
    "port": lambda x: x.get("id.orig_p", 0),
    "ip": lambda x: x.get("id.orig_h", 0)
  }
}

def zeek_to_network_ecs(log):
    ecs_log = {}
    for field_name, mapping in ecs_network_from_zeek.items():
        ecs_value = mapping(log)
        if ecs_value != None:
            ecs_log[field_name] = ecs_value
    return ecs_log

def zeek_to_network_ocsf(log, schema=ocsf_network_from_zeek):
    ocsf_log = {}
    for field_name, mapping in schema.items():
        if type(mapping) == dict:
            ocsf_value = zeek_to_network_ocsf(log, schema=mapping)
        else:
            ocsf_value = mapping(log)
        if ocsf_value != None:
            ocsf_log[field_name] = ocsf_value
    return ocsf_log

def zeek_to_network_cim(log):
    cim_log = {}
    for field_name, mapping in cim_network_from_zeek.items():
        cim_value = mapping(log)
        if cim_value != None:
            cim_log[field_name] = cim_value
    return cim_log

def zeek_to_ecs(log):
    ecs_log = {}
    for field_name, mapping in ecs_http_from_zeek.items():
        ecs_value = mapping(log)
        if ecs_value != None:
            ecs_log[field_name] = ecs_value
    return ecs_log


def find_all(name, path):
    result = []
    for root, dirs, files in os.walk(path):
        if name in files:
            result.append(os.path.join(root, name))
    return result

def zeek_to_cim(log):
    cim_log = {}
    for field_name, mapping in cim_http_from_zeek.items():
        cim_value = mapping(log)
        if cim_value != None:
            cim_log[field_name] = cim_value
    return cim_log

if __name__ == "__main__":
    # HTTP
    cim_logs = []
    ocsf_logs = []
    ecs_logs = []
    http_files = find_all("http.log", base_dir)
    for logfile in http_files:
        zeek_json = ""
        r = open(logfile, 'r')
        for line in r:
            zeek_json = json.loads(line)
            cim_log = zeek_to_cim(zeek_json)
            cim_logs.append(cim_log)
            ecs_log = zeek_to_ecs(zeek_json)
            ecs_logs.append(ecs_log)
            ocsf_log = zeek_to_ocsf(zeek_json)
            ocsf_logs.append(ocsf_log)
        r.close()
    w = open(os.path.join(output_dir, "cim_http.log"), 'w')
    json.dump(cim_logs, w)
    w.close()
    w = open(os.path.join(output_dir, "ecs_http.log"), 'w')
    json.dump(ecs_logs, w)
    w.close()
    w = open(os.path.join(output_dir, "ocsf_http.log"), 'w')
    json.dump(ocsf_logs, w)
    w.close()

    # Network
    cim_logs = []
    ocsf_logs = []
    ecs_logs = []
    net_files = find_all("conn.log", base_dir)
    for logfile in net_files:
        zeek_json = ""
        r = open(logfile, 'r')
        for line in r:
            zeek_json = json.loads(line)
            cim_log = zeek_to_network_cim(zeek_json)
            cim_logs.append(cim_log)
            ecs_log = zeek_to_network_ecs(zeek_json)
            ecs_logs.append(ecs_log)
            ocsf_log = zeek_to_network_ocsf(zeek_json)
            ocsf_logs.append(ocsf_log)
        r.close()
    w = open(os.path.join(output_dir, "cim_network.log"), 'w')
    json.dump(cim_logs, w)
    w.close()
    w = open(os.path.join(output_dir, "ecs_network.log"), 'w')
    json.dump(ecs_logs, w)
    w.close()
    w = open(os.path.join(output_dir, "ocsf_network.log"), 'w')
    json.dump(ocsf_logs, w)
    w.close()
