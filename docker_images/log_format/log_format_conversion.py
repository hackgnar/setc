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
    # CIM
    cim_logs = []
    http_files = find_all("http.log", base_dir)
    for logfile in http_files:
        zeek_json = ""
        r = open(logfile, 'r')
        for line in r:
            zeek_json = json.loads(line)
            cim_log = zeek_to_cim(zeek_json)
            cim_logs.append(cim_log)
            print(zeek_json)
        r.close()
    w = open(os.path.join(output_dir, "http_cim.log"), 'w')
    json.dump(cim_logs, w)
    w.close()
