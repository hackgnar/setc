FROM ubuntu

RUN mkdir -p /data/logs
RUN apt update
RUN apt -y install python3 python3-urllib3
COPY log_format_conversion.py /opt/log_format_conversion.py

CMD [ "/data/zeek", "/data/logs" ]
ENTRYPOINT [ "/usr/bin/python3", "/opt/log_format_conversion.py" ]
