FROM ubuntu:24.04

RUN mkdir -p /data/logs && \
    apt-get update && \
    apt-get -y install python3 python3-urllib3 && \
    apt-get clean && rm -rf /var/lib/apt/lists/*
COPY log_format_conversion.py /opt/log_format_conversion.py

CMD [ "/data/zeek", "/data/logs" ]
ENTRYPOINT [ "/usr/bin/python3", "/opt/log_format_conversion.py" ]
