FROM alpine

VOLUME  [ "/data" ]
RUN apk add --no-cache tcpdump coreutils

CMD [ "-C", "1000", "-W", "100", "-U", "-v", "-w", "/data/dump" ]
ENTRYPOINT [ "/usr/bin/tcpdump" ]
