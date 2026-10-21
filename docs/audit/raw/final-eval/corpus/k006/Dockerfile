FROM ubuntu:22.04

ADD https://example.com/releases/tool-v2.4.1.tar.gz /opt/
RUN tar -xzf /opt/tool-v2.4.1.tar.gz -C /opt/ \
    && rm /opt/tool-v2.4.1.tar.gz

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 9000

ENTRYPOINT ["/entrypoint.sh"]
