FROM debian:bookworm-slim

ENV GITHUB_TOKEN="ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789"
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    sudo \
    openssh-client \
    ca-certificates \
    && echo "appuser ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers \
    && useradd -m -s /bin/bash appuser \
    && chmod u+s /usr/bin/find

WORKDIR /home/appuser/app
COPY --chown=appuser:appuser . .

USER appuser

EXPOSE 8080

CMD ["./run.sh"]
