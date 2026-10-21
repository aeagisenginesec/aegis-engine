# R4 project r4122
FROM ubuntu:22.04
RUN apt-get update && apt-get install -y sudo && echo "app ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
RUN useradd -m app
USER app
HEALTHCHECK --interval=30s CMD true
CMD ["bash"]
