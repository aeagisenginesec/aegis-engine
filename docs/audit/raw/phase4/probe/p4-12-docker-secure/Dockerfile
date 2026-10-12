FROM ubuntu:24.04
RUN groupadd -r app && useradd -r -g app app
WORKDIR /app
COPY . /app
USER app
CMD ["./app"]
