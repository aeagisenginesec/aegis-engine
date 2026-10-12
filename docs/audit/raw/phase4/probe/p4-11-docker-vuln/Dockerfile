FROM ubuntu
ENV DB_PASSWORD=placeholder-not-a-real-secret
ADD . /app
RUN apt-get update && apt-get install -y curl
CMD ["./app"]
