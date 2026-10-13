FROM redis:7.2.5

COPY redis.conf /usr/local/etc/redis/redis.conf

EXPOSE 6379

HEALTHCHECK --interval=30s --timeout=3s --retries=3 CMD true

CMD ["redis-server", "/usr/local/etc/redis/redis.conf"]
