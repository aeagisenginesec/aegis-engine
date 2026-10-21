FROM alpine:3.20.2

RUN apk add --no-cache nginx \
    && mkdir -p /run/nginx /var/www/html

COPY nginx.conf /etc/nginx/nginx.conf
COPY html/ /var/www/html/

EXPOSE 80

HEALTHCHECK --interval=30s --timeout=3s \
    CMD wget -qO- http://localhost/ || exit 1

CMD ["nginx", "-g", "daemon off;"]
