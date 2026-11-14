FROM caddy:2-alpine@sha256:eb4d35b7452d1ab6171fbdbe8d9275b2301dad6dad92115d91e19fb9b24d510f
# The official binary carries a low-port capability. This profile listens on
# high container ports, so remove it and run with no capabilities as a user.
RUN setcap -r /usr/bin/caddy && chown -R 10001:10001 /data /config
COPY deploy/Caddyfile /etc/caddy/Caddyfile
USER 10001:10001
CMD ["caddy", "run", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"]
