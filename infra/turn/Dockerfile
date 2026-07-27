FROM coturn/coturn:4.6.3-r0

COPY entrypoint.sh /usr/local/bin/aether-turn-entrypoint
RUN chmod 0555 /usr/local/bin/aether-turn-entrypoint

ENTRYPOINT ["/usr/local/bin/aether-turn-entrypoint"]
