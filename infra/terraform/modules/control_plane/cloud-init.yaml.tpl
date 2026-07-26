#cloud-config
# Aether-X Control Plane — Go management + ClickHouse + WireGuard.

write_files:
  - path: /etc/systemd/system/aether-control.service
    content: |
      [Unit]
      Description=Aether-X Control Plane (Go Management)
      After=network-online.target docker.service
      Wants=network-online.target
      [Service]
      ExecStart=/usr/bin/docker run --rm --net=host \
        -e AETHER_HTTP_ADDR=0.0.0.0:8080 \
        -e AETHER_MTLS_ENABLED=true \
        -e AETHER_JWT_SECRET=${jwt_secret} \
        -e AETHER_CLICKHOUSE_DSN=${clickhouse_dsn} \
        ${control_image}
      Restart=always
      RestartSec=5
      [Install]
      WantedBy=multi-user.target

  - path: /opt/aether/docker-compose.yml
    content: |
      services:
        clickhouse:
          image: clickhouse/clickhouse-server:24.3
          mem_limit: 2g
          ports: ["8123:8123", "9000:9000"]
          volumes: ["chdata:/var/lib/clickhouse"]
          environment:
            CLICKHOUSE_USER: aether
            CLICKHOUSE_PASSWORD: changeme
            CLICKHOUSE_DB: aether
      volumes:
        chdata:

runcmd:
  - apt-get update
  - apt-get install -y docker.io docker-compose-v2 wireguard
  - systemctl enable --now docker
  - cd /opt/aether && docker compose up -d
  - systemctl daemon-reload
  - systemctl enable --now aether-control
  - ufw allow 8080/tcp
  - ufw allow 22/tcp
  - ufw allow ${wg_port}/udp
