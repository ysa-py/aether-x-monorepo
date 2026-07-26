#cloud-config
# Aether-X Edge Node — kernel tuning + zero-trust firewall + core-supervisor.

write_files:
  - path: /etc/sysctl.d/99-aether-x.conf
    content: |
%{ for key, value in sysctl_config ~}      ${key} = ${value}
%{ endfor ~}

  - path: /etc/systemd/system/aether-supervisor.service
    content: |
      [Unit]
      Description=Aether-X Core Supervisor (Rust Data Plane)
      After=network-online.target docker.service
      Wants=network-online.target
      [Service]
      ExecStart=/usr/bin/docker run --rm --net=host --cap-add=NET_ADMIN \
        -e AETHER_SUPERVISOR_ADDR=0.0.0.0:7070 \
        -e AETHER_MTLS_ENABLED=true \
        ${supervisor_image}
      Restart=always
      RestartSec=5
      [Install]
      WantedBy=multi-user.target

runcmd:
  - sysctl --system
  - ufw --force reset
  - ufw default deny incoming
  - ufw default allow outgoing
  - ufw allow 22/tcp
  - ufw allow ${wg_port}/udp
%{ for port in proxy_ports ~}  - ufw allow ${port}/tcp
%{ endfor ~}  - ufw --force enable
  - apt-get update
  - apt-get install -y docker.io wireguard
  - systemctl enable --now docker
  - systemctl daemon-reload
  - systemctl enable --now aether-supervisor
