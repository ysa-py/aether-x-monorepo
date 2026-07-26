terraform {
  required_providers {
    hcloud = {
      source  = "hetznercloud/hcloud"
      version = "~> 1.45"
    }
  }
}

resource "hcloud_server" "edge" {
  name        = "${var.name_prefix}-edge-${format("%02d", var.index)}"
  image       = var.image
  server_type = var.server_type
  location    = var.location
  ssh_keys    = var.ssh_keys
  user_data = templatefile("${path.module}/cloud-init.yaml.tpl", {
    sysctl_config    = var.sysctl_config
    proxy_ports      = var.proxy_ports
    wg_port          = var.wg_port
    wg_ip            = var.wg_ip
    supervisor_image = var.supervisor_image
  })
  labels = {
    role      = "edge-node"
    component = "core-supervisor"
    env       = var.environment
  }
}
