terraform {
  required_providers {
    hcloud = {
      source  = "hetznercloud/hcloud"
      version = "~> 1.45"
    }
  }
}

resource "hcloud_server" "cp" {
  name        = "${var.name_prefix}-control-plane"
  image       = var.image
  server_type = var.server_type
  location    = var.location
  ssh_keys    = var.ssh_keys
  user_data = templatefile("${path.module}/cloud-init.yaml.tpl", {
    control_image  = var.control_image
    clickhouse_dsn = var.clickhouse_dsn
    jwt_secret     = var.jwt_secret
    wg_port        = var.wg_port
    wg_ip          = var.wg_ip
  })
  labels = {
    role      = "control-plane"
    component = "go-control"
    env       = var.environment
  }
}
