# ── Control Plane ───────────────────────────────────────────────────────────
module "control_plane" {
  source         = "../../modules/control_plane"
  name_prefix    = var.name_prefix
  ssh_keys       = var.ssh_keys
  control_image  = var.control_image
  jwt_secret     = var.jwt_secret
  clickhouse_dsn = var.clickhouse_dsn
  wg_ip          = "10.10.0.1/24"
  location       = var.location
  environment    = "prod"
}

# ── Edge Nodes ──────────────────────────────────────────────────────────────
module "edge_nodes" {
  count  = var.edge_count
  source = "../../modules/edge_node"

  name_prefix      = var.name_prefix
  index            = count.index
  ssh_keys         = var.ssh_keys
  supervisor_image = var.supervisor_image
  wg_ip            = "10.10.0.${count.index + 2}/24"
  location         = var.location
  environment      = "prod"
}

# ── WireGuard Mesh ──────────────────────────────────────────────────────────
module "wireguard_mesh" {
  source     = "../../modules/wireguard_mesh"
  output_dir = "./wg-configs"
  nodes = concat(
    [{ name = "control-plane", wg_ip = "10.10.0.1/24", wg_port = 51820 }],
    [for i in range(var.edge_count) : {
      name    = "${var.name_prefix}-edge-${format("%02d", i)}"
      wg_ip   = "10.10.0.${i + 2}/24"
      wg_port = 51820
    }]
  )
}
