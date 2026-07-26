output "control_plane_ip" {
  value = module.control_plane.ipv4_address
}

output "edge_node_ips" {
  value = [for e in module.edge_nodes : e.ipv4_address]
}

output "ssh_control_plane" {
  value = module.control_plane.ssh_command
}

output "ssh_edge_nodes" {
  value = [for e in module.edge_nodes : e.ssh_command]
}

output "wireguard_configs" {
  value = module.wireguard_mesh.config_files
}

output "wg_topology" {
  value = {
    control_plane = "10.10.0.1/24"
    edge_nodes    = [for i in range(var.edge_count) : "10.10.0.${i + 2}/24"]
  }
}
