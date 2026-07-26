output "server_id" {
  value = hcloud_server.edge.id
}

output "ipv4_address" {
  value = hcloud_server.edge.ipv4_address
}

output "ipv6_address" {
  value = hcloud_server.edge.ipv6_address
}

output "wg_ip" {
  value = var.wg_ip
}

output "ssh_command" {
  value = "ssh root@${hcloud_server.edge.ipv4_address}"
}
