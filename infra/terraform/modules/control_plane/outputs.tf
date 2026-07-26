output "server_id" {
  value = hcloud_server.cp.id
}

output "ipv4_address" {
  value = hcloud_server.cp.ipv4_address
}

output "ipv6_address" {
  value = hcloud_server.cp.ipv6_address
}

output "wg_ip" {
  value = var.wg_ip
}

output "ssh_command" {
  value = "ssh root@${hcloud_server.cp.ipv4_address}"
}
