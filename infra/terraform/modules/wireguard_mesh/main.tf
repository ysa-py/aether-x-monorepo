terraform {
  required_providers {
    local = {
      source  = "hashicorp/local"
      version = "~> 2.5"
    }
  }
}

# Generates WireGuard config templates for each node. Private keys are NOT
# stored in Terraform state — they are generated on each node at first boot
# via `wg genkey`, preserving zero-trust separation.
resource "local_file" "wg_config" {
  for_each = { for n in var.nodes : n.name => n }
  content = templatefile("${path.module}/wg-node.conf.tpl", {
    node_name = each.value.name
    wg_ip     = each.value.wg_ip
    wg_port   = each.value.wg_port
    peers     = [for p in var.nodes : p if p.name != each.key]
  })
  filename        = "${var.output_dir}/${each.key}-wg0.conf"
  file_permission = "0600"
}
