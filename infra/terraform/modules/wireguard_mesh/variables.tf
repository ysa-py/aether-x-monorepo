variable "nodes" {
  type = list(object({
    name    = string
    wg_ip   = string
    wg_port = number
  }))
  description = "List of mesh nodes with WG IPs and ports."
}

variable "output_dir" {
  type        = string
  default     = "./wg-configs"
  description = "Directory to write generated WG config files."
}
