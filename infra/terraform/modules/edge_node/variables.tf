variable "name_prefix" {
  type        = string
  description = "Name prefix for resources."
}

variable "index" {
  type        = number
  description = "Zero-based node index for unique naming."
}

variable "image" {
  type        = string
  default     = "ubuntu-2404"
  description = "Cloud image for the VPS."
}

variable "server_type" {
  type        = string
  default     = "cpx21"
  description = "Hetzner server type (vCPU + RAM)."
}

variable "location" {
  type        = string
  default     = "nbg1"
  description = "Datacenter location (nbg1 = Nuremberg, hel1 = Helsinki, ash = Ashburn)."
}

variable "ssh_keys" {
  type        = list(string)
  description = "Hetzner SSH key names to inject."
}

variable "proxy_ports" {
  type        = list(number)
  default     = [443, 8388, 8389]
  description = "Inbound TCP ports the proxy listens on."
}

variable "wg_port" {
  type        = number
  default     = 51820
  description = "WireGuard UDP port."
}

variable "wg_ip" {
  type        = string
  description = "WireGuard interface IP (e.g. 10.10.0.2/24)."
}

variable "supervisor_image" {
  type        = string
  default     = "aetherx/core-supervisor:0.1.0"
  description = "Docker image for the Rust data plane."
}

variable "environment" {
  type        = string
  default     = "prod"
  description = "Environment label."
}

variable "sysctl_config" {
  type = map(string)
  default = {
    "net.core.rmem_max"               = "134217728"
    "net.core.wmem_max"               = "134217728"
    "net.ipv4.tcp_rmem"               = "4096 87380 134217728"
    "net.ipv4.tcp_wmem"               = "4096 65536 134217728"
    "net.core.default_qdisc"          = "fq"
    "net.ipv4.tcp_congestion_control" = "bbr"
    "net.ipv4.icmp_ratelimit"         = "0"
    "net.ipv4.tcp_fastopen"           = "3"
    "net.ipv4.ip_local_port_range"    = "10000 65535"
  }
  description = "Kernel sysctl tuning for high-throughput networking."
}
