variable "hcloud_token" {
  type        = string
  sensitive   = true
  description = "Hetzner Cloud API token. NEVER commit — use TF_VAR_hcloud_token."
}

variable "name_prefix" {
  type        = string
  default     = "aether-x"
  description = "Resource name prefix."
}

variable "location" {
  type        = string
  default     = "nbg1"
  description = "Hetzner datacenter."
}

variable "ssh_keys" {
  type        = list(string)
  default     = ["aether-x-ssh"]
  description = "Hetzner SSH key names."
}

variable "edge_count" {
  type        = number
  default     = 2
  description = "Number of edge (data-plane) nodes."
}

variable "supervisor_image" {
  type        = string
  default     = "aetherx/core-supervisor:0.1.0"
  description = "Docker image for the Rust data plane."
}

variable "control_image" {
  type        = string
  default     = "aetherx/control-plane:0.1.0"
  description = "Docker image for the Go control plane."
}

variable "jwt_secret" {
  type        = string
  sensitive   = true
  description = "JWT signing secret for the control plane."
}

variable "clickhouse_dsn" {
  type        = string
  sensitive   = true
  default     = "clickhouse://aether:changeme@127.0.0.1:9000/aether"
  description = "ClickHouse DSN for telemetry persistence."
}
