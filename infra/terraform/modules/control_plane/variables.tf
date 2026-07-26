variable "name_prefix" {
  type = string
}

variable "image" {
  type    = string
  default = "ubuntu-2404"
}

variable "server_type" {
  type    = string
  default = "cpx31"
}

variable "location" {
  type    = string
  default = "nbg1"
}

variable "ssh_keys" {
  type = list(string)
}

variable "control_image" {
  type    = string
  default = "aetherx/control-plane:0.1.0"
}

variable "clickhouse_dsn" {
  type      = string
  sensitive = true
  default   = "clickhouse://aether:changeme@127.0.0.1:9000/aether"
}

variable "jwt_secret" {
  type      = string
  sensitive = true
}

variable "wg_port" {
  type    = number
  default = 51820
}

variable "wg_ip" {
  type = string
}

variable "environment" {
  type    = string
  default = "prod"
}
