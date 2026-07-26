output "config_files" {
  value = { for k, f in local_file.wg_config : k => f.filename }
}
