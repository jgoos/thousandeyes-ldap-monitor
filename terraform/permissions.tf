resource "thousandeyes_role" "monitoring_config_admin" {
  name        = "Monitoring Config Administrator"
  description = "Role for managing LDAP monitoring resources"
  permissions = [
    "Edit tests",
    "Edit alert rules",
    "Edit test templates",
    "View all agents"
  ]
}

resource "thousandeyes_group" "monitoring_config" {
  name  = "ThousandEyes Monitoring Config"
  roles = [thousandeyes_role.monitoring_config_admin.id]
}
