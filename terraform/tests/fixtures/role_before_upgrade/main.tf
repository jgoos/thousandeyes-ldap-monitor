# The role as earlier versions declared it (no count), to give the upgrade tests a prior state.
terraform {
  required_providers {
    thousandeyes = {
      source = "thousandeyes/thousandeyes"
    }
  }
}

resource "thousandeyes_role" "monitoring_config_admin" {
  name        = "Monitoring Administrator"
  permissions = ["101"]
}

output "role_id" {
  value = thousandeyes_role.monitoring_config_admin.role_id
}
