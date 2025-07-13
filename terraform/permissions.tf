resource "thousandeyes_role" "monitoring_config_admin" {
  name        = "Monitoring Administrator"
  permissions = [
    "View tests",
    "Edit tests and run instant tests",
    "View alert rules",
    "Edit alert rules",
    "View test templates",
    "Edit test templates",
    "View agents in account group"
  ]
}

resource "thousandeyes_account_group" "monitoring_config" {
  account_group_name = "ThousandEyes Monitoring Config"
  # Note: This group will be used to assign users with the Monitoring Administrator role
}
