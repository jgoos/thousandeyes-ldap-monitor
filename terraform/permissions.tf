# Access for a dedicated monitoring user: a least-privilege role, held in the monitoring account
# group by a user that Terraform creates. By default the role and its permission lookups exist
# only when monitoring_user is set: a role nobody holds grants nothing, creating one needs an
# Organization Admin token (Edit roles), and the lookups need a token that may call
# GET /v7/permissions. create_monitoring_role = true keeps the role without a monitoring_user.

locals {
  create_monitoring_role = coalesce(var.create_monitoring_role, var.monitoring_user != null)
}

resource "thousandeyes_account_group" "monitoring_config" {
  account_group_name = "ThousandEyes Monitoring Config"
}

# The role takes permission IDs. The provider finds each ID by the permission's API name (the
# "permission" field of GET /v7/permissions), not by its UI label.
data "thousandeyes_permission" "monitoring" {
  for_each = local.create_monitoring_role ? var.monitoring_role_permissions : tomap({})

  permission_name = each.value
}

resource "thousandeyes_role" "monitoring_config_admin" {
  count = local.create_monitoring_role ? 1 : 0

  name        = "Monitoring Administrator"
  permissions = [for permission in data.thousandeyes_permission.monitoring : permission.permission_id]
}

# Earlier versions created the role unconditionally. If yours exists, set
# create_monitoring_role = true before upgrading, or Terraform deletes it (README.md, Upgrading).
moved {
  from = thousandeyes_role.monitoring_config_admin
  to   = thousandeyes_role.monitoring_config_admin[0]
}

# Terraform creates and owns this user. The API replaces a user's role assignments as a whole, so
# this assignment becomes the user's only one, and destroy deletes the user. Use a dedicated
# account, never the token owner's or a person's (see README.md).
resource "thousandeyes_user" "monitoring" {
  count = var.monitoring_user == null ? 0 : 1

  name                   = coalesce(var.monitoring_user.name, var.monitoring_user.email)
  email                  = var.monitoring_user.email
  login_account_group_id = thousandeyes_account_group.monitoring_config.aid

  account_group_roles {
    account_group_id = thousandeyes_account_group.monitoring_config.aid
    role_ids         = thousandeyes_role.monitoring_config_admin[*].role_id
  }

  lifecycle {
    precondition {
      condition     = local.create_monitoring_role
      error_message = "monitoring_user holds the Monitoring Administrator role; leave create_monitoring_role null or set it to true."
    }
  }
}
