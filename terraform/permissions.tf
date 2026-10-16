# Access for a dedicated monitoring user: a least-privilege role, held by a user that Terraform
# creates in the account group where the tests live (account_group_id). By default the role and
# its permission lookups exist only when monitoring_user is set: a role nobody holds grants
# nothing, creating one needs an Organization Admin token (Edit roles), and the lookups need a
# token that may call GET /v7/permissions. create_monitoring_role = true keeps the role without a
# monitoring_user. With neither, this file makes no API calls, so a token that may only manage
# tests and alert rules can run the configuration (README.md, Token).

locals {
  create_monitoring_role = coalesce(var.create_monitoring_role, var.monitoring_user != null)
}

# Earlier versions always created a "ThousandEyes Monitoring Config" account group that nothing
# used. It needed an Organization Admin token on every plan, and every workspace made its own.
# Terraform now forgets it without deleting it (README.md, Upgrading). A group made here could not
# hold the tests: no test or alert rule resource takes an account group, and the provider's
# account_group_id must be known when Terraform plans.
removed {
  from = thousandeyes_account_group.monitoring_config

  lifecycle {
    destroy = false
  }
}

# The role takes permission IDs. The provider finds each ID by the permission's API name (the
# "permission" field of GET /v7/permissions), not by its UI label.
data "thousandeyes_permission" "monitoring" {
  for_each = local.create_monitoring_role ? var.monitoring_role_permissions : tomap({})

  permission_name = each.value
}

# Earlier versions created this role without count. Terraform moves such a role to index 0 by
# itself; create_monitoring_role = true keeps it (README.md, Upgrading).
resource "thousandeyes_role" "monitoring_config_admin" {
  count = local.create_monitoring_role ? 1 : 0

  name        = "Monitoring Administrator"
  permissions = [for permission in data.thousandeyes_permission.monitoring : permission.permission_id]

  # Deleting the role revokes it from everyone who holds it, including users assigned by hand. To
  # remove it on purpose, run terraform state rm, or delete this block first.
  lifecycle {
    prevent_destroy = true
  }
}

# Terraform creates and owns this user. The API replaces a user's role assignments as a whole, so
# this assignment becomes the user's only one. Use a dedicated account, never the token owner's or
# a person's (see README.md).
resource "thousandeyes_user" "monitoring" {
  count = var.monitoring_user == null ? 0 : 1

  name                   = coalesce(var.monitoring_user.name, var.monitoring_user.email)
  email                  = var.monitoring_user.email
  login_account_group_id = var.account_group_id

  account_group_roles {
    account_group_id = var.account_group_id
    role_ids         = thousandeyes_role.monitoring_config_admin[*].role_id
  }

  lifecycle {
    # Destroying the resource deletes the user (DELETE /v7/users/{id}), an imported one included.
    # To stop managing it on purpose, run terraform state rm, or delete this line first.
    prevent_destroy = true

    precondition {
      condition     = local.create_monitoring_role
      error_message = "monitoring_user holds the Monitoring Administrator role; leave create_monitoring_role null or set it to true."
    }
    precondition {
      condition     = var.account_group_id != null
      error_message = "monitoring_user needs account_group_id: the ID of the account group where the LDAP tests live."
    }
  }
}
