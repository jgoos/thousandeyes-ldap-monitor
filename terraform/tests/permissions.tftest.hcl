# Role and monitoring user (permissions.tf), against a mocked provider. Runs that check values
# the API computes (IDs) use command = apply, which the mock provider fills in without an account.
mock_provider "thousandeyes" {
  mock_resource "thousandeyes_account_group" {
    defaults = {
      aid = "7001"
    }
  }
  mock_resource "thousandeyes_role" {
    defaults = {
      role_id = "8001"
    }
  }
}

variables {
  te_api_token   = "mock-token"
  agent_ids      = ["1001"]
  credential_ids = ["2001", "2002"]
  # The account group the tests live in; the module-created group gets aid 7001 from the mock.
  account_group_id = "6001"
}

run "no_monitoring_user_creates_no_role_or_user" {
  command = plan

  assert {
    condition     = length(thousandeyes_role.monitoring_config_admin) == 0 && length(thousandeyes_user.monitoring) == 0
    error_message = "Without monitoring_user there should be no role and no user."
  }
  assert {
    condition     = length(data.thousandeyes_permission.monitoring) == 0
    error_message = "Without monitoring_user no permission should be looked up (GET /v7/permissions needs a management permission)."
  }
}

run "create_monitoring_role_true_creates_the_role_without_a_user" {
  command = plan

  variables {
    create_monitoring_role = true
  }

  assert {
    condition     = length(thousandeyes_role.monitoring_config_admin) == 1 && length(thousandeyes_user.monitoring) == 0
    error_message = "create_monitoring_role = true should create the role, and no user."
  }
  assert {
    condition     = length(thousandeyes_role.monitoring_config_admin[0].permissions) == length(var.monitoring_role_permissions)
    error_message = "The role should get every resolved permission ID."
  }
}

run "create_monitoring_role_false_creates_no_role" {
  command = plan

  variables {
    create_monitoring_role = false
  }

  assert {
    condition     = length(thousandeyes_role.monitoring_config_admin) == 0 && length(data.thousandeyes_permission.monitoring) == 0
    error_message = "create_monitoring_role = false should create no role and look up no permission."
  }
}

run "create_monitoring_role_false_rejects_a_monitoring_user" {
  command = plan

  variables {
    create_monitoring_role = false
    monitoring_user        = { email = "svc-ldap-monitor@example.com" }
  }

  expect_failures = [thousandeyes_user.monitoring]
}

run "monitoring_user_requires_account_group_id" {
  command = plan

  variables {
    account_group_id = null
    monitoring_user  = { email = "svc-ldap-monitor@example.com" }
  }

  expect_failures = [thousandeyes_user.monitoring]
}

run "role_takes_permission_ids_from_the_data_source" {
  command = plan

  variables {
    monitoring_user = { email = "svc-ldap-monitor@example.com" }
  }

  override_data {
    target = data.thousandeyes_permission.monitoring["View tests"]
    values = { permission_id = "101" }
  }
  override_data {
    target = data.thousandeyes_permission.monitoring["Edit tests and run instant tests"]
    values = { permission_id = "102" }
  }

  assert {
    condition     = tomap({ for label, permission in data.thousandeyes_permission.monitoring : label => permission.permission_name }) == var.monitoring_role_permissions
    error_message = "Each role permission should be looked up by its API name."
  }
  assert {
    condition     = toset(thousandeyes_role.monitoring_config_admin[0].permissions) == toset([for permission in data.thousandeyes_permission.monitoring : permission.permission_id])
    error_message = "The role should hold exactly the permission IDs the data source resolved."
  }
  assert {
    condition     = contains(thousandeyes_role.monitoring_config_admin[0].permissions, "101") && contains(thousandeyes_role.monitoring_config_admin[0].permissions, "102")
    error_message = "Resolved IDs should reach the role."
  }
  assert {
    condition     = length(setintersection(thousandeyes_role.monitoring_config_admin[0].permissions, toset(concat(keys(var.monitoring_role_permissions), values(var.monitoring_role_permissions))))) == 0
    error_message = "The role should hold IDs, not labels or names."
  }
}

run "default_role_is_least_privilege" {
  command = plan

  variables {
    monitoring_user = { email = "svc-ldap-monitor@example.com" }
  }

  assert {
    condition = toset(keys(var.monitoring_role_permissions)) == toset([
      "API access",
      "View tests",
      "Edit tests and run instant tests",
      "Create web transaction tests",
      "View alert rules",
      "Edit alert rules",
      "View agents in account group",
    ])
    error_message = "The default role should hold only what this configuration needs (no templates, no management permissions)."
  }
  assert {
    condition     = length(thousandeyes_role.monitoring_config_admin[0].permissions) == length(var.monitoring_role_permissions)
    error_message = "Every permission should resolve to its own ID."
  }
}

run "monitoring_user_holds_the_role_in_the_tests_account_group" {
  command = apply

  variables {
    monitoring_user = { email = "svc-ldap-monitor@example.com", name = "LDAP monitoring" }
  }

  assert {
    condition     = thousandeyes_user.monitoring[0].email == "svc-ldap-monitor@example.com" && thousandeyes_user.monitoring[0].name == "LDAP monitoring"
    error_message = "The user should get the configured email and name."
  }
  assert {
    condition     = thousandeyes_user.monitoring[0].login_account_group_id == "6001"
    error_message = "The user should log in to account_group_id, where the tests live."
  }
  assert {
    condition = [for assignment in thousandeyes_user.monitoring[0].account_group_roles : {
      account_group_id = assignment.account_group_id
      role_ids         = assignment.role_ids
      }] == [{
      account_group_id = "6001"
      role_ids         = toset(["8001"])
    }]
    error_message = "The user's only assignment should be the role in account_group_id, not in the module-created group."
  }
  assert {
    condition     = output.monitoring_role_id == "8001" && output.monitoring_user_id == thousandeyes_user.monitoring[0].uid
    error_message = "Outputs should expose the role and user IDs."
  }
}

run "user_name_defaults_to_email" {
  command = plan

  variables {
    monitoring_user = { email = "svc-ldap-monitor@example.com" }
  }

  assert {
    condition     = thousandeyes_user.monitoring[0].name == "svc-ldap-monitor@example.com"
    error_message = "Without a name, the user should be named after its email address."
  }
}

run "rejects_labels_as_permission_names" {
  command = plan

  variables {
    monitoring_role_permissions = { "Edit tests and run instant tests" = "Edit tests and run instant tests" }
  }

  expect_failures = [var.monitoring_role_permissions]
}

run "rejects_an_invalid_monitoring_user_email" {
  command = plan

  variables {
    monitoring_user = { email = "svc-ldap-monitor" }
  }

  expect_failures = [var.monitoring_user]
}
