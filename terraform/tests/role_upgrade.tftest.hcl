# Upgrading a configuration whose role was created by an earlier version (no count): with
# create_monitoring_role = true the role stays, at index 0. Runs share state through state_key,
# which needs Terraform 1.11 or later.
mock_provider "thousandeyes" {
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
}

run "role_created_before_upgrade" {
  command   = apply
  state_key = "upgrade"

  module {
    source = "./tests/fixtures/role_before_upgrade"
  }

  # An ID a new role would not get (the mock default is 8001).
  override_resource {
    target = thousandeyes_role.monitoring_config_admin
    values = { role_id = "5001" }
  }
}

run "create_monitoring_role_true_keeps_the_existing_role" {
  command   = plan
  state_key = "upgrade"

  variables {
    create_monitoring_role = true
  }

  # The kept role has the ID from state (5001); a new one would get the mock default (8001).
  assert {
    condition     = thousandeyes_role.monitoring_config_admin[0].role_id == run.role_created_before_upgrade.role_id
    error_message = "The role created before the upgrade should stay (at index 0), not be replaced."
  }
}
