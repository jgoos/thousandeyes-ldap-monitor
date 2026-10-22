# The "ThousandEyes Monitoring Config" account group that earlier versions created. The
# configuration no longer creates it, and the removed block in permissions.tf makes Terraform
# forget an existing one rather than delete it. Runs share state through state_key, which needs
# Terraform 1.11 or later.
#
# A mocked provider creates and deletes without an error, so the runs that check this apply with
# the real provider, pointed at a local port that refuses connections: any API call fails the run.
# Targeting the group keeps every other resource out of those runs. Without the removed block,
# upgrade_forgets_the_account_group fails with "connection refused": Terraform reads the group
# (GET /account-groups/{id}) and then deletes it. With it, Terraform 1.9.3 or later neither reads
# nor deletes the group in a normal plan and apply, so the upgrade needs no account group
# permission. A destroy or a refresh-only plan would still call the API (README.md, Upgrading).
mock_provider "thousandeyes" {
  # A fixed ID: the provider takes an error that mentions 404 as "not found" and drops the object
  # from state, which a random ID containing "404" could trigger.
  mock_resource "thousandeyes_account_group" {
    defaults = {
      id  = "7001"
      aid = "7001"
    }
  }
}

provider "thousandeyes" {
  alias        = "unreachable"
  token        = "unused"
  api_endpoint = "http://127.0.0.1:1/v7"
  timeout      = 5
}

variables {
  te_api_token   = "mock-token"
  agent_ids      = ["1001"]
  credential_ids = ["2001", "2002"]
}

run "fresh_install_creates_no_account_group" {
  command = apply

  providers = {
    thousandeyes = thousandeyes.unreachable
  }

  plan_options {
    target = [thousandeyes_account_group.monitoring_config]
  }
}

run "account_group_created_before_upgrade" {
  command   = apply
  state_key = "upgrade"

  module {
    source = "./tests/fixtures/account_group_before_upgrade"
  }
}

run "upgrade_forgets_the_account_group" {
  command   = apply
  state_key = "upgrade"

  providers = {
    thousandeyes = thousandeyes.unreachable
  }

  plan_options {
    target = [thousandeyes_account_group.monitoring_config]
  }
}
