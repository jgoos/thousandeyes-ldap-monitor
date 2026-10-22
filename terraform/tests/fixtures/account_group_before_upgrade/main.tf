# The account group as earlier versions declared it, to give the upgrade test a prior state.
# Those versions also declared the role, but its labels-for-IDs bug should have made creating it
# fail; tests/role_upgrade.tftest.hcl covers a state that has the role.
terraform {
  required_providers {
    thousandeyes = {
      source = "thousandeyes/thousandeyes"
    }
  }
}

resource "thousandeyes_account_group" "monitoring_config" {
  account_group_name = "ThousandEyes Monitoring Config"
}
