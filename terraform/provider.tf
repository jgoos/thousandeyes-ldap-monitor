terraform {
  # 1.7 or later (the removed block in permissions.tf). terraform test needs 1.11 or later
  # (mock_provider, and state_key in the upgrade tests).
  required_version = ">= 1.7.0"

  required_providers {
    thousandeyes = {
      source = "thousandeyes/thousandeyes"
      # Pinned exactly: 3.x minor and patch releases have removed attributes and values (3.2.0
      # dropped alert_type "web-transaction"). Upgrade on purpose, then run validate and test.
      version = "3.2.10"
    }
  }
}

provider "thousandeyes" {
  token = var.te_api_token
  # Null falls back to the TE_AID environment variable, then to the token owner's default group.
  account_group_id = var.account_group_id
}
