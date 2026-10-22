terraform {
  # 1.9.3 or later: before 1.9.3, Terraform still reads (GET) an object that a removed block
  # forgets (hashicorp/terraform#35458), which a token without account group permissions fails.
  # terraform test needs 1.11 or later (mock_provider, and state_key in the upgrade tests).
  required_version = ">= 1.9.3"

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
