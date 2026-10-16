terraform {
  required_version = ">= 1.5.0"

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
}
