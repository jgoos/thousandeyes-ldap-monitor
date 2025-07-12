terraform {
  required_providers {
    thousandeyes = {
      source  = "thousandeyes/thousandeyes"
      version = "~> 0.16.0"
    }
  }
}

provider "thousandeyes" {
  auth_token = var.te_api_token
}
