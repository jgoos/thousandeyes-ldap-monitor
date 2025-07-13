terraform {
  required_providers {
    thousandeyes = {
      source  = "thousandeyes/thousandeyes"
      version = ">= 3.0.0"
    }
  }
}

provider "thousandeyes" {
  token = var.te_api_token
}
