# ThousandEyes LDAP Monitoring Terraform Module

This directory contains Terraform configuration files that automate LDAP monitoring using ThousandEyes. The code creates a reusable transaction test template from `ldap-monitor.js`, sets up minimal permissions, and deploys individual tests with alerting for any number of LDAP servers.

## Prerequisites

- [Terraform](https://www.terraform.io/) installed.
- Access to a ThousandEyes account.
- **Initial setup requirement:** the API token used for the first `terraform apply` must belong to a user with permissions to create roles and groups (for example, a user with the `Account Admin` role).

## Configuration

Create a `terraform.tfvars` file in this directory and populate the required variables:

```hcl
te_api_token = "<your-api-token>"
te_user_email = "user@example.com"

ldap_servers = [
  {
    name     = "Primary LDAP Server (DC1)"
    hostname = "ldaps://dc1.example.com"
    port     = 636
  },
  {
    name     = "Secondary LDAP Server (DC2)"
    hostname = "ldaps://dc2.example.com"
    port     = 636
  }
]

agent_ids = ["123", "456"]
```

## Usage

Initialize and apply the configuration:

```bash
terraform init
terraform plan
terraform apply
```

## Post-Deployment Recommendation

Following the principle of least privilege, add your primary user or a dedicated service account to the newly created `ThousandEyes Monitoring Config` group after the initial deployment. Generate a new API token from that user and use it for future Terraform runs.
