# ThousandEyes LDAP Monitoring Terraform Module

This directory contains Terraform configuration that automates LDAP monitoring with ThousandEyes. It deploys one transaction test per LDAP server, running `ldap-monitor.js`, with an alert rule for failed or timed-out runs. It also creates a role and an account group for monitoring administration.

Each test's URL is an LDAP URL (RFC 4516), such as `ldaps://dc1.example.com:636/` or `ldaps://dc1.example.com:3269/DC=example,DC=com`. The script reads its target from the URL, so every test monitors its own server.

## Prerequisites

- [Terraform](https://www.terraform.io/) 1.5 or later.
- Access to a ThousandEyes account.
- **Initial setup requirement:** the API token used for the first `terraform apply` must belong to a user with permissions to create roles and groups (for example, a user with the `Account Admin` role).
- The script's credentials, created in the ThousandEyes UI or API (`Settings ▸ Secure Credentials`): `ldapMonUser`, `ldapMonPass`, and any optional ones you use (`ldapCaBase64`, `ldapAllowCleartext`, ...). Terraform attaches them to the tests by ID only, so their values never enter Terraform state. List their IDs with `GET /v7/credentials`.

## Configuration

Create a `terraform.tfvars` file in this directory:

```hcl
te_api_token  = "<your-api-token>"
te_user_email = "user@example.com"

ldap_servers = [
  {
    name     = "Primary LDAP Server (DC1)"
    hostname = "dc1.example.com" # host name or IP address only, no ldaps:// prefix
  },
  {
    name     = "Global Catalog (DC1)"
    hostname = "dc1.example.com"
    port     = 3269
    base_dn  = "DC=example,DC=com" # empty or omitted: search the Root DSE
  },
]

agent_ids      = ["123", "456"]
credential_ids = ["1001", "1002"] # ldapMonUser, ldapMonPass, plus optional credentials

# Optional
alert_email_recipients = ["ldap-oncall@example.com"]
# interval   = 300 # seconds: 60, 120, 300, 600, 900, 1800 or 3600
# time_limit = 30  # seconds, 5-180 and at most half the interval
```

| `ldap_servers` field | Default | Notes |
|---|---|---|
| `hostname` | (required) | Host name or IP address, without a scheme or port |
| `port` | 636 with TLS, 389 without | |
| `tls` | `true` | `false` uses plain LDAP. The script then refuses to bind unless the `ldapAllowCleartext` credential is in `credential_ids`, because a simple bind sends the password unencrypted |
| `base_dn` | `""` (Root DSE) | Spaces, `/`, `?` and `#` are percent-encoded in the URL |

The alert rule fires when a run completes with errors or times out (`txCompletionHasError`, `txCompletionTimedOut`). By default it needs 2 failing rounds out of 5. Change this with `alert_rounds_violating_required` and `alert_rounds_violating_out_of`. Tests collect console logs, so the script's PASS summary and failure messages are visible in the test views.

## Usage

```bash
terraform init
terraform plan
terraform apply
```

## Checks without a ThousandEyes account

`terraform test` plans the configuration against a mocked provider. It checks the test URLs, credentials, time limit, alert rule and input validation, and needs no API token. CI runs it with `terraform fmt -check` and `terraform validate`.

## Provider version

The provider is pinned to an exact version, and `.terraform.lock.hcl` records its checksums for Linux, macOS and Windows. Releases within 3.x have removed attributes and values; 3.2.0, for example, dropped the `web-transaction` alert type. To upgrade, change the version in `provider.tf`, then run `terraform init -upgrade`, `terraform validate` and `terraform test`, and commit the lock file.

## Post-Deployment Recommendation

Following the principle of least privilege, add your primary user or a dedicated service account to the newly created `ThousandEyes Monitoring Config` group after the initial deployment. Generate a new API token from that user and use it for future Terraform runs.

> **Known issue:** the role's `permissions` are given as UI labels. The provider expects permission IDs (see the `thousandeyes_permission` data source). Nothing assigns the role to the group, and `te_user_email` is not used yet. Until this is fixed, `apply` may fail on the role. This has not been verified against a live account.
