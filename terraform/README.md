# ThousandEyes LDAP Monitoring Terraform Module

This directory contains Terraform configuration that automates LDAP monitoring with ThousandEyes. It deploys one transaction test per LDAP server, running `ldap-monitor.js`, with an alert rule for failed or timed-out runs. It also creates a role and an account group for monitoring administration.

Each test's URL is an LDAP URL (RFC 4516), such as `ldaps://dc1.example.com:636/` or `ldaps://dc1.example.com:3269/DC=example,DC=com`. The script reads its target from the URL, so every test monitors its own server.

## Prerequisites

- [Terraform](https://www.terraform.io/) 1.7 or later (`terraform test` uses provider mocking).
- Access to a ThousandEyes account.
- An API token from an `Organization Admin`, for every plan and apply. The configuration manages an account group (and, with `monitoring_user`, a role and a user), which needs more than `Account Admin`. See [Monitoring user and role](#monitoring-user-and-role).
- The script's credentials, created in the ThousandEyes UI or API (`Settings ▸ Secure Credentials`): `ldapMonUser`, `ldapMonPass`, and any optional ones you use (`ldapCaBase64`, `ldapAllowCleartext`, ...). Terraform attaches them to the tests by ID only, so their values never enter Terraform state. List their IDs with `GET /v7/credentials`.

## Configuration

Create a `terraform.tfvars` file in this directory:

```hcl
te_api_token = "<your-api-token>"

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
| `base_dn` | `""` (Root DSE) | Spaces, `/`, `?` and `#` are percent-encoded in the URL. The URL always ends in `/` plus the DN, so an empty `base_dn` searches the Root DSE even when an `ldapBaseDN` credential is attached |

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

## Monitoring user and role

The configuration always creates the `ThousandEyes Monitoring Config` account group. Set `monitoring_user` to also create a `Monitoring Administrator` role and a user who holds it in that account group (`permissions.tf`):

```hcl
monitoring_user = {
  email = "svc-ldap-monitor@example.com" # a dedicated account
  name  = "LDAP monitoring"              # optional, defaults to the email address
}
```

Without `monitoring_user` there is no role, no user and no permission lookup, and the `monitoring_role_id` and `monitoring_user_id` outputs are null. [MONITORING_GROUP_GUIDE.md](../docs/MONITORING_GROUP_GUIDE.md) describes the same setup in the ThousandEyes UI.

### Terraform owns the user

The provider has no resource that only adds a role to a user. `thousandeyes_user` creates the user (`POST /v7/users`, which emails the address a registration link) and owns it from then on:

- Its only role assignment is the role in the monitoring account group, which is also its login account group. The API replaces a user's role assignments as a whole, so the next apply removes any other assignment.
- `terraform destroy`, or setting `monitoring_user` back to null, deletes the user.

Use a dedicated account, never the token owner's or a person's: managing your own user would replace your Organization Admin assignments with this role. To manage an existing dedicated user rather than create one, import it before the first apply and read the plan:

```bash
terraform import 'thousandeyes_user.monitoring[0]' <uid> # uid from GET /v7/users
```

To keep the user when you stop managing it, run `terraform state rm 'thousandeyes_user.monitoring[0]'` before you clear `monitoring_user`.

`te_user_email` is gone; remove it from `terraform.tfvars`. It was documented as the token owner's address but nothing used it (the provider needs only the token), and reusing it for this user would have turned every existing configuration into one that manages its owner's account.

### Role permissions

The role takes permission IDs. `monitoring_role_permissions` maps each UI label to its API name (the `permission` field of `GET /v7/permissions`), and the `thousandeyes_permission` data source resolves each name to its ID. The default grants only what the LDAP tests and alert rules need:

| Permission (UI label) | API name (default) | Needed for |
|---|---|---|
| API access | `API_ACCESS` | Working through the API, as Terraform does |
| View tests | `SETTINGS_TESTS_READ` | Reading the tests, and the credentials they attach (`GET /v7/credentials`) |
| Edit tests and run instant tests | `SETTINGS_TESTS_UPDATE` | Creating, changing and deleting tests, and attaching credentials and alert rules to them |
| Create web transaction tests | `SETTINGS_TESTS_CREATE_TX_TESTS` | The tests are transaction tests that run `ldap-monitor.js` |
| View alert rules | `SETTINGS_ALERTS_READ` | Reading the alert rules |
| Edit alert rules | `SETTINGS_ALERTS_UPDATE` | Creating, changing and deleting the alert rules |
| View agents in account group | `SETTINGS_AGENTS_READ` | Seeing the Enterprise Agents that `agent_ids` names |

Not granted: test templates (none are used), `View sensitive data in web transaction scripts` (Terraform attaches credentials by ID and never reads their values), and every management permission.

> **Check the API names.** ThousandEyes publishes the labels ([Built-in Roles and Permissions](https://docs.thousandeyes.com/product-documentation/user-management/rbac/built-in-roles-and-permissions)) but no list of names. `SETTINGS_TESTS_UPDATE` appears in its documentation; `SETTINGS_TESTS_READ` and `SETTINGS_TESTS_CREATE_TX_TESTS` are inferred from the Credentials API reference, and the other names from the same pattern. None has been checked against a live account. A wrong name stops `terraform plan` with `unable to locate any permission with the name` before anything changes. List the names in your account and set `monitoring_role_permissions` to match:
>
> ```bash
> curl -s -H "Authorization: Bearer $TE_API_TOKEN" https://api.thousandeyes.com/v7/permissions |
>   jq -r '.permissions[] | "\(.label)\t\(.permission)"' | sort
> ```

### Token and account group

Use an Organization Admin token for every plan and apply, not only the first. Creating the account group needs `Edit all account groups` and refreshing it needs `View all account groups settings`; creating and editing roles needs `Edit roles`; and `GET /v7/permissions` answers only to users with a management permission. A token from the monitoring user cannot run this configuration.

> **Limitation:** the provider creates the tests and alert rules in the token's current account group, not in `ThousandEyes Monitoring Config`. The role applies only in the monitoring account group, so the monitoring user does not see these tests until they live there.
