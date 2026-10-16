# ThousandEyes LDAP Monitoring Terraform Module

This directory contains Terraform configuration that automates LDAP monitoring with ThousandEyes. It deploys one transaction test per LDAP server, running `ldap-monitor.js`, with an alert rule for failed or timed-out runs. It also creates a role and an account group for monitoring administration.

Each test's URL is an LDAP URL (RFC 4516), such as `ldaps://dc1.example.com:636/` or `ldaps://dc1.example.com:3269/DC=example,DC=com`. The script reads its target from the URL, so every test monitors its own server.

## Prerequisites

- [Terraform](https://www.terraform.io/) 1.7 or later. `terraform test` needs 1.11 or later (provider mocking, and `state_key` in the upgrade tests).
- Access to a ThousandEyes account.
- An API token whose user holds, in the account group the tests live in, the seven test, alert rule and agent permissions listed under [Token](#token). The defaults need no `Organization Admin`. `monitoring_user` or `create_monitoring_role = true` does, for every plan and apply (see [Monitoring user and role](#monitoring-user-and-role)).
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

Set `monitoring_user` to create a `Monitoring Administrator` role and a dedicated user who holds it in the account group where the tests live (`permissions.tf`). `account_group_id` names that group and is then required:

```hcl
account_group_id = "1234" # the account group the LDAP tests live in
monitoring_user = {
  email = "svc-ldap-monitor@example.com" # a dedicated account
  name  = "LDAP monitoring"              # optional, defaults to the email address
}
```

Without `monitoring_user` there is no role, no user and no permission lookup, and the `monitoring_role_id` and `monitoring_user_id` outputs are null. `create_monitoring_role` overrides this for the role:

| `create_monitoring_role` | Role and permission lookups |
|---|---|
| `null` (default) | Only with `monitoring_user` |
| `true` | Always, for example to keep a role created before upgrading (see [Upgrading](#upgrading)) |
| `false` | Never; `monitoring_user` then fails the plan, because the user needs the role |

The default keeps the role opt-in: a wrong permission name stops `terraform plan` (see [Role permissions](#role-permissions)), and the role needs an Organization Admin token. Without the role and user, a token with only the monitoring permissions can run the configuration (see [Token](#token)). [MONITORING_GROUP_GUIDE.md](../docs/MONITORING_GROUP_GUIDE.md) describes the same setup in the ThousandEyes UI.

**Enable it in one workspace only.** Roles and users belong to the organization, not to a workspace or an account group. If you apply this configuration more than once, for example once per region, set `monitoring_user` or `create_monitoring_role` in one workspace and leave both unset in the others. Otherwise each workspace creates its own `Monitoring Administrator` role (a duplicate or a name conflict), and two workspaces cannot own the same user. The other workspaces then need no Organization Admin token. The managed user holds the role only in its own workspace's `account_group_id`. For workspaces in other account groups, assign the role to a different user in the UI (Part 2 of the guide). An assignment you add to the managed user does not last, because its next apply replaces the user's assignments.

### Account group

`account_group_id` also goes to the provider, so the tests and alert rules are managed in that group. Null (the default) leaves the provider as before: the `TE_AID` environment variable, or else the token owner's default account group. Look up IDs with `GET /v7/account-groups` (the `aid` field).

Set it to the group where the tests already live. The provider reads each test in the configured group. In another group the read returns 404, the provider takes the test as deleted, and the plan creates it again in the new group. The old tests keep running in the old group until you delete them by hand.

The configuration creates no account group. A group created in the same apply could not hold the tests: no test or alert rule resource takes an account group of its own, and the provider's `account_group_id` must be known when Terraform plans. Create the group first (UI or API), then set `account_group_id` to it.

### Terraform owns the user

The provider has no resource that only adds a role to a user. `thousandeyes_user` creates the user (`POST /v7/users`, which emails the address a registration link) and owns it from then on:

- Its only role assignment is the role in `account_group_id`, which is also its login account group. The API replaces a user's role assignments as a whole, so the next apply removes any other assignment.
- Destroying it deletes the user (`DELETE /v7/users/{id}`), an imported one included. `prevent_destroy` blocks that: `terraform destroy`, or setting `monitoring_user` back to null, stops with "Instance cannot be destroyed".

Use a dedicated account, never the token owner's or a person's: managing your own user would replace your Organization Admin assignments with this role. To manage an existing dedicated user rather than create one, import it before the first apply and read the plan:

```bash
terraform import 'thousandeyes_user.monitoring[0]' <uid> # uid from GET /v7/users
```

To stop managing the user, run `terraform state rm 'thousandeyes_user.monitoring[0]'` before you clear `monitoring_user` (the user stays in ThousandEyes). To let Terraform delete it, remove its `prevent_destroy` line first.

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

The role also has `prevent_destroy`: deleting it would revoke it from everyone who holds it, including users assigned by hand. To remove it on purpose, run `terraform state rm 'thousandeyes_role.monitoring_config_admin[0]'` (the role stays in ThousandEyes), or remove its `prevent_destroy` line first.

If you already made a `Monitoring Administrator` role by hand (an earlier version of the guide described one), import it rather than create a second role with the same name. The next apply replaces its permissions with this list, because the API replaces the whole list.

```bash
terraform import 'thousandeyes_role.monitoring_config_admin[0]' <roleId> # roleId from GET /v7/roles
```

### Token

The token a plan or apply needs depends on whether the configuration manages the role:

| Configuration | Token |
|---|---|
| Defaults: `monitoring_user` and `create_monitoring_role` unset | A user who holds the seven permissions in [Role permissions](#role-permissions) in the tests' account group, and nothing more. The monitoring user's own token qualifies |
| `monitoring_user`, or `create_monitoring_role = true` | An Organization Admin, for every plan and apply, not only the first |

With the defaults, Terraform manages only the tests and the alert rules, in the provider's account group (`account_group_id`, else `TE_AID`, else the token owner's default group). It makes no role, user, permission or account group call (`tests/permissions.tftest.hcl` and `tests/account_group_upgrade.tftest.hcl` check this). Give the token's user the role in that account group only.

The role and user need more. Creating and editing roles needs `Edit roles`, which `Account Admin` lacks, and `GET /v7/permissions`, which the role's permission lookups call, answers only to users with a management permission.

### Upgrading

- **Role.** Earlier versions always declared the role, with UI labels where the API expects permission IDs, so creating it should have failed. Check before your first plan with this version:

  ```bash
  terraform state list | grep thousandeyes_role
  ```

  If that lists `thousandeyes_role.monitoring_config_admin`, for example because you then assigned the role by hand, set `create_monitoring_role = true`. Terraform keeps the role and moves it to `thousandeyes_role.monitoring_config_admin[0]` by itself. It also replaces the role's permissions with the resolved IDs. With the defaults, the plan would delete the role; `prevent_destroy` stops it with "Instance cannot be destroyed" instead.
- **`te_user_email`** is deprecated and ignored, and a future release removes it. Delete it from `terraform.tfvars` and from any `-var` arguments. It was documented as the token owner's address, but nothing used it (the provider needs only the token). Reusing it for the monitoring user would have made every existing configuration manage its owner's account.
- **`account_group_id`** is new and optional. Leave it unset unless you set `monitoring_user`; then set it to the group the tests are in now (see [Account group](#account-group)).
- **Account group.** Earlier versions always created a `ThousandEyes Monitoring Config` account group, which nothing used. A `removed` block now makes Terraform forget it without deleting it. The plan says it "will no longer be managed by Terraform", and the apply drops it from state. Terraform neither reads nor deletes the group, so a token without account group permissions can apply the upgrade. Apply it once in every workspace that created a group. The `monitoring_group_id` output is gone. The group stays in ThousandEyes. If nothing else uses it, delete it by hand in the UI, or with `DELETE /v7/account-groups/{aid}` and an Organization Admin token. `GET /v7/account-groups/{aid}?expand=user,agent` lists its users and agents first.
