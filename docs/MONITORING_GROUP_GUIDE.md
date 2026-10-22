**How to Set Up the Monitoring Role and User**

### Introduction
When you set `monitoring_user` (and `account_group_id`), the Terraform configuration in [`terraform/`](../terraform/README.md#monitoring-user-and-role) creates a `Monitoring Administrator` role. It also creates a dedicated user who holds that role in the account group where the LDAP tests live (`terraform/permissions.tf`). `create_monitoring_role = true` creates the role without a user. This guide describes the same setup in the ThousandEyes UI, for when you do not let Terraform manage the role and user. If Terraform already manages them, do not repeat these steps: a second role with the same name would be separate from Terraform's.

ThousandEyes has no user groups. A user gets access by holding a role in an account group, and can hold a different role in each account group.

### Prerequisites
You need the **Organization Admin** role, because creating roles (`Edit roles`) is not part of **Account Admin**. You also need the account group the LDAP tests live in: the one Terraform's `account_group_id` names, or else the default account group of the token Terraform runs with.

---

### Part 1: Create the Role
1. Go to **Manage > Account Settings > Users and Roles > Roles**.
2. Click **+ New Role** and name it `Monitoring Administrator`.
3. Grant exactly these permissions, and nothing else:
   * `API access` – To work through the API, as Terraform does.
   * `View tests` – To read the tests and the credentials they attach.
   * `Edit tests and run instant tests` – To create, change and delete tests, and to attach credentials and alert rules to them.
   * `Create web transaction tests` – The LDAP tests are transaction tests that run `ldap-monitor.js`.
   * `View alert rules` – To read the alert rules.
   * `Edit alert rules` – To create, change and delete the alert rules.
   * `View agents in account group` – To see the Enterprise Agents the tests run on.
4. Click **Save**.

The role grants no test templates (the configuration uses none), no `View sensitive data in web transaction scripts` (credentials are attached by ID; their values are never read) and no management permissions.

### Part 2: Add the Monitoring User
Use a dedicated account, not your own or a person's.

1. Go to **Manage > Account Settings > Users and Roles > Users**.
2. Click **+ New Users** and enter the account's email address.
3. Under **Account Group**, select the account group the LDAP tests live in, then the role `Monitoring Administrator`. Add no other account groups.
4. Set **Login Account Group** to that same account group.
5. Click **Add New Users**. ThousandEyes emails the address a registration link.

### Next Steps
The monitoring user can now manage the LDAP tests and alert rules in that account group. Its API token is also expected to be enough to run the Terraform configuration in that group, as long as `monitoring_user` and `create_monitoring_role` are unset there. This has not been checked against a live account. If the API rejects the provider's test expand options, also grant `View tags` and `View BGP monitors`. Confirm with a `terraform plan` and `terraform apply` using that token (see [Token](../terraform/README.md#token)). Creating the role and the user needs an Organization Admin. So does every plan and apply of a configuration in which Terraform manages them.

Set up the role once per organization, here or with Terraform in one workspace, even when you apply the configuration in several workspaces (for example one per region). Earlier versions of the configuration also created a `ThousandEyes Monitoring Config` account group in every workspace. Nothing used it, and the current version no longer manages it. Run one normal `terraform apply` after upgrading and before any `terraform destroy`, or run `terraform state rm thousandeyes_account_group.monitoring_config` first. Until then, a destroy still deletes the group, and a refresh-only plan still reads it. After that apply, you can delete the group by hand ([Upgrading](../terraform/README.md#upgrading)).
