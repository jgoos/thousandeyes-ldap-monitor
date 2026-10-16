**How to Set Up the Monitoring Account Group, Role and User**

### Introduction
The Terraform configuration in [`terraform/`](../terraform/README.md#monitoring-user-and-role) creates the `ThousandEyes Monitoring Config` account group and, when you set `monitoring_user`, a `Monitoring Administrator` role and a dedicated user who holds that role in the account group (`terraform/permissions.tf`). This guide describes the same setup in the ThousandEyes UI, for when you do not let Terraform manage the role and user.

ThousandEyes has no user groups. A user gets access by holding a role in an account group, and can hold a different role in each account group.

### Prerequisites
You need the **Organization Admin** role. Creating account groups (`Edit all account groups`) and roles (`Edit roles`) is not part of **Account Admin**.

---

### Part 1: Create the Account Group
Skip this part if you apply the Terraform configuration: it always creates this account group.

1. Go to **Manage > Account Settings > Users and Roles > Account Groups**.
2. Click **+ New Account Group**.
3. Name it `ThousandEyes Monitoring Config`.
4. Click **Add New Account Group**.

### Part 2: Create the Role
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

### Part 3: Add the Monitoring User
Use a dedicated account, not your own or a person's.

1. Go to **Manage > Account Settings > Users and Roles > Users**.
2. Click **+ New Users** and enter the account's email address.
3. Under **Account Group**, select `ThousandEyes Monitoring Config` and the role `Monitoring Administrator`. Add no other account groups.
4. Set **Login Account Group** to `ThousandEyes Monitoring Config`.
5. Click **Add New Users**. ThousandEyes emails the address a registration link.

### Next Steps
The monitoring user can now manage tests and alert rules in the `ThousandEyes Monitoring Config` account group. Terraform still needs an Organization Admin token, because it manages the account group (and, with `monitoring_user`, the role and the user).

The Terraform configuration creates its tests and alert rules in the token's current account group, not in `ThousandEyes Monitoring Config`, so the monitoring user does not see them until they live in that group.
