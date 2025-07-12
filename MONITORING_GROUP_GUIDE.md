**How to Create a ThousandEyes Group for Monitoring Configuration**

### Introduction
Creating a dedicated group for managing ThousandEyes monitoring is a best practice. It allows you to delegate the creation and configuration of tests and alert rules while adhering to the principle of least privilege. By isolating these permissions in a group, you keep account administration organized and secure. This guide walks you through the steps to set up that group, which is necessary before assigning users or service accounts to manage monitoring.

### Prerequisites
You must have a role with permissions to manage users and roles (for example, the **Account Admin** role).

---

### Part 1: Create a New Role with Required Permissions
1. Navigate to **Account Settings** > **Users & Roles**, then select the **Roles** tab.
2. Click **Add New Role**.
3. Name the role something descriptive, such as `Monitoring Administrator`.
4. Grant these permissions (each with its purpose):
   * `View tests` – To see existing tests.
   * `Edit tests` – To create, edit, and delete tests (monitors).
   * `View alert rules` – To see existing alert rules.
   * `Edit alert rules` – To create, edit, and delete alert rules.
   * `View test templates` – To view available test templates.
   * `Edit test templates` – To create and manage new test templates.
   * `View all agents` – To assign Cloud and Enterprise agents to tests.
5. Save the new role.

### Part 2: Create a New Group and Assign the Role
1. Staying in **Users & Roles**, switch to the **Groups** tab.
2. Click **Add New Group**.
3. Give the group a descriptive name, such as `ThousandEyes Monitoring Config`.
4. Assign the previously created `Monitoring Administrator` role to this group.
5. Save the new group.

### Next Steps
Your setup is complete. Any user or service account added to the `ThousandEyes Monitoring Config` group will have the necessary permissions to manage monitoring tests, alert rules, and templates.
