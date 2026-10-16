output "monitoring_group_id" {
  description = "ID of the account group created for monitoring configuration"
  value       = thousandeyes_account_group.monitoring_config.aid
}

output "monitoring_role_id" {
  description = "ID of the Monitoring Administrator role"
  value       = thousandeyes_role.monitoring_config_admin.role_id
}

output "ldap_alert_rule_id" {
  description = "ID of the LDAP transaction failure alert rule"
  value       = thousandeyes_alert_rule.ldap_alert_rule.rule_id
}

output "ldap_test_ids" {
  description = "Test ID per LDAP server name"
  value       = { for name, test in thousandeyes_web_transaction.ldap_test : name => test.test_id }
}

output "ldap_test_urls" {
  description = "LDAP URL each test probes, per LDAP server name"
  value       = { for name, test in local.ldap_tests : name => test.url }
}
