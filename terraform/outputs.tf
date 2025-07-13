output "monitoring_group_id" {
  value = thousandeyes_account_group.monitoring_config.aid
}

output "monitoring_role_id" {
  value = thousandeyes_role.monitoring_config_admin.role_id
}

output "ldap_alert_rule_id" {
  value = thousandeyes_alert_rule.ldap_alert_rule.rule_id
}

output "ldap_test_ids" {
  value = { for name, test in thousandeyes_web_transaction.ldap_test : name => test.test_id }
}
