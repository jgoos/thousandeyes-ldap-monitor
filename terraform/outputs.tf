output "monitoring_group_id" {
  value = thousandeyes_group.monitoring_config.id
}

output "monitoring_role_id" {
  value = thousandeyes_role.monitoring_config_admin.id
}

output "ldap_alert_rule_id" {
  value = thousandeyes_alert_rule.ldap_alert_rule.id
}

output "ldap_test_ids" {
  value = { for name, test in thousandeyes_transaction_test.ldap_test : name => test.id }
}
