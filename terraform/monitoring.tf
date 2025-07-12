resource "thousandeyes_alert_rule" "ldap_alert_rule" {
  rule_name  = "LDAP Transaction Failure"
  alert_type = "TRANSACTION"
  expression = "( ( num-errors >= 3 ) )"
}

resource "thousandeyes_transaction_test" "ldap_test" {
  for_each   = { for server in var.ldap_servers : server.name => server }

  test_name  = "LDAP Check - ${each.value.name}"
  template_id = thousandeyes_transaction_test.ldap_template.id
  alert_rules = [thousandeyes_alert_rule.ldap_alert_rule.id]
  server      = "${each.value.hostname}:${each.value.port}"
  agents      = var.agent_ids
}
