resource "thousandeyes_alert_rule" "ldap_alert_rule" {
  rule_name                 = "LDAP Transaction Failure"
  alert_type                = "web-transaction"
  expression                = "( ( num-errors >= 3 ) )"
  rounds_violating_required = 2
  rounds_violating_out_of   = 5
}

resource "thousandeyes_web_transaction" "ldap_test" {
  for_each = { for server in var.ldap_servers : server.name => server }

  test_name          = "LDAP Check - ${each.value.name}"
  url                = "ldaps://${each.value.hostname}:${each.value.port}"
  transaction_script = file("${path.module}/../ldap-monitor.js")
  agents             = var.agent_ids
  alert_rules        = [thousandeyes_alert_rule.ldap_alert_rule.rule_id]
  interval           = 300
}
