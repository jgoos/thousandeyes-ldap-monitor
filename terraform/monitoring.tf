locals {
  # One test per server. The script reads its target from the test URL, an RFC 4516 LDAP URL:
  # ldap[s]://host:port/baseDN. An empty base DN searches the Root DSE.
  ldap_tests = {
    for server in var.ldap_servers : server.name => {
      url = format("%s://%s:%d/%s",
        server.tls ? "ldaps" : "ldap",
        strcontains(server.hostname, ":") ? "[${server.hostname}]" : server.hostname,
        coalesce(server.port, server.tls ? 636 : 389),
        # Escape only what an LDAP URL needs escaped in the DN, so the URL stays readable.
        replace(replace(replace(replace(replace(server.base_dn, "%", "%25"), " ", "%20"), "?", "%3F"), "#", "%23"), "/", "%2F"),
      )
    }
  }
}

resource "thousandeyes_alert_rule" "ldap_alert_rule" {
  rule_name  = "LDAP Transaction Failure"
  alert_type = "web-transactions"
  # The script throws on any connection, TLS, LDAP result, timeout or latency failure, which
  # ThousandEyes records as a transaction with errors. A run cut off by the time limit times out.
  expression                = "((txCompletionHasError == true) || (txCompletionTimedOut == true))"
  rounds_violating_required = var.alert_rounds_violating_required
  rounds_violating_out_of   = var.alert_rounds_violating_out_of

  dynamic "notifications" {
    for_each = length(var.alert_email_recipients) > 0 ? [var.alert_email_recipients] : []
    content {
      email {
        recipients = notifications.value
      }
    }
  }
}

resource "thousandeyes_web_transaction" "ldap_test" {
  for_each = local.ldap_tests

  test_name                 = "LDAP Check - ${each.key}"
  url                       = each.value.url
  transaction_script        = file("${path.module}/../ldap-monitor.js")
  agents                    = var.agent_ids
  credentials               = var.credential_ids
  interval                  = var.interval
  time_limit                = var.time_limit
  flag_collect_console_logs = true
  alerts_enabled            = true
  alert_rules               = [thousandeyes_alert_rule.ldap_alert_rule.rule_id]

  lifecycle {
    precondition {
      condition     = var.time_limit <= var.interval / 2
      error_message = "time_limit must be at most half of interval; ThousandEyes caps the time limit at 0.5 x interval."
    }
  }
}
