# Plan-only checks with a mocked provider: no ThousandEyes account or token is needed.
mock_provider "thousandeyes" {}

variables {
  te_api_token   = "mock-token"
  te_user_email  = "monitor@example.com"
  agent_ids      = ["1001"]
  credential_ids = ["2001", "2002"]
}

run "test_urls_follow_rfc4516" {
  command = plan

  variables {
    ldap_servers = [
      { name = "default", hostname = "dc1.example.com" },
      { name = "gc", hostname = "dc1.example.com", port = 3269, base_dn = "DC=example,DC=com" },
      { name = "plain", hostname = "ldap.example.com", tls = false },
      { name = "ipv6", hostname = "2001:db8::10" },
      { name = "escaped", hostname = "ldap.example.com", base_dn = "ou=R&D / Ops?,dc=example,dc=com" },
    ]
  }

  assert {
    condition     = thousandeyes_web_transaction.ldap_test["default"].url == "ldaps://dc1.example.com:636/"
    error_message = "A TLS server without a port or base DN should get ldaps://host:636/ (Root DSE)."
  }
  assert {
    condition     = thousandeyes_web_transaction.ldap_test["gc"].url == "ldaps://dc1.example.com:3269/DC=example,DC=com"
    error_message = "Port and base DN should appear in the URL."
  }
  assert {
    condition     = thousandeyes_web_transaction.ldap_test["plain"].url == "ldap://ldap.example.com:389/"
    error_message = "tls = false should give ldap:// on port 389."
  }
  assert {
    condition     = thousandeyes_web_transaction.ldap_test["ipv6"].url == "ldaps://[2001:db8::10]:636/"
    error_message = "IPv6 addresses should be bracketed."
  }
  assert {
    condition     = thousandeyes_web_transaction.ldap_test["escaped"].url == "ldaps://ldap.example.com:636/ou=R&D%20%2F%20Ops%3F,dc=example,dc=com"
    error_message = "Spaces, slashes and question marks in the base DN should be percent-encoded."
  }
}

run "tests_carry_credentials_time_limit_and_console_logs" {
  command = plan

  assert {
    condition     = alltrue([for t in thousandeyes_web_transaction.ldap_test : toset(t.credentials) == toset(["2001", "2002"])])
    error_message = "Every test should have the credential IDs attached."
  }
  assert {
    condition     = alltrue([for t in thousandeyes_web_transaction.ldap_test : t.time_limit == 30 && t.flag_collect_console_logs && t.alerts_enabled])
    error_message = "Tests should use the time limit, collect console logs and enable alerts."
  }
}

run "alert_rule_uses_transaction_metrics" {
  command = plan

  variables {
    alert_email_recipients = ["ldap-oncall@example.com"]
  }

  assert {
    condition     = thousandeyes_alert_rule.ldap_alert_rule.alert_type == "web-transactions"
    error_message = "The alert type for transaction tests is web-transactions."
  }
  assert {
    condition     = thousandeyes_alert_rule.ldap_alert_rule.expression == "((txCompletionHasError == true) || (txCompletionTimedOut == true))"
    error_message = "The rule should fire on transaction errors and timeouts."
  }
  assert {
    condition     = length(thousandeyes_alert_rule.ldap_alert_rule.notifications) == 1
    error_message = "Recipients should produce an email notification."
  }
}

run "rejects_a_scheme_in_hostname" {
  command = plan

  variables {
    ldap_servers = [{ name = "bad", hostname = "ldaps://dc1.example.com" }]
  }

  expect_failures = [var.ldap_servers]
}

run "rejects_a_time_limit_above_half_the_interval" {
  command = plan

  variables {
    interval   = 60
    time_limit = 45
  }

  expect_failures = [thousandeyes_web_transaction.ldap_test]
}
