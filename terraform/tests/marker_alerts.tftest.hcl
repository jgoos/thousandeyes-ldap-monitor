# Latency alert rules on the script's markers (marker_alerts.tf), against a mocked provider.
mock_provider "thousandeyes" {}

variables {
  te_api_token   = "mock-token"
  te_user_email  = "monitor@example.com"
  agent_ids      = ["1001"]
  credential_ids = ["2001", "2002"]
}

run "default_rules_alert_on_slow_bind_and_search" {
  command = plan

  assert {
    condition     = toset(keys(thousandeyes_alert_rule.ldap_marker_duration)) == toset(["ldap-bind", "ldap-search"])
    error_message = "By default there should be one rule each for the ldap-bind and ldap-search markers."
  }
  assert {
    condition     = thousandeyes_alert_rule.ldap_marker_duration["ldap-bind"].expression == "((marker[((markerName == \"ldap-bind\"))]((markerDuration >= 300 ms))))"
    error_message = "The bind rule should fire when the ldap-bind marker lasts 300 ms or more."
  }
  assert {
    condition     = thousandeyes_alert_rule.ldap_marker_duration["ldap-search"].expression == "((marker[((markerName == \"ldap-search\"))]((markerDuration >= 300 ms))))"
    error_message = "The search rule should fire when the ldap-search marker lasts 300 ms or more."
  }
  assert {
    condition     = alltrue([for r in thousandeyes_alert_rule.ldap_marker_duration : r.alert_type == "web-transactions" && r.rounds_violating_required == 2 && r.rounds_violating_out_of == 5])
    error_message = "Marker rules are transaction rules and use the same rounds as the failure rule."
  }
}

run "thresholds_are_set_per_marker" {
  command = plan

  variables {
    marker_alert_thresholds_ms = { "ldap-bind" = 500, "ldaps-ssl-handshake" = 800 }
    alert_email_recipients     = ["ldap-oncall@example.com"]
  }

  assert {
    condition     = toset(keys(thousandeyes_alert_rule.ldap_marker_duration)) == toset(["ldap-bind", "ldaps-ssl-handshake"])
    error_message = "There should be one rule per configured marker."
  }
  assert {
    condition     = thousandeyes_alert_rule.ldap_marker_duration["ldaps-ssl-handshake"].expression == "((marker[((markerName == \"ldaps-ssl-handshake\"))]((markerDuration >= 800 ms))))"
    error_message = "Each rule should use its own marker's threshold."
  }
  assert {
    condition     = thousandeyes_alert_rule.ldap_marker_duration["ldap-bind"].rule_name == "LDAP Slow ldap-bind (500 ms)"
    error_message = "The rule name should say which marker and threshold it alerts on."
  }
  assert {
    condition     = alltrue([for r in thousandeyes_alert_rule.ldap_marker_duration : length(r.notifications) == 1])
    error_message = "Marker rules should notify the same recipients as the failure rule."
  }
}

run "tests_carry_the_marker_rules" {
  # apply, so the mocked provider fills in the rule IDs that the tests reference.
  command = apply

  assert {
    condition = alltrue([for t in thousandeyes_web_transaction.ldap_test : toset(t.alert_rules) == toset(concat(
      [thousandeyes_alert_rule.ldap_alert_rule.rule_id],
      [for r in thousandeyes_alert_rule.ldap_marker_duration : r.rule_id],
    ))])
    error_message = "Every test should carry the failure rule and each marker rule."
  }
  assert {
    condition     = alltrue([for t in thousandeyes_web_transaction.ldap_test : length(t.alert_rules) == 3])
    error_message = "Every test should carry three distinct rules: failure, ldap-bind and ldap-search."
  }
  assert {
    condition     = length(output.ldap_marker_alert_rule_ids) == 2
    error_message = "The output should list the rule ID per marker."
  }
}

run "an_empty_map_disables_latency_alerts" {
  command = apply

  variables {
    marker_alert_thresholds_ms = {}
  }

  assert {
    condition     = length(thousandeyes_alert_rule.ldap_marker_duration) == 0
    error_message = "An empty map should create no marker rules."
  }
  assert {
    condition     = alltrue([for t in thousandeyes_web_transaction.ldap_test : toset(t.alert_rules) == toset([thousandeyes_alert_rule.ldap_alert_rule.rule_id])])
    error_message = "Without marker rules, tests should carry only the failure rule."
  }
}

run "rejects_a_marker_the_script_does_not_record" {
  command = plan

  variables {
    marker_alert_thresholds_ms = { "ldap-connect" = 300 }
  }

  expect_failures = [var.marker_alert_thresholds_ms]
}

run "rejects_a_threshold_that_is_not_a_positive_whole_number" {
  command = plan

  variables {
    marker_alert_thresholds_ms = { "ldap-bind" = 0.5 }
  }

  expect_failures = [var.marker_alert_thresholds_ms]
}
