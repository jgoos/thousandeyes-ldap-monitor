resource "thousandeyes_transaction_test" "ldap_template" {
  test_name = "LDAP Monitor Template"
  template  = true
  script    = file("${path.module}/../ldap-monitor.js")
  interval  = 300
}
