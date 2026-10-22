# Latency alerts. The script does not judge latency itself; it records a ThousandEyes marker per
# step, and these rules alert when a marker lasts too long. Marker names must match those in
# ldap-monitor.js (the unit tests pin them down).

variable "marker_alert_thresholds_ms" {
  description = <<-EOT
    Alert when a step of the script takes at least this many milliseconds: one alert rule per
    marker, using the rounds and recipients of the failure rule. Markers the script records:
    - ldap-bind: the simple bind round trip.
    - ldap-search: the base-scope search round trip.
    - ldaps-ssl-handshake: TCP connect and TLS handshake, across all attempts (LDAPS tests).
    - ldap-tcp-connect: TCP connect, across all attempts (plain LDAP tests).
    An empty map creates no latency alerts.
  EOT
  type        = map(number)
  default = {
    "ldap-bind"   = 300
    "ldap-search" = 300
  }

  validation {
    condition = alltrue([for name in keys(var.marker_alert_thresholds_ms) :
    contains(["ldap-bind", "ldap-search", "ldaps-ssl-handshake", "ldap-tcp-connect"], name)])
    error_message = "Marker names must be ldap-bind, ldap-search, ldaps-ssl-handshake or ldap-tcp-connect."
  }

  validation {
    condition     = alltrue([for ms in values(var.marker_alert_thresholds_ms) : ms >= 1 && floor(ms) == ms])
    error_message = "Each threshold must be a whole number of milliseconds, 1 or more."
  }
}

resource "thousandeyes_alert_rule" "ldap_marker_duration" {
  for_each = var.marker_alert_thresholds_ms

  rule_name  = "LDAP Slow ${each.key} (${each.value} ms)"
  alert_type = "web-transactions"
  # Marker metric syntax from https://developer.cisco.com/docs/thousandeyes/alert-rule-metadata/
  expression                = "((marker[((markerName == \"${each.key}\"))]((markerDuration >= ${each.value} ms))))"
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

locals {
  marker_alert_rule_ids = [for rule in thousandeyes_alert_rule.ldap_marker_duration : rule.rule_id]
}

output "ldap_marker_alert_rule_ids" {
  description = "ID of the latency alert rule per marker name"
  value       = { for name, rule in thousandeyes_alert_rule.ldap_marker_duration : name => rule.rule_id }
}
