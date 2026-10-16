variable "te_api_token" {
  description = "API token for ThousandEyes user"
  type        = string
  sensitive   = true
}

variable "te_user_email" {
  description = "Email address associated with API token"
  type        = string
}

variable "ldap_servers" {
  description = <<-EOT
    LDAP servers to monitor, one test each.
    - hostname: host name or IP address only, without a scheme (ldaps://) or port.
    - port: defaults to 636 with TLS and 389 without.
    - tls: false monitors plain LDAP. The script then refuses to bind unless the
      ldapAllowCleartext credential is among credential_ids.
    - base_dn: search base; empty searches the Root DSE.
  EOT
  type = list(object({
    name     = string
    hostname = string
    port     = optional(number)
    tls      = optional(bool, true)
    base_dn  = optional(string, "")
  }))
  default = [
    {
      name     = "Primary LDAP Server (DC1)"
      hostname = "dc1.example.com"
      port     = 636
    },
    {
      name     = "Secondary LDAP Server (DC2)"
      hostname = "dc2.example.com"
      port     = 636
    }
  ]

  validation {
    condition     = alltrue([for s in var.ldap_servers : can(regex("^([A-Za-z0-9-]+\\.)*[A-Za-z0-9-]+$|^[0-9A-Fa-f:.]+$", s.hostname))])
    error_message = "Each hostname must be a bare host name or IP address, without a scheme such as ldaps:// and without a port."
  }

  validation {
    condition     = alltrue([for s in var.ldap_servers : s.port == null || (s.port >= 1 && s.port <= 65535)])
    error_message = "Each port must be between 1 and 65535."
  }

  validation {
    condition     = length(distinct([for s in var.ldap_servers : s.name])) == length(var.ldap_servers)
    error_message = "Server names must be unique; each one names a test."
  }
}

variable "agent_ids" {
  description = "List of ThousandEyes agent IDs to run the tests"
  type        = list(string)
}

variable "credential_ids" {
  description = <<-EOT
    IDs of the ThousandEyes credentials the script reads: ldapMonUser and ldapMonPass, plus any
    optional ones you use (ldapCaBase64, ldapAllowCleartext, ldapBaseDN, ldapBindOnly,
    ldapDebugMode). Create them in the ThousandEyes UI or API rather than in Terraform, so their
    values stay out of Terraform state.
  EOT
  type        = list(string)

  validation {
    condition     = length(var.credential_ids) >= 2
    error_message = "Attach at least the ldapMonUser and ldapMonPass credentials."
  }
}

variable "interval" {
  description = "Seconds between test rounds"
  type        = number
  default     = 300

  validation {
    condition     = contains([60, 120, 300, 600, 900, 1800, 3600], var.interval)
    error_message = "interval must be one of 60, 120, 300, 600, 900, 1800 or 3600."
  }
}

variable "time_limit" {
  description = "Seconds a round may run. The script stops about 10% (at least 1 s) earlier to report its own timeout."
  type        = number
  default     = 30

  validation {
    condition     = var.time_limit >= 5 && var.time_limit <= 180
    error_message = "time_limit must be between 5 and 180 seconds."
  }
}

variable "alert_rounds_violating_required" {
  description = "Failing rounds needed to raise the alert, out of alert_rounds_violating_out_of"
  type        = number
  default     = 2
}

variable "alert_rounds_violating_out_of" {
  description = "Rounds considered when counting failing rounds (1-10)"
  type        = number
  default     = 5

  validation {
    condition     = var.alert_rounds_violating_out_of >= 1 && var.alert_rounds_violating_out_of <= 10
    error_message = "alert_rounds_violating_out_of must be between 1 and 10."
  }
}

variable "alert_email_recipients" {
  description = "Email addresses notified when the alert rule fires; empty sends no notifications"
  type        = list(string)
  default     = []
}
