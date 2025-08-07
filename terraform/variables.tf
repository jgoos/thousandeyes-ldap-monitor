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
  description = "A list of LDAP servers to monitor. `hostname` should exclude any protocol prefix."
  type = list(object({
    name     = string
    hostname = string # Hostname without protocol prefix
    port     = number
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
}

variable "agent_ids" {
  description = "List of ThousandEyes agent IDs to run the tests"
  type        = list(string)
}
