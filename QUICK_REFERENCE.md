# LDAP Monitoring - Quick Reference Guide

## Essential Setup Checklist

### ✅ Required Secure Credentials (Always Needed)
```
ldapHost     = "your-ldap-server.com"
ldapMonUser  = "cn=monitor,ou=svc,dc=example,dc=com"
ldapMonPass  = "your-password"
```

### ⚙️ Optional Secure Credentials
```
ldapCaBase64 = "LS0tLS1CRUdJTi..."    # For self-signed certificates
ldapPort     = "636"                  # Default: 636 (LDAPS)
ldapBaseDN   = "ou=People,dc=example,dc=com"  # Search base
ldapFilter   = "(objectClass=*)"      # Search filter
ldapAttrs    = "cn,mail,uid"          # Attributes to retrieve
ldapBindOnly = "true"                 # Skip search (auth only)
```

## Common Configuration Patterns

### 🔒 Basic LDAPS Health Check
```
ldapHost     = "ldap.company.com"
ldapMonUser  = "cn=monitor,dc=company,dc=com"
ldapMonPass  = "secure-password"
```

### 🏢 Active Directory
```
ldapHost     = "dc01.corp.company.com"
ldapMonUser  = "cn=ldap-monitor,ou=Service Accounts,dc=corp,dc=company,dc=com"
ldapMonPass  = "ad-password"
ldapBaseDN   = "dc=corp,dc=company,dc=com"
ldapFilter   = "(sAMAccountName=*)"
ldapAttrs    = "sAMAccountName,displayName,mail"
```

### 🐧 OpenLDAP
```
ldapHost     = "ldap.openldap.org"
ldapMonUser  = "cn=monitor,dc=openldap,dc=org"
ldapMonPass  = "ldap-password"
ldapBaseDN   = "ou=People,dc=openldap,dc=org"
ldapFilter   = "(uid=*)"
ldapAttrs    = "uid,cn,mail"
```

### ⚡ Fast Authentication Only
```
ldapHost     = "auth.company.com"
ldapMonUser  = "cn=auth-check,dc=company,dc=com"
ldapMonPass  = "auth-password"
ldapBindOnly = "true"  # ~50% faster, skips search
```

### 🔐 Self-Signed Certificates
```
ldapHost     = "internal-ldap.company.local"
ldapMonUser  = "cn=monitor,dc=company,dc=local"
ldapMonPass  = "internal-password"
ldapCaBase64 = "LS0tLS1CRUdJTi..."  # Base64-encoded CA cert
```

## Troubleshooting Quick Fixes

### ❌ "Missing LDAP host"
- Create `ldapHost` credential with server hostname/IP

### ❌ "Missing credentials"
- Create `ldapMonUser` and `ldapMonPass` credentials
- Verify agent has access to both credentials

### ❌ "Connection failed"
- Check firewall rules for port 636 (LDAPS) or 389 (LDAP)
- Test: `telnet your-server 636`

### ❌ "Certificate validation failed"
- Add `ldapCaBase64` credential with base64-encoded CA certificate
- Get cert: `openssl s_client -connect server:636 -showcerts`

### ❌ "Bind failed: invalidCredentials"
- Verify full DN format: `cn=user,ou=group,dc=domain,dc=com`
- Test manually: `ldapsearch -H ldaps://server:636 -D "bind-dn" -W`

### ❌ "Search failed: noSuchObject"
- Set `ldapBaseDN = "USE_BIND_DN"` for auto-detection
- Or remove `ldapBaseDN` credential for Root DSE search

### ⚠️ "Slow bind/search"
- Normal if latency is expected
- Use `ldapBindOnly = "true"` for faster checks
- Consider closer ThousandEyes agent

## Performance Tuning

### 🚀 Maximum Speed
```
ldapBindOnly = "true"                 # Skip search (~50% faster)
```

### ⚡ Lightweight Search
```
ldapBaseDN   = ""                     # Root DSE (fastest base)
ldapFilter   = "(objectClass=*)"      # Simple presence filter
# Remove ldapAttrs for minimal data
```

### 🎯 Targeted Monitoring
```
ldapBaseDN   = "USE_BIND_DN"          # Search only monitor account
ldapAttrs    = "cn"                   # Minimal attributes
```

## Testing Commands

### Basic LDAPS Test
```bash
ldapsearch -x -H ldaps://server:636 \
  -D "cn=monitor,dc=example,dc=com" \
  -W -b "" -s base "(objectClass=*)"
```

### Certificate Check
```bash
openssl s_client -connect server:636 -verify_return_error
```

### Extract Certificate for ldapCaBase64
```bash
echo | openssl s_client -connect server:636 2>/dev/null | \
  openssl x509 | base64 | tr -d '\n'
```

## Expected Console Output

### ✅ Successful Monitoring
```
Testing LDAP server: ldap.company.com (ldap.company.com:636)
Connection established in 45 ms
Bind RTT: 125 ms
Search RTT: 78 ms
Total operation time: 248 ms
```

### ✅ Bind-Only Mode
```
Testing LDAP server: auth.company.com (auth.company.com:636)
Bind RTT: 89 ms
BIND-ONLY MODE: Skipping search operation as requested
Total operation time: 121 ms
```

## Emergency Deployment

### Minimal Working Configuration
1. Create these 3 credentials:
   ```
   ldapHost     = "your-server"
   ldapMonUser  = "your-bind-dn"
   ldapMonPass  = "your-password"
   ```

2. Copy `ldap-monitor.js` to ThousandEyes Transaction test

3. Enable credential access in script editor (🔐 icon)

4. Click Validate to test

5. Deploy with 1-minute interval

**That's it!** The script auto-configures for basic LDAPS monitoring.