# ThousandEyes LDAP Health Monitoring Script

Comprehensive LDAPS monitoring for ThousandEyes Enterprise Agents with advanced search capabilities and robust error handling.

> **Important:** ThousandEyes Transaction tests only support a single JavaScript file. While this repository contains multiple files for documentation and examples, only `ldap-monitor.js` should be copied into the ThousandEyes platform.

## Overview

This repository contains an enterprise-grade JavaScript monitoring script for ThousandEyes that provides:

### **Core Features**
- **Direct LDAPS Monitoring**: No proxy required, connects directly to LDAP servers
- **LDAPv3 Simple Bind**: Comprehensive authentication with detailed error analysis
- **Flexible Search Operations**: Configurable filters, attributes, and search scopes
- **Custom CA Certificate Support**: Self-signed certificate compatibility for LDAPS
- **Intelligent Error Handling**: 24 comprehensive LDAP result codes with solutions
- **Performance Monitoring**: Sub-300ms response time monitoring with detailed metrics
- **Bind-Only Mode**: Authentication verification without search operations

### **Enhanced Capabilities**
- **Custom Search Filters**: Support for presence, equality, and complex LDAP filters
- **Attribute Retrieval**: Specify which LDAP attributes to return
- **Multiple Server Types**: Optimized for Active Directory, OpenLDAP, and RFC-compliant servers
- **Retry Logic**: Intelligent connection retry with exponential backoff
- **SearchResultDone Detection**: Advanced algorithm with ASCII text filtering
- **Comprehensive Logging**: Essential troubleshooting information without debug pollution

## Repository Structure

While ThousandEyes only supports single-file scripts, this repository includes additional files for better maintainability and documentation:

- **`ldap-monitor.js`** - The main monitoring script (copy this to ThousandEyes)
- **`ldap-monitor-config.example.js`** - Example configurations for different LDAP server types (reference only)
- **`docs/README.md`** - Setup instructions and documentation
- **`package.json`** - Project metadata
- **`.gitignore`** - Version control configuration

The example configuration file shows different settings for various LDAP implementations (Active Directory, OpenLDAP, etc.) that you can reference when modifying the settings in the main script.

## Quick Start Guide

### Prerequisites
- ThousandEyes Enterprise Agents with network access to LDAP server
- LDAP service account with read permissions
- CA certificate for LDAPS (if using self-signed certificates)

### 1. Configure Secure Credentials

**Navigation:** `Settings ▸ Secure Credentials ▸ Add Credential`

#### **Required Credentials**

**LDAP Authentication:**
- **Name:** `ldapMonUser`
- **Value:** Full bind DN (e.g., `cn=monitor,ou=svc,dc=example,dc=com`)
- **Agent Access:** Select Enterprise Agents that will run the test

**Password:**
- **Name:** `ldapMonPass`  
- **Value:** Authentication password
- **Agent Access:** Select the same agents as ldapMonUser

**LDAP Server:**
- **Name:** `ldapHost`
- **Value:** LDAP server hostname or IP (e.g., `ldap.example.com`)
- **Agent Access:** Select the same agents

#### **Optional Credentials**

**LDAPS Certificate (recommended for self-signed certificates):**
- **Name:** `ldapCaBase64`
- **Value:** Base64-encoded CA certificate(s) in PEM format
- **Agent Access:** Select the same agents

**Server Port:**
- **Name:** `ldapPort`
- **Value:** `389` (LDAP) or `636` (LDAPS, default)
- **Agent Access:** Select the same agents

**Search Configuration:**
- **Name:** `ldapBaseDN`
- **Value:** Search base DN (e.g., `ou=People,dc=example,dc=com`) or `USE_BIND_DN` for auto-detection
- **Agent Access:** Select the same agents

**Custom Search Filter:**
- **Name:** `ldapFilter`
- **Value:** LDAP filter (e.g., `(cn=*)`, `(objectClass=*)`, `(sAMAccountName=*)`)
- **Agent Access:** Select the same agents

**Attribute Retrieval:**
- **Name:** `ldapAttrs`
- **Value:** Comma-separated attributes (e.g., `cn,mail,uid`)
- **Agent Access:** Select the same agents

**Bind-Only Mode:**
- **Name:** `ldapBindOnly`
- **Value:** `true` to skip search and only verify authentication
- **Agent Access:** Select the same agents

> **Security Note:** All credentials are encrypted at rest and never appear in screenshots, reports, or API payloads.

### 2. Create Transaction Test

**Navigation:** `Test Settings → Add New Test` (top-right)

In the "Add New Test" pane:
- Choose `Browser Synthetics → Transaction`

### 3. Add the Monitoring Script

In the Steps panel:
1. Click `Script` (looks like `{ }`)
2. Delete the stub Selenium code
3. Copy the **entire contents** of `ldap-monitor.js` and paste it into the editor
   - **Important:** Only use the main script file - ThousandEyes doesn't support multiple files or imports

### 4. Configure Credential Access

In the Script editor:
1. Click the key icon (🔐) above the editor
2. Enable access to your required credentials:
   - **Always required:** `ldapMonUser`, `ldapMonPass`, `ldapHost`
   - **Optional:** `ldapCaBase64`, `ldapPort`, `ldapBaseDN`, `ldapFilter`, `ldapAttrs`, `ldapBindOnly`
3. The script automatically reads these credentials at runtime
4. No plaintext credentials will ever appear in the script

### 5. Select Agents and Monitoring Frequency

**Agents dropdown** (just below the script):
- Select Enterprise Agent(s) with network access to your LDAP server
- Consider geographic proximity for accurate latency measurements
- Optionally add Cloud Agents for external monitoring perspective
- **Recommended Interval:** 1 minute for real-time monitoring

### 6. Configure Alerting

**Navigation:** `Alerts → Enable`

**Recommended Alert Configuration:**
- **Alert Rule:** Create new rule or reuse existing Transaction alert
- **Trigger Condition:** `Test status = Fail` for 2-3 consecutive rounds
- **Performance Threshold:** Consider separate alerts for response time thresholds

### 7. Validate Configuration

**Pre-deployment Testing:**
1. Click `Validate` in Instant Test (right side of the screen)
2. Review console output for:
   - `Testing LDAP server: [hostname]:[port]`
   - `Bind RTT: X ms`
   - `Search RTT: X ms` (if not using bind-only mode)
   - `Total operation time: X ms`
3. No error messages = successful configuration

### 8. Deploy and Monitor

1. Click `Create New Test` to activate monitoring
2. Data collection begins immediately
3. Access results via `Test Views → Transaction`

## Configuration Examples

The script reads all configuration from ThousandEyes Secure Credentials. Here are common configuration patterns:

### **Basic LDAPS Monitoring**
```
Required Credentials:
ldapHost     = "ldap.example.com"
ldapMonUser  = "cn=monitor,ou=svc,dc=example,dc=com"  
ldapMonPass  = "your-secure-password"
```

### **Active Directory Integration**
```
Required Credentials:
ldapHost     = "dc01.corp.example.com"
ldapMonUser  = "cn=ldap-monitor,ou=Service Accounts,dc=corp,dc=example,dc=com"
ldapMonPass  = "your-ad-password"

Optional Enhancements:
ldapBaseDN   = "dc=corp,dc=example,dc=com"
ldapFilter   = "(sAMAccountName=*)"
ldapAttrs    = "sAMAccountName,displayName,mail"
```

### **OpenLDAP with Custom Search**
```
Required Credentials:
ldapHost     = "ldap.openldap.org"
ldapMonUser  = "cn=monitor,dc=openldap,dc=org"
ldapMonPass  = "monitor-password"

Optional Enhancements:
ldapBaseDN   = "ou=People,dc=openldap,dc=org"
ldapFilter   = "(uid=*)"
ldapAttrs    = "uid,cn,mail,telephoneNumber"
```

### **Bind-Only Authentication Check**
```
Required Credentials:
ldapHost     = "auth.example.com"
ldapMonUser  = "cn=auth-check,ou=monitoring,dc=example,dc=com"
ldapMonPass  = "auth-password"

Performance Optimization:
ldapBindOnly = "true"    # Skip search, only verify authentication
```

### **Self-Signed Certificate Support**
```
Required Credentials:
ldapHost     = "internal-ldap.company.local"
ldapMonUser  = "cn=monitor,dc=company,dc=local"
ldapMonPass  = "internal-password"

LDAPS Configuration:
ldapCaBase64 = "LS0tLS1CRUdJTi..."  # Base64-encoded CA certificate
ldapPort     = "636"                 # Explicit LDAPS port
```

## Monitoring Output

### **Successful Operation Console Output**
```
Testing LDAP server: dc01.corp.example.com (dc01.corp.example.com:636)
Connection established in 45 ms
Sending LDAP bind request (67 bytes) for user: cn=monitor,ou=svc,dc=corp,dc=example,dc=com
Bind RTT: 125 ms
Using search scope: 2 (0=base, 1=one-level, 2=subtree)
Search mode: Manual/organizational search
Search filter: (sAMAccountName=*)
Requesting attributes: sAMAccountName,displayName,mail
Sending LDAP search request (89 bytes) - baseDN: 'dc=corp,dc=example,dc=com', filter: '(sAMAccountName=*)'
Search RTT: 78 ms
Search completed successfully
Total operation time: 248 ms
Performance breakdown:
  - Connection: 45 ms
  - Bind: 125 ms
  - Search: 78 ms
```

### **Bind-Only Mode Output**
```
Testing LDAP server: auth.example.com (auth.example.com:636)
Connection established in 32 ms
Bind RTT: 89 ms
BIND-ONLY MODE: Skipping search operation as requested
LDAP authentication verified successfully - monitoring complete
Total operation time: 121 ms
Performance breakdown (bind-only mode):
  - Connection: 32 ms
  - Bind: 89 ms
  - Search: skipped (bind-only mode)
```

### **Error Conditions**
The script will throw errors (causing test failure) for:
- **Authentication Failures**: Invalid credentials, account lockout, insufficient permissions
- **Connection Issues**: Network timeouts, certificate validation failures, port accessibility
- **Search Failures**: Invalid base DN, malformed filters, server-side search restrictions
- **Performance Thresholds**: Operations exceeding 300ms default threshold
- **Protocol Errors**: Malformed LDAP responses, unsupported operations

## Requirements

- ThousandEyes Enterprise or Cloud Agents
- LDAP server with monitoring account credentials
- Network connectivity from agents to LDAP server on configured port

## Troubleshooting Guide

### **Configuration Issues**

#### "Missing LDAP host: Ensure ldapHost credential is configured"
**Cause:** The required `ldapHost` credential is missing or not accessible.

**Solution:**
1. Create `ldapHost` credential in `Settings ▸ Secure Credentials`
2. Set value to your LDAP server hostname or IP address
3. Ensure the agent running the test has access to this credential
4. Verify credential name is exactly `ldapHost` (case-sensitive)

#### "Missing credentials: Ensure ldapMonUser and ldapMonPass are configured"
**Cause:** Required authentication credentials are missing or inaccessible.

**Solution:**
1. Create both `ldapMonUser` and `ldapMonPass` credentials
2. Verify credentials exist in `Settings ▸ Secure Credentials`
3. Ensure the agent has access to both credentials
4. Check credential names match exactly (case-sensitive)

#### "Warning: Invalid port 'X', using default 636"
**Cause:** The `ldapPort` credential contains an invalid port number.

**Solution:**
1. Set `ldapPort` to either `389` (LDAP) or `636` (LDAPS)
2. Remove `ldapPort` credential to use default 636 (LDAPS)
3. Verify port matches your LDAP server configuration

### **Connection Issues**

#### "Connection failed after X attempts"
**Cause:** Network connectivity, firewall, or server availability issues.

**Solution:**
1. Verify LDAP server hostname/IP in `ldapHost` credential
2. Check firewall rules between agent and LDAP server
3. Test connectivity: `telnet your-ldap-server 636`
4. Verify LDAP service is running and accepting connections
5. For LDAPS: Ensure port 636 is open and TLS is configured

#### "TLS/Certificate validation failed after X attempts"
**Cause:** LDAPS certificate validation issues (common with self-signed certificates).

**Solution:**
1. **For self-signed certificates:** Create `ldapCaBase64` credential with base64-encoded CA certificate
2. **Get your CA certificate:**
   ```bash
   openssl s_client -connect your-ldap-server:636 -showcerts
   # Copy the certificate(s) and base64 encode them
   ```
3. **For internal CAs:** Ensure the CA certificate is properly formatted in PEM format
4. Test certificate manually: `openssl s_client -connect ldap.example.com:636`

### **Authentication Issues**

#### "Bind failed: invalidCredentials (49/0x31)"
**Cause:** Incorrect bind DN or password.

**Solution:**
1. Verify full bind DN format in `ldapMonUser`: `cn=monitor,ou=svc,dc=example,dc=com`
2. Check for typos in the Distinguished Name structure
3. Verify password in `ldapMonPass` credential
4. Test credentials manually:
   ```bash
   ldapsearch -x -H ldaps://your-server:636 \
     -D "cn=monitor,ou=svc,dc=example,dc=com" \
     -W -b "" -s base "(objectClass=*)"
   ```
5. Ensure account is not locked, expired, or disabled

#### "Bind failed: insufficientAccessRights (50/0x32)"
**Cause:** Monitoring account lacks necessary read permissions.

**Solution:**
1. Verify account has read access to the directory
2. For Active Directory: Ensure account has "Read" permissions
3. For OpenLDAP: Check ACL configuration in `slapd.conf` or `cn=config`
4. Test with broader permissions temporarily to isolate the issue
5. Contact LDAP administrator to verify account permissions

#### "Bind failed: strongerAuthRequired (8/0x8)"
**Cause:** Server requires stronger authentication (e.g., LDAPS instead of LDAP).

**Solution:**
1. Use LDAPS (port 636) instead of LDAP (port 389)
2. Set `ldapPort` credential to `636`
3. Provide `ldapCaBase64` credential if using self-signed certificates
4. Verify server TLS configuration

### **Search Issues**

#### "Search failed: noSuchObject (32/0x20)"
**Cause:** The base DN specified in `ldapBaseDN` doesn't exist.

**Solution:**
1. Verify base DN exists: `ou=People,dc=example,dc=com`
2. Use `USE_BIND_DN` in `ldapBaseDN` to auto-detect from bind DN
3. Remove `ldapBaseDN` credential to use Root DSE search
4. Test with `ldapsearch` to verify base DN:
   ```bash
   ldapsearch -x -H ldaps://server:636 -D "bind-dn" -W \
     -b "ou=People,dc=example,dc=com" -s base "(objectClass=*)"
   ```

#### "Search failed: SearchResultDone not found"
**Cause:** Server returned non-standard LDAP response or response truncation.

**Solution:**
1. Try bind-only mode: Set `ldapBindOnly` credential to `true`
2. Simplify search: Remove `ldapBaseDN` credential for Root DSE search
3. Change filter: Use `(objectClass=*)` in `ldapFilter` credential
4. Check server logs for errors or non-standard behavior

### **Performance Issues**

#### "Slow bind: X ms (>300ms threshold)"
**Cause:** High latency or server performance issues.

**Solution:**
1. **Expected high latency:** This is informational - monitor trends
2. **Unexpected latency:**
   - Check network latency between agent and server
   - Verify LDAP server performance and load
   - Consider using geographically closer agent
   - Monitor server-side LDAP logs for performance insights

#### "Slow search: X ms (>300ms threshold)"
**Cause:** Search operation exceeding performance threshold.

**Solution:**
1. **Optimize search:**
   - Use `ldapBindOnly = "true"` to skip search entirely
   - Use smaller search scope with specific base DN
   - Limit attributes: Set `ldapAttrs = "cn"` for minimal data
2. **Server tuning:**
   - Check LDAP server indexing on searched attributes
   - Verify server has adequate resources (CPU, memory)
   - Monitor concurrent LDAP operations

### **Advanced Configuration**

#### **Custom Search Filters**
The script supports various LDAP filter types through the `ldapFilter` credential:

**Presence Filters** (recommended for health checks):
```
ldapFilter = "(objectClass=*)"     # Any object with objectClass attribute
ldapFilter = "(cn=*)"              # Any object with common name
ldapFilter = "(uid=*)"             # Any object with user ID (OpenLDAP)
ldapFilter = "(sAMAccountName=*)"  # Any object with sAMAccountName (AD)
```

**Complex Filters** (fallback to objectClass presence):
```
ldapFilter = "(|(cn=admin)(uid=admin))"  # Will use (objectClass=*) internally
```

#### **Attribute Optimization**
Minimize network traffic and improve performance by requesting specific attributes:

**Minimal Monitoring** (fastest):
```
ldapAttrs = "cn"  # Only common name
```

**User Account Monitoring**:
```
ldapAttrs = "cn,uid,mail,telephoneNumber"  # OpenLDAP
ldapAttrs = "sAMAccountName,displayName,mail"  # Active Directory
```

**No Attributes** (DN only):
```
# Remove ldapAttrs credential or set to empty string
```

#### **Performance Optimization Strategies**

**Ultra-Fast Authentication Check**:
```
ldapBindOnly = "true"    # Skip search entirely (~50% faster)
```

**Lightweight Search**:
```
ldapBaseDN   = ""        # Root DSE search (fastest search base)
ldapFilter   = "(objectClass=*)"
# Remove ldapAttrs credential for minimal data transfer
```

**Targeted Search**:
```
ldapBaseDN   = "USE_BIND_DN"  # Search only the monitoring account
ldapFilter   = "(objectClass=*)"
ldapAttrs    = "cn"
```

### **Testing Before Deployment**

Validate your configuration using standard LDAP tools before deploying to ThousandEyes:

#### **Basic Connectivity Test**
```bash
# Test LDAPS connection and certificate
openssl s_client -connect your-ldap-server:636 -verify_return_error

# Test LDAP bind and search
ldapsearch -x -H ldaps://your-ldap-server:636 \
  -D "cn=monitor,ou=svc,dc=example,dc=com" \
  -W \
  -b "" -s base "(objectClass=*)"
```

#### **Custom Filter Testing**
```bash
# Test your custom filter
ldapsearch -x -H ldaps://your-ldap-server:636 \
  -D "cn=monitor,ou=svc,dc=example,dc=com" \
  -W \
  -b "ou=People,dc=example,dc=com" \
  -s sub "(sAMAccountName=*)" \
  sAMAccountName displayName mail
```

#### **Certificate Preparation for Self-Signed**
```bash
# Extract certificate from server
echo | openssl s_client -connect your-ldap-server:636 2>/dev/null | \
  openssl x509 -out ldap-cert.pem

# Convert to base64 for ldapCaBase64 credential
base64 -i ldap-cert.pem | tr -d '\n'
```

## Enterprise Deployment Patterns

### **Multi-Server Monitoring**

For organizations with multiple LDAP servers, create separate tests with consistent naming:

**Test Naming Convention:**
- `LDAP Health - DC01 (Primary)`
- `LDAP Health - DC02 (Secondary)`  
- `LDAP Health - OpenLDAP (DMZ)`

**Server-Specific Credentials:**
```
# Primary Domain Controller
ldapHost = "dc01.corp.example.com"
ldapMonUser = "cn=ldap-monitor,ou=Service Accounts,dc=corp,dc=example,dc=com"

# Secondary Domain Controller  
ldapHost = "dc02.corp.example.com"
ldapMonUser = "cn=ldap-monitor,ou=Service Accounts,dc=corp,dc=example,dc=com"

# DMZ OpenLDAP Server
ldapHost = "ldap.dmz.example.com"
ldapMonUser = "cn=monitor,dc=dmz,dc=example,dc=com"
ldapFilter = "(uid=*)"
```

### **High Availability Monitoring**

**Load Balancer Health Checks:**
```
# Monitor through load balancer VIP
ldapHost = "ldap-vip.example.com"
ldapBindOnly = "true"           # Fast health check
```

**Regional Deployment:**
- **Americas**: Monitor from US agents → US LDAP servers
- **EMEA**: Monitor from EU agents → EU LDAP servers  
- **APAC**: Monitor from APAC agents → APAC LDAP servers

### **Alert Management Best Practices**

#### **Tiered Alerting Strategy**
1. **Level 1 - Performance Degradation**
   - Trigger: Response time > 300ms for 2 consecutive rounds
   - Action: Log and monitor trends

2. **Level 2 - Service Impact**  
   - Trigger: Authentication failures for 3 consecutive rounds
   - Action: Alert operations team

3. **Level 3 - Service Outage**
   - Trigger: Connection failures for 5 consecutive rounds
   - Action: Page on-call engineer

#### **Alert Correlation**
- Group alerts by data center/region to identify widespread issues
- Correlate with dependent application alerts (email, SSO, etc.)
- Use ThousandEyes integrations with PagerDuty, ServiceNow, or Slack

### **Compliance and Audit Requirements**

#### **SOC 2 / ISO 27001 Compliance**
- **Monitoring Coverage**: Document all critical LDAP infrastructure
- **Alert Response**: Maintain logs of alert response times
- **Access Control**: Use role-based access to ThousandEyes credentials
- **Change Management**: Track all monitoring configuration changes

#### **Audit Trail**
- Monitor authentication success/failure rates
- Track certificate expiration dates (via ldapCaBase64 certificates)
- Document baseline performance metrics for capacity planning

## Technical Specifications

### **Script Capabilities**
- **Protocol Support**: LDAP (389) and LDAPS (636) with TLS 1.2/1.3
- **Authentication**: LDAPv3 Simple Bind with comprehensive error handling
- **Search Operations**: Configurable filters, attributes, and search scopes
- **Error Handling**: 24 standard LDAP result codes with detailed diagnostics
- **Performance**: Optimized for <300ms response times, <67KB script size
- **Compatibility**: Active Directory, OpenLDAP, ApacheDS, and RFC 4511 compliant servers

### **Network Requirements**
- **Outbound Connectivity**: Agents need access to LDAP server ports
- **Firewall Rules**: Port 636 (LDAPS) or 389 (LDAP) outbound from agent subnets
- **Certificate Validation**: For LDAPS, ensure certificate chain is trusted or use ldapCaBase64

### **Security Implementation**
- **Credential Encryption**: All sensitive data stored in ThousandEyes Secure Credentials
- **Zero Trust**: No hardcoded credentials or configuration in script
- **TLS Enforcement**: Supports custom CA certificates for internal PKI
- **Minimal Permissions**: Monitor accounts require only read access to tested base DNs

## Support and Contributing

### **Getting Help**
1. **Configuration Issues**: Review troubleshooting guide above
2. **Performance Optimization**: Check advanced configuration patterns
3. **Custom Requirements**: Script supports extensive customization via credentials

### **Contributing Improvements**
To contribute enhancements to this monitoring script:

1. **Testing**: Validate changes against multiple LDAP server types
2. **Documentation**: Update README with new configuration options
3. **Compatibility**: Ensure changes work within ThousandEyes environment constraints
4. **Examples**: Provide real-world use cases and configuration samples

## License

This LDAP monitoring script is provided as-is for use with the ThousandEyes platform. 

**Compatibility**: ThousandEyes Enterprise Agents with JavaScript transaction support.  
**Version**: Enhanced for enterprise monitoring with comprehensive error handling and flexible configuration.
