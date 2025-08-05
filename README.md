# thousandeyes-ldap-monitor

Self-contained ThousandEyes script that performs an LDAP/LDAPS bind + search and alerts on latency.

> **Important:** ThousandEyes Transaction tests only support a single JavaScript file. While this repository contains multiple files for documentation and examples, only `ldap-monitor.js` should be copied into the ThousandEyes platform.

## Overview

This repository contains a JavaScript monitoring script designed for ThousandEyes that:

- Performs authenticated LDAPv3 simple bind operations
- Executes fast base-scope searches against Root DSE
- Measures and reports round-trip times for both operations
- Alerts when operations exceed configurable thresholds (default: 300ms)
- Supports both LDAP (port 389) and LDAPS (port 636) with TLS 1.2/1.3

## Repository Structure

While ThousandEyes only supports single-file scripts, this repository includes additional files for better maintainability and documentation:

- **`ldap-monitor.js`** - The main monitoring script (copy this to ThousandEyes)
- **`ldap-monitor-config.example.js`** - Example configurations for different LDAP server types (reference only)
- **`docs/README.md`** - Setup instructions and documentation
- **`package.json`** - Project metadata
- **`.gitignore`** - Version control configuration

The example configuration file shows different settings for various LDAP implementations (Active Directory, OpenLDAP, etc.) that you can reference when modifying the settings in the main script.

## Setup Instructions

Follow these steps to configure LDAP monitoring in ThousandEyes:

### 1. Store Credentials Securely

**Navigation:** `Settings ▸ Secure Credentials ▸ Add Credential`

#### Required Credentials

Create these secure credential entries:

**LDAP Bind User:**
- **Name:** `ldapMonUser`
- **Value:** Paste the full bind DN (e.g., `cn=monitor,ou=svc,dc=example,dc=com`)
- **Agent Access:** Tick the Enterprise (and/or Cloud) Agents that will run the test

**LDAP Bind Password:**
- **Name:** `ldapMonPass`
- **Value:** Paste the account's password
- **Agent Access:** Tick the same agents selected for ldapMonUser

**CA Certificate (LDAPS only):**
- **Name:** `ldapCaBase64`
- **Value:** Base64-encoded CA certificate(s) for LDAPS connections with self-signed or custom certificates
- **Agent Access:** Tick the same agents (only needed if using custom certificates with LDAPS)
- **Note:** Leave empty or omit if using system CA certificates

#### Optional Configuration Credentials

These credentials can override the default values:

**LDAP Server Hostname:**
- **Name:** `ldapHost`
- **Value:** LDAP server hostname or IP address (default: `ldap.example.com`)

**LDAP Server Port:**
- **Name:** `ldapPort`
- **Value:** LDAP server port number (default: `636` for LDAPS, use `389` for LDAP)

**Base DN for Search:**
- **Name:** `ldapBaseDN` (or alternatives: `ldapbasedn`, `LdapBaseDN`, `LDAPBASEDN`, `ldap_base_dn`, `LDAP_BASE_DN`)
- **Value:** Base DN for search operations (default: uses bind DN for base scope search)
- **Note:** Leave empty to search Root DSE

**Debug Mode:**
- **Name:** `ldapDebugMode`
- **Value:** Set to `true` for verbose debugging output (default: `false`)

**Bind-Only Mode:**
- **Name:** `ldapBindOnly`
- **Value:** Set to `true`, `1`, or `yes` to skip search operations and only test bind (default: `false`)

> **Security Note:** Secure Credential entries are encrypted at rest and never appear in screenshots, reports, or API payloads.

### 2. Create a New Test

**Navigation:** `Test Settings → Add New Test` (top-right)

In the "Add New Test" pane:
- Choose `Browser Synthetics → Transaction`

### 3. Add the Monitoring Script

In the Steps panel:
1. Click `Script` (looks like `{ }`)
2. Delete the stub Selenium code
3. Copy the **entire contents** of `ldap-monitor.js` and paste it into the editor
   - Note: Only use the main script file - ThousandEyes doesn't support multiple files or imports

### 4. Configure Credential Access

In the Script editor:
1. Click the key icon above the editor
2. Tick all credentials you've configured:
   - **Required:** `ldapMonUser` and `ldapMonPass`
   - **Optional:** `ldapCaBase64`, `ldapHost`, `ldapPort`, `ldapBaseDN`, `ldapDebugMode`, `ldapBindOnly`
3. Only select credentials you've actually created - the script will use defaults for missing optional credentials
4. No plaintext credentials will ever appear in the script

### 5. Select Agents and Monitoring Frequency

**Agents dropdown** (just below the script):
- Select Enterprise Agent(s) that sit next to the LDAP server
- Optionally add Cloud Agents for outside-in checks
- Leave Interval at 1 minute unless lighter sampling is needed

### 6. Configure Alerting

**Navigation:** `Alerts → Enable`

Options:
- Re-use an existing Transaction alert rule, or
- Create a new rule that triggers on `Test status = Fail` for 3 consecutive rounds

### 7. Test the Configuration

**Validation:**
1. Click `Validate` in Instant Test (right side)
2. The platform runs the script once
3. Check Console output for bind + search RTT
4. No errors = successful configuration

### 8. Save and Deploy

Click `Create New Test` - data starts flowing immediately.

## Script Configuration

The script uses **Secure Credentials** for all configuration instead of hardcoded values. This provides better security and easier management across multiple tests.

### Configuration Method

All settings are configured through ThousandEyes Secure Credentials:
- **Required credentials** must be configured for the script to work
- **Optional credentials** override built-in defaults when provided
- Missing optional credentials will use sensible defaults

### Default Values

When optional credentials are not provided, the script uses these defaults:
- **Host:** `ldap.example.com` (override with `ldapHost` credential)
- **Port:** `636` for LDAPS (override with `ldapPort` credential)
- **Timeout:** Test timeout from ThousandEyes (typically 5000ms)
- **Slow threshold:** `300ms` for both bind and search operations
- **Base DN:** Uses bind DN for base scope search (override with `ldapBaseDN` credential)
- **Retry attempts:** 2 with 100ms delay between attempts
- **TLS version:** Minimum TLSv1.2 for LDAPS connections
- **Debug mode:** Disabled (enable with `ldapDebugMode=true` credential)
- **Bind-only mode:** Disabled (enable with `ldapBindOnly=true` credential)

## Monitoring Output

The script provides console output showing:
- `Bind RTT: X ms` - Time taken for authentication
- `Search RTT: X ms` - Time taken for directory search

The script will throw errors (causing test failure) if:
- Bind fails due to bad credentials or connectivity issues
- Search fails due to unexpected LDAP responses
- Either operation exceeds the configured `slowMs` threshold

## Requirements

- ThousandEyes Enterprise or Cloud Agents
- LDAP server with monitoring account credentials
- Network connectivity from agents to LDAP server on configured port

## Troubleshooting

### Common Error Messages and Solutions

#### "Missing credentials: Ensure ldapMonUser and ldapMonPass are configured"
**Cause:** The required secure credentials are not properly configured or not accessible to the agent.

**Solution:**
1. Verify credentials exist in `Settings ▸ Secure Credentials`
2. Ensure the agent running the test has access to both required credentials
3. Check that credential names match exactly: `ldapMonUser` and `ldapMonPass`
4. Verify credential access is enabled in the script editor (key icon)
5. For LDAPS with custom certificates, ensure `ldapCaBase64` credential is properly configured

#### "Connection failed after X attempts"
**Cause:** Network connectivity issues or LDAP server is down.

**Solution:**
1. Verify the LDAP server hostname/IP and port are correct (use `ldapHost` and `ldapPort` credentials to override defaults)
2. Check firewall rules between the agent and LDAP server
3. For LDAPS (port 636), ensure TLS certificates are valid
4. Test connectivity manually: `telnet ldap.example.com 636`
5. Verify TLS version compatibility (script requires TLS 1.2 minimum, supports 1.3)

#### "TLS/Certificate validation failed"
**Cause:** LDAPS certificate validation failed due to self-signed or custom CA certificates.

**Solution:**
1. For self-signed certificates, configure the `ldapCaBase64` credential with your CA certificate
2. Convert your CA certificate to base64: `base64 -w 0 ca-certificate.pem`
3. Store the entire base64 string in the `ldapCaBase64` secure credential
4. Ensure the certificate chain is complete if using intermediate CAs
5. Enable debug mode (`ldapDebugMode: true`) to see detailed TLS handshake information

#### "Bind failed: invalidCredentials"
**Cause:** The bind DN or password is incorrect.

**Solution:**
1. Verify the full bind DN format (e.g., `cn=monitor,ou=svc,dc=example,dc=com`)
2. Check for special characters in the password that may need escaping
3. Test credentials manually using `ldapsearch` or similar tool
4. Ensure the account is not locked or expired

#### "Bind failed: insufficientAccessRights"
**Cause:** The monitoring account lacks necessary permissions.

**Solution:**
1. Verify the account has read access to the Root DSE
2. Check LDAP server access control lists (ACLs)
3. Contact your LDAP administrator to verify account permissions

#### "Slow bind: X ms (>300ms threshold)"
**Cause:** LDAP server performance issues or network latency.

**Solution:**
1. Increase the `slowMs` threshold if this is expected behavior
2. Check LDAP server load and performance metrics
3. Verify network latency between agent and LDAP server
4. Consider using a closer agent or optimizing LDAP server

### Performance Tuning

#### Adjusting Thresholds
Different LDAP implementations have different performance characteristics. The default 300ms threshold works well for most environments, but you may need to adjust based on your setup:

- **Active Directory**: May require higher thresholds (400-500ms)
- **OpenLDAP**: Typically faster (100-200ms)  
- **Load Balanced setups**: Should have tighter SLAs (150-250ms)

#### Optimizing Search Operations
The script automatically optimizes search operations by:
- Using the bind DN as the search base for maximum compatibility
- Limiting search scope to `base` (single entry lookup)
- Using simple present filters (`objectClass=*`)
- Supporting bind-only mode (`ldapBindOnly: true`) for restrictive environments

#### Troubleshooting with Debug Mode
Enable detailed logging with the `ldapDebugMode: true` credential to see:
- Connection establishment details
- TLS handshake information (cipher, certificates)
- LDAP request/response timing and parsing
- BER encoding/decoding operations
- Vendor-specific response handling

### Testing Outside ThousandEyes

Before deploying to ThousandEyes, test your LDAP configuration locally using the same values you'll configure in secure credentials:

```bash
# Test LDAP bind (non-TLS) - substitute your actual values
ldapsearch -x -H ldap://[your-ldapHost]:389 \
  -D "[your-ldapMonUser]" \
  -w "[your-ldapMonPass]" \
  -b "" -s base "(objectClass=*)"

# Test LDAPS bind (TLS) - substitute your actual values  
ldapsearch -x -H ldaps://[your-ldapHost]:636 \
  -D "[your-ldapMonUser]" \
  -w "[your-ldapMonPass]" \
  -b "" -s base "(objectClass=*)"

# Test with custom base DN if using ldapBaseDN credential
ldapsearch -x -H ldaps://[your-ldapHost]:636 \
  -D "[your-ldapMonUser]" \
  -w "[your-ldapMonPass]" \
  -b "[your-ldapBaseDN]" -s base "(objectClass=*)"
```

Replace the bracketed placeholders with the actual values you'll store in your secure credentials.

## Advanced Configuration

### LDAP Server-Specific Settings

Different LDAP implementations may require specific configurations. Use secure credentials to customize the monitoring for your environment:

#### Active Directory
```
ldapHost: dc01.corp.example.com
ldapPort: 636
ldapBaseDN: DC=corp,DC=example,DC=com
ldapCaBase64: <base64-encoded-ca-cert> (if using custom certificates)
```

#### OpenLDAP
```
ldapHost: openldap.example.com
ldapPort: 636
ldapBaseDN: dc=example,dc=com
```

#### Oracle Directory Server / Red Hat Directory Server
```
ldapHost: rhds.example.com
ldapPort: 636
ldapBaseDN: dc=example,dc=com
ldapBindOnly: true (recommended for compatibility)
```

### Special Operating Modes

#### Debug Mode
Enable verbose debugging output to troubleshoot connectivity issues:
```
ldapDebugMode: true
```
This will log detailed information about connection attempts, TLS handshakes, and LDAP response parsing.

#### Bind-Only Mode
For LDAP servers that have restrictive search permissions or non-standard search responses, you can test only the bind operation:
```
ldapBindOnly: true
```
This mode skips the search operation and reports success after a successful bind, making it compatible with more restrictive LDAP configurations.

### CA Certificate Configuration

For LDAPS connections with self-signed or custom CA certificates, provide the certificate in base64 format:

1. Obtain your CA certificate in PEM format
2. Convert to base64: `base64 -w 0 ca-certificate.pem`
3. Store the base64 string in the `ldapCaBase64` credential
4. The script supports certificate chains (multiple certificates in one PEM file)

### Configuration Examples

Instead of modifying the script code, configure everything through secure credentials. This approach provides better security and easier management across multiple tests.

### Monitoring Multiple LDAP Servers

To monitor multiple LDAP servers:

1. Create separate tests for each server
2. Use descriptive test names (e.g., "LDAP Monitor - DC01", "LDAP Monitor - DC02")
3. Configure appropriate agents near each server
4. Set up alert rules that consider your redundancy setup

### Integration with Alert Management

Best practices for alerting:

1. **Alert Fatigue Prevention**
   - Set appropriate thresholds based on baseline performance
   - Use consecutive round failures (3+) to avoid transient issues
   - Configure maintenance windows for planned outages

2. **Escalation Policies**
   - Primary alerts: Operations team
   - Escalation after 15 minutes: Infrastructure team
   - Include LDAP server details in alert notifications

3. **Alert Correlation**
   - Group LDAP alerts by data center or region
   - Correlate with application alerts that depend on LDAP

## Contributing

To contribute improvements to this monitoring script:

1. Test changes thoroughly in your environment
2. Document any new configuration options
3. Include examples for different LDAP server types
4. Submit pull requests with clear descriptions

## Security Considerations

- Never commit credentials to version control
- Use ThousandEyes Secure Credentials for all sensitive data
- Regularly rotate monitoring account passwords
- Use read-only accounts with minimal permissions
- Enable LDAPS (TLS) for encrypted communications (supports TLS 1.2 and 1.3)
- Monitor from trusted network segments when possible

## License

This monitoring script is provided as-is for use with ThousandEyes platform.
