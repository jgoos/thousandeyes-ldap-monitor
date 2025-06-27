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
- **`README.md`** - Setup instructions and documentation
- **`CHANGELOG.md`** - Version history and improvements
- **`package.json`** - Project metadata
- **`.gitignore`** - Version control configuration

The example configuration file shows different settings for various LDAP implementations (Active Directory, OpenLDAP, etc.) that you can reference when modifying the settings in the main script.

## Setup Instructions

Follow these steps to configure LDAP monitoring in ThousandEyes:

### 1. Store Credentials Securely

**Navigation:** `Settings ▸ Secure Credentials ▸ Add Credential`

Create two secure credential entries:

**First Credential:**
- **Name:** `ldapMonUser`
- **Value:** Paste the full bind DN (e.g., `cn=monitor,ou=svc,dc=example,dc=com`)
- **Agent Access:** Tick the Enterprise (and/or Cloud) Agents that will run the test

**Second Credential:**
- **Name:** `ldapMonPass`
- **Value:** Paste the account's password
- **Agent Access:** Tick the same agents selected for ldapMonUser

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
2. Tick `ldapMonUser` and `ldapMonPass` to allow `credentials.get()` to access them at runtime
3. No plaintext credentials will ever appear in the script

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

The script includes user-tunable settings at the top:

```javascript
const host      = 'ldap.example.com';  // FQDN or IP
const port      = 636;                 // 389 = LDAP, 636 = LDAPS
const timeoutMs = 5000;                // socket timeout
const slowMs    = 300;                 // alert threshold in ms
const baseDN    = '';                  // '' = Root DSE (fastest search)
const filter    = '(objectClass=*)';   // match-all filter
const tlsMinVersion = 'TLSv1.2';      // minimum TLS version (supports 1.2, 1.3)
```

Modify these values according to your LDAP server configuration before deploying.

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
**Cause:** The secure credentials are not properly configured or not accessible to the agent.

**Solution:**
1. Verify credentials exist in `Settings ▸ Secure Credentials`
2. Ensure the agent running the test has access to both credentials
3. Check that credential names match exactly: `ldapMonUser` and `ldapMonPass`

#### "Connection failed after X attempts"
**Cause:** Network connectivity issues or LDAP server is down.

**Solution:**
1. Verify the LDAP server hostname/IP and port are correct
2. Check firewall rules between the agent and LDAP server
3. For LDAPS (port 636), ensure TLS certificates are valid
4. Test connectivity manually: `telnet ldap.example.com 636`
5. Verify TLS version compatibility (script requires TLS 1.2 minimum, supports 1.3)

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
Different LDAP implementations have different performance characteristics:

- **Active Directory**: May require higher thresholds (400-500ms)
- **OpenLDAP**: Typically faster (100-200ms)
- **Load Balanced setups**: Should have tighter SLAs (150-250ms)

#### Optimizing Search Operations
- Use Root DSE (`baseDN = ''`) for fastest response times
- Limit search scope to `base` (already configured)
- Use simple filters like `(objectClass=*)`

### Testing Outside ThousandEyes

Before deploying to ThousandEyes, test your LDAP configuration locally:

```bash
# Test LDAP bind (non-TLS)
ldapsearch -x -H ldap://ldap.example.com:389 \
  -D "cn=monitor,ou=svc,dc=example,dc=com" \
  -w "password" \
  -b "" -s base "(objectClass=*)"

# Test LDAPS bind (TLS)
ldapsearch -x -H ldaps://ldap.example.com:636 \
  -D "cn=monitor,ou=svc,dc=example,dc=com" \
  -w "password" \
  -b "" -s base "(objectClass=*)"
```

## Advanced Configuration

### Using the Example Configuration File

This repository includes `ldap-monitor-config.example.js` with pre-configured templates for common LDAP servers. Since ThousandEyes doesn't support file imports, you'll need to:

1. Open `ldap-monitor-config.example.js` to review example configurations
2. Copy the relevant settings from the example that matches your LDAP server type
3. Manually update the configuration values at the top of `ldap-monitor.js`
4. Paste the modified script into ThousandEyes

For example, if you're monitoring Active Directory, you might update your script settings to:
```javascript
const host      = 'dc01.corp.example.com';
const port      = 636;
const timeoutMs = 5000;
const slowMs    = 500;  // AD can be slower
const baseDN    = 'DC=corp,DC=example,DC=com';
```

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
