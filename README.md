# thousandeyes-ldap-monitor

Self-contained ThousandEyes transaction script that checks an LDAP or LDAPS server: connect, bind, a base-scope search and Root DSE checks. Each step is a ThousandEyes marker, so alert rules on marker durations catch slow steps.

> **Important:** ThousandEyes Transaction tests only support a single JavaScript file. While this repository contains multiple files for documentation, tests and Terraform, only `ldap-monitor.js` should be copied into the ThousandEyes platform.

## Overview

This repository contains a JavaScript monitoring script designed for ThousandEyes that:

- Performs an authenticated LDAPv3 simple bind
- Runs a base-scope search of the Root DSE, or of a base DN you configure
- Checks what the Root DSE reports: LDAPv3 support, Active Directory synchronization (`isSynchronized`), clock skew (`currentTime`), and optionally an expected naming context
- Warns in its log when the LDAPS server certificate expires soon
- Fails the run on any error, with a one-line message that starts with its class (`CONFIG`, `TCP`, `TLS`, `TIMEOUT`, `BIND`, `SEARCH`, `ROOTDSE`)
- Records each step as a ThousandEyes marker (`ldap-tcp-connect` or `ldaps-ssl-handshake`, `ldap-bind`, `ldap-search`). The script does not judge latency itself: alert rules on marker durations do, set with `marker_alert_thresholds_ms` in the Terraform (default 300 ms for `ldap-bind` and `ldap-search`)
- Supports LDAPS (TLS 1.2/1.3) on any port, and plain LDAP only when you opt in, because a simple bind sends the password as is
- Takes the server, port and search base from the test URL, so each test can monitor its own server

## Repository Structure

- **`ldap-monitor.js`** - The monitoring script (copy this to ThousandEyes)
- **`terraform/`** - Creates one test per server, plus the failure and latency alert rules ([terraform/README.md](terraform/README.md))
- **`test/`** - Test harness: unit tests against scripted LDAP responses, and an integration test against 389 Directory Server
- **`docs/DESIGN_DOCUMENT.md`** - Design for a multi-region deployment
- **`docs/MONITORING_GROUP_GUIDE.md`** - Setting up the monitoring role and user in the ThousandEyes UI
- **`docs/diagrams/`** - Generator for the architecture diagrams
- **`package.json`**, **`eslint.config.js`** - Development tooling

## Setup Instructions

Follow these steps to configure LDAP monitoring in the ThousandEyes UI. To create the tests with Terraform instead, see [Deploying with Terraform](#deploying-with-terraform).

### 1. Store Credentials Securely

**Navigation:** `Network & App Synthetics ▸ Test Settings ▸ Credentials Repository ▸ Add New Credential`

Create these two credentials:

**LDAP Bind User:**
- **Name:** `ldapMonUser`
- **Value:** Paste the full bind DN (e.g., `cn=monitor,ou=svc,dc=example,dc=com`)

**LDAP Bind Password:**
- **Name:** `ldapMonPass`
- **Value:** Paste the account's password

Add any optional credentials from the [Credentials](#credentials) table, for example `ldapCaBase64` when the server certificate comes from a private CA.

> **Security note:** Secure Credentials keep secrets out of the script, but they are not hidden from users or the API. Anyone with the **View sensitive data in web transaction scripts** permission can view credential values in the Credentials Repository and retrieve them through the ThousandEyes API. To block this for everyone, an administrator with the **Edit security & authentication settings** permission can enable **Disable global credential retrieval** under `Manage ▸ Account Settings ▸ Organization Settings ▸ Security and Authentication ▸ Credentials Repository`. We recommend enabling it. It overrides the view permission for every role, makes the Credentials Repository tab inactive for all users, and also stops ThousandEyes support staff from accessing credentials ([Working With Secure Credentials](https://docs.thousandeyes.com/product-documentation/browser-synthetics/transaction-tests/getting-started/working-with-secure-credentials)).

### 2. Create a New Test

**Navigation:** `Network & App Synthetics ▸ Test Settings ▸ Add New Test` (top-right)

In the "Add New Test" pane:
- Choose `Browser Synthetics → Transaction`
- Set the **URL** to the server as an LDAP URL (RFC 4516):
  - `ldaps://ldap.example.com/` for LDAPS on port 636, searching the Root DSE
  - `ldaps://dc01.example.com:3269/DC=example,DC=com` for another port, or to search a base DN
  - `ldap://ldap.example.com:389/` for plain LDAP (also set `ldapAllowCleartext`)
- Put special characters in the DN in percent-encoded form, for example `%26` for `&`. Attributes, scope and filter parts are not supported.
- If the URL field does not accept an LDAP URL, enter any other URL and set the `ldapHost` and `ldapPort` credentials instead

See [Target and search base](#target-and-search-base) for how the URL and the credentials combine.

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
   - **Optional:** `ldapCaBase64`, `ldapHost`, `ldapPort`, `ldapBaseDN`, `ldapAllowCleartext`, `ldapBindOnly`, `ldapExpectedNamingContext`, `ldapMaxClockSkewSeconds`, `ldapCertWarnDays`, `ldapRequireEntry`, `ldapDebugMode` (see the [Credentials](#credentials) table)
3. The script sees only the credentials attached to the test. An optional credential that exists but is not ticked here is silently ignored, and its default applies. With Terraform, put its ID in `credential_ids`
4. No plaintext credentials will ever appear in the script

### 5. Select Agents, Interval and Time Limit

**Agents dropdown** (just below the script):
- Select Enterprise Agent(s) that sit next to the LDAP server
- Optionally add Cloud Agents for outside-in checks
- **Interval:** 5 minutes is the Terraform default. A shorter interval detects outages sooner: with the default alert rule, an alert needs 2 failing rounds
- **Time limit:** 30 seconds is the default. ThousandEyes caps it at half the interval or 180 seconds, whichever is lower. The script stops about 10% earlier (at least 1 second) so that its own timeout message is reported

### 6. Configure Alerting

The script fails a run only on errors; a slow bind or search passes. Latency alerts need alert rules on marker durations. Terraform creates all of these rules and attaches them to every test. Without Terraform, create them as follows.

**Failure rule:**
1. `Manage ▸ Alert Rules`, **Cloud & Enterprise Agents** tab, add a rule with Alert Type **Web ▸ Transaction**
2. Under **Alert Conditions**, choose **Transaction**, add two conditions, one for a transaction that completes with an error and one for a transaction that times out, and set the rule to match **Any** of them (OR), not all. As an API or Terraform expression: `((txCompletionHasError == true) || (txCompletionTimedOut == true))`
3. Require 2 failing rounds out of 5 (Terraform's default), and add notifications
4. Associate the rule with the LDAP test(s) and agents, and enable alerts on the test

**Latency rules**, one per marker:
1. Add another **Web ▸ Transaction** rule
2. Under **Alert Conditions**, choose **Markers/Asserts**, select the marker `ldap-bind` by name, and alert when its duration is at least 300 ms. As an API or Terraform expression: `((marker[((markerName == "ldap-bind"))]((markerDuration >= 300 ms))))` ([alert rule metadata](https://developer.cisco.com/docs/thousandeyes/alert-rule-metadata/); the unit `ms` is part of the expression)
3. Repeat for `ldap-search`, and optionally for `ldaps-ssl-handshake` (LDAPS) or `ldap-tcp-connect` (plain LDAP). See [Markers](#markers)
4. Associate each rule with the LDAP test(s) and agents

> **Upgrading from a version with `slowMs`?** A slow bind or search no longer fails the run, so create the latency rules above to keep latency alerts. See [Upgrading from earlier versions](#upgrading-from-earlier-versions) for the other changes.

### 7. Test the Configuration

**Validation:**
1. Click `Validate` in Instant Test (right side)
2. The platform runs the script once
3. Check the console output for the `LDAP Monitor: PASS` line, or the failure message
4. No errors = successful configuration

### 8. Save and Deploy

Click `Create New Test` - data starts flowing immediately.

## Deploying with Terraform

`terraform/` creates one transaction test per LDAP server, each with an LDAP URL built from `hostname`, `port`, `tls` and `base_dn`, plus the failure alert rule and one latency alert rule per entry in `marker_alert_thresholds_ms`. It needs Terraform 1.9.3 or later ([terraform/README.md](terraform/README.md) gives the version `terraform test` needs) and pins the ThousandEyes provider to an exact version. The credentials are created outside Terraform and attached by ID (`credential_ids`), so their values stay out of Terraform state. Variables, examples and the alert expressions are in [terraform/README.md](terraform/README.md).

Terraform can optionally create a dedicated monitoring user with a least-privilege role (`monitoring_user`, `create_monitoring_role`); see [terraform/README.md](terraform/README.md#monitoring-user-and-role). With the defaults it creates neither, and its API token needs no Organization Admin: the seven monitoring permissions in the tests' account group are expected to be sufficient, though not yet verified against a live account. If the API rejects the test expand options, also grant View tags and View BGP monitors.

## Upgrading from earlier versions

Earlier versions of the script (those with `slowMs`) behaved differently in ways that can change a test's result:

- **Latency no longer fails the run.** `slowMs` (300 ms) is gone. Create latency alert rules on the markers (see [6. Configure Alerting](#6-configure-alerting)); Terraform creates them from `marker_alert_thresholds_ms`.
- **The search base moved from the bind DN to the Root DSE.** Earlier versions always searched the bind account's own entry. Now the search reads the Root DSE, unless the test URL has a DN path or, without a path, `ldapBaseDN` is set (see [Target and search base](#target-and-search-base)). To keep searching the account's entry, put its DN in the URL, for example `ldaps://ldap.example.com/cn=monitor,ou=svc,dc=example,dc=com`.
- **Root DSE checks can fail a run** with `ROOTDSE:`: a server clock more than 300 s from the agent clock, an Active Directory `isSynchronized` of `FALSE`, or a `supportedLDAPVersion` without 3. Set `ldapMaxClockSkewSeconds` to `0` (or higher) to turn off or relax the skew check. The checks run only on a Root DSE search, so a base DN (in the URL or `ldapBaseDN`) or `ldapBindOnly` skips all of them.
- **Plain LDAP is refused.** An `ldap://` URL or port 389 fails with `CONFIG:` unless `ldapAllowCleartext` is set.
- **The target comes from the test URL** when it is an `ldap://` or `ldaps://` URL; `ldapHost` and `ldapPort` are used only otherwise. With neither, the run fails with `CONFIG:` instead of trying `ldap.example.com`.
- **`ldapPort` is validated.** Anything but `389` or `636` fails with `CONFIG:`. Before, `abc` or `0` silently meant 636, and `389x` meant 389.
- **Only `ldapBaseDN` is read.** The spellings `ldapbasedn`, `LdapBaseDN`, `LDAPBASEDN`, `ldap_base_dn` and `LDAP_BASE_DN` are no longer read. They never had an effect: earlier versions searched the bind DN whatever the base DN credential said.
- **Failure messages changed.** Each now starts with its class (see [Failure classes](#failure-classes)). Update anything that matches on the old text, such as `Bind failed:` or `Slow bind:`.

## Script Configuration

The script reads its target from the test URL and everything else from **Secure Credentials**; nothing is configured by editing the script. Optional credentials override built-in defaults.

### Target and search base

1. **The test URL**, when it is an `ldap://` or `ldaps://` URL. The scheme selects TLS, the port defaults to 389 or 636, and the path decides the search base:
   - A `/` path is authoritative. `ldaps://ldap.example.com/` searches the Root DSE, even when the `ldapBaseDN` credential is set, and `ldaps://ldap.example.com/dc=example,dc=com` searches that DN.
   - No path (`ldaps://ldap.example.com`): `ldapBaseDN` if set, else the Root DSE.
2. **The `ldapHost` and `ldapPort` credentials**, when the test URL is not an LDAP URL. The port must be `636` (LDAPS, the default) or `389` (plain LDAP). The search base is `ldapBaseDN` if set, else the Root DSE. Credentials apply to the whole account group, so prefer the test URL when you monitor more than one server.

Terraform always builds a URL with a `/` path, so set `base_dn` there; an `ldapBaseDN` credential has no effect on those tests. With no server at all, the run fails with `CONFIG: no LDAP server configured. …`.

### Credentials

| Credential | Default | Effect |
|---|---|---|
| `ldapMonUser` | (required) | Full bind DN of the monitoring account |
| `ldapMonPass` | (required) | Its password |
| `ldapCaBase64` | system CAs | CA certificate(s) for LDAPS, as PEM text or base64-encoded PEM. See [CA Certificate Configuration](#ca-certificate-configuration) |
| `ldapHost`, `ldapPort` | (unset), `636` | Server and port when the test URL is not an LDAP URL. `ldapPort` must be `389` or `636`; anything else, including a value that is not a whole number, is a `CONFIG` error. See [Target and search base](#target-and-search-base) |
| `ldapBaseDN` | Root DSE | Search base when the test URL has no `/` path |
| `ldapAllowCleartext` | off | Allow the bind over plain LDAP. Without it, a plain-LDAP target fails with a `CONFIG` error before connecting (RFC 4513 section 5.1.3) |
| `ldapBindOnly` | off | Skip the search; the run passes after a successful bind |
| `ldapExpectedNamingContext` | (unset) | A DN the Root DSE must list in `namingContexts`, compared ignoring letter case and spaces around `,`, `=` and `+`; an escaped character such as `\,` stays part of the value, and a DN longer than 4096 characters matches nothing. Needs the Root DSE search: with a base DN or `ldapBindOnly`, the run fails with a `CONFIG` error rather than skipping the check |
| `ldapMaxClockSkewSeconds` | `300` | Most the Root DSE `currentTime` may differ from the agent clock (Kerberos' default tolerance). `0` turns the check off. A `currentTime` that is not a GeneralizedTime is not checked; debug mode logs that |
| `ldapCertWarnDays` | `30` | Log a warning when the LDAPS server certificate expires within this many days. `0` turns the warning off. The run still passes |
| `ldapRequireEntry` | off | Fail a search that returns no entry. See below |
| `ldapDebugMode` | off | Verbose output. See [Debug Mode](#debug-mode) |

On/off credentials (`ldapAllowCleartext`, `ldapBindOnly`, `ldapRequireEntry`) accept `true`, `1` or `yes` in any letter case; `ldapDebugMode` accepts exactly `true`. Number credentials (`ldapPort`, `ldapMaxClockSkewSeconds`, `ldapCertWarnDays`) must be whole numbers, or the run fails with a `CONFIG` error.

**Why `ldapRequireEntry` is opt-in:** a server may answer a base-scope search with success and no entry instead of `noSuchObject`. 389 Directory Server does this for a base DN that does not exist when the account can read only its own entry. So without `ldapRequireEntry`, a missing base DN can pass. Set it when the monitoring account can read the base entry, so that a missing or unreadable base DN fails the run.

### Fixed behaviour

These are built into the script:
- **Time budget:** the test's time limit (default 30 seconds). Every connect and read is bounded by it, and the script stops about 10% early (at least 1 second) so that its own timeout message is reported
- **Retries:** up to 2 retries of a failed connection, 100 ms apart, within the time limit. TLS and certificate errors are not retried
- **TLS:** minimum TLSv1.2. The server certificate is verified, and the host name is sent as SNI unless it is an IP address
- **Search:** base scope, filter `(objectClass=*)`, size limit 1, server time limit 5 seconds. The Root DSE search requests the five attributes the checks read; a base DN search requests no attributes (`1.1`)
- **Latency:** never fails the run. Alert rules on marker durations judge it (see [Monitoring Output](#monitoring-output))

## Monitoring Output

### Markers

Each step is a ThousandEyes marker, and alert rules on marker duration catch slow steps. In Terraform, `marker_alert_thresholds_ms` sets one rule per marker; `{}` creates no latency rules.

| Marker | Measures | Terraform default threshold |
|---|---|---|
| `ldap-bind` | Simple bind round trip | 300 ms |
| `ldap-search` | Base-scope search round trip (absent with `ldapBindOnly`) | 300 ms |
| `ldaps-ssl-handshake` | TCP connect and TLS handshake, across all attempts (LDAPS) | none |
| `ldap-tcp-connect` | TCP connect, across all attempts (plain LDAP) | none |

The connect markers are off by default because they span every connect attempt, and a TLS handshake from a distant agent can take longer than 300 ms. Each connect attempt also has its own `ldap-attempt-N` marker.

### Console output

A passing run ends with one summary line:

```
LDAP Monitor: PASS - Total 48ms (connect: 21ms, bind: 14ms, search: 13ms); certificate expires in 21 days; vendorVersion: 389-Directory/3.1.1
LDAP Monitor: PASS - Total 52ms (connect: 24ms, bind: 15ms, search: 13ms); clock skew: +1 s
LDAP Monitor: PASS (Bind-Only) - Total 35ms (connect: 21ms, bind: 14ms)
```

The notes after the timings appear only when they apply: `certificate expires in N days` when the LDAPS certificate expires within `ldapCertWarnDays`, and, from the Root DSE, `vendorVersion: …` and `clock skew: ±N s` when the server publishes `vendorVersion` and `currentTime` (Active Directory publishes `currentTime`).

Other lines: `Establishing LDAPS connection with …` and `TLS cipher: …; peer CN: …` for LDAPS, `Connection attempt N failed: …` for each failed connect attempt, `Certificate/TLS error on attempt N: …` before a `TLS:` failure, and `Warning: …` lines for a certificate that expires soon or a cleartext bind.

### Failure classes

A failed run throws one line that starts with its class; the console shows it as `Test failed: <message>`.

| Prefix | Meaning |
|---|---|
| `CONFIG:` | Missing or invalid configuration; nothing was sent |
| `TCP:` | The connection could not be opened (name lookup, refused, unreachable) |
| `TLS:` | The TLS handshake or certificate verification failed |
| `TIMEOUT:` | A connect or a server response took longer than the time limit allows |
| `BIND:`, `SEARCH:` | A protocol error during that operation, such as the server closing the connection |
| `BIND rc=N <name>:`, `SEARCH rc=N <name>:` | The server returned that LDAP result code, for example `BIND rc=49 invalidCredentials:`. A code the script does not know reads `BIND rc=N: Unknown LDAP result code (0x..)` |
| `ROOTDSE:` | The Root DSE reports a problem; every problem found is on the same line |

## Requirements

- ThousandEyes Enterprise or Cloud Agents
- LDAP server with monitoring account credentials
- Network connectivity from agents to LDAP server on configured port
- For `terraform/`: Terraform 1.9.3 or later and a ThousandEyes API token

## Troubleshooting

### Common Error Messages and Solutions

#### `CONFIG: missing credentials: ensure ldapMonUser and ldapMonPass are configured`
**Cause:** The required secure credentials are not properly configured or not accessible to the test.

**Solution:**
1. Verify credentials exist in `Network & App Synthetics ▸ Test Settings ▸ Credentials Repository`
2. Check that credential names match exactly: `ldapMonUser` and `ldapMonPass`
3. Verify credential access is enabled in the script editor (key icon), or that their IDs are in Terraform's `credential_ids`

#### Other `CONFIG:` messages
The message names the setting. The most common:
- `CONFIG: refusing to send the bind password to ldap.example.com:389 without TLS (RFC 4513 section 5.1.3). …` - use an `ldaps://` URL, or set `ldapAllowCleartext` to accept the risk
- `CONFIG: no LDAP server configured. …` - set the test URL to an LDAP URL, or set `ldapHost`
- `CONFIG: ldapExpectedNamingContext needs the Root DSE search, so it cannot be used with …` - remove the base DN from the URL (keep the trailing `/`), or remove `ldapBindOnly`
- `CONFIG: ldapCaBase64 holds no certificate; …` or `CONFIG: ldapCaBase64 holds an empty certificate block; paste the whole PEM certificate` - store the complete PEM certificate, from `-----BEGIN CERTIFICATE-----` to `-----END CERTIFICATE-----`, as text or base64-encoded

#### `TCP: connection to ldap.example.com:636 failed after 3 attempts: …`
**Cause:** Network connectivity issues, or the LDAP server is down. The text after the colon is the network error, for example a refused connection (`ECONNREFUSED`) or a failed name lookup (`ENOTFOUND`).

**Solution:**
1. Verify the host name and port in the test URL (or the `ldapHost` and `ldapPort` credentials)
2. Check firewall rules between the agent and the LDAP server
3. Test connectivity from the agent's network: `nc -vz ldap.example.com 636`

#### `TLS: handshake with ldap.example.com:636 failed: …`
**Cause:** The TLS handshake or certificate verification failed, usually because the certificate comes from a private CA. The text after "failed:" is the TLS library's reason, for example `self-signed certificate in certificate chain`. TLS errors are not retried.

**Solution:**
1. Store the CA certificate in the `ldapCaBase64` credential, as PEM text or base64-encoded (`base64 -w 0 ca-certificate.pem`)
2. Ensure the certificate chain is complete if using intermediate CAs
3. Check that the certificate names the host in the test URL
4. Verify TLS version compatibility (the script requires TLS 1.2 or later)
5. Enable debug mode (`ldapDebugMode: true`) to log which CA certificates are used

#### `TIMEOUT: …`
**Cause:** A connect or a server response did not arrive within the time limit, for example `TIMEOUT: connect to ldap.example.com:636 timed out after 26999 ms (attempt 1)` or `TIMEOUT: bind: waiting for the server response timed out after 1800 ms`.

**Solution:**
1. A connect timeout usually means a firewall drops the packets; check the path as for `TCP:`
2. A bind or search timeout means the server accepted the connection but did not answer; check the server's load and logs
3. Raise the test's time limit if the server is known to be slow

#### `BIND rc=49 invalidCredentials: …`
**Cause:** The bind DN or password is incorrect, or the account is locked or expired. The server's diagnostic message follows `server:`; for Active Directory, its `data` code says which.

**Solution:**
1. Verify the full bind DN format (e.g., `cn=monitor,ou=svc,dc=example,dc=com`)
2. Test the credentials with `ldapsearch` (see [Testing Outside ThousandEyes](#testing-outside-thousandeyes))
3. Ensure the account is not locked or expired

#### `BIND rc=50 insufficientAccessRights: …` or `SEARCH rc=50 insufficientAccessRights: …`
**Cause:** The monitoring account lacks a permission: to bind at all (some servers restrict which accounts may bind), or to read the search base.

**Solution:**
1. Verify the account may bind and has read access to the Root DSE or the base DN
2. Check the LDAP server's access control lists (ACLs)
3. Use bind-only mode (`ldapBindOnly`) if the account may not search

#### `SEARCH rc=32 noSuchObject: …`
**Cause:** The base DN does not exist. `matchedDN` in the message is the closest entry that does.

**Solution:** Correct the DN in the test URL (or `ldapBaseDN`). Percent-encode special characters.

#### `SEARCH: no entry returned for …`
**Cause:** `ldapRequireEntry` is set, and the search succeeded without an entry: the base DN may not exist, or the account may not be allowed to read it.

**Solution:** Check the DN and the account's read access, or remove `ldapRequireEntry` (see [Credentials](#credentials)).

#### `ROOTDSE: …`
**Cause:** The Root DSE reports a problem. Several can be on the same line, separated by `;`:
- `isSynchronized is FALSE: …` - an Active Directory domain controller that is not fully synchronized
- `supportedLDAPVersion lists … but not 3`
- `namingContexts does not include "…"; the server lists …` - the server does not hold `ldapExpectedNamingContext`
- `server clock is N s ahead of the agent clock …; the limit is 300 s (ldapMaxClockSkewSeconds)` - or `behind`; Kerberos fails beyond its tolerance

**Solution:** Fix the server, or for clock skew check NTP on both the server and the agent. Set `ldapMaxClockSkewSeconds` to `0` to turn the skew check off.

#### Latency alert `LDAP Slow ldap-bind (300 ms)`
**Cause:** A marker lasted at least its threshold. The run itself passed.

**Solution:**
1. Check LDAP server load and performance metrics
2. Compare agents: latency from one agent only points at the network path
3. If the latency is expected, raise the threshold in `marker_alert_thresholds_ms` (see [Adjusting Latency Thresholds](#adjusting-latency-thresholds))

#### `Warning: the server certificate … expires in N days, …`
**Cause:** The LDAPS server certificate expires within `ldapCertWarnDays`. The run still passes, and the PASS summary adds `certificate expires in N days`. Console output cannot raise an alert, so look for it in the test's console logs.

**Solution:** Renew the certificate, or set `ldapCertWarnDays` to change or turn off the warning.

### Performance Tuning

#### Adjusting Latency Thresholds
Latency alerts come from `marker_alert_thresholds_ms` in Terraform (default 300 ms for `ldap-bind` and `ldap-search`), not from the script. Base thresholds on the baseline you observe. Starting points:

- **Active Directory**: 400-500 ms
- **OpenLDAP**: 100-200 ms
- **Load-balanced setups**: tighter, 150-250 ms

```hcl
marker_alert_thresholds_ms = {
  "ldap-bind"           = 500
  "ldap-search"         = 500
  "ldaps-ssl-handshake" = 1000
}
```

Every test in one Terraform configuration carries the same latency rules. For different thresholds per server type, use separate configurations or workspaces. The configuration creates no account group, and the role and user are opt-in (`monitoring_user`, `create_monitoring_role`): enable them in one workspace only, or each workspace creates its own role.

#### Optimizing Search Operations
The search is kept small:
- It searches the Root DSE, which every LDAPv3 server provides, unless you configure a base DN
- Scope `base` (a single entry), filter `(objectClass=*)` and size limit 1
- From the Root DSE it requests only the five attributes the checks read: `namingContexts`, `supportedLDAPVersion`, `vendorVersion`, `isSynchronized` and `currentTime`
- From a base DN it requests no attributes (`1.1`): only the result code matters, and the entry may be the account's own
- Bind-only mode (`ldapBindOnly`) skips the search for restrictive environments

#### Troubleshooting with Debug Mode
Enable detailed logging with the `ldapDebugMode: true` credential to see:
- The target and where it came from (test URL or `ldapHost`), and the search base
- Whether custom or system CA certificates are used, and the server certificate's expiry date
- Bind and search round-trip times and result codes, and the search's base, filter and attributes
- The five requested Root DSE attributes, as the server returned them, and whether `currentTime` could not be parsed

### Testing Outside ThousandEyes

Before deploying to ThousandEyes, test your LDAP configuration locally using the same values you'll configure in secure credentials:

```bash
# Test LDAP bind (non-TLS) - substitute your actual values
ldapsearch -x -H ldap://[your-ldapHost]:389 \
  -D "[your-ldapMonUser]" \
  -w "[your-ldapMonPass]" \
  -b "" -s base "(objectClass=*)" \
  namingContexts supportedLDAPVersion vendorVersion isSynchronized currentTime

# Test LDAPS bind (TLS) - substitute your actual values
ldapsearch -x -H ldaps://[your-ldapHost]:636 \
  -D "[your-ldapMonUser]" \
  -w "[your-ldapMonPass]" \
  -b "" -s base "(objectClass=*)" \
  namingContexts supportedLDAPVersion vendorVersion isSynchronized currentTime

# Test with a base DN, as in the test URL or the ldapBaseDN credential
ldapsearch -x -H ldaps://[your-ldapHost]:636 \
  -D "[your-ldapMonUser]" \
  -w "[your-ldapMonPass]" \
  -b "[your-base-DN]" -s base "(objectClass=*)" 1.1
```

Replace the bracketed placeholders with the actual values you'll store in your secure credentials.

## Advanced Configuration

### LDAP Server-Specific Settings

Example test URLs for common servers. Add `ldapCaBase64` when the server certificate comes from a private CA.

#### Active Directory
```
ldaps://dc01.example.com/DC=example,DC=com        domain controller
ldaps://dc01.example.com:3269/                    global catalog over TLS
```

For a domain controller, the Root DSE checks are the most useful: set `ldapExpectedNamingContext` to the domain DN (for example `DC=example,DC=com`) and use a Root DSE URL, so that `isSynchronized` and clock skew are checked as well.

#### OpenLDAP, 389 Directory Server / Red Hat Directory Server, NetIQ eDirectory
```
ldaps://ldap.example.com/                         Root DSE
ldaps://ldap.example.com/dc=example,dc=com        a naming context
```

### Special Operating Modes

#### Debug Mode
Enable verbose debugging output to troubleshoot connectivity issues:
```
ldapDebugMode: true
```
The value must be exactly `true`. See [Troubleshooting with Debug Mode](#troubleshooting-with-debug-mode) for what it logs.

#### Bind-Only Mode
For LDAP servers that have restrictive search permissions or non-standard search responses, you can test only the bind operation:
```
ldapBindOnly: true
```
This mode skips the search operation and reports success after a successful bind, making it compatible with more restrictive LDAP configurations. The Root DSE checks are skipped too.

### CA Certificate Configuration

For LDAPS connections with self-signed or custom CA certificates:

1. Obtain your CA certificate in PEM format
2. Store it in the `ldapCaBase64` credential as PEM text, or base64-encoded: `base64 -w 0 ca-certificate.pem`
3. Line breaks that the credential field turns into spaces are restored
4. The script supports certificate chains (multiple certificates in one PEM file)

### Monitoring Multiple LDAP Servers

To monitor multiple LDAP servers:

1. Create separate tests for each server, each with that server's LDAP URL as the test URL. The credentials can be shared. Terraform does this from its `ldap_servers` list.
2. Use descriptive test names (e.g., "LDAP Monitor - DC01", "LDAP Monitor - DC02")
3. Configure appropriate agents near each server
4. Set up alert rules that consider your redundancy setup

### Integration with Alert Management

Best practices for alerting:

1. **Alert Fatigue Prevention**
   - Set latency thresholds based on baseline performance
   - Require more than one failing round to avoid transient issues (Terraform's default is 2 of 5)
   - Configure maintenance windows for planned outages

2. **Escalation Policies**
   - Primary alerts: Operations team
   - Escalation after 15 minutes: Infrastructure team
   - Include LDAP server details in alert notifications

3. **Alert Correlation**
   - Group LDAP alerts by data center or region
   - Correlate with application alerts that depend on LDAP

## Development and Testing

The test harness runs the deployable `ldap-monitor.js` unmodified under Node, with a local stand-in for the ThousandEyes `thousandeyes` module. Requires Node.js 22.15 or later.

```bash
npm ci
npm test                  # scripted LDAP server scenarios, no network access needed
npm run test:integration  # real 389 Directory Server container (podman or docker)
npm run lint
```

- `test/support/thousandeyes-stub.js` is the stand-in runtime. It follows documented ThousandEyes behaviour: markers throw when restarted or stopped twice, `test.getSettings().timeout` is in seconds, and credentials must be associated with the test. Where the vendor docs are silent, it makes the assumptions listed at the top of the file: `socket.read()` at end of stream, `socket.setTimeout()`, and TLS sockets with `getCipher()` and `getPeerCertificate()` as in Node's `tls` module. Its `peerCertificate` option (`'absent'`, `'throws'`, or a certificate object) covers a runtime without `getPeerCertificate()`, which the script feature-detects. Confirm those with the real-agent validation workflow (`runtime_facts` input); see docs/REAL_AGENT_VALIDATION.md.
- `test/support/fake-ldap-server.js` plays back scripted LDAP responses, such as long-form BER lengths, split TCP segments, a Notice of Disconnection, and slow replies.
- Tests marked `todo` describe the correct behaviour for a known bug. They fail today without failing the run. Remove `todo` in the change that fixes the bug.
- CI (`.github/workflows/ci.yml`) runs lint, `npm run validate` and unit tests on Node 22 and 24, the 389 DS integration test, and `terraform fmt -check`, `terraform validate` and `terraform test`.
- `.github/workflows/real-agent-validation.yml` runs `ldap-monitor.js` once on a real ThousandEyes agent as a web-transaction instant test (manual or nightly; never on pull requests). It skips until it is configured. Set-up and the stub assumptions it checks: [docs/REAL_AGENT_VALIDATION.md](docs/REAL_AGENT_VALIDATION.md).

## Contributing

To contribute improvements to this monitoring script:

1. Run `npm run lint`, `npm test` and `npm run test:integration`, and `terraform test` in `terraform/` for Terraform changes
2. Document any new configuration options in the [Credentials](#credentials) table
3. Include examples for different LDAP server types
4. Submit pull requests with clear descriptions

## Security Considerations

- Never commit credentials to version control
- Use ThousandEyes Secure Credentials for all sensitive data, and enable **Disable global credential retrieval** so that their values cannot be read back in the web app or through the API (see [1. Store Credentials Securely](#1-store-credentials-securely))
- Regularly rotate monitoring account passwords
- Use a read-only account with minimal permissions: it needs only to bind and to read the Root DSE or the base entry
- Enable LDAPS (TLS) for encrypted communications (supports TLS 1.2 and 1.3). The script refuses a bind over plain LDAP unless `ldapAllowCleartext` is set
- Monitor from trusted network segments when possible

## License

This monitoring script is provided as-is for use with ThousandEyes platform.
