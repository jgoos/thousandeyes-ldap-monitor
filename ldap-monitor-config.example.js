/**
 * LDAP Monitoring Configuration Examples
 * 
 * IMPORTANT: The enhanced ldap-monitor.js script uses ThousandEyes Secure Credentials
 * for all configuration. These examples show the credential names and values to use.
 * 
 * Do NOT modify the script directly - configure via Secure Credentials instead.
 */

// =============================================================================
// BASIC LDAPS MONITORING
// =============================================================================
const basicLdapsCredentials = {
  // Required credentials
  ldapHost: 'ldap.example.com',                    // Server hostname or IP
  ldapMonUser: 'cn=monitor,ou=svc,dc=example,dc=com', // Full bind DN
  ldapMonPass: 'your-secure-password',             // Authentication password
  
  // Optional credentials (defaults shown)
  ldapPort: '636',                                 // 389=LDAP, 636=LDAPS (default)
  ldapBaseDN: '',                                  // Empty = Root DSE (fastest)
  ldapFilter: '(objectClass=*)',                   // Default presence filter
  // ldapAttrs: 'cn,mail',                         // Specific attributes (optional)
  // ldapBindOnly: 'true',                         // Auth only, skip search (optional)
  // ldapCaBase64: 'LS0tLS1CRUdJTi...',            // Self-signed cert support (optional)
};

// =============================================================================
// ACTIVE DIRECTORY CONFIGURATION
// =============================================================================
const activeDirectoryCredentials = {
  // Required credentials
  ldapHost: 'dc01.corp.example.com',
  ldapMonUser: 'cn=ldap-monitor,ou=Service Accounts,dc=corp,dc=example,dc=com',
  ldapMonPass: 'AD-monitoring-password',
  
  // Active Directory optimizations
  ldapBaseDN: 'dc=corp,dc=example,dc=com',         // Domain base DN
  ldapFilter: '(sAMAccountName=*)',                // AD-specific filter
  ldapAttrs: 'sAMAccountName,displayName,mail',    // Common AD attributes
  
  // Performance considerations for AD
  // Default 300ms threshold may need adjustment for slower AD responses
};

// =============================================================================
// OPENLDAP CONFIGURATION
// =============================================================================
const openLdapCredentials = {
  // Required credentials
  ldapHost: 'ldap.openldap.org',
  ldapMonUser: 'cn=monitor,dc=openldap,dc=org',
  ldapMonPass: 'openldap-password',
  
  // OpenLDAP optimizations
  ldapBaseDN: 'ou=People,dc=openldap,dc=org',      // People organizational unit
  ldapFilter: '(uid=*)',                           // Unix user ID filter
  ldapAttrs: 'uid,cn,mail,telephoneNumber',        // Common POSIX attributes
  
  // OpenLDAP typically faster than AD
  // Default 300ms threshold usually appropriate
};

// =============================================================================
// HIGH-PERFORMANCE AUTHENTICATION CHECK
// =============================================================================
const bindOnlyCredentials = {
  // Required credentials
  ldapHost: 'auth.example.com',
  ldapMonUser: 'cn=auth-check,ou=monitoring,dc=example,dc=com',
  ldapMonPass: 'auth-only-password',
  
  // Performance optimization - skip search entirely
  ldapBindOnly: 'true',                            // ~50% faster execution
  
  // Use for:
  // - Load balancer health checks
  // - High-frequency monitoring (every 30 seconds)
  // - Authentication-only validation
};

// =============================================================================
// SELF-SIGNED CERTIFICATE SUPPORT
// =============================================================================
const selfSignedCertCredentials = {
  // Required credentials
  ldapHost: 'internal-ldap.company.local',
  ldapMonUser: 'cn=monitor,dc=company,dc=local',
  ldapMonPass: 'internal-password',
  
  // Self-signed certificate support
  ldapCaBase64: 'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0t...', // Base64-encoded CA certificate
  
  // How to get your certificate:
  // 1. Extract: openssl s_client -connect server:636 -showcerts
  // 2. Save certificate part to file.pem
  // 3. Encode: base64 -i file.pem | tr -d '\n'
  // 4. Use result as ldapCaBase64 value
};

// =============================================================================
// MULTI-FOREST ACTIVE DIRECTORY
// =============================================================================
const multiForestAdCredentials = {
  // Forest 1 (corp.example.com)
  forest1: {
    ldapHost: 'dc01.corp.example.com',
    ldapMonUser: 'cn=ldap-monitor,ou=Service Accounts,dc=corp,dc=example,dc=com',
    ldapMonPass: 'corp-password',
    ldapBaseDN: 'dc=corp,dc=example,dc=com',
    ldapFilter: '(sAMAccountName=*)',
  },
  
  // Forest 2 (emea.example.com)
  forest2: {
    ldapHost: 'dc01.emea.example.com',
    ldapMonUser: 'cn=ldap-monitor,ou=Service Accounts,dc=emea,dc=example,dc=com',
    ldapMonPass: 'emea-password',
    ldapBaseDN: 'dc=emea,dc=example,dc=com',
    ldapFilter: '(sAMAccountName=*)',
  }
  
  // NOTE: Create separate ThousandEyes tests for each forest
  // Use descriptive test names: "LDAP Health - Corp Forest", "LDAP Health - EMEA Forest"
};

// =============================================================================
// LDAP OVER NON-STANDARD PORT
// =============================================================================
const nonStandardPortCredentials = {
  // Required credentials
  ldapHost: 'ldap.special.example.com',
  ldapMonUser: 'cn=monitor,dc=special,dc=example,dc=com',
  ldapMonPass: 'special-password',
  
  // Non-standard port configuration
  ldapPort: '11636',                               // Custom LDAPS port
  
  // Ensure firewall allows outbound access to custom port from ThousandEyes agents
};

// =============================================================================
// DEPLOYMENT CHECKLIST
// =============================================================================
/* 
BEFORE DEPLOYING TO THOUSANDEYES:

1. ✅ TEST CONNECTIVITY
   ldapsearch -x -H ldaps://your-server:636 -D "your-bind-dn" -W -b "" -s base "(objectClass=*)"

2. ✅ CREATE SECURE CREDENTIALS
   - Navigate to Settings ▸ Secure Credentials ▸ Add Credential
   - Create credentials with exact names shown above (case-sensitive)
   - Grant access to the Enterprise Agents that will run the test

3. ✅ SCRIPT DEPLOYMENT
   - Copy entire contents of ldap-monitor.js to ThousandEyes Transaction test
   - Enable credential access in script editor (🔐 icon)
   - Select required credentials: ldapHost, ldapMonUser, ldapMonPass
   - Select optional credentials as needed

4. ✅ VALIDATION
   - Click "Validate" to test configuration
   - Check console output for successful bind and search
   - Verify no error messages in output

5. ✅ PRODUCTION DEPLOYMENT
   - Set 1-minute interval for real-time monitoring
   - Configure alerting for test failures
   - Monitor initially to establish baseline performance

PERFORMANCE BENCHMARKS:
- Bind-only mode: ~50-150ms
- With search: ~100-300ms  
- Threshold alerts: >300ms default

*/ 