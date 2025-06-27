/**
 * Example configuration for LDAP monitoring
 * Copy this file and customize for your environment
 */

// Basic LDAP server configuration
export const ldapConfig = {
  // Primary LDAP server
  host: 'ldap.example.com',        // FQDN or IP address
  port: 636,                       // 389 for LDAP, 636 for LDAPS
  
  // Performance thresholds
  timeoutMs: 5000,                 // Socket timeout in milliseconds
  slowMs: 300,                     // Alert threshold for slow operations
  
  // Retry configuration
  retryDelayMs: 100,               // Delay between retry attempts
  maxRetries: 2,                   // Maximum number of retry attempts
  
  // Search parameters
  baseDN: '',                      // Base DN for search ('' = Root DSE)
  filter: '(objectClass=*)',       // LDAP search filter
  
  // TLS options (for LDAPS)
  tlsOptions: {
    minVersion: 'TLSv1.2',         // Minimum TLS version
    // rejectUnauthorized: true,   // Verify server certificate (if supported)
  }
};

// Example configurations for common LDAP servers

// Active Directory example
export const activeDirectoryConfig = {
  host: 'dc01.corp.example.com',
  port: 636,
  timeoutMs: 5000,
  slowMs: 500,  // AD can be slower
  baseDN: 'DC=corp,DC=example,DC=com',
  filter: '(objectClass=*)'
};

// OpenLDAP example
export const openLdapConfig = {
  host: 'ldap.example.org',
  port: 389,
  timeoutMs: 3000,
  slowMs: 200,
  baseDN: 'dc=example,dc=org',
  filter: '(objectClass=*)'
};

// Load balancer health check example
export const loadBalancerConfig = {
  host: 'ldap-vip.example.com',
  port: 636,
  timeoutMs: 2000,  // Shorter timeout for LB checks
  slowMs: 150,      // Tighter SLA for load balanced setup
  baseDN: '',       // Root DSE for fastest response
  filter: '(objectClass=*)'
}; 