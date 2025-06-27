# Changelog

All notable changes to the ThousandEyes LDAP Monitor project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2024-01-XX

### Added
- Initial release of ThousandEyes LDAP monitoring script
- Support for both LDAP (port 389) and LDAPS (port 636) protocols
- Authenticated LDAPv3 simple bind operations
- Fast base-scope search against Root DSE
- Performance metrics tracking with configurable thresholds
- Automatic retry logic for transient connection failures
- Enhanced error handling with specific LDAP error code mapping
- Detailed performance breakdown (connection, bind, search times)
- Input validation for credentials and configuration
- JSDoc documentation for BER encoding functions
- Comprehensive README with setup instructions
- Troubleshooting guide with common error solutions
- Example configuration file with templates for different LDAP servers
- Security best practices documentation

### Important Notes
- ThousandEyes Transaction tests only support single JavaScript files
- The `ldap-monitor-config.example.js` file is provided for reference only
- All configuration must be done directly in the main `ldap-monitor.js` file

### Configuration Options
- `host`: LDAP server hostname or IP
- `port`: 389 (LDAP) or 636 (LDAPS)
- `timeoutMs`: Socket timeout (default: 5000ms)
- `slowMs`: Performance alert threshold (default: 300ms)
- `baseDN`: Base DN for search (default: '' for Root DSE)
- `filter`: LDAP search filter (default: '(objectClass=*)')
- `retryDelayMs`: Delay between retries (default: 100ms)
- `maxRetries`: Maximum retry attempts (default: 2)

### Security
- Uses ThousandEyes Secure Credentials for authentication
- No plaintext passwords in code or logs
- Supports TLS 1.2+ for LDAPS connections
- Credentials encrypted at rest 