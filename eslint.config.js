import js from '@eslint/js';
import globals from 'globals';

export default [
  { ignores: ['node_modules/', 'docs/'] },
  js.configs.recommended,
  {
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: 'module',
      globals: { ...globals.node },
    },
  },
  {
    // ldapBaseDN is read but not used yet (audit B17); a warning until the config change fixes it.
    files: ['ldap-monitor.js'],
    rules: {
      'no-unused-vars': 'warn',
    },
  },
];
