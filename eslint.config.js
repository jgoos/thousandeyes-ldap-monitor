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
    // Existing findings in the script, reported as warnings until the protocol and transport
    // rewrites fix them (unused catch bindings, dropped error causes: audit B13).
    files: ['ldap-monitor.js'],
    rules: {
      'no-unused-vars': 'warn',
      'preserve-caught-error': 'warn',
    },
  },
];
