/**
 * File Permission Rules
 * Checks for insecure file permissions on sensitive files
 */

const rules = [
  {
    id: 'permission-sensitive-files',
    severity: 'warning',
    description: 'Sensitive file has insecure permissions',
    patterns: [
      '.env',
      'api_key',
      'credentials.json',
      'secrets.json',
      'config.json',
      '.pem',
      '.key',
      'id_rsa',
      'id_ed25519',
      'id_ecdsa',
      '.p12',
      '.pfx',
    ],
    recommendation: 'Set file permissions to 600 (owner read/write only): chmod 600 <file>',
  },
];

module.exports = { rules };
