import type { Rule } from "../types.js";

/**
 * PII Detection Rules
 * Detects hardcoded personally identifiable information in skill/config files
 */

export const rules: Rule[] = [
  {
    id: 'pii-email',
    severity: 'medium',
    description: 'Email address detected in configuration',
    pattern: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g,
    recommendation: 'Use environment variables or a secrets manager for email addresses',
    falsePositiveCheck: (_match, _content, filePath) => {
      // Skip common false positives in example/test files
      return /\.(test|spec|example|sample)\./i.test(filePath);
    },
  },
  {
    id: 'pii-phone',
    severity: 'medium',
    description: 'Phone number detected in configuration',
    // US/international formats: +1-234-567-8901, (234) 567-8901, 234-567-8901, +81-90-1234-5678
    pattern: /(?:\+?1[-.\s]?)?\(?[2-9]\d{2}\)?[-.\s]?\d{3}[-.\s]?\d{4}|\+\d{1,3}[-.\s]?\d{1,4}[-.\s]?\d{2,4}[-.\s]?\d{3,4}/g,
    recommendation: 'Do not hardcode phone numbers in configuration files',
  },
  {
    id: 'pii-ssn',
    severity: 'critical',
    description: 'Social Security Number (SSN) detected',
    // Format: XXX-XX-XXXX (excludes 000, 666, 900-999 prefixes per SSA rules)
    pattern: /\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b/g,
    recommendation: 'Never store SSNs in configuration. Use encrypted storage with strict access controls.',
  },
  {
    id: 'pii-credit-card',
    severity: 'critical',
    description: 'Credit card number detected',
    // Visa, Mastercard, Amex, Discover with optional separators
    pattern: /\b(?:4[0-9]{3}[-\s]?[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{4}|5[1-5][0-9]{2}[-\s]?[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{4}|3[47][0-9]{2}[-\s]?[0-9]{6}[-\s]?[0-9]{5}|6(?:011|5[0-9]{2})[-\s]?[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{4})\b/g,
    recommendation: 'Never store credit card numbers in code. Use a PCI-compliant payment processor.',
  },
  {
    id: 'pii-public-ip',
    severity: 'low',
    description: 'Public IP address detected in configuration',
    // IPv4 - excludes private ranges (10.x, 172.16-31.x, 192.168.x, 127.x) and 0.0.0.0
    pattern: /\b(?!10\.)(?!127\.)(?!172\.(?:1[6-9]|2\d|3[01])\.)(?!192\.168\.)(?!0\.0\.0\.0)(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\b/g,
    recommendation: 'Use environment variables or DNS names instead of hardcoded IP addresses',
  },
];

// CommonJS compatibility
module.exports = { rules };
