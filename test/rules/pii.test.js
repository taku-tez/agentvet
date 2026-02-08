/**
 * PII Detection Rules Unit Tests
 */

const { test, describe } = require('node:test');
const assert = require('node:assert');
const { rules } = require('../../dist/rules/pii.js');

describe('PII Detection Rules', () => {

  function testRule(ruleId, content, shouldMatch) {
    const rule = rules.find(r => r.id === ruleId);
    assert.ok(rule, `Rule ${ruleId} should exist`);
    rule.pattern.lastIndex = 0;
    const matches = rule.pattern.test(content);
    assert.strictEqual(matches, shouldMatch,
      `Rule ${ruleId} ${shouldMatch ? 'should' : 'should not'} match: ${content.substring(0, 80)}`);
  }

  describe('Email Detection', () => {
    test('should detect email addresses', () => {
      testRule('pii-email', 'contact: user@example.com', true);
      testRule('pii-email', 'admin@company.co.jp', true);
    });

    test('should not match non-email strings', () => {
      testRule('pii-email', 'no email here', false);
    });
  });

  describe('Phone Number Detection', () => {
    test('should detect US phone numbers', () => {
      testRule('pii-phone', 'call 234-567-8901', true);
      testRule('pii-phone', 'phone: (234) 567-8901', true);
    });

    test('should detect international phone numbers', () => {
      testRule('pii-phone', 'tel: +81-90-1234-5678', true);
    });

    test('should not match random numbers', () => {
      testRule('pii-phone', 'version 1.2.3', false);
    });
  });

  describe('SSN Detection', () => {
    test('should detect SSN patterns', () => {
      testRule('pii-ssn', 'ssn: 123-45-6789', true);
    });

    test('should not match invalid SSN prefixes', () => {
      testRule('pii-ssn', 'id: 000-12-3456', false);
      testRule('pii-ssn', 'id: 666-12-3456', false);
      testRule('pii-ssn', 'id: 900-12-3456', false);
    });

    test('should not match non-SSN patterns', () => {
      testRule('pii-ssn', 'code: ABC-DE-FGHI', false);
    });
  });

  describe('Credit Card Detection', () => {
    test('should detect Visa numbers', () => {
      testRule('pii-credit-card', 'card: 4111-1111-1111-1111', true);
      testRule('pii-credit-card', 'card: 4111111111111111', true);
    });

    test('should detect Mastercard numbers', () => {
      testRule('pii-credit-card', 'card: 5500 0000 0000 0004', true);
    });

    test('should detect Amex numbers', () => {
      testRule('pii-credit-card', 'card: 378282246310005', true);
    });

    test('should not match random numbers', () => {
      testRule('pii-credit-card', 'id: 1234567890', false);
    });
  });

  describe('Public IP Detection', () => {
    test('should detect public IP addresses', () => {
      testRule('pii-public-ip', 'server: 8.8.8.8', true);
      testRule('pii-public-ip', 'host: 203.0.113.1', true);
    });

    test('should not match private IPs', () => {
      testRule('pii-public-ip', 'host: 10.0.0.1', false);
      testRule('pii-public-ip', 'host: 192.168.1.1', false);
      testRule('pii-public-ip', 'host: 172.16.0.1', false);
    });

    test('should not match localhost', () => {
      testRule('pii-public-ip', 'host: 127.0.0.1', false);
    });
  });

  describe('Rule metadata', () => {
    test('should have correct severities', () => {
      const severityMap = {
        'pii-email': 'medium',
        'pii-phone': 'medium',
        'pii-ssn': 'critical',
        'pii-credit-card': 'critical',
        'pii-public-ip': 'low',
      };

      for (const [id, expectedSeverity] of Object.entries(severityMap)) {
        const rule = rules.find(r => r.id === id);
        assert.ok(rule, `Rule ${id} should exist`);
        assert.strictEqual(rule.severity, expectedSeverity, `${id} severity should be ${expectedSeverity}`);
      }
    });

    test('should have 5 PII rules total', () => {
      assert.strictEqual(rules.length, 5);
    });
  });
});
