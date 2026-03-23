import { describe, it } from 'node:test';
import assert from 'node:assert';
import { rules } from '../../dist/rules/mcp-supply-chain.js';

/**
 * MCP Supply Chain Security Rules Tests – Batch 3 (Issue #15)
 */

const testPattern = (ruleId, content, shouldMatch) => {
  const rule = rules.find(r => r.id === ruleId);
  assert.ok(rule, `Rule ${ruleId} should exist`);
  rule.pattern.lastIndex = 0;
  const result = rule.pattern.test(content);
  assert.strictEqual(
    result,
    shouldMatch,
    `Rule ${ruleId} should ${shouldMatch ? 'match' : 'not match'}: ${content.substring(0, 120)}`
  );
};

describe('MCP Supply Chain Batch 3 Rules', () => {

  describe('Rule existence', () => {
    const batch3Rules = [
      'mcp-supply-chain-database-uri-env',
      'mcp-supply-chain-stripe-key-env',
      'mcp-supply-chain-unrestricted-filesystem',
    ];
    for (const id of batch3Rules) {
      it(`rule ${id} should exist`, () => {
        assert.ok(rules.find(r => r.id === id), `Missing rule: ${id}`);
      });
    }
  });

  // ----------------------------------------------------------------
  // Database URI in env block
  // ----------------------------------------------------------------
  describe('mcp-supply-chain-database-uri-env', () => {
    it('should detect hardcoded PostgreSQL URI', () => {
      testPattern('mcp-supply-chain-database-uri-env',
        '{"env": {"DB": "postgresql://admin:secret@db.example.com:5432/mydb"}}',
        true);
    });

    it('should detect hardcoded MongoDB+SRV URI', () => {
      testPattern('mcp-supply-chain-database-uri-env',
        '{"env": {"MONGO": "mongodb+srv://user:pass@cluster0.abc.mongodb.net/prod"}}',
        true);
    });

    it('should detect hardcoded MySQL URI', () => {
      testPattern('mcp-supply-chain-database-uri-env',
        '{"env": {"DB_URL": "mysql://root:password@localhost:3306/app"}}',
        true);
    });

    it('should not match env var reference', () => {
      testPattern('mcp-supply-chain-database-uri-env',
        '{"env": {"DATABASE_URL": "${DATABASE_URL}"}}',
        false);
    });
  });

  // ----------------------------------------------------------------
  // Stripe secret key in env block
  // ----------------------------------------------------------------
  describe('mcp-supply-chain-stripe-key-env', () => {
    it('should detect sk_live_ key in env', () => {
      testPattern('mcp-supply-chain-stripe-key-env',
        '{"env": {"STRIPE_KEY": "sk_live_abc123def456"}}',
        true);
    });

    it('should detect rk_live_ restricted key in env', () => {
      testPattern('mcp-supply-chain-stripe-key-env',
        '{"env": {"API_KEY": "rk_live_xyz789"}}',
        true);
    });

    it('should not match sk_test_ key', () => {
      testPattern('mcp-supply-chain-stripe-key-env',
        '{"env": {"STRIPE_KEY": "sk_test_abc123"}}',
        false);
    });

    it('should not match env var reference', () => {
      testPattern('mcp-supply-chain-stripe-key-env',
        '{"env": {"STRIPE_KEY": "${STRIPE_SECRET_KEY}"}}',
        false);
    });
  });

  // ----------------------------------------------------------------
  // Unrestricted filesystem access
  // ----------------------------------------------------------------
  describe('mcp-supply-chain-unrestricted-filesystem', () => {
    it('should detect root directory access "/"', () => {
      testPattern('mcp-supply-chain-unrestricted-filesystem',
        '{"args": ["--directory", "/"]}',
        true);
    });

    it('should detect /root access', () => {
      testPattern('mcp-supply-chain-unrestricted-filesystem',
        '{"args": ["/root"]}',
        true);
    });

    it('should detect /home access', () => {
      testPattern('mcp-supply-chain-unrestricted-filesystem',
        '{"args": ["/home", "--readonly"]}',
        true);
    });

    it('should not match specific project directory', () => {
      testPattern('mcp-supply-chain-unrestricted-filesystem',
        '{"args": ["/home/user/project"]}',
        false);
    });

    it('should not match /root/myapp (specific subdirectory)', () => {
      testPattern('mcp-supply-chain-unrestricted-filesystem',
        '{"args": ["/root/myapp"]}',
        false);
    });
  });
});
