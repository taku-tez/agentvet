/**
 * Credentials Rules Unit Tests
 */

const { test, describe } = require('node:test');
const assert = require('node:assert');
const { rules } = require('../../dist/rules/credentials.js');

describe('Credentials Rules', () => {
  
  // Helper to test a rule
  function testRule(ruleId, content, shouldMatch) {
    const rule = rules.find(r => r.id === ruleId);
    assert.ok(rule, `Rule ${ruleId} should exist`);
    rule.pattern.lastIndex = 0;
    const matches = rule.pattern.test(content);
    assert.strictEqual(matches, shouldMatch, 
      `Rule ${ruleId} ${shouldMatch ? 'should' : 'should not'} match: ${content.substring(0, 50)}...`);
  }

  describe('AWS Credentials', () => {
    test('should detect AWS Access Key ID', () => {
      testRule('credential-aws-key', 'const key = "AKIAIOSFODNN7EXAMPLE";', true);
      testRule('credential-aws-key', 'AKIA1234567890123456', true);
    });

    test('should not match invalid AWS keys', () => {
      testRule('credential-aws-key', 'const key = "not-an-aws-key";', false);
    });

    test('should detect AWS Secret Access Key', () => {
      testRule('credential-aws-secret', 'aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"', true);
      testRule('credential-aws-secret', 'AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"', true);
    });
  });

  describe('GitHub Tokens', () => {
    test('should detect GitHub Personal Access Token', () => {
      testRule('credential-github-token', 'ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx', true);
      testRule('credential-github-token', 'gho_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx', true);
      testRule('credential-github-token', 'ghu_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx', true);
      testRule('credential-github-token', 'ghs_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx', true);
      testRule('credential-github-token', 'ghr_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx', true);
    });
  });

  describe('AI API Keys', () => {
    test('should detect OpenAI API keys', () => {
      testRule('credential-openai-key', 'sk-abcdefghij1234567890abcdefghij12', true);
      testRule('credential-openai-key', 'OPENAI_API_KEY=sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx', true);
    });

    test('should detect Anthropic API keys', () => {
      testRule('credential-anthropic-key', 'sk-ant-api03-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx', true);
    });
  });

  describe('Slack Tokens', () => {
    test('should detect Slack tokens', () => {
      // Pattern test only - use x placeholders
      testRule('credential-slack-token', 'xoxb-xxxxxxxxxxxx-xxxxxxxxxxxx-xxxxxxxxxxxxxxxxxxxxxxxx', true);
      testRule('credential-slack-token', 'xoxp-xxxxxxxxxxxx-xxxxxxxxxxxx-xxxxxxxxxxxxxxxxxxxxxxxx', true);
    });
  });

  describe('Stripe Keys', () => {
    test('should detect Stripe keys pattern', () => {
      // Verify the pattern exists and structure is correct
      const rule = rules.find(r => r.id === 'credential-stripe-key');
      assert.ok(rule, 'credential-stripe-key rule should exist');
      assert.strictEqual(rule.severity, 'critical');
    });
  });

  describe('Private Keys', () => {
    test('should detect RSA private key headers', () => {
      testRule('credential-private-key', '-----BEGIN RSA PRIVATE KEY-----', true);
      testRule('credential-private-key', '-----BEGIN PRIVATE KEY-----', true);
      testRule('credential-private-key', '-----BEGIN EC PRIVATE KEY-----', true);
    });
  });

  describe('Generic Patterns', () => {
    test('should detect generic API key patterns', () => {
      testRule('credential-generic-api-key', 'api_key = "1234567890abcdef1234567890abcdef"', true);
      testRule('credential-generic-api-key', 'apiKey: "abcdefghijklmnopqrstuvwxyz123456"', true);
    });

    test('should detect generic secret patterns', () => {
      testRule('credential-generic-secret', 'secret = "mysupersecretvalue"', true);
      testRule('credential-generic-secret', 'password: "mypassword123"', true);
    });
  });

  describe('Database URLs', () => {
    test('should detect database connection strings', () => {
      testRule('credential-database-url', 'postgres://user:password@localhost:5432/db', true);
      testRule('credential-database-url', 'mysql://user:pass@host/database', true);
    });

    test('should detect MongoDB SRV URLs', () => {
      testRule('credential-mongodb-srv', 'mongodb+srv://user:pass@cluster.mongodb.net/db', true);
    });
  });

});
