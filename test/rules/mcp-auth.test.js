import { describe, it } from 'node:test';
import assert from 'node:assert';
import { rules } from '../../dist/rules/mcp-auth.js';

/**
 * MCP Authentication & Agent Identity Security Rules Tests
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

describe('MCP Auth Security Rules', () => {

  describe('Rule existence', () => {
    const expectedRules = [
      'mcp-auth-hardcoded-bearer-token',
      'mcp-auth-hardcoded-session-token',
      'mcp-auth-hardcoded-github-token',
      'mcp-auth-tls-verify-disabled',
      'mcp-auth-no-verify-flag',
      'mcp-auth-static-nonce',
      'mcp-auth-missing-expiry',
      'mcp-auth-cors-wildcard',
      'mcp-auth-cors-credentials-wildcard',
      'mcp-auth-trust-all-agents',
      'mcp-auth-disable-agent-verification',
    ];

    it('all expected rules should exist', () => {
      for (const ruleId of expectedRules) {
        const rule = rules.find(r => r.id === ruleId);
        assert.ok(rule, `Rule ${ruleId} should exist`);
      }
    });

    it('all rules should have required fields', () => {
      for (const rule of rules) {
        assert.ok(rule.id, `Rule should have id`);
        assert.ok(rule.severity, `Rule ${rule.id} should have severity`);
        assert.ok(rule.description, `Rule ${rule.id} should have description`);
        assert.ok(rule.pattern, `Rule ${rule.id} should have pattern`);
        assert.ok(rule.recommendation, `Rule ${rule.id} should have recommendation`);
        assert.ok(rule.category, `Rule ${rule.id} should have category`);
      }
    });

    it('all rules should have category mcp-auth', () => {
      for (const rule of rules) {
        assert.strictEqual(rule.category, 'mcp-auth', `Rule ${rule.id} should have category mcp-auth`);
      }
    });
  });

  describe('Hardcoded Bearer Token detection', () => {
    it('should detect hardcoded Bearer token', () => {
      testPattern('mcp-auth-hardcoded-bearer-token',
        '{"headers": {"Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.sig"}}',
        true);
    });

    it('should detect Bearer token in agent config', () => {
      testPattern('mcp-auth-hardcoded-bearer-token',
        '{"transport": {"headers": {"Authorization": "Bearer sk-abcdefghijklmnopqrstuvwxyz12345678901"}}}',
        true);
    });

    it('should not match short placeholder', () => {
      testPattern('mcp-auth-hardcoded-bearer-token',
        '{"Authorization": "Bearer ${TOKEN}"}',
        false);
    });
  });

  describe('Hardcoded Session Token detection', () => {
    it('should detect SESSION_TOKEN in env', () => {
      testPattern('mcp-auth-hardcoded-session-token',
        '{"env": {"SESSION_TOKEN": "abcdefghijklmnopqrstuvwxyz1234567890"}}',
        true);
    });

    it('should detect ACCESS_TOKEN in env', () => {
      testPattern('mcp-auth-hardcoded-session-token',
        '{"env": {"ACCESS_TOKEN": "sk-proj-abcdefghijklmnopqrstuvwxyz"}}',
        true);
    });
  });

  describe('GitHub Token detection', () => {
    it('should detect ghp_ token', () => {
      testPattern('mcp-auth-hardcoded-github-token',
        '{"env": {"GITHUB_TOKEN": "ghp_abcdefghijklmnopqrstuvwxyz1234567890"}}',
        true);
    });

    it('should detect github_pat_ token', () => {
      testPattern('mcp-auth-hardcoded-github-token',
        '{"GITHUB_PAT": "github_pat_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}',
        true);
    });
  });

  describe('TLS Verification bypass detection', () => {
    it('should detect verify_ssl: false', () => {
      testPattern('mcp-auth-tls-verify-disabled',
        '{"transport": {"verify_ssl": false, "url": "https://agent.internal"}}',
        true);
    });

    it('should detect insecure: true pattern', () => {
      testPattern('mcp-auth-tls-verify-disabled',
        '{"connection": {"tls_verify": false}}',
        true);
    });

    it('should detect --insecure flag in command', () => {
      testPattern('mcp-auth-no-verify-flag',
        'npx @modelcontextprotocol/server-fetch --insecure https://agent.internal/mcp',
        true);
    });

    it('should detect --no-verify flag', () => {
      testPattern('mcp-auth-no-verify-flag',
        'uvx mcp-server-connect --no-verify --url https://internal-agent:8080',
        true);
    });
  });

  describe('CORS wildcard detection', () => {
    it('should detect wildcard CORS origin', () => {
      testPattern('mcp-auth-cors-wildcard',
        '{"server": {"cors_origin": "*", "port": 8080}}',
        true);
    });

    it('should detect Access-Control-Allow-Origin wildcard', () => {
      testPattern('mcp-auth-cors-wildcard',
        '{"headers": {"Access-Control-Allow-Origin": "*"}}',
        true);
    });

    it('should not match specific origin', () => {
      testPattern('mcp-auth-cors-wildcard',
        '{"cors_origin": "https://agent.example.com"}',
        false);
    });
  });

  describe('Agent trust policy detection', () => {
    it('should detect trust_policy: all', () => {
      testPattern('mcp-auth-trust-all-agents',
        '{"agent_config": {"trust_policy": "all", "allow_tool_calls": true}}',
        true);
    });

    it('should detect agent_trust: any', () => {
      testPattern('mcp-auth-trust-all-agents',
        '{"multi_agent": {"agent_trust": "any"}}',
        true);
    });

    it('should not match specific trust policy', () => {
      testPattern('mcp-auth-trust-all-agents',
        '{"trust_policy": "verified-signed-jwt"}',
        false);
    });

    it('should detect verify_agent: false', () => {
      testPattern('mcp-auth-disable-agent-verification',
        '{"a2a": {"verify_agent": false, "endpoint": "https://agent2.internal"}}',
        true);
    });

    it('should detect agent_verification: false', () => {
      testPattern('mcp-auth-disable-agent-verification',
        '{"orchestrator": {"agent_verification": false}}',
        true);
    });
  });

});
