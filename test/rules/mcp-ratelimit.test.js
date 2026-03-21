import { describe, it } from 'node:test';
import assert from 'node:assert';
import { rules } from '../../dist/rules/mcp-ratelimit.js';

const testPattern = (ruleId, content, shouldMatch) => {
  const rule = rules.find(r => r.id === ruleId);
  assert.ok(rule, `Rule ${ruleId} should exist`);
  rule.pattern.lastIndex = 0;
  const result = rule.pattern.test(content);
  assert.strictEqual(result, shouldMatch,
    `Rule ${ruleId} should ${shouldMatch ? 'match' : 'not match'}: ${content.substring(0, 100)}`);
};

describe('MCP Rate Limiting & DoS Protection Rules', () => {

  describe('Rule existence', () => {
    const expectedRules = [
      'mcp-ratelimit-no-max-requests',
      'mcp-ratelimit-unlimited-tokens',
      'mcp-ratelimit-unlimited-tool-calls',
      'mcp-ratelimit-no-timeout',
      'mcp-ratelimit-excessive-timeout',
      'mcp-ratelimit-unlimited-concurrency',
      'mcp-ratelimit-no-backpressure',
      'mcp-ratelimit-no-cost-limit',
      'mcp-ratelimit-no-session-limit',
    ];

    it('all expected rules should exist', () => {
      for (const ruleId of expectedRules) {
        assert.ok(rules.find(r => r.id === ruleId), `Rule ${ruleId} should exist`);
      }
    });

    it('all rules should have required fields', () => {
      for (const rule of rules) {
        assert.ok(rule.id);
        assert.ok(rule.severity);
        assert.ok(rule.description);
        assert.ok(rule.pattern);
        assert.ok(rule.recommendation);
        assert.strictEqual(rule.category, 'mcp-ratelimit');
      }
    });
  });

  describe('Unlimited token budget detection', () => {
    it('should detect max_tokens: -1', () => {
      testPattern('mcp-ratelimit-unlimited-tokens',
        '{"agent": {"model": "claude-opus-4", "max_tokens": -1}}',
        true);
    });

    it('should detect max_tokens: 1000000', () => {
      testPattern('mcp-ratelimit-unlimited-tokens',
        '{"max_tokens": 1000000}',
        true);
    });

    it('should not match reasonable token limit', () => {
      testPattern('mcp-ratelimit-unlimited-tokens',
        '{"max_tokens": 8192}',
        false);
    });
  });

  describe('Unlimited tool calls detection', () => {
    it('should detect max_tool_calls: -1', () => {
      testPattern('mcp-ratelimit-unlimited-tool-calls',
        '{"agent": {"max_tool_calls": -1}}',
        true);
    });

    it('should detect max_tool_calls: 0', () => {
      testPattern('mcp-ratelimit-unlimited-tool-calls',
        '{"orchestrator": {"max_tool_calls": 0}}',
        true);
    });

    it('should not match reasonable limit', () => {
      testPattern('mcp-ratelimit-unlimited-tool-calls',
        '{"max_tool_calls": 50}',
        false);
    });
  });

  describe('Excessive timeout detection', () => {
    it('should detect timeout > 5 minutes (e.g. 600000ms)', () => {
      testPattern('mcp-ratelimit-excessive-timeout',
        '{"tools": {"search": {"timeout": 600000}}}',
        true);
    });

    it('should not flag 30 second timeout', () => {
      testPattern('mcp-ratelimit-excessive-timeout',
        '{"timeout": 30000}',
        false);
    });
  });

  describe('Unlimited concurrency detection', () => {
    it('should detect max_concurrent: -1', () => {
      testPattern('mcp-ratelimit-unlimited-concurrency',
        '{"server": {"max_concurrent": -1}}',
        true);
    });

    it('should detect max_connections: 99999', () => {
      testPattern('mcp-ratelimit-unlimited-concurrency',
        '{"max_connections": 99999}',
        true);
    });

    it('should not flag reasonable limit', () => {
      testPattern('mcp-ratelimit-unlimited-concurrency',
        '{"max_concurrent": 10}',
        false);
    });
  });

  describe('Queue backpressure detection', () => {
    it('should detect queue_size: -1', () => {
      testPattern('mcp-ratelimit-no-backpressure',
        '{"queue": {"queue_size": -1, "policy": "drop_oldest"}}',
        true);
    });
  });

});
