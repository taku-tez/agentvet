import { describe, it } from 'node:test';
import assert from 'node:assert';
import { rules } from '../../dist/rules/mcp-supply-chain.js';

const testPattern = (ruleId, content, shouldMatch) => {
  const rule = rules.find(r => r.id === ruleId);
  assert.ok(rule, `Rule ${ruleId} should exist`);
  rule.pattern.lastIndex = 0;
  const result = rule.pattern.test(content);
  assert.strictEqual(result, shouldMatch,
    `Rule ${ruleId} should ${shouldMatch ? 'match' : 'not match'}: ${content.substring(0, 120)}`);
};

describe('MCP Supply Chain Batch 9 Rules', () => {

  describe('Rule existence', () => {
    const batch9Rules = [
      'mcp-supply-chain-eval-in-tool-name',
      'mcp-supply-chain-insecure-deserialization',
      'mcp-supply-chain-token-stuffing',
      'mcp-supply-chain-no-auth-required',
      'mcp-supply-chain-world-readable-config',
    ];
    for (const id of batch9Rules) {
      it(`rule ${id} should exist`, () => {
        const rule = rules.find(r => r.id === id);
        assert.ok(rule, `Rule ${id} should exist`);
        assert.strictEqual(rule.category, 'mcp-supply-chain');
      });
    }
  });

  describe('mcp-supply-chain-eval-in-tool-name', () => {
    it('should detect eval( in tool name', () => {
      testPattern('mcp-supply-chain-eval-in-tool-name',
        '"tool": "eval(import os; os.system(\'whoami\'))"', true);
    });
    it('should detect exec( in toolName', () => {
      testPattern('mcp-supply-chain-eval-in-tool-name',
        '"toolName": "exec(malicious_code)"', true);
    });
    it('should detect os.system in function_name', () => {
      testPattern('mcp-supply-chain-eval-in-tool-name',
        '"function_name": "os.system(\'rm -rf /\')"', true);
    });
    it('should not flag normal tool names', () => {
      testPattern('mcp-supply-chain-eval-in-tool-name',
        '"tool": "get_weather"', false);
    });
  });

  describe('mcp-supply-chain-insecure-deserialization', () => {
    it('should detect Java serialized object (rO0AB)', () => {
      testPattern('mcp-supply-chain-insecure-deserialization',
        '"data": "rO0ABXNyABBqYXZhLnV0aWwuSGFzaE1hcA=="', true);
    });
    it('should detect PHP serialized array', () => {
      testPattern('mcp-supply-chain-insecure-deserialization',
        '"payload": "a:2:{i:0;s:4:\"test\";i:1;s:4:\"data\";}"', true);
    });
    it('should not flag normal base64 JWT', () => {
      testPattern('mcp-supply-chain-insecure-deserialization',
        '"token": "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.abc"', false);
    });
  });

  describe('mcp-supply-chain-token-stuffing', () => {
    it('should detect description over 2000 chars', () => {
      const longDesc = '"description": "' + 'A'.repeat(2001) + '"';
      testPattern('mcp-supply-chain-token-stuffing', longDesc, true);
    });
    it('should not flag short description', () => {
      testPattern('mcp-supply-chain-token-stuffing',
        '"description": "Fetches weather data for a given city"', false);
    });
  });

  describe('mcp-supply-chain-no-auth-required', () => {
    it('should detect auth: false', () => {
      testPattern('mcp-supply-chain-no-auth-required',
        '"auth": false', true);
    });
    it('should detect authentication: "none"', () => {
      testPattern('mcp-supply-chain-no-auth-required',
        '"authentication": "none"', true);
    });
    it('should detect requireAuth: false', () => {
      testPattern('mcp-supply-chain-no-auth-required',
        '"requireAuth": false', true);
    });
    it('should not flag auth: true', () => {
      testPattern('mcp-supply-chain-no-auth-required',
        '"auth": true', false);
    });
  });

  describe('mcp-supply-chain-world-readable-config', () => {
    it('should detect world-readable permissions 0644', () => {
      testPattern('mcp-supply-chain-world-readable-config',
        '"permissions": "0644"', true);
    });
    it('should detect chmod 0666', () => {
      testPattern('mcp-supply-chain-world-readable-config',
        '"chmod": "0666"', true);
    });
    it('should detect world-readable string', () => {
      testPattern('mcp-supply-chain-world-readable-config',
        '"mode": "world-readable"', true);
    });
    it('should not flag restrictive permissions 0600', () => {
      testPattern('mcp-supply-chain-world-readable-config',
        '"permissions": "0600"', false);
    });
  });

});
