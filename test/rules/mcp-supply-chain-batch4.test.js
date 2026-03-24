import { describe, it } from 'node:test';
import assert from 'node:assert';
import { rules } from '../../dist/rules/mcp-supply-chain.js';

/**
 * MCP Supply Chain Security Rules Tests – Batch 4 (Issue #15)
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

describe('MCP Supply Chain Batch 4 Rules', () => {

  describe('Rule existence', () => {
    const batch4Rules = [
      'mcp-supply-chain-typosquat-uvx',
      'mcp-supply-chain-github-actions-oidc-env',
      'mcp-supply-chain-aws-session-token-env',
      'mcp-supply-chain-npx-no-yes-flag',
      'mcp-supply-chain-localhost-non-standard-port',
    ];
    for (const id of batch4Rules) {
      it(`rule ${id} should exist`, () => {
        const rule = rules.find(r => r.id === id);
        assert.ok(rule, `Rule ${id} should exist`);
        assert.strictEqual(rule.category, 'mcp-supply-chain');
      });
    }
  });

  describe('mcp-supply-chain-typosquat-uvx', () => {
    it('should detect uvx mcp-server (generic name)', () => {
      testPattern('mcp-supply-chain-typosquat-uvx',
        `"command": "uvx", "args": ["mcp-server"]`,
        true);
    });

    it('should detect uvx mcptools (squatted package)', () => {
      testPattern('mcp-supply-chain-typosquat-uvx',
        `"command": "uvx", "args": ["mcptools"]`,
        true);
    });

    it('should detect npx mcp-tools', () => {
      testPattern('mcp-supply-chain-typosquat-uvx',
        `"command": "npx", "args": ["mcp-tools"]`,
        true);
    });

    it('should detect uvx mcp-util', () => {
      testPattern('mcp-supply-chain-typosquat-uvx',
        `"command": "uvx", "args": ["mcp-util"]`,
        true);
    });

    it('should detect mcp-server-fetch (also generic/suspicious)', () => {
      testPattern('mcp-supply-chain-typosquat-uvx',
        `"command": "uvx", "args": ["mcp-server-fetch@0.6.2"]`,
        true);
    });
  });

  describe('mcp-supply-chain-github-actions-oidc-env', () => {
    it('should detect GITHUB_TOKEN passed to MCP env', () => {
      testPattern('mcp-supply-chain-github-actions-oidc-env',
        '"env": {"GITHUB_TOKEN": "ghs_16C7e42F292c6912E7710c838347Ae178B4a"}',
        true);
    });

    it('should detect ACTIONS_RUNTIME_TOKEN passed to MCP env', () => {
      testPattern('mcp-supply-chain-github-actions-oidc-env',
        `"env": {"SOME_KEY": "value", "ACTIONS_RUNTIME_TOKEN": "ghs_xxx"}`,
        true);
    });

    it('should detect ACTIONS_ID_TOKEN_REQUEST_TOKEN', () => {
      testPattern('mcp-supply-chain-github-actions-oidc-env',
        `"env": {"ACTIONS_ID_TOKEN_REQUEST_TOKEN": "v2.eyJ..."}`,
        true);
    });

    it('should not flag non-Actions env variables', () => {
      testPattern('mcp-supply-chain-github-actions-oidc-env',
        '"env": {"API_KEY": "${MY_API_KEY}", "BASE_URL": "https://api.example.com"}',
        false);
    });
  });

  describe('mcp-supply-chain-aws-session-token-env', () => {
    it('should detect hardcoded AWS_SESSION_TOKEN', () => {
      testPattern('mcp-supply-chain-aws-session-token-env',
        `"env": {"AWS_SESSION_TOKEN": "AQoXnyc4lcK4EXAMPLE"}`,
        true);
    });

    it('should detect hardcoded AWS_SECURITY_TOKEN', () => {
      testPattern('mcp-supply-chain-aws-session-token-env',
        `"env": {"AWS_SECURITY_TOKEN": "AQoZz...EXAMPLETOKEN"}`,
        true);
    });

    it('should not flag env var placeholder references', () => {
      testPattern('mcp-supply-chain-aws-session-token-env',
        '"env": {"AWS_SESSION_TOKEN": "${AWS_SESSION_TOKEN}"}',
        false);
    });
  });

  describe('mcp-supply-chain-localhost-non-standard-port', () => {
    it('should detect localhost:3000 connection', () => {
      testPattern('mcp-supply-chain-localhost-non-standard-port',
        `"url": "http://localhost:3000/"`,
        true);
    });

    it('should detect 127.0.0.1:8080 connection', () => {
      testPattern('mcp-supply-chain-localhost-non-standard-port',
        `"url": "http://127.0.0.1:8080/"`,
        true);
    });

    it('should detect https localhost high port', () => {
      testPattern('mcp-supply-chain-localhost-non-standard-port',
        `"url": "https://localhost:9000/"`,
        true);
    });

    it('should not flag well-known low ports', () => {
      testPattern('mcp-supply-chain-localhost-non-standard-port',
        `"url": "http://localhost:80/"`,
        false);
    });

    it('should not flag external URLs', () => {
      testPattern('mcp-supply-chain-localhost-non-standard-port',
        `"url": "https://api.example.com:8080/"`,
        false);
    });
  });

});
