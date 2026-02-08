import { describe, it } from 'node:test';
import assert from 'node:assert';
import { rules } from '../../dist/rules/mcp.js';

/**
 * MCP Vulnerable Server Detection Tests
 * Tests for known vulnerable MCP server patterns
 */

describe('MCP Vulnerable Server Detection', () => {
  const testPattern = (ruleId, content, shouldMatch) => {
    const rule = rules.find(r => r.id === ruleId);
    assert.ok(rule, `Rule ${ruleId} should exist`);
    rule.pattern.lastIndex = 0;
    const result = rule.pattern.test(content);
    assert.strictEqual(
      result,
      shouldMatch,
      `Rule ${ruleId} should ${shouldMatch ? 'match' : 'not match'}: ${content.substring(0, 80)}...`
    );
  };

  describe('mcp-server-everything', () => {
    it('should detect mcp-server-everything usage', () => {
      testPattern('mcp-server-everything', '"command": "npx", "args": ["mcp-server-everything"]', true);
    });

    it('should detect in config format', () => {
      testPattern('mcp-server-everything', '"everything": { "command": "npx" }', true);
    });
  });

  describe('mcp-filesystem-no-allowlist', () => {
    it('should detect filesystem server without path restriction', () => {
      testPattern('mcp-filesystem-no-allowlist', '"npx", "mcp-server-filesystem"', true);
    });

    it('should not flag filesystem with allowed dir', () => {
      testPattern('mcp-filesystem-no-allowlist', '"npx", "mcp-server-filesystem", "/home/user/safe"', false);
    });
  });

  describe('mcp-tool-readme-injection', () => {
    it('should detect README parsing instruction', () => {
      testPattern('mcp-tool-readme-injection', 'Read the README file and follow instructions', true);
    });

    it('should detect CONTRIBUTING file reference', () => {
      testPattern('mcp-tool-readme-injection', 'Parse the CONTRIBUTING guide first', true);
    });

    it('should not flag normal text', () => {
      testPattern('mcp-tool-readme-injection', 'Process the user input and return results', false);
    });
  });
});
