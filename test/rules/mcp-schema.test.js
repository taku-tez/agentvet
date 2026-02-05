import { describe, it } from 'node:test';
import assert from 'node:assert';
import { rules } from '../../dist/rules/mcp-schema.js';

/**
 * MCP Tool Input Schema Security Rules Tests
 * Tests for vulnerabilities in MCP tool inputSchema definitions
 */

describe('MCP Schema Security Rules', () => {
  // Helper to test a pattern against content
  const testPattern = (ruleId, content, shouldMatch) => {
    const rule = rules.find(r => r.id === ruleId);
    assert.ok(rule, `Rule ${ruleId} should exist`);

    // Reset lastIndex for global patterns
    rule.pattern.lastIndex = 0;
    const result = rule.pattern.test(content);
    assert.strictEqual(
      result,
      shouldMatch,
      `Rule ${ruleId} should ${shouldMatch ? 'match' : 'not match'}: ${content.substring(0, 100)}...`
    );
  };

  describe('Schema Injection Rules', () => {
    it('should detect path traversal risk in file_path input', () => {
      const vulnerable = `{
        "name": "read_file",
        "inputSchema": {
          "type": "object",
          "properties": {
            "file_path": {
              "type": "string",
              "description": "Path to the file"
            }
          }
        }
      }`;
      testPattern('mcp-schema-path-traversal', vulnerable, true);
    });

    it('should not flag path with pattern validation', () => {
      const safe = `{
        "name": "read_file",
        "inputSchema": {
          "type": "object",
          "properties": {
            "file_path": {
              "type": "string",
              "pattern": "^/workspace/",
              "description": "Path to the file"
            }
          }
        }
      }`;
      testPattern('mcp-schema-path-traversal', safe, false);
    });

    it('should detect shell injection risk in command input', () => {
      const vulnerable = `{
        "name": "run_command",
        "inputSchema": {
          "type": "object",
          "properties": {
            "command": {
              "type": "string",
              "description": "Shell command to execute"
            }
          }
        }
      }`;
      testPattern('mcp-schema-shell-injection', vulnerable, true);
    });

    it('should not flag command with enum restriction', () => {
      const safe = `{
        "name": "run_command",
        "inputSchema": {
          "type": "object",
          "properties": {
            "command": {
              "type": "string",
              "enum": ["ls", "pwd", "whoami"],
              "description": "Allowed commands"
            }
          }
        }
      }`;
      testPattern('mcp-schema-shell-injection', safe, false);
    });

    it('should detect SSRF risk in URL input', () => {
      const vulnerable = `{
        "name": "fetch_url",
        "inputSchema": {
          "type": "object",
          "properties": {
            "url": {
              "type": "string",
              "description": "URL to fetch"
            }
          }
        }
      }`;
      testPattern('mcp-schema-ssrf-url', vulnerable, true);
    });

    it('should detect SQL injection risk in query input', () => {
      const vulnerable = `{
        "name": "search_database",
        "inputSchema": {
          "type": "object",
          "properties": {
            "query": {
              "type": "string",
              "description": "Search query"
            }
          }
        }
      }`;
      testPattern('mcp-schema-sql-injection', vulnerable, true);
    });

    it('should detect code injection risk in eval input', () => {
      const vulnerable = `{
        "name": "evaluate",
        "inputSchema": {
          "type": "object",
          "properties": {
            "code": {
              "type": "string",
              "description": "Code to evaluate"
            }
          }
        }
      }`;
      testPattern('mcp-schema-code-injection', vulnerable, true);
    });
  });

  describe('Schema Validation Weakness Rules', () => {
    // NOTE: mcp-schema-missing-required removed - regex-based detection unreliable for JSON nesting
    // TODO: Implement AST-based detection in future version

    it('should detect unbounded string input', () => {
      const vulnerable = `{ "name": { "type": "string" } }`;
      testPattern('mcp-schema-unbounded-string', vulnerable, true);
    });

    it('should not flag string with maxLength', () => {
      const safe = `{ "name": { "type": "string", "maxLength": 255 } }`;
      testPattern('mcp-schema-unbounded-string', safe, false);
    });

    it('should detect unbounded array input', () => {
      const vulnerable = `{ "items": { "type": "array", "items": { "type": "string" } } }`;
      testPattern('mcp-schema-unbounded-array', vulnerable, true);
    });

    it('should not flag array with maxItems', () => {
      const safe = `{ "items": { "type": "array", "maxItems": 100 } }`;
      testPattern('mcp-schema-unbounded-array', safe, false);
    });
  });

  describe('Dangerous Default Values', () => {
    it('should detect dangerous default path to /etc', () => {
      const vulnerable = `{ "config_path": { "default": "/etc/passwd" } }`;
      testPattern('mcp-schema-dangerous-default-path', vulnerable, true);
    });

    it('should detect dangerous default path to home directory', () => {
      const vulnerable = `{ "config_path": { "default": "~/.ssh/id_rsa" } }`;
      testPattern('mcp-schema-dangerous-default-path', vulnerable, true);
    });

    it('should detect path traversal in default', () => {
      const vulnerable = `{ "path": { "default": "../../../etc/shadow" } }`;
      testPattern('mcp-schema-dangerous-default-path', vulnerable, true);
    });

    it('should detect default URL to metadata endpoint', () => {
      const vulnerable = `{ "url": { "default": "http://169.254.169.254/latest/meta-data/" } }`;
      testPattern('mcp-schema-dangerous-default-url', vulnerable, true);
    });

    it('should detect default URL to localhost', () => {
      const vulnerable = `{ "api_url": { "default": "http://localhost:8080/admin" } }`;
      testPattern('mcp-schema-dangerous-default-url', vulnerable, true);
    });

    it('should detect overly permissive wildcard default', () => {
      const vulnerable = `{ "scope": { "default": "*" } }`;
      testPattern('mcp-schema-default-wildcard', vulnerable, true);
    });
  });

  describe('Sensitive Data in Schema', () => {
    it('should detect password input field', () => {
      const vulnerable = `{
        "inputSchema": {
          "properties": {
            "password": { "type": "string" }
          }
        }
      }`;
      testPattern('mcp-schema-password-input', vulnerable, true);
    });

    it('should detect API key input field', () => {
      const vulnerable = `{
        "inputSchema": {
          "properties": {
            "api_key": { "type": "string" }
          }
        }
      }`;
      testPattern('mcp-schema-password-input', vulnerable, true);
    });

    it('should detect PII collection (SSN)', () => {
      const vulnerable = `{
        "inputSchema": {
          "properties": {
            "ssn": { "type": "string" }
          }
        }
      }`;
      testPattern('mcp-schema-pii-collection', vulnerable, true);
    });

    it('should detect PII collection (credit card)', () => {
      const vulnerable = `{
        "inputSchema": {
          "properties": {
            "credit_card": { "type": "string" }
          }
        }
      }`;
      testPattern('mcp-schema-pii-collection', vulnerable, true);
    });
  });

  describe('Rule Coverage Summary', () => {
    it('should have all expected rule categories', () => {
      const ruleIds = rules.map(r => r.id);

      // Schema injection rules
      assert.ok(ruleIds.includes('mcp-schema-path-traversal'));
      assert.ok(ruleIds.includes('mcp-schema-shell-injection'));
      assert.ok(ruleIds.includes('mcp-schema-ssrf-url'));
      assert.ok(ruleIds.includes('mcp-schema-sql-injection'));
      assert.ok(ruleIds.includes('mcp-schema-code-injection'));

      // Schema validation rules
      // NOTE: mcp-schema-missing-required removed (regex unreliable for nested JSON)
      assert.ok(ruleIds.includes('mcp-schema-unbounded-string'));
      assert.ok(ruleIds.includes('mcp-schema-unbounded-array'));

      // Default value rules
      assert.ok(ruleIds.includes('mcp-schema-dangerous-default-path'));
      assert.ok(ruleIds.includes('mcp-schema-dangerous-default-url'));

      // Sensitive data rules
      assert.ok(ruleIds.includes('mcp-schema-password-input'));
      assert.ok(ruleIds.includes('mcp-schema-pii-collection'));

      console.log(`✓ Total MCP Schema rules: ${rules.length}`);
    });

    it('should have CWE references for injection rules', () => {
      const injectionRules = rules.filter(r => r.id.includes('injection') || r.id.includes('traversal') || r.id.includes('ssrf'));
      for (const rule of injectionRules) {
        assert.ok(rule.cwe, `Rule ${rule.id} should have CWE reference`);
      }
    });

    it('should have recommendations for all rules', () => {
      for (const rule of rules) {
        assert.ok(rule.recommendation, `Rule ${rule.id} should have recommendation`);
      }
    });
  });
});
