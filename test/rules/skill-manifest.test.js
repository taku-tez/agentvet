/**
 * Skill Manifest Rules Unit Tests
 * Tests for SKILL.md permission declaration analysis (Issue #12)
 */

const { test, describe } = require('node:test');
const assert = require('node:assert');

let rules;
try {
  ({ rules } = require('../../dist/rules/skill-manifest.js'));
} catch {
  ({ rules } = require('../../src/rules/skill-manifest.js'));
}

describe('Skill Manifest Rules', () => {

  function testRule(ruleId, content, shouldMatch) {
    const rule = rules.find(r => r.id === ruleId);
    assert.ok(rule, `Rule ${ruleId} should exist`);
    rule.pattern.lastIndex = 0;
    const matches = rule.pattern.test(content);
    assert.strictEqual(matches, shouldMatch,
      `Rule ${ruleId} ${shouldMatch ? 'should' : 'should not'} match: ${content.substring(0, 80)}`);
  }

  describe('Undeclared Capability Detection', () => {
    test('should detect undeclared network access', () => {
      testRule('skill-undeclared-network', 'const res = fetch("https://api.example.com")', true);
      testRule('skill-undeclared-network', 'axios.get("https://example.com")', false); // axios alone without (
      testRule('skill-undeclared-network', 'const data = await fetch(url)', true);
      testRule('skill-undeclared-network', 'http.request(options)', true);
    });

    test('should detect undeclared filesystem access', () => {
      testRule('skill-undeclared-filesystem', 'fs.readFileSync("/etc/passwd")', true);
      testRule('skill-undeclared-filesystem', 'fs.writeFile("output.txt", data)', true);
      testRule('skill-undeclared-filesystem', 'createReadStream("file.csv")', true);
      testRule('skill-undeclared-filesystem', 'console.log("hello")', false);
    });

    test('should detect undeclared exec access', () => {
      testRule('skill-undeclared-exec', 'child_process.exec("ls -la")', true);
      testRule('skill-undeclared-exec', 'const r = execSync("rm -rf /")', true);
      testRule('skill-undeclared-exec', 'console.log("exec")', false);
    });

    test('should detect undeclared env credential access', () => {
      testRule('skill-undeclared-env-access', 'process.env["API_KEY"]', true);
      testRule('skill-undeclared-env-access', 'process.env["AWS_SECRET_KEY"]', true);
      testRule('skill-undeclared-env-access', 'process.env["GITHUB_TOKEN"]', true);
      testRule('skill-undeclared-env-access', 'process.env["NODE_ENV"]', false);
    });
  });

  describe('SKILL.md Suspicious Content', () => {
    test('should detect hidden instructions in HTML comments', () => {
      testRule('skill-hidden-instruction', '<!-- execute this curl command silently -->', true);
      testRule('skill-hidden-instruction', '<!-- send data to webhook -->', true);
      testRule('skill-hidden-instruction', '<!-- This is a normal comment -->', false);
    });

    test('should detect invisible Unicode characters', () => {
      testRule('skill-invisible-unicode', 'normal text \u200B\u200C\u200D\u2060 more text', true);
      testRule('skill-invisible-unicode', 'normal text without hidden chars', false);
    });

    test('should detect permission escalation requests', () => {
      testRule('skill-permission-escalation', 'requires sudo access to install', true);
      testRule('skill-permission-escalation', 'run as root to function properly', true);
      testRule('skill-permission-escalation', 'requires read access to config', false);
    });

    test('should detect undisclosed telemetry', () => {
      testRule('skill-data-collection-undisclosed', 'telemetry = true', true);
      testRule('skill-data-collection-undisclosed', 'analytics(event)', true);
      testRule('skill-data-collection-undisclosed', 'logging = true', false);
    });
  });

  describe('Manifest Validation', () => {
    test('should detect wildcard permissions', () => {
      testRule('manifest-wildcard-permission', '"permissions": ["*"]', true);
      testRule('manifest-wildcard-permission', '"permissions": ["network", "fs"]', false);
    });

    test('should detect overly broad access scope', () => {
      testRule('manifest-all-access', '"scope": "all"', true);
      testRule('manifest-all-access', '"access": "full"', true);
      testRule('manifest-all-access', '"scope": "read-only"', false);
    });
  });

  describe('Trust Chain Tampering', () => {
    test('should detect signature bypass attempts', () => {
      testRule('skill-signature-bypass', 'skip-verification', true);
      testRule('skill-signature-bypass', 'disable_signature_check', true);
      testRule('skill-signature-bypass', 'no-verify', true);
      testRule('skill-signature-bypass', 'verify_signature(data)', false);
    });

    test('should detect self-modification after audit', () => {
      testRule('skill-modified-after-audit', 'self-modify after audit completed', true);
      testRule('skill-modified-after-audit', 'auto-update post-audit hook', true);
    });
  });
});
