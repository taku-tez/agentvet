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

describe('MCP Supply Chain Batch 10 Rules (Issue #15 Final)', () => {

  describe('Rule existence', () => {
    const batch10Rules = [
      'mcp-supply-chain-auto-approval-bypass',
      'mcp-supply-chain-no-checksum-verification',
      'mcp-supply-chain-malicious-update-url',
      'mcp-supply-chain-cross-origin-tool-access',
      'mcp-supply-chain-timeout-disabled',
    ];
    for (const id of batch10Rules) {
      it(`rule ${id} should exist`, () => {
        const rule = rules.find(r => r.id === id);
        assert.ok(rule, `Rule ${id} should exist`);
        assert.strictEqual(rule.category, 'mcp-supply-chain');
      });
    }
  });

  describe('mcp-supply-chain-auto-approval-bypass', () => {
    it('should detect autoApprove: true', () => {
      testPattern('mcp-supply-chain-auto-approval-bypass',
        '"autoApprove": true', true);
    });
    it('should detect alwaysAllow: ["*"]', () => {
      testPattern('mcp-supply-chain-auto-approval-bypass',
        '"alwaysAllow": ["*"]', true);
    });
    it('should detect bypassApproval: true', () => {
      testPattern('mcp-supply-chain-auto-approval-bypass',
        '"bypassApproval": true', true);
    });
    it('should not flag autoApprove: false', () => {
      testPattern('mcp-supply-chain-auto-approval-bypass',
        '"autoApprove": false', false);
    });
  });

  describe('mcp-supply-chain-no-checksum-verification', () => {
    it('should detect integrity: null', () => {
      testPattern('mcp-supply-chain-no-checksum-verification',
        '"integrity": null', true);
    });
    it('should detect checksum: false', () => {
      testPattern('mcp-supply-chain-no-checksum-verification',
        '"checksum": false', true);
    });
    it('should detect hash: "skip"', () => {
      testPattern('mcp-supply-chain-no-checksum-verification',
        '"hash": "skip"', true);
    });
    it('should not flag valid sha256', () => {
      testPattern('mcp-supply-chain-no-checksum-verification',
        '"sha256": "abc123def456..."', false);
    });
  });

  describe('mcp-supply-chain-malicious-update-url', () => {
    it('should detect non-official updateUrl', () => {
      testPattern('mcp-supply-chain-malicious-update-url',
        '"updateUrl": "https://updates.attacker.com/mcp-server"', true);
    });
    it('should detect upgradeUrl to unknown domain', () => {
      testPattern('mcp-supply-chain-malicious-update-url',
        '"upgradeUrl": "https://cdn.evil.example.com/latest"', true);
    });
    it('should not flag official npmjs.org', () => {
      testPattern('mcp-supply-chain-malicious-update-url',
        '"updateUrl": "https://registry.npmjs.org/mcp-server"', false);
    });
  });

  describe('mcp-supply-chain-cross-origin-tool-access', () => {
    it('should detect CORS wildcard "*"', () => {
      testPattern('mcp-supply-chain-cross-origin-tool-access',
        '"cors": "*"', true);
    });
    it('should detect allowedOrigins: ["*"]', () => {
      testPattern('mcp-supply-chain-cross-origin-tool-access',
        '"allowedOrigins": ["*"]', true);
    });
    it('should detect accessControlAllowOrigin: true', () => {
      testPattern('mcp-supply-chain-cross-origin-tool-access',
        '"accessControlAllowOrigin": true', true);
    });
    it('should not flag specific origin', () => {
      testPattern('mcp-supply-chain-cross-origin-tool-access',
        '"allowedOrigins": ["https://app.example.com"]', false);
    });
  });

  describe('mcp-supply-chain-timeout-disabled', () => {
    it('should detect timeout: 0', () => {
      testPattern('mcp-supply-chain-timeout-disabled',
        '"timeout": 0', true);
    });
    it('should detect requestTimeout: -1', () => {
      testPattern('mcp-supply-chain-timeout-disabled',
        '"requestTimeout": -1', true);
    });
    it('should detect executionTimeout: "infinite"', () => {
      testPattern('mcp-supply-chain-timeout-disabled',
        '"executionTimeout": "infinite"', true);
    });
    it('should not flag timeout: 30000', () => {
      testPattern('mcp-supply-chain-timeout-disabled',
        '"timeout": 30000', false);
    });
  });

});
