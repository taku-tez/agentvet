/**
 * NeMo Report Format Tests
 */

const { test, describe } = require('node:test');
const assert = require('node:assert');

let printNemo;
try {
  ({ printNemo } = require('../dist/reporter.js'));
} catch {
  ({ printNemo } = require('../src/reporter.js'));
}

describe('NeMo Report Format', () => {
  test('should produce valid NeMo-compatible JSON', () => {
    const results = {
      scannedFiles: 10,
      findings: [
        {
          ruleId: 'config-no-guardrails',
          severity: 'medium',
          description: 'No guardrails configured',
          file: 'config.yaml',
          line: 5,
          recommendation: 'Add guardrails',
          category: 'guardrails',
          snippet: 'system_prompt: hello',
        },
      ],
      summary: { critical: 0, high: 0, warning: 1, info: 0, total: 1 },
    };

    const output = printNemo(results);
    const parsed = JSON.parse(output);

    assert.strictEqual(parsed.config_id, 'agentvet');
    assert.ok(parsed.scan_results);
    assert.strictEqual(parsed.scan_results.failed, 1);
    assert.strictEqual(parsed.scan_results.passed, 10);
    assert.strictEqual(parsed.scan_results.total, 11);
    assert.strictEqual(parsed.scan_results.details.length, 1);
    assert.strictEqual(parsed.scan_results.details[0].rule_id, 'config-no-guardrails');
    assert.strictEqual(parsed.scan_results.details[0].status, 'failed');
  });

  test('should handle empty findings', () => {
    const results = {
      scannedFiles: 5,
      findings: [],
      summary: { critical: 0, high: 0, warning: 0, info: 0, total: 0 },
    };

    const output = printNemo(results);
    const parsed = JSON.parse(output);

    assert.strictEqual(parsed.scan_results.failed, 0);
    assert.strictEqual(parsed.scan_results.passed, 5);
    assert.strictEqual(parsed.scan_results.details.length, 0);
  });

  test('should include all required fields in details', () => {
    const results = {
      scannedFiles: 1,
      findings: [{
        ruleId: 'test-rule',
        severity: 'high',
        description: 'Test finding',
        file: 'test.js',
        line: 10,
        recommendation: 'Fix it',
        category: 'test',
        match: 'bad code',
      }],
      summary: { total: 1 },
    };

    const output = printNemo(results);
    const detail = JSON.parse(output).scan_results.details[0];

    assert.strictEqual(detail.rule_id, 'test-rule');
    assert.strictEqual(detail.severity, 'high');
    assert.strictEqual(detail.status, 'failed');
    assert.strictEqual(detail.description, 'Test finding');
    assert.strictEqual(detail.file, 'test.js');
    assert.strictEqual(detail.line, 10);
    assert.strictEqual(detail.recommendation, 'Fix it');
    assert.strictEqual(detail.category, 'test');
    assert.strictEqual(detail.evidence, 'bad code');
  });
});
