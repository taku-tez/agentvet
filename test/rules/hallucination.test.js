/**
 * Hallucination Risk Rules Unit Tests
 */

const { test, describe } = require('node:test');
const assert = require('node:assert');

let rules;
try {
  ({ rules } = require('../../dist/rules/hallucination.js'));
} catch {
  ({ rules } = require('../../src/rules/hallucination.js'));
}

describe('Hallucination Rules', () => {

  function testRule(ruleId, content, shouldMatch) {
    const rule = rules.find(r => r.id === ruleId);
    assert.ok(rule, `Rule ${ruleId} should exist`);
    rule.pattern.lastIndex = 0;
    const matches = rule.pattern.test(content);
    assert.strictEqual(matches, shouldMatch,
      `Rule ${ruleId} ${shouldMatch ? 'should' : 'should not'} match: ${content.substring(0, 100)}`);
  }

  test('should have 3 hallucination rules', () => {
    assert.strictEqual(rules.length, 3);
  });

  describe('hallucination-high-temperature', () => {
    test('detects temperature: 1.5', () => {
      testRule('hallucination-high-temperature', 'temperature: 1.5', true);
    });
    test('detects temperature=2.0', () => {
      testRule('hallucination-high-temperature', 'temperature=2.0', true);
    });
    test('detects temp: 1.1', () => {
      testRule('hallucination-high-temperature', 'temp: 1.1', true);
    });
    test('does not flag temperature: 0.7', () => {
      testRule('hallucination-high-temperature', 'temperature: 0.7', false);
    });
    test('does not flag temperature: 1.0', () => {
      testRule('hallucination-high-temperature', 'temperature: 1.0', false);
    });
  });

  describe('hallucination-no-grounding', () => {
    test('detects RAG config without grounding', () => {
      testRule('hallucination-no-grounding', 'rag: enabled\n  chunks: 5\n', true);
    });
    test('detects vector_store config without citation', () => {
      testRule('hallucination-no-grounding', 'vector_store: pinecone\n  index: main\n', true);
    });
    test('false positive check passes when grounding present', () => {
      const rule = rules.find(r => r.id === 'hallucination-no-grounding');
      assert.ok(rule.falsePositiveCheck);
      const result = rule.falsePositiveCheck(null, 'rag: enabled\ngrounding: true', 'config.yaml');
      assert.strictEqual(result, true);
    });
  });

  describe('hallucination-no-max-tokens', () => {
    test('detects model config without max_tokens', () => {
      testRule('hallucination-no-max-tokens', 'model: gpt-4\n  temperature: 0.7\n\n', true);
    });
    test('false positive check passes when max_tokens present', () => {
      const rule = rules.find(r => r.id === 'hallucination-no-max-tokens');
      assert.ok(rule.falsePositiveCheck);
      const result = rule.falsePositiveCheck(null, 'model: gpt-4\nmax_tokens: 1000', 'config.yaml');
      assert.strictEqual(result, true);
    });
  });

  test('all rules have severity medium', () => {
    for (const rule of rules) {
      assert.strictEqual(rule.severity, 'medium', `Rule ${rule.id} should have medium severity`);
    }
  });
});
