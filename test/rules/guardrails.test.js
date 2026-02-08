/**
 * Guardrails & Topic Restriction Rules Unit Tests
 */

const { test, describe } = require('node:test');
const assert = require('node:assert');

let rules;
try {
  ({ rules } = require('../../dist/rules/guardrails.js'));
} catch {
  ({ rules } = require('../../src/rules/guardrails.js'));
}

describe('Guardrails Rules', () => {

  function testRule(ruleId, content, shouldMatch) {
    const rule = rules.find(r => r.id === ruleId);
    assert.ok(rule, `Rule ${ruleId} should exist`);
    rule.pattern.lastIndex = 0;
    const matches = rule.pattern.test(content);
    assert.strictEqual(matches, shouldMatch,
      `Rule ${ruleId} ${shouldMatch ? 'should' : 'should not'} match: ${content.substring(0, 80)}`);
  }

  function testFalsePositive(ruleId, content, shouldBeFalsePositive) {
    const rule = rules.find(r => r.id === ruleId);
    assert.ok(rule, `Rule ${ruleId} should exist`);
    if (rule.falsePositiveCheck) {
      const result = rule.falsePositiveCheck(null, content, 'test.yaml');
      assert.strictEqual(result, shouldBeFalsePositive,
        `Rule ${ruleId} falsePositiveCheck should return ${shouldBeFalsePositive}`);
    }
  }

  test('should have 4 guardrails rules', () => {
    assert.strictEqual(rules.length, 4);
  });

  describe('config-no-guardrails', () => {
    test('should match agent config without guardrails', () => {
      testRule('config-no-guardrails', 'system_prompt: You are a helpful assistant', true);
      testRule('config-no-guardrails', 'agent_config = { model: "gpt-4" }', true);
    });

    test('should suppress when guardrails are configured', () => {
      testFalsePositive('config-no-guardrails',
        'system_prompt: hello\nguardrails_config: enabled', true);
      testFalsePositive('config-no-guardrails',
        'system_prompt: hello\nnemo_guardrails: true', true);
      testFalsePositive('config-no-guardrails',
        'system_prompt: hello\ncontent_filter: on', true);
      testFalsePositive('config-no-guardrails',
        'system_prompt: hello\nsafety_settings: strict', true);
      testFalsePositive('config-no-guardrails',
        'system_prompt: hello\nopenai_moderation: true', true);
    });

    test('should not suppress when no guardrails', () => {
      testFalsePositive('config-no-guardrails',
        'system_prompt: You are a helpful assistant\nmodel: gpt-4', false);
    });

    test('severity should be medium', () => {
      const rule = rules.find(r => r.id === 'config-no-guardrails');
      assert.strictEqual(rule.severity, 'medium');
    });
  });

  describe('config-no-input-filter', () => {
    test('should match config without input filter', () => {
      testRule('config-no-input-filter', 'system_message: Be nice', true);
    });

    test('should suppress when input filter configured', () => {
      testFalsePositive('config-no-input-filter',
        'system_prompt: hello\ninput_filter: enabled', true);
      testFalsePositive('config-no-input-filter',
        'system_prompt: hello\ninput_validation: strict', true);
      testFalsePositive('config-no-input-filter',
        'system_prompt: hello\ninput_rail: check', true);
    });

    test('should not suppress when no input filter', () => {
      testFalsePositive('config-no-input-filter',
        'system_prompt: hello\nmodel: gpt-4', false);
    });
  });

  describe('config-no-output-filter', () => {
    test('should match config without output filter', () => {
      testRule('config-no-output-filter', 'llm_config: something', true);
    });

    test('should suppress when output filter configured', () => {
      testFalsePositive('config-no-output-filter',
        'system_prompt: hello\noutput_filter: enabled', true);
      testFalsePositive('config-no-output-filter',
        'system_prompt: hello\nresponse_filter: on', true);
      testFalsePositive('config-no-output-filter',
        'system_prompt: hello\noutput_rail: check', true);
    });

    test('should not suppress when no output filter', () => {
      testFalsePositive('config-no-output-filter',
        'system_prompt: hello\nmodel: gpt-4', false);
    });
  });

  describe('config-no-topic-restriction', () => {
    test('should match config without topic restriction', () => {
      testRule('config-no-topic-restriction', 'system_prompt: You are helpful', true);
    });

    test('should suppress when topic restrictions present', () => {
      testFalsePositive('config-no-topic-restriction',
        'system_prompt: hello\nallowed_topics: finance, tech', true);
      testFalsePositive('config-no-topic-restriction',
        'system_prompt: hello\nblocked_topics: violence', true);
      testFalsePositive('config-no-topic-restriction',
        'system_prompt: Do not discuss politics\nmodel: gpt-4', true);
      testFalsePositive('config-no-topic-restriction',
        'system_prompt: Only discuss cooking recipes\nmodel: gpt-4', true);
      testFalsePositive('config-no-topic-restriction',
        'instructions: never talk about competitors', true);
    });

    test('should not suppress when no topic restriction', () => {
      testFalsePositive('config-no-topic-restriction',
        'system_prompt: You are a helpful assistant\nmodel: gpt-4', false);
    });

    test('severity should be low', () => {
      const rule = rules.find(r => r.id === 'config-no-topic-restriction');
      assert.strictEqual(rule.severity, 'low');
    });
  });
});
