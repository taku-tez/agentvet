'use strict';
const { test, describe } = require('node:test');
const assert = require('node:assert');
let rules;
try {
  ({ rules } = require('../../dist/rules/agentic-loop.js'));
} catch {
  ({ rules } = require('../../src/rules/agentic-loop.js'));
}

describe('Agentic Loop Detection Rules', () => {
  function testRule(ruleId, content, shouldMatch) {
    const rule = rules.find(r => r.id === ruleId);
    assert.ok(rule, `Rule ${ruleId} should exist`);
    rule.pattern.lastIndex = 0;
    const matches = rule.pattern.test(content);
    assert.strictEqual(matches, shouldMatch,
      `Rule ${ruleId} ${shouldMatch ? 'should' : 'should not'} match: ${content.substring(0, 100)}`);
  }

  // ── Self-invocation ──────────────────────────────────────────
  describe('Agent Self-Invocation', () => {
    test('should detect agent.run calling agent itself', () => {
      testRule('agentic-loop-self-invoke',
        'const result = agent.run(agent.buildPrompt())', true);
    });
    test('should detect assistant.invoke with recursive param', () => {
      testRule('agentic-loop-self-invoke',
        'llm.invoke(self.get_next_task())', true);
    });
    test('should not flag normal agent invocation without self-reference', () => {
      testRule('agentic-loop-self-invoke',
        'const r = model.complete("What is 2+2?")', false);
    });
    test('should not flag tool invocation with user input', () => {
      testRule('agentic-loop-self-invoke',
        'agent.run(userInput)', false);
    });
  });

  // ── Unlimited retry ──────────────────────────────────────────
  describe('Unlimited Retry Loop', () => {
    test('should detect retry loop with no limit', () => {
      testRule('agentic-loop-unlimited-retry',
        'retry = 0; while (true) { agent.call() }', true);
    });
    test('should detect retries forever keyword', () => {
      testRule('agentic-loop-unlimited-retry',
        'retries_loop forever { llm.complete() }', true);
    });
    test('should not match retry loop with max_retries', () => {
      testRule('agentic-loop-unlimited-retry',
        'retry = 0; max_retries = 3; while (retry < max_retries) { attempt() }', false);
    });
    test('should not match retry with retry_limit set', () => {
      testRule('agentic-loop-unlimited-retry',
        'retries = 0; retry_limit = 5; while (retries < retry_limit) { call() }', false);
    });
  });

  // ── Rule existence and severity checks ───────────────────────
  describe('Rule Metadata', () => {
    test('all rules have id', () => {
      rules.forEach(r => assert.ok(r.id, 'Rule must have id'));
    });
    test('all rules have severity', () => {
      rules.forEach(r => {
        assert.ok(['critical', 'high', 'medium', 'low', 'info'].includes(r.severity),
          `Rule ${r.id} has invalid severity: ${r.severity}`);
      });
    });
    test('all rules have recommendation', () => {
      rules.forEach(r => assert.ok(r.recommendation, `Rule ${r.id} missing recommendation`));
    });
    test('agentic-loop-self-invoke rule exists', () => {
      assert.ok(rules.find(r => r.id === 'agentic-loop-self-invoke'));
    });
    test('agentic-loop-no-iteration-limit rule exists', () => {
      assert.ok(rules.find(r => r.id === 'agentic-loop-no-iteration-limit'));
    });
    test('agentic-loop-recursive-no-depth rule exists', () => {
      assert.ok(rules.find(r => r.id === 'agentic-loop-recursive-no-depth'));
    });
    test('agentic-loop-unlimited-retry rule exists', () => {
      assert.ok(rules.find(r => r.id === 'agentic-loop-unlimited-retry'));
    });
    test('agentic-loop-thought-without-stop rule exists', () => {
      assert.ok(rules.find(r => r.id === 'agentic-loop-thought-without-stop'));
    });
  });
});
