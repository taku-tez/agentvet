'use strict';
const { test, describe } = require('node:test');
const assert = require('node:assert');
let rules;
try {
  ({ rules } = require('../../dist/rules/insecure-llm-endpoint.js'));
} catch {
  ({ rules } = require('../../src/rules/insecure-llm-endpoint.js'));
}

describe('Insecure LLM Endpoint Rules', () => {
  function testRule(ruleId, content, shouldMatch) {
    const rule = rules.find(r => r.id === ruleId);
    assert.ok(rule, `Rule ${ruleId} should exist`);
    rule.pattern.lastIndex = 0;
    const matches = rule.pattern.test(content);
    assert.strictEqual(matches, shouldMatch,
      `Rule ${ruleId} ${shouldMatch ? 'should' : 'should not'} match: ${content.substring(0, 100)}`);
  }

  // ── HTTP endpoint ─────────────────────────────────────────────
  describe('Plaintext HTTP LLM Endpoint', () => {
    test('should detect http:// in base_url for remote host', () => {
      testRule('insecure-llm-endpoint-http',
        'base_url = "http://api.mycompany.com/v1"', true);
    });
    test('should detect http:// in api_base', () => {
      testRule('insecure-llm-endpoint-http',
        'api_base: "http://llm.internal.example.com/v1"', true);
    });
    test('should not flag https:// endpoint', () => {
      testRule('insecure-llm-endpoint-http',
        'base_url = "https://api.openai.com/v1"', false);
    });
    test('should not flag localhost http (dev use)', () => {
      testRule('insecure-llm-endpoint-http',
        'base_url = "http://localhost:11434/v1"', false);
    });
    test('should not flag 127.0.0.1 http (loopback)', () => {
      testRule('insecure-llm-endpoint-http',
        'endpoint = "http://127.0.0.1:8080/api"', false);
    });
  });

  // ── Deprecated model ──────────────────────────────────────────
  describe('Deprecated Model Name', () => {
    test('should detect gpt-4-0314 deprecated model', () => {
      testRule('insecure-llm-endpoint-deprecated-model',
        'model = "gpt-4-0314"', true);
    });
    test('should detect gpt-3.5-turbo-0301 deprecated model', () => {
      testRule('insecure-llm-endpoint-deprecated-model',
        'model_name: "gpt-3.5-turbo-0301"', true);
    });
    test('should detect text-davinci-003', () => {
      testRule('insecure-llm-endpoint-deprecated-model',
        'engine = "text-davinci-003"', true);
    });
    test('should not flag current gpt-4 alias', () => {
      testRule('insecure-llm-endpoint-deprecated-model',
        'model = "gpt-4"', false);
    });
    test('should not flag gpt-4o', () => {
      testRule('insecure-llm-endpoint-deprecated-model',
        'model = "gpt-4o"', false);
    });
  });

  // ── Default port ──────────────────────────────────────────────
  describe('Default/Common Port Endpoint', () => {
    test('should detect Ollama default port 11434', () => {
      testRule('insecure-llm-endpoint-default-port',
        'base_url = "http://192.168.1.100:11434"', true);
    });
    test('should detect LM Studio port 1234', () => {
      testRule('insecure-llm-endpoint-default-port',
        'api_base: "http://myserver.local:1234/v1"', true);
    });
    test('should not flag standard HTTPS without default LLM port', () => {
      testRule('insecure-llm-endpoint-default-port',
        'base_url = "https://api.openai.com/v1"', false);
    });
    test('should not flag standard port 443', () => {
      testRule('insecure-llm-endpoint-default-port',
        'endpoint = "https://myapi.com:443/v1"', false);
    });
  });

  // ── Hardcoded IP ──────────────────────────────────────────────
  describe('Hardcoded IP Address', () => {
    test('should detect hardcoded public IP in endpoint', () => {
      testRule('insecure-llm-endpoint-hardcoded-ip',
        'base_url = "https://203.0.113.42/v1"', true);
    });
    test('should detect hardcoded IP with port', () => {
      testRule('insecure-llm-endpoint-hardcoded-ip',
        'api_base: "http://10.0.0.5:8000/api"', true);
    });
    test('should not flag localhost IP', () => {
      testRule('insecure-llm-endpoint-hardcoded-ip',
        'url = "http://127.0.0.1:11434"', false);
    });
    test('should not flag hostname-based URL', () => {
      testRule('insecure-llm-endpoint-hardcoded-ip',
        'base_url = "https://api.openai.com/v1"', false);
    });
  });

  // ── Rule metadata ─────────────────────────────────────────────
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
    test('all rules have cwe', () => {
      rules.forEach(r => assert.ok(r.cwe, `Rule ${r.id} missing cwe`));
    });
    test('insecure-llm-endpoint-http exists', () => {
      assert.ok(rules.find(r => r.id === 'insecure-llm-endpoint-http'));
    });
    test('insecure-llm-endpoint-deprecated-model exists', () => {
      assert.ok(rules.find(r => r.id === 'insecure-llm-endpoint-deprecated-model'));
    });
    test('insecure-llm-endpoint-default-port exists', () => {
      assert.ok(rules.find(r => r.id === 'insecure-llm-endpoint-default-port'));
    });
    test('insecure-llm-endpoint-hardcoded-ip exists', () => {
      assert.ok(rules.find(r => r.id === 'insecure-llm-endpoint-hardcoded-ip'));
    });
  });
});
