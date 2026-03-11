/**
 * Agent Memory Security Rules Tests
 */

const { describe, test } = require('node:test');
const assert = require('node:assert');

let rules;
try {
  ({ agentMemory } = require('../../dist/rules/index.js'));
  rules = agentMemory.rules;
} catch {
  const mod = require('../../src/rules/agent-memory.js');
  rules = mod.rules;
}

function matchRule(ruleId, text) {
  const rule = rules.find(r => r.id === ruleId);
  if (!rule) throw new Error(`Rule not found: ${ruleId}`);
  if (rule.pattern instanceof RegExp) {
    rule.pattern.lastIndex = 0;
    return rule.pattern.test(text);
  }
  return false;
}

// ─── agent-memory-unvalidated-write ──────────────────────────────────────────
describe('agent-memory-unvalidated-write', () => {
  test('should detect userInput written directly to memory.add()', () => {
    assert.ok(matchRule('agent-memory-unvalidated-write', `memory.add(userInput)`));
  });
  test('should detect req.body written to memory.store()', () => {
    assert.ok(matchRule('agent-memory-unvalidated-write', `mem.store(req.body.text, { userId })`));
  });
  test('should detect req.query written to longterm.save()', () => {
    assert.ok(matchRule('agent-memory-unvalidated-write', `longterm.save(req.query.q)`));
  });
  test('should detect message.content written to memory.remember()', () => {
    assert.ok(matchRule('agent-memory-unvalidated-write', `agent_memory.remember(message.content)`));
  });
  test('should NOT flag sanitized input', () => {
    assert.strictEqual(matchRule('agent-memory-unvalidated-write', `memory.add(sanitized(userInput))`), false);
  });
  test('should NOT flag internal data object', () => {
    assert.strictEqual(matchRule('agent-memory-unvalidated-write', `memory.add({ fact: 'The sky is blue' })`), false);
  });
});

// ─── agent-memory-raw-llm-response ───────────────────────────────────────────
describe('agent-memory-raw-llm-response', () => {
  test('should detect raw LLM response stored in memory', () => {
    assert.ok(matchRule('agent-memory-raw-llm-response', `memory.save(llmResponse.content)`));
  });
  test('should detect completion.text stored', () => {
    assert.ok(matchRule('agent-memory-raw-llm-response', `mem.add(completion.text, opts)`));
  });
  test('should detect modelResponse stored', () => {
    assert.ok(matchRule('agent-memory-raw-llm-response', `recall_store.store(modelResponse.output, key)`));
  });
  test('should detect ai.output stored verbatim', () => {
    assert.ok(matchRule('agent-memory-raw-llm-response', `longterm.remember(ai.output)`));
  });
  test('should NOT flag a literal string stored', () => {
    assert.strictEqual(matchRule('agent-memory-raw-llm-response', `memory.save("The user prefers dark mode")`), false);
  });
});

// ─── agent-memory-path-traversal ─────────────────────────────────────────────
describe('agent-memory-path-traversal', () => {
  test('should detect path.join with memory and userId from req.params', () => {
    assert.ok(matchRule('agent-memory-path-traversal',
      `const memPath = path.join(__dirname, 'memory', req.params.userId);`));
  });
  test('should detect fs.readFile with memory and req.query input', () => {
    assert.ok(matchRule('agent-memory-path-traversal',
      `fs.readFile(path.join(memDir, req.query.session), 'utf8', cb);`));
  });
  test('should NOT flag static memory path', () => {
    assert.strictEqual(matchRule('agent-memory-path-traversal',
      `const memPath = path.join(__dirname, 'memory', 'default.json');`), false);
  });
});

// ─── agent-memory-no-access-check ────────────────────────────────────────────
describe('agent-memory-no-access-check', () => {
  test('should detect memory.get(req.body.userId)', () => {
    assert.ok(matchRule('agent-memory-no-access-check', `const data = memory.get(req.body.userId)`));
  });
  test('should detect recall.fetch(params.id)', () => {
    assert.ok(matchRule('agent-memory-no-access-check', `recall.fetch(params.id)`));
  });
  test('should detect longterm.load(userId) without auth', () => {
    assert.ok(matchRule('agent-memory-no-access-check', `longterm.load(userId)`));
  });
});

// ─── agent-memory-sensitive-data ─────────────────────────────────────────────
describe('agent-memory-sensitive-data', () => {
  test('should detect password stored in memory', () => {
    assert.ok(matchRule('agent-memory-sensitive-data', `memory.store({ password: user.password })`));
  });
  test('should detect api_key stored in recall_store', () => {
    assert.ok(matchRule('agent-memory-sensitive-data', `recall_store.add({ api_key: creds.key })`));
  });
  test('should detect access_token stored in longterm', () => {
    assert.ok(matchRule('agent-memory-sensitive-data', `longterm.remember({ access_token: token })`));
  });
  test('should NOT flag regular preference data', () => {
    assert.strictEqual(matchRule('agent-memory-sensitive-data', `memory.store({ theme: 'dark', lang: 'en' })`), false);
  });
});

// ─── agent-memory-no-ttl ─────────────────────────────────────────────────────
describe('agent-memory-no-ttl', () => {
  test('should detect ConversationBufferMemory without TTL', () => {
    assert.ok(matchRule('agent-memory-no-ttl', `const mem = new ConversationBufferMemory({ returnMessages: true })`));
  });
  test('should detect ZepMemory without TTL', () => {
    assert.ok(matchRule('agent-memory-no-ttl', `new ZepMemory({ sessionId: userId, baseURL: zapUrl })`));
  });
  test('should detect RedisChatMessageHistory without TTL', () => {
    assert.ok(matchRule('agent-memory-no-ttl', `new RedisChatMessageHistory({ sessionId: sid, client: redis })`));
  });
  test('should NOT flag memory with ttl set', () => {
    assert.strictEqual(matchRule('agent-memory-no-ttl',
      `new ZepMemory({ sessionId: userId, ttl: 3600 })`), false);
  });
});

// ─── agent-memory-unsafe-deserialize ─────────────────────────────────────────
describe('agent-memory-unsafe-deserialize', () => {
  test('should detect pickle.loads on memory file', () => {
    assert.ok(matchRule('agent-memory-unsafe-deserialize', `state = pickle.loads(memory_data)`));
  });
  test('should detect torch.load on checkpoint', () => {
    assert.ok(matchRule('agent-memory-unsafe-deserialize', `model = torch.load(checkpoint_path)`));
  });
  test('should detect eval on recall data', () => {
    assert.ok(matchRule('agent-memory-unsafe-deserialize', `config = eval(recall_store_data)`));
  });
  test('should detect joblib.load on agent_state', () => {
    assert.ok(matchRule('agent-memory-unsafe-deserialize', `joblib.load(agent_state_file)`));
  });
  test('should NOT flag JSON.parse', () => {
    assert.strictEqual(matchRule('agent-memory-unsafe-deserialize', `const data = JSON.parse(memoryJson)`), false);
  });
});

// ─── agent-memory-shared-unscoped ────────────────────────────────────────────
describe('agent-memory-shared-unscoped', () => {
  test('should detect shared_memory.add()', () => {
    assert.ok(matchRule('agent-memory-shared-unscoped', `shared_memory.add(newFact)`));
  });
  test('should detect global_memory.store()', () => {
    assert.ok(matchRule('agent-memory-shared-unscoped', `global_memory.store(entry)`));
  });
  test('should detect team_memory.set()', () => {
    assert.ok(matchRule('agent-memory-shared-unscoped', `team_memory.set(key, value)`));
  });
  test('should detect pool_memory.write()', () => {
    assert.ok(matchRule('agent-memory-shared-unscoped', `pool_memory.write(ctx, data)`));
  });
});

// ─── agent-memory-tool-output-injection ──────────────────────────────────────
describe('agent-memory-tool-output-injection', () => {
  test('should detect tool_result stored directly in memory', () => {
    assert.ok(matchRule('agent-memory-tool-output-injection', `memory.save(tool_result.content, key)`));
  });
  test('should detect action_output stored in recall_store', () => {
    assert.ok(matchRule('agent-memory-tool-output-injection', `recall_store.add(action_output.text)`));
  });
  test('should detect function_result stored in memory', () => {
    assert.ok(matchRule('agent-memory-tool-output-injection', `mem.remember(function_result.output)`));
  });
  test('should detect tool_response stored verbatim', () => {
    assert.ok(matchRule('agent-memory-tool-output-injection', `memory.store(tool_response.result)`));
  });
  test('should NOT flag metadata storage', () => {
    assert.strictEqual(matchRule('agent-memory-tool-output-injection',
      `memory.save({ tool: 'search', timestamp: Date.now() })`), false);
  });
});
