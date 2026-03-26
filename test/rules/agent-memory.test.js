/**
 * Agent Memory Security Rules Unit Tests
 * Tests for memory poisoning, unsafe write, cross-session leaks,
 * reflection loops, and related agent memory attacks.
 */

const { describe, test } = require('node:test');
const assert = require('node:assert');
const { rules } = require('../../dist/rules/agent-memory.js');

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

describe('Agent Memory Security Rules', () => {

  // ============================================
  // Unvalidated Memory Write
  // ============================================
  describe('agent-memory-unvalidated-write', () => {
    test('detects memory.save with raw user input', () => {
      assert.ok(matches('agent-memory-unvalidated-write',
        'memory.save(user_input)'));
    });

    test('detects memory.add with raw user message', () => {
      assert.ok(matches('agent-memory-unvalidated-write',
        'memory.add(user_message)'));
    });

    test('detects mem.store with request body', () => {
      assert.ok(matches('agent-memory-unvalidated-write',
        'mem.store(request.body)'));
    });
  });

  // ============================================
  // Raw LLM Response Stored in Memory
  // ============================================
  describe('agent-memory-raw-llm-response', () => {
    test('detects memory.save with llm_response', () => {
      assert.ok(matches('agent-memory-raw-llm-response',
        'memory.save(llm_response)'));
    });

    test('detects mem.store with model_output', () => {
      assert.ok(matches('agent-memory-raw-llm-response',
        'mem.store(model_output)'));
    });
  });

  // ============================================
  // Unsafe Deserialization
  // ============================================
  describe('agent-memory-unsafe-deserialize', () => {
    test('detects pickle.load on memory file', () => {
      assert.ok(matches('agent-memory-unsafe-deserialize',
        'pickle.load(open("agent_memory.pkl", "rb"))'));
    });

    test('detects pickle.loads on agent_state', () => {
      assert.ok(matches('agent-memory-unsafe-deserialize',
        'state = pickle.loads(agent_state_bytes)'));
    });
  });

  // ============================================
  // Sensitive Data in Memory
  // ============================================
  describe('agent-memory-sensitive-data', () => {
    test('detects memory.save with password', () => {
      assert.ok(matches('agent-memory-sensitive-data',
        'memory.save({"password": user_password})'));
    });

    test('detects mem.store with api_key', () => {
      assert.ok(matches('agent-memory-sensitive-data',
        'mem.store(api_key=secret_key)'));
    });
  });

  // ============================================
  // Shared Memory Without Scoping
  // ============================================
  describe('agent-memory-shared-unscoped', () => {
    test('detects shared_memory.add without scoping', () => {
      assert.ok(matches('agent-memory-shared-unscoped',
        'shared_memory.add(task_result)'));
    });

    test('detects global_memory.store', () => {
      assert.ok(matches('agent-memory-shared-unscoped',
        'global_memory.store(agent_output)'));
    });

    test('detects team_memory.save', () => {
      assert.ok(matches('agent-memory-shared-unscoped',
        'team_memory.save(context)'));
    });
  });

  // ============================================
  // Tool Output Injected into Memory
  // ============================================
  describe('agent-memory-tool-output-injection', () => {
    test('detects memory.add with tool_result', () => {
      assert.ok(matches('agent-memory-tool-output-injection',
        'memory.add(tool_result)'));
    });

    test('detects mem.store with tool_output', () => {
      assert.ok(matches('agent-memory-tool-output-injection',
        'mem.store(tool_output)'));
    });

    test('detects memory.save with action_result', () => {
      assert.ok(matches('agent-memory-tool-output-injection',
        'memory.save(action_result)'));
    });
  });

  // ============================================
  // Memory Reflection Loop
  // ============================================
  describe('agent-memory-reflection-loop', () => {
    test('detects memory write using memory read result', () => {
      assert.ok(matches('agent-memory-reflection-loop',
        'memory.update(memory.get("last_context"))'));
    });

    test('detects mem.save wrapping mem.recall', () => {
      assert.ok(matches('agent-memory-reflection-loop',
        'mem.save(mem.recall("prior_instructions"))'));
    });

    test('detects long_term.store wrapping long_term.search', () => {
      assert.ok(matches('agent-memory-reflection-loop',
        'long_term.store(long_term.search(query))'));
    });
  });

  // ============================================
  // Cross-Session Memory Leak
  // ============================================
  describe('agent-memory-cross-session-leak', () => {
    test('detects vector_store.similarity_search without filter', () => {
      assert.ok(matches('agent-memory-cross-session-leak',
        'vector_store.similarity_search(query)'));
    });

    test('detects memory.search call', () => {
      assert.ok(matches('agent-memory-cross-session-leak',
        'memory.search(user_query)'));
    });

    test('detects chroma.query without user scope', () => {
      assert.ok(matches('agent-memory-cross-session-leak',
        'chroma.query(query_texts=[user_input])'));
    });

    test('detects pinecone.retrieve call', () => {
      assert.ok(matches('agent-memory-cross-session-leak',
        'pinecone.retrieve(embedding)'));
    });

    test('detects qdrant.search call', () => {
      assert.ok(matches('agent-memory-cross-session-leak',
        'qdrant.search(vectors=query_vector)'));
    });
  });

});
