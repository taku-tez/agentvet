const { describe, it } = require('node:test');
const assert = require('node:assert');
const { rules } = require('../../dist/rules/agent-session-hijack.js');

describe('Agent Session Hijacking Rules', () => {
  describe('agent-session-token-in-url', () => {
    const rule = rules.find(r => r.id === 'agent-session-token-in-url');

    it('should detect session_id in URL query parameter', () => {
      const code = 'const url = baseUrl + "?session_id=" + token;';
      assert.ok(rule.pattern.test(code));
    });

    it('should detect agent_token in redirect URL', () => {
      rule.pattern.lastIndex = 0;
      const code = 'redirect = endpoint + "?agent_token=" + agentAuth;';
      assert.ok(rule.pattern.test(code));
    });

    it('should detect conversation_id in link', () => {
      rule.pattern.lastIndex = 0;
      const code = 'link = "https://app.com/chat?conversation_id=" + convId;';
      assert.ok(rule.pattern.test(code));
    });
  });

  describe('agent-session-shared-static', () => {
    const rule = rules.find(r => r.id === 'agent-session-shared-static');

    it('should detect hardcoded session token', () => {
      const code = 'const SESSION = "abc123def456ghi789";';
      assert.ok(rule.pattern.test(code));
    });

    it('should detect static session_id assignment', () => {
      rule.pattern.lastIndex = 0;
      const code = 'session_id = "fixed-session-token-12345"';
      assert.ok(rule.pattern.test(code));
    });

    it('should detect hardcoded AGENT_TOKEN', () => {
      rule.pattern.lastIndex = 0;
      const code = 'const AGENT_TOKEN = "sk-agent-prod-token-xyz";';
      assert.ok(rule.pattern.test(code));
    });
  });

  describe('agent-session-no-expiry', () => {
    const rule = rules.find(r => r.id === 'agent-session-no-expiry');

    it('should detect session creation without TTL', () => {
      const code = 'const sess = create_session({ userId: "123", role: "agent" });\nreturn sess;';
      assert.ok(rule.pattern.test(code));
    });

    it('should detect session start without expiry', () => {
      rule.pattern.lastIndex = 0;
      const code = 'session.start({ agentId: "bot-1" })\nlogger.info("started");';
      assert.ok(rule.pattern.test(code));
    });
  });

  describe('agent-session-cross-tenant', () => {
    const rule = rules.find(r => r.id === 'agent-session-cross-tenant');

    it('should detect session lookup without tenant scope', () => {
      const code = 'const sess = get_session(session_id) { return db.find(session_id); }';
      assert.ok(rule.pattern.test(code));
    });

    it('should detect session find by id only', () => {
      rule.pattern.lastIndex = 0;
      const code = 'session.get(id) { return store[id]; }';
      assert.ok(rule.pattern.test(code));
    });
  });

  describe('agent-session-context-injection', () => {
    const rule = rules.find(r => r.id === 'agent-session-context-injection');

    it('should detect unvalidated context restore', () => {
      const code = 'const ctx = restore_session(sessionId); messages.push(ctx.history);';
      assert.ok(rule.pattern.test(code));
    });

    it('should detect deserialized session loaded into prompt', () => {
      rule.pattern.lastIndex = 0;
      const code = 'const state = deserialize_context(data); prompt = state.system;';
      assert.ok(rule.pattern.test(code));
    });

    it('should detect hydrated conversation appended to context', () => {
      rule.pattern.lastIndex = 0;
      const code = 'const conv = hydrate_conversation(stored); context.concat(conv.messages);';
      assert.ok(rule.pattern.test(code));
    });
  });
});
