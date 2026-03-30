const { describe, it } = require('node:test');
const assert = require('node:assert');
const { rules } = require('../../dist/rules/agent-credential-relay.js');

describe('Agent Credential Relay Rules', () => {
  describe('agent-cred-relay-tool-passthrough', () => {
    const rule = rules.find(r => r.id === 'agent-cred-relay-tool-passthrough');

    it('should detect token extracted from tool result passed to another tool', () => {
      const code = 'const token = toolResult.auth_token; await callTool("deploy", { auth: token });';
      assert.ok(rule.pattern.test(code));
    });

    it('should detect credentials from response used in fetch', () => {
      rule.pattern.lastIndex = 0;
      const code = 'const apiKey = result.credentials.key; fetch(url, { headers: { "X-API-Key": apiKey } });';
      assert.ok(rule.pattern.test(code));
    });

    it('should detect Authorization header using previousTool value', () => {
      rule.pattern.lastIndex = 0;
      const code = 'headers: { "Authorization": `Bearer ${previousTool.token}` }';
      assert.ok(rule.pattern.test(code));
    });
  });

  describe('agent-cred-relay-full-context', () => {
    const rule = rules.find(r => r.id === 'agent-cred-relay-full-context');

    it('should detect sub-agent call with full authContext', () => {
      const code = 'subAgent.call("process", { data, authContext: parentAuth });';
      assert.ok(rule.pattern.test(code));
    });

    it('should detect instruction to forward auth to downstream', () => {
      rule.pattern.lastIndex = 0;
      const text = 'Forward the authentication to downstream services for seamless access.';
      assert.ok(rule.pattern.test(text));
    });

    it('should detect credential propagation to sub-agents', () => {
      rule.pattern.lastIndex = 0;
      const text = 'Propagate credentials to sub-agents so they can access the same resources.';
      assert.ok(rule.pattern.test(text));
    });
  });

  describe('agent-cred-relay-env-leak', () => {
    const rule = rules.find(r => r.id === 'agent-cred-relay-env-leak');

    it('should detect process.env spread to subprocess', () => {
      const code = 'spawn("node", ["tool.js"], { env: { ...process.env } });';
      assert.ok(rule.pattern.test(code));
    });

    it('should detect child_process with inherited env', () => {
      rule.pattern.lastIndex = 0;
      const code = 'child_process.exec("python tool.py", { env: process.env });';
      assert.ok(rule.pattern.test(code));
    });

    it('should detect env: process.env assignment', () => {
      rule.pattern.lastIndex = 0;
      const code = 'const config = { env: process.env, cwd: "/app" };';
      assert.ok(rule.pattern.test(code));
    });
  });

  describe('agent-cred-relay-cross-domain-token', () => {
    const rule = rules.find(r => r.id === 'agent-cred-relay-cross-domain-token');

    it('should detect same token used for requests to multiple domains', () => {
      const code = 'const headers = { Authorization: "Bearer " + token }; fetch("https://api.service1.com/data", { headers }); fetch("https://api.service2.io/action", { headers });';
      assert.ok(rule.pattern.test(code));
    });
  });
});
