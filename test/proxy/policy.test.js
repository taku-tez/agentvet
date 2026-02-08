const { describe, it } = require('node:test');
const assert = require('node:assert');
const { PolicyEngine } = require('../../dist/proxy/policy.js');

describe('PolicyEngine', () => {
  const makePolicy = (rules, defaults = { action: 'allow' }, injection) => ({
    version: '1.0',
    name: 'test',
    rules,
    defaults,
    injection,
  });

  const makeRequest = (method, toolName, args = {}) => ({
    jsonrpc: '2.0',
    id: 1,
    method,
    params: { name: toolName, arguments: args },
  });

  it('should allow non-tool requests', () => {
    const engine = new PolicyEngine(makePolicy([
      { id: 'block-all', match: { toolPattern: '*' }, action: 'block' },
    ]));
    const result = engine.evaluate({ jsonrpc: '2.0', id: 1, method: 'tools/list' });
    assert.strictEqual(result.action, 'allow');
  });

  it('should block matching tool by name', () => {
    const engine = new PolicyEngine(makePolicy([
      { id: 'block-bash', match: { tool: ['bash', 'shell'] }, action: 'block', reason: 'No shell' },
    ]));
    const result = engine.evaluate(makeRequest('tools/call', 'bash'));
    assert.strictEqual(result.action, 'block');
    assert.strictEqual(result.rule.id, 'block-bash');
  });

  it('should allow non-matching tool', () => {
    const engine = new PolicyEngine(makePolicy([
      { id: 'block-bash', match: { tool: ['bash'] }, action: 'block' },
    ]));
    const result = engine.evaluate(makeRequest('tools/call', 'read_file'));
    assert.strictEqual(result.action, 'allow');
  });

  it('should match tool pattern with wildcard', () => {
    const engine = new PolicyEngine(makePolicy([
      { id: 'block-delete', match: { toolPattern: '*delete*' }, action: 'block' },
    ]));
    assert.strictEqual(engine.evaluate(makeRequest('tools/call', 'delete_file')).action, 'block');
    assert.strictEqual(engine.evaluate(makeRequest('tools/call', 'file_delete')).action, 'block');
    assert.strictEqual(engine.evaluate(makeRequest('tools/call', 'read_file')).action, 'allow');
  });

  it('should match argument contains', () => {
    const engine = new PolicyEngine(makePolicy([
      { id: 'block-env', match: { toolPattern: '*', args: { path: { contains: '.env' } } }, action: 'block' },
    ]));
    assert.strictEqual(engine.evaluate(makeRequest('tools/call', 'read_file', { path: '/app/.env' })).action, 'block');
    assert.strictEqual(engine.evaluate(makeRequest('tools/call', 'read_file', { path: '/app/config.js' })).action, 'allow');
  });

  it('should match argument regex', () => {
    const engine = new PolicyEngine(makePolicy([
      { id: 'block-ssh', match: { toolPattern: '*', args: { path: { matches: '\\.ssh/' } } }, action: 'block' },
    ]));
    assert.strictEqual(engine.evaluate(makeRequest('tools/call', 'read_file', { path: '/home/user/.ssh/id_rsa' })).action, 'block');
  });

  it('should match argument equals', () => {
    const engine = new PolicyEngine(makePolicy([
      { id: 'block-rm', match: { tool: ['exec'], args: { command: { equals: 'rm -rf /' } } }, action: 'block' },
    ]));
    assert.strictEqual(engine.evaluate(makeRequest('tools/call', 'exec', { command: 'rm -rf /' })).action, 'block');
    assert.strictEqual(engine.evaluate(makeRequest('tools/call', 'exec', { command: 'ls' })).action, 'allow');
  });

  it('should support negation in arg match', () => {
    const engine = new PolicyEngine(makePolicy([
      { id: 'block-non-txt', match: { tool: ['write_file'], args: { path: { not: { matches: '\\.txt$' } } } }, action: 'block' },
    ]));
    assert.strictEqual(engine.evaluate(makeRequest('tools/call', 'write_file', { path: 'test.txt' })).action, 'allow');
    assert.strictEqual(engine.evaluate(makeRequest('tools/call', 'write_file', { path: 'test.sh' })).action, 'block');
  });

  it('should use first matching rule', () => {
    const engine = new PolicyEngine(makePolicy([
      { id: 'allow-read', match: { tool: ['read_file'] }, action: 'allow' },
      { id: 'block-all-file', match: { toolPattern: '*file*' }, action: 'block' },
    ]));
    assert.strictEqual(engine.evaluate(makeRequest('tools/call', 'read_file')).action, 'allow');
    assert.strictEqual(engine.evaluate(makeRequest('tools/call', 'write_file')).action, 'block');
  });

  it('should fall back to default action', () => {
    const engine = new PolicyEngine(makePolicy([], { action: 'block' }));
    assert.strictEqual(engine.evaluate(makeRequest('tools/call', 'anything')).action, 'block');
  });

  it('should warn on matching tool', () => {
    const engine = new PolicyEngine(makePolicy([
      { id: 'warn-network', match: { tool: ['fetch'] }, action: 'warn', reason: 'Network access' },
    ]));
    const result = engine.evaluate(makeRequest('tools/call', 'fetch'));
    assert.strictEqual(result.action, 'warn');
    assert.strictEqual(result.reason, 'Network access');
  });

  it('should track events', () => {
    const engine = new PolicyEngine(makePolicy([
      { id: 'block-bash', match: { tool: ['bash'] }, action: 'block', reason: 'No shell' },
    ]));
    engine.evaluate(makeRequest('tools/call', 'bash'));
    engine.evaluate(makeRequest('tools/call', 'read_file'));
    const events = engine.getEvents();
    assert.strictEqual(events.length, 1);
    assert.strictEqual(events[0].type, 'block');
    assert.strictEqual(events[0].toolName, 'bash');
  });

  it('should handle multiple contains patterns', () => {
    const engine = new PolicyEngine(makePolicy([
      { id: 'block-secrets', match: { toolPattern: '*', args: { path: { contains: ['.env', 'secrets', 'credentials'] } } }, action: 'block' },
    ]));
    assert.strictEqual(engine.evaluate(makeRequest('tools/call', 'read_file', { path: '/secrets/key' })).action, 'block');
    assert.strictEqual(engine.evaluate(makeRequest('tools/call', 'read_file', { path: '/app/main.js' })).action, 'allow');
  });
});
