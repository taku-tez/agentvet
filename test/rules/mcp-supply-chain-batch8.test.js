import { describe, it } from 'node:test';
import assert from 'node:assert';
import { rules } from '../../dist/rules/mcp-supply-chain.js';

const testPattern = (ruleId, content, shouldMatch) => {
  const rule = rules.find(r => r.id === ruleId);
  assert.ok(rule, `Rule ${ruleId} should exist`);
  rule.pattern.lastIndex = 0;
  const result = rule.pattern.test(content);
  assert.strictEqual(result, shouldMatch,
    `Rule ${ruleId} should ${shouldMatch ? 'match' : 'not match'}: ${content.substring(0, 120)}`);
};

describe('MCP Supply Chain Batch 8 Rules', () => {

  describe('Rule existence', () => {
    const batch8Rules = [
      'mcp-supply-chain-secret-in-server-name',
      'mcp-supply-chain-ssrf-via-tool-arg',
      'mcp-supply-chain-tool-call-spoofing',
      'mcp-supply-chain-ipc-socket-exposure',
      'mcp-supply-chain-debug-mode-enabled',
    ];
    for (const id of batch8Rules) {
      it(`rule ${id} should exist`, () => {
        const rule = rules.find(r => r.id === id);
        assert.ok(rule, `Rule ${id} should exist`);
        assert.strictEqual(rule.category, 'mcp-supply-chain');
      });
    }
  });

  describe('mcp-supply-chain-secret-in-server-name', () => {
    it('should detect OpenAI key in name', () => {
      testPattern('mcp-supply-chain-secret-in-server-name',
        '"name": "weather-sk-proj-abc1234567890abcdef1234567890"', true);
    });
    it('should detect GitHub PAT in description', () => {
      testPattern('mcp-supply-chain-secret-in-server-name',
        '"description": "Server ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ12345678ab"', true);
    });
    it('should detect AWS access key in server name', () => {
      testPattern('mcp-supply-chain-secret-in-server-name',
        '"serverName": "deploy-AKIAIOSFODNN7EXAMPLE"', true);
    });
    it('should not flag normal server names', () => {
      testPattern('mcp-supply-chain-secret-in-server-name',
        '"name": "weather-forecast-server"', false);
    });
  });

  describe('mcp-supply-chain-ssrf-via-tool-arg', () => {
    it('should detect AWS metadata endpoint in url arg', () => {
      testPattern('mcp-supply-chain-ssrf-via-tool-arg',
        '"url": "http://169.254.169.254/latest/meta-data/"', true);
    });
    it('should detect GCP metadata endpoint', () => {
      testPattern('mcp-supply-chain-ssrf-via-tool-arg',
        '"endpoint": "http://metadata.google.internal/computeMetadata/v1/"', true);
    });
    it('should detect Alibaba Cloud metadata', () => {
      testPattern('mcp-supply-chain-ssrf-via-tool-arg',
        '"fetch_url": "http://100.100.100.200/latest/meta-data/"', true);
    });
    it('should not flag normal URLs', () => {
      testPattern('mcp-supply-chain-ssrf-via-tool-arg',
        '"url": "https://api.openweathermap.org/data/2.5/weather"', false);
    });
  });

  describe('mcp-supply-chain-ipc-socket-exposure', () => {
    it('should detect /tmp socket path', () => {
      testPattern('mcp-supply-chain-ipc-socket-exposure',
        '"socketPath": "/tmp/mcp-server.sock"', true);
    });
    it('should detect /tmp pipe', () => {
      testPattern('mcp-supply-chain-ipc-socket-exposure',
        '"pipe": "/tmp/mcp.pipe"', true);
    });
    it('should not flag paths in restricted directories', () => {
      testPattern('mcp-supply-chain-ipc-socket-exposure',
        '"socketPath": "/var/run/mcp/server.sock"', false);
    });
  });

  describe('mcp-supply-chain-debug-mode-enabled', () => {
    it('should detect --debug flag in args array', () => {
      testPattern('mcp-supply-chain-debug-mode-enabled',
        '"args": ["server", "--debug", "--port", "3000"]', true);
    });
    it('should detect --verbose flag', () => {
      testPattern('mcp-supply-chain-debug-mode-enabled',
        '"args": ["--verbose", "start"]', true);
    });
    it('should detect --trace flag', () => {
      testPattern('mcp-supply-chain-debug-mode-enabled',
        '"args": ["run", "--trace"]', true);
    });
    it('should not flag normal args', () => {
      testPattern('mcp-supply-chain-debug-mode-enabled',
        '"args": ["start", "--port", "3000", "--host", "localhost"]', false);
    });
  });

});
