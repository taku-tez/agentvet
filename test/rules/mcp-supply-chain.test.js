import { describe, it } from 'node:test';
import assert from 'node:assert';
import { rules } from '../../dist/rules/mcp-supply-chain.js';

/**
 * MCP Supply Chain Security Rules Tests (Issue #15)
 */

const testPattern = (ruleId, content, shouldMatch) => {
  const rule = rules.find(r => r.id === ruleId);
  assert.ok(rule, `Rule ${ruleId} should exist`);
  rule.pattern.lastIndex = 0;
  const result = rule.pattern.test(content);
  assert.strictEqual(
    result,
    shouldMatch,
    `Rule ${ruleId} should ${shouldMatch ? 'match' : 'not match'}: ${content.substring(0, 120)}`
  );
};

describe('MCP Supply Chain Security Rules', () => {

  describe('Rule existence', () => {
    const expectedRules = [
      'mcp-supply-chain-hardcoded-aws-key',
      'mcp-supply-chain-hardcoded-gcp-key',
      'mcp-supply-chain-slack-webhook-env',
      'mcp-supply-chain-openai-key-env',
      'mcp-supply-chain-git-url-server',
      'mcp-supply-chain-local-path-server',
      'mcp-supply-chain-unpinned-npx',
      'mcp-supply-chain-unofficial-anthropic-pkg',
      'mcp-supply-chain-privileged-exec',
      'mcp-supply-chain-docker-privileged',
      'mcp-supply-chain-host-network',
      'mcp-supply-chain-host-pid',
      'mcp-supply-chain-volume-etc-mount',
      'mcp-supply-chain-full-env-exposure',
      'mcp-supply-chain-ssh-key-env',
    ];
    for (const id of expectedRules) {
      it(`rule ${id} should exist`, () => {
        assert.ok(rules.find(r => r.id === id), `Missing rule: ${id}`);
      });
    }
  });

  // ----------------------------------------------------------------
  // AWS Key in env block
  // ----------------------------------------------------------------
  describe('mcp-supply-chain-hardcoded-aws-key', () => {
    it('detects AKIA key in env block', () => {
      testPattern('mcp-supply-chain-hardcoded-aws-key',
        '{"env":{"AWS_ACCESS_KEY_ID":"AKIAIOSFODNN7EXAMPLE1234"}}', true);
    });
    it('detects ASIA key in env block', () => {
      testPattern('mcp-supply-chain-hardcoded-aws-key',
        '"env": { "KEY": "ASIAXXX1234567890ABCD" }', true);
    });
    it('does not flag env var reference', () => {
      testPattern('mcp-supply-chain-hardcoded-aws-key',
        '"env": { "AWS_ACCESS_KEY_ID": "${AWS_ACCESS_KEY_ID}" }', false);
    });
  });

  // ----------------------------------------------------------------
  // OpenAI / Anthropic key in env block
  // ----------------------------------------------------------------
  describe('mcp-supply-chain-openai-key-env', () => {
    it('detects sk- key in OPENAI_API_KEY env', () => {
      testPattern('mcp-supply-chain-openai-key-env',
        '"env": { "OPENAI_API_KEY": "sk-abcdefghijklmnopqrstuvwxyz123456" }', true);
    });
    it('detects sk-ant- key in ANTHROPIC_API_KEY env', () => {
      testPattern('mcp-supply-chain-openai-key-env',
        '"env": { "ANTHROPIC_API_KEY": "sk-ant-api03-xxxxxxxxxxxxxxxxxxxxxxxxxxxx" }', true);
    });
    it('does not flag placeholder', () => {
      testPattern('mcp-supply-chain-openai-key-env',
        '"env": { "OPENAI_API_KEY": "${OPENAI_API_KEY}" }', false);
    });
  });

  // ----------------------------------------------------------------
  // Slack webhook in env block
  // ----------------------------------------------------------------
  describe('mcp-supply-chain-slack-webhook-env', () => {
    it('detects Slack webhook URL in env', () => {
      testPattern('mcp-supply-chain-slack-webhook-env',
        '"env": { "NOTIFY_URL": "https://hooks.slack.com/services/T123/B456/abc123def456" }', true);
    });
    it('does not flag plain API URL', () => {
      testPattern('mcp-supply-chain-slack-webhook-env',
        '"env": { "API_URL": "https://api.slack.com/methods/chat.postMessage" }', false);
    });
  });

  // ----------------------------------------------------------------
  // Git URL MCP server
  // ----------------------------------------------------------------
  describe('mcp-supply-chain-git-url-server', () => {
    it('detects git URL server launch', () => {
      testPattern('mcp-supply-chain-git-url-server',
        '"command": "node", "args": ["https://github.com/evil/mcp-server.git"]', true);
    });
    it('does not flag normal npx usage', () => {
      testPattern('mcp-supply-chain-git-url-server',
        '"command": "npx", "args": ["@modelcontextprotocol/server-filesystem@1.0.0"]', false);
    });
  });

  // ----------------------------------------------------------------
  // Unpinned npx server
  // ----------------------------------------------------------------
  describe('mcp-supply-chain-unpinned-npx', () => {
    it('detects unpinned npx server', () => {
      testPattern('mcp-supply-chain-unpinned-npx',
        '"command": "npx", "args": ["mcp-server-brave-search", "--port", "3000"]', true);
    });
    it('does not flag pinned version', () => {
      testPattern('mcp-supply-chain-unpinned-npx',
        '"command": "npx", "args": ["@modelcontextprotocol/server-filesystem@1.2.3"]', false);
    });
  });

  // ----------------------------------------------------------------
  // Privileged exec
  // ----------------------------------------------------------------
  describe('mcp-supply-chain-privileged-exec', () => {
    it('detects sudo in command', () => {
      testPattern('mcp-supply-chain-privileged-exec',
        '"command": "sudo", "args": ["node", "server.js"]', true);
    });
    it('does not flag normal node command', () => {
      testPattern('mcp-supply-chain-privileged-exec',
        '"command": "node", "args": ["server.js"]', false);
    });
  });

  // ----------------------------------------------------------------
  // Docker privileged
  // ----------------------------------------------------------------
  describe('mcp-supply-chain-docker-privileged', () => {
    it('detects --privileged flag', () => {
      testPattern('mcp-supply-chain-docker-privileged',
        '"args": ["run", "--privileged", "mcp-image"]', true);
    });
    it('does not flag normal docker run', () => {
      testPattern('mcp-supply-chain-docker-privileged',
        '"args": ["run", "-p", "3000:3000", "mcp-image"]', false);
    });
  });

  // ----------------------------------------------------------------
  // Host network
  // ----------------------------------------------------------------
  describe('mcp-supply-chain-host-network', () => {
    it('detects --network=host', () => {
      testPattern('mcp-supply-chain-host-network',
        '"args": ["run", "--network=host", "mcp-image"]', true);
    });
    it('does not flag --network bridge', () => {
      testPattern('mcp-supply-chain-host-network',
        '"args": ["run", "--network=bridge", "mcp-image"]', false);
    });
  });

  // ----------------------------------------------------------------
  // Sensitive volume mount
  // ----------------------------------------------------------------
  describe('mcp-supply-chain-volume-etc-mount', () => {
    it('detects /etc mount', () => {
      testPattern('mcp-supply-chain-volume-etc-mount',
        '"args": ["run", "-v /etc:/etc:ro", "mcp-image"]', true);
    });
    it('does not flag data volume', () => {
      testPattern('mcp-supply-chain-volume-etc-mount',
        '"args": ["run", "-v /data/myapp:/app/data", "mcp-image"]', false);
    });
  });

  // ----------------------------------------------------------------
  // SSH key in env
  // ----------------------------------------------------------------
  describe('mcp-supply-chain-ssh-key-env', () => {
    it('detects SSH_KEY env var', () => {
      testPattern('mcp-supply-chain-ssh-key-env',
        '"env": { "SSH_KEY": "/home/user/.ssh/id_rsa" }', true);
    });
    it('detects id_rsa path in env', () => {
      testPattern('mcp-supply-chain-ssh-key-env',
        '"env": { "GIT_SSH_KEY": "/root/.ssh/id_ed25519" }', true);
    });
    it('does not flag unrelated env var', () => {
      testPattern('mcp-supply-chain-ssh-key-env',
        '"env": { "APP_PORT": "3000" }', false);
    });
  });

  // ----------------------------------------------------------------
  // Category metadata
  // ----------------------------------------------------------------
  describe('category metadata', () => {
    it('all rules have mcp-supply-chain category', () => {
      for (const rule of rules) {
        assert.strictEqual(rule.category, 'mcp-supply-chain',
          `Rule ${rule.id} should have category mcp-supply-chain`);
      }
    });
    it('all rules have severity', () => {
      for (const rule of rules) {
        assert.ok(['critical','high','medium','warning'].includes(rule.severity),
          `Rule ${rule.id} has invalid severity: ${rule.severity}`);
      }
    });
    it('all rules have recommendation', () => {
      for (const rule of rules) {
        assert.ok(rule.recommendation && rule.recommendation.length > 20,
          `Rule ${rule.id} needs a meaningful recommendation`);
      }
    });
  });
});

// ----------------------------------------------------------------
// Additional Rules (Issue #15 continuation)
// ----------------------------------------------------------------

describe('mcp-supply-chain-unpinned-uvx', () => {
  it('flags uvx without version pin', () => {
    testPattern('mcp-supply-chain-unpinned-uvx',
      '"command": "uvx", "args": ["mcp-server-fetch", "--port", "3000"]', true);
  });

  it('flags uvx with bare package name', () => {
    testPattern('mcp-supply-chain-unpinned-uvx',
      '"command": "uvx", "args": ["some-mcp-tool"]', true);
  });

  it('does not flag uvx with pinned version', () => {
    testPattern('mcp-supply-chain-unpinned-uvx',
      '"command": "uvx", "args": ["mcp-server-fetch==1.2.3"]', false);
  });

  it('does not flag non-uvx commands', () => {
    testPattern('mcp-supply-chain-unpinned-uvx',
      '"command": "npx", "args": ["@modelcontextprotocol/server-filesystem"]', false);
  });
});

describe('mcp-supply-chain-github-raw-url', () => {
  it('flags raw.githubusercontent.com URL', () => {
    testPattern('mcp-supply-chain-github-raw-url',
      '"args": ["https://raw.githubusercontent.com/user/repo/main/server.js"]', true);
  });

  it('flags GitHub archive URL', () => {
    testPattern('mcp-supply-chain-github-raw-url',
      '"command": "node", "args": ["https://github.com/user/repo/raw/main/index.js"]', true);
  });

  it('does not flag published npm packages from GitHub releases', () => {
    testPattern('mcp-supply-chain-github-raw-url',
      '"command": "npx", "args": ["@modelcontextprotocol/server-github@1.0.0"]', false);
  });

  it('does not flag regular HTTPS server URLs', () => {
    testPattern('mcp-supply-chain-github-raw-url',
      '"url": "https://api.example.com/mcp"', false);
  });
});

describe('mcp-supply-chain-database-url-env', () => {
  it('flags PostgreSQL URL with credentials', () => {
    testPattern('mcp-supply-chain-database-url-env',
      '"env": { "DATABASE_URL": "postgres://admin:secret@localhost:5432/mydb" }', true);
  });

  it('flags MongoDB URI with credentials', () => {
    testPattern('mcp-supply-chain-database-url-env',
      '"env": { "MONGODB_URI": "mongodb://user:pass@cluster.mongodb.net/db" }', true);
  });

  it('flags Redis URL with credentials', () => {
    testPattern('mcp-supply-chain-database-url-env',
      '"env": { "REDIS_URL": "redis://user:secret@redis.example.com:6379" }', true);
  });

  it('does not flag DB URL without credentials', () => {
    testPattern('mcp-supply-chain-database-url-env',
      '"env": { "DATABASE_URL": "postgres://localhost:5432/mydb" }', false);
  });

  it('does not flag env vars referencing variable substitution', () => {
    testPattern('mcp-supply-chain-database-url-env',
      '"env": { "DB_HOST": "localhost", "DB_PORT": "5432" }', false);
  });
});

describe('mcp-supply-chain-payment-api-key-env', () => {
  it('flags Stripe live key in env', () => {
    testPattern('mcp-supply-chain-payment-api-key-env',
      '"env": { "STRIPE_SECRET_KEY": "sk_live_abc123xyz789longkey" }', true);
  });

  it('flags Stripe test key in env', () => {
    testPattern('mcp-supply-chain-payment-api-key-env',
      '"env": { "STRIPE_API_KEY": "sk_test_verylongkeystring123" }', true);
  });

  it('does not flag Stripe env var name without a real key value', () => {
    testPattern('mcp-supply-chain-payment-api-key-env',
      '"env": { "STRIPE_KEY": "${STRIPE_SECRET_KEY}" }', false);
  });

  it('does not flag unrelated env vars', () => {
    testPattern('mcp-supply-chain-payment-api-key-env',
      '"env": { "APP_ENV": "production", "PORT": "3000" }', false);
  });
});

describe('mcp-supply-chain-writable-host-mount', () => {
  it('flags host mount without :ro flag', () => {
    testPattern('mcp-supply-chain-writable-host-mount',
      '"args": ["-v /home/user/data:/data"]', true);
  });

  it('flags host mount with explicit :rw', () => {
    testPattern('mcp-supply-chain-writable-host-mount',
      '"args": ["-v /var/log:/logs:rw"]', true);
  });

  it('does not flag read-only host mounts', () => {
    testPattern('mcp-supply-chain-writable-host-mount',
      '"args": ["-v /home/user/config:/config:ro"]', false);
  });
});
