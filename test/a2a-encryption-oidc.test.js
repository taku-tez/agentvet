/**
 * A2A Security Scanner — Encryption & OIDC Advanced Tests
 * Covers: TLS enforcement, non-standard ports, internal endpoints, OIDC discovery URL checks
 * Note: checkEncryption only runs when --url option is provided (not --config)
 */

const { test, describe } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const os = require('os');

let A2AScanner;
try {
  ({ A2AScanner } = require('../dist/a2a/index.js'));
} catch {
  ({ A2AScanner } = require('../src/a2a/index.js'));
}

function writeTempCard(card) {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'a2a-enc-test-'));
  const filePath = path.join(tmpDir, 'agent.json');
  fs.writeFileSync(filePath, JSON.stringify(card, null, 2));
  return filePath;
}

function cleanup(filePath) {
  try {
    fs.unlinkSync(filePath);
    fs.rmdirSync(path.dirname(filePath));
  } catch {}
}

// ====================================================
// Encryption: HTTP vs HTTPS (via --url option)
// ====================================================
describe('A2A Encryption — HTTP cleartext detection', () => {
  test('should flag HTTP endpoint as critical TLS violation', async () => {
    // Using --url option: checkEncryption runs even if fetch fails
    const scanner = new A2AScanner({ url: 'http://nonexistent-host-12345.example.com/agent' });
    const result = await scanner.scan();
    const finding = result.findings.find(f => f.id === 'a2a-tls-not-configured');
    assert.ok(finding, 'should detect HTTP cleartext as critical finding');
    assert.strictEqual(finding.severity, 'critical');
    assert.ok(finding.evidence?.includes('http://'));
  });

  test('should NOT flag HTTPS endpoint for TLS violation', async () => {
    const scanner = new A2AScanner({ url: 'https://nonexistent-host-12345.example.com/agent' });
    const result = await scanner.scan();
    const finding = result.findings.find(f => f.id === 'a2a-tls-not-configured');
    assert.strictEqual(finding, undefined, 'HTTPS endpoint should not trigger TLS finding');
  });

  test('HTTP finding should recommend HTTPS', async () => {
    const scanner = new A2AScanner({ url: 'http://nonexistent-host-12345.example.com/agent' });
    const result = await scanner.scan();
    const finding = result.findings.find(f => f.id === 'a2a-tls-not-configured');
    assert.ok(finding?.recommendation?.includes('HTTPS') || finding?.recommendation?.includes('TLS'));
  });

  test('HTTP finding should have CWE-319', async () => {
    const scanner = new A2AScanner({ url: 'http://nonexistent-host-12345.example.com/agent' });
    const result = await scanner.scan();
    const finding = result.findings.find(f => f.id === 'a2a-tls-not-configured');
    assert.strictEqual(finding?.cwe, 'CWE-319');
  });

  test('encryption check should be marked as ran even when fetch fails', async () => {
    const scanner = new A2AScanner({ url: 'http://nonexistent-host-12345.example.com/agent' });
    const result = await scanner.scan();
    assert.strictEqual(result.checks.encryption, true);
  });
});

// ====================================================
// Encryption: Non-standard port
// ====================================================
describe('A2A Encryption — Non-standard port detection', () => {
  test('should flag non-standard port 9000 as info finding', async () => {
    const scanner = new A2AScanner({ url: 'https://nonexistent-host-12345.example.com:9000/agent' });
    const result = await scanner.scan();
    const finding = result.findings.find(f => f.id === 'a2a-tls-nonstandard-port');
    assert.ok(finding, 'should flag non-standard port');
    assert.strictEqual(finding.severity, 'info');
    assert.ok(finding.title?.includes('9000'));
  });

  test('should NOT flag standard port 443', async () => {
    const scanner = new A2AScanner({ url: 'https://nonexistent-host-12345.example.com:443/agent' });
    const result = await scanner.scan();
    const finding = result.findings.find(f => f.id === 'a2a-tls-nonstandard-port');
    assert.strictEqual(finding, undefined, 'port 443 should not trigger nonstandard port finding');
  });

  test('should NOT flag standard port 80', async () => {
    const scanner = new A2AScanner({ url: 'http://nonexistent-host-12345.example.com:80/agent' });
    const result = await scanner.scan();
    const finding = result.findings.find(f => f.id === 'a2a-tls-nonstandard-port');
    assert.strictEqual(finding, undefined, 'port 80 should not trigger nonstandard port finding');
  });

  test('should NOT flag standard port 8443', async () => {
    const scanner = new A2AScanner({ url: 'https://nonexistent-host-12345.example.com:8443/agent' });
    const result = await scanner.scan();
    const finding = result.findings.find(f => f.id === 'a2a-tls-nonstandard-port');
    assert.strictEqual(finding, undefined, 'port 8443 should not trigger nonstandard port finding');
  });

  test('should flag port 3000 as non-standard', async () => {
    const scanner = new A2AScanner({ url: 'https://nonexistent-host-12345.example.com:3000/agent' });
    const result = await scanner.scan();
    const finding = result.findings.find(f => f.id === 'a2a-tls-nonstandard-port');
    assert.ok(finding, 'port 3000 should be flagged as non-standard');
  });

  test('should flag port 8080 as non-standard', async () => {
    const scanner = new A2AScanner({ url: 'https://nonexistent-host-12345.example.com:8080/agent' });
    const result = await scanner.scan();
    const finding = result.findings.find(f => f.id === 'a2a-tls-nonstandard-port');
    assert.ok(finding, 'port 8080 should be flagged as non-standard');
  });
});

// ====================================================
// Encryption: Internal/localhost endpoint
// ====================================================
describe('A2A Encryption — Internal endpoint detection', () => {
  test('should flag localhost endpoint as medium risk', async () => {
    const scanner = new A2AScanner({ url: 'https://localhost/agent' });
    const result = await scanner.scan();
    const finding = result.findings.find(f => f.id === 'a2a-tls-internal-endpoint');
    assert.ok(finding, 'should detect localhost as internal endpoint');
    assert.strictEqual(finding.severity, 'medium');
  });

  test('should flag 127.0.0.1 as internal endpoint', async () => {
    const scanner = new A2AScanner({ url: 'https://127.0.0.1/agent' });
    const result = await scanner.scan();
    const finding = result.findings.find(f => f.id === 'a2a-tls-internal-endpoint');
    assert.ok(finding, 'should detect 127.0.0.1 as loopback');
  });

  test('should flag 192.168.x.x as internal endpoint', async () => {
    const scanner = new A2AScanner({ url: 'https://192.168.1.100/agent' });
    const result = await scanner.scan();
    const finding = result.findings.find(f => f.id === 'a2a-tls-internal-endpoint');
    assert.ok(finding, 'should detect 192.168.x.x as internal');
  });

  test('should flag 10.x.x.x as internal endpoint', async () => {
    const scanner = new A2AScanner({ url: 'https://10.0.0.1/agent' });
    const result = await scanner.scan();
    const finding = result.findings.find(f => f.id === 'a2a-tls-internal-endpoint');
    assert.ok(finding, 'should detect 10.x.x.x as internal');
  });

  test('should flag 172.16.x.x as internal endpoint', async () => {
    const scanner = new A2AScanner({ url: 'https://172.16.0.1/agent' });
    const result = await scanner.scan();
    const finding = result.findings.find(f => f.id === 'a2a-tls-internal-endpoint');
    assert.ok(finding, 'should detect 172.16.x.x as RFC1918 internal');
  });

  test('should NOT flag public domain as internal', async () => {
    const scanner = new A2AScanner({ url: 'https://nonexistent-host-12345.example.com/agent' });
    const result = await scanner.scan();
    const finding = result.findings.find(f => f.id === 'a2a-tls-internal-endpoint');
    assert.strictEqual(finding, undefined, 'public domain should not trigger internal endpoint finding');
  });
});

// ====================================================
// OIDC Scheme Checks (via --config)
// ====================================================
describe('A2A Authentication — OIDC scheme validation', () => {
  test('should flag OIDC scheme missing openIdConnectUrl', async () => {
    const card = {
      name: 'OidcAgent',
      url: 'https://api.example.com/agent',
      version: '1.0',
      securitySchemes: {
        oidcScheme: {
          type: 'openIdConnect',
          // openIdConnectUrl intentionally omitted
        },
      },
    };
    const filePath = writeTempCard(card);
    try {
      const scanner = new A2AScanner({ config: filePath });
      const result = await scanner.scan();
      const finding = result.findings.find(f => f.id === 'a2a-auth-oidc-no-url');
      assert.ok(finding, 'should detect missing OIDC discovery URL');
      assert.strictEqual(finding.severity, 'high');
      assert.strictEqual(finding.cwe, 'CWE-287');
    } finally {
      cleanup(filePath);
    }
  });

  test('should flag OIDC discovery URL using HTTP as critical', async () => {
    const card = {
      name: 'InsecureOidcAgent',
      url: 'https://api.example.com/agent',
      version: '1.0',
      securitySchemes: {
        oidcScheme: {
          type: 'openIdConnect',
          openIdConnectUrl: 'http://sso.example.com/.well-known/openid-configuration',
        },
      },
    };
    const filePath = writeTempCard(card);
    try {
      const scanner = new A2AScanner({ config: filePath });
      const result = await scanner.scan();
      const finding = result.findings.find(f => f.id === 'a2a-auth-oidc-http');
      assert.ok(finding, 'should detect HTTP OIDC discovery URL');
      assert.strictEqual(finding.severity, 'critical');
      assert.ok(finding.evidence?.includes('http://'));
      assert.strictEqual(finding.cwe, 'CWE-319');
    } finally {
      cleanup(filePath);
    }
  });

  test('should NOT flag OIDC scheme with valid HTTPS discovery URL', async () => {
    const card = {
      name: 'SecureOidcAgent',
      url: 'https://api.example.com/agent',
      version: '1.0',
      securitySchemes: {
        oidcScheme: {
          type: 'openIdConnect',
          openIdConnectUrl: 'https://sso.example.com/.well-known/openid-configuration',
        },
      },
    };
    const filePath = writeTempCard(card);
    try {
      const scanner = new A2AScanner({ config: filePath });
      const result = await scanner.scan();
      const oidcFindings = result.findings.filter(f =>
        f.id === 'a2a-auth-oidc-no-url' || f.id === 'a2a-auth-oidc-http'
      );
      assert.strictEqual(oidcFindings.length, 0, 'valid OIDC config should not trigger OIDC findings');
    } finally {
      cleanup(filePath);
    }
  });

  test('OIDC missing URL finding should include scheme name in title', async () => {
    const card = {
      name: 'OidcAgent',
      url: 'https://api.example.com/agent',
      version: '1.0',
      securitySchemes: {
        myOidcScheme: {
          type: 'openIdConnect',
        },
      },
    };
    const filePath = writeTempCard(card);
    try {
      const scanner = new A2AScanner({ config: filePath });
      const result = await scanner.scan();
      const finding = result.findings.find(f => f.id === 'a2a-auth-oidc-no-url');
      assert.ok(finding?.title?.includes('myOidcScheme'), 'finding title should include scheme name');
    } finally {
      cleanup(filePath);
    }
  });

  test('should handle multiple OIDC schemes — one valid one invalid', async () => {
    const card = {
      name: 'MultiOidcAgent',
      url: 'https://api.example.com/agent',
      version: '1.0',
      securitySchemes: {
        goodOidc: {
          type: 'openIdConnect',
          openIdConnectUrl: 'https://good-sso.example.com/.well-known/openid-configuration',
        },
        badOidc: {
          type: 'openIdConnect',
          // missing openIdConnectUrl
        },
      },
    };
    const filePath = writeTempCard(card);
    try {
      const scanner = new A2AScanner({ config: filePath });
      const result = await scanner.scan();
      const noUrlFindings = result.findings.filter(f => f.id === 'a2a-auth-oidc-no-url');
      assert.strictEqual(noUrlFindings.length, 1, 'should flag exactly one missing URL finding');
      assert.ok(noUrlFindings[0].title?.includes('badOidc'), 'should identify the bad scheme by name');
    } finally {
      cleanup(filePath);
    }
  });
});

// ====================================================
// Combined: Multiple encryption issues in one URL
// ====================================================
describe('A2A Encryption — multiple findings combined', () => {
  test('should report TLS, internal, and port findings for http://192.168.0.50:9000', async () => {
    const scanner = new A2AScanner({ url: 'http://192.168.0.50:9000/agent' });
    const result = await scanner.scan();
    const tlsFinding = result.findings.find(f => f.id === 'a2a-tls-not-configured');
    const internalFinding = result.findings.find(f => f.id === 'a2a-tls-internal-endpoint');
    const portFinding = result.findings.find(f => f.id === 'a2a-tls-nonstandard-port');
    assert.ok(tlsFinding, 'should detect HTTP cleartext');
    assert.ok(internalFinding, 'should detect internal IP');
    assert.ok(portFinding, 'should detect non-standard port');
  });

  test('clean https public endpoint on port 443 should have no encryption findings', async () => {
    const scanner = new A2AScanner({ url: 'https://nonexistent-host-12345.example.com:443/agent' });
    const result = await scanner.scan();
    const encFindings = result.findings.filter(f =>
      f.id.startsWith('a2a-tls-')
    );
    assert.strictEqual(encFindings.length, 0, 'clean endpoint should have no TLS findings');
  });
});
