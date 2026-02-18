import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { rules } from '../../dist/rules/jwt.js';

describe('JWT Security Rules', () => {
  it('should have 13 JWT rules', () => {
    assert.equal(rules.length, 13);
  });

  describe('jwt-alg-none', () => {
    const rule = rules.find(r => r.id === 'jwt-alg-none');

    it('detects algorithm: "none"', () => {
      assert.match('algorithm: "none"', rule.pattern);
    });

    it('detects alg = \'none\'', () => {
      // Reset lastIndex for global regex
      rule.pattern.lastIndex = 0;
      assert.match("alg = 'none'", rule.pattern);
    });

    it('does not match algorithm: "HS256"', () => {
      rule.pattern.lastIndex = 0;
      assert.doesNotMatch('algorithm: "HS256"', rule.pattern);
    });
  });

  describe('jwt-algorithms-none-array', () => {
    const rule = rules.find(r => r.id === 'jwt-algorithms-none-array');

    it('detects algorithms: ["none", "HS256"]', () => {
      rule.pattern.lastIndex = 0;
      assert.match('algorithms: ["none", "HS256"]', rule.pattern);
    });

    it('does not match algorithms: ["RS256"]', () => {
      rule.pattern.lastIndex = 0;
      assert.doesNotMatch('algorithms: ["RS256"]', rule.pattern);
    });
  });

  describe('jwt-verify-disabled', () => {
    const rule = rules.find(r => r.id === 'jwt-verify-disabled');

    it('detects verify: false', () => {
      rule.pattern.lastIndex = 0;
      assert.match('verify: false', rule.pattern);
    });

    it('detects verify_signature = False', () => {
      rule.pattern.lastIndex = 0;
      assert.match('verify_signature = False', rule.pattern);
    });

    it('does not match verify: true', () => {
      rule.pattern.lastIndex = 0;
      assert.doesNotMatch('verify: true', rule.pattern);
    });
  });

  describe('jwt-decode-unverified', () => {
    const rule = rules.find(r => r.id === 'jwt-decode-unverified');

    it('detects jwt.decode(token)', () => {
      rule.pattern.lastIndex = 0;
      assert.match('jwt.decode(token, options)', rule.pattern);
    });

    it('detects jwt.decode(req.cookies.token)', () => {
      rule.pattern.lastIndex = 0;
      assert.match('jwt.decode(req.cookies.token)', rule.pattern);
    });
  });

  describe('jwt-hardcoded-secret', () => {
    const rule = rules.find(r => r.id === 'jwt-hardcoded-secret');

    it('detects jwt.sign(payload, "my-secret")', () => {
      rule.pattern.lastIndex = 0;
      assert.match('jwt.sign(payload, "my-secret-key-here")', rule.pattern);
    });

    it('does not match jwt.sign(payload, process.env.SECRET)', () => {
      rule.pattern.lastIndex = 0;
      assert.doesNotMatch('jwt.sign(payload, process.env.SECRET)', rule.pattern);
    });
  });

  describe('jwt-weak-secret-keyword', () => {
    const rule = rules.find(r => r.id === 'jwt-weak-secret-keyword');

    it('detects JWT_SECRET = "secret"', () => {
      rule.pattern.lastIndex = 0;
      assert.match('JWT_SECRET = "secret"', rule.pattern);
    });

    it('detects jwt_secret: "changeme"', () => {
      rule.pattern.lastIndex = 0;
      assert.match('jwt_secret: "changeme"', rule.pattern);
    });

    it('does not match jwt_secret: "a8f2k9..."', () => {
      rule.pattern.lastIndex = 0;
      assert.doesNotMatch('jwt_secret: "a8f2k9x7p3m1n5"', rule.pattern);
    });
  });

  describe('jwt-alg-confusion-risk', () => {
    const rule = rules.find(r => r.id === 'jwt-alg-confusion-risk');

    it('detects public key verify with HS256 in algorithms', () => {
      rule.pattern.lastIndex = 0;
      assert.match(
        'jwt.verify(token, publicKey, { algorithms: ["RS256", "HS256"] })',
        rule.pattern
      );
    });

    it('does not match verify with only RS256', () => {
      rule.pattern.lastIndex = 0;
      assert.doesNotMatch(
        'jwt.verify(token, publicKey, { algorithms: ["RS256"] })',
        rule.pattern
      );
    });
  });

  describe('jwt-kid-injection', () => {
    const rule = rules.find(r => r.id === 'jwt-kid-injection');

    it('detects kid used in readFileSync', () => {
      rule.pattern.lastIndex = 0;
      assert.match('header.kid + readFileSync(path)', rule.pattern);
    });
  });

  describe('jwt-token-in-url', () => {
    const rule = rules.find(r => r.id === 'jwt-token-in-url');

    it('detects token in URL query param', () => {
      rule.pattern.lastIndex = 0;
      assert.match('url = "https://api.example.com/data?token=eyJ..."', rule.pattern);
    });

    it('detects jwt in redirect URL', () => {
      rule.pattern.lastIndex = 0;
      assert.match('redirect = "/callback?jwt=abc123"', rule.pattern);
    });
  });

  describe('jwt-token-in-log', () => {
    const rule = rules.find(r => r.id === 'jwt-token-in-log');

    it('detects console.log with token', () => {
      rule.pattern.lastIndex = 0;
      assert.match('console.log("Auth token:", token)', rule.pattern);
    });

    it('detects logger.info with token', () => {
      rule.pattern.lastIndex = 0;
      assert.match('logger.info("token value: " + token)', rule.pattern);
    });
  });

  it('all rules have severity critical, high, or medium', () => {
    for (const rule of rules) {
      assert.ok(
        ['critical', 'high', 'medium'].includes(rule.severity),
        `${rule.id} has unexpected severity: ${rule.severity}`
      );
    }
  });

  it('all rules have CWE references', () => {
    for (const rule of rules) {
      assert.ok(rule.cwe, `${rule.id} missing CWE reference`);
    }
  });

  it('all rules have recommendations', () => {
    for (const rule of rules) {
      assert.ok(rule.recommendation, `${rule.id} missing recommendation`);
    }
  });
});
