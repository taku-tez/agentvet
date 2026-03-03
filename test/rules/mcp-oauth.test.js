import { describe, it } from 'node:test';
import assert from 'node:assert';
import { rules } from '../../dist/rules/mcp-oauth.js';

/**
 * MCP OAuth 2.0 Security Rules Tests
 */

describe('MCP OAuth 2.0 Security Rules', () => {
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

  // ============================================
  // Missing PKCE
  // ============================================
  describe('Missing PKCE (mcp-oauth-missing-pkce)', () => {
    it('should detect OAuth authorization URL without code_challenge', () => {
      testPattern(
        'mcp-oauth-missing-pkce',
        'authorizationUrl = "https://auth.example.com/oauth/authorize?response_type=code&client_id=abc"',
        true
      );
    });

    it('should detect authorization_url without code_challenge', () => {
      testPattern(
        'mcp-oauth-missing-pkce',
        'authorization_url = "https://mcp.example.com/auth?client_id=xyz&response_type=code"',
        true
      );
    });

    it('should mark as false positive when code_challenge is present', () => {
      const rule = rules.find(r => r.id === 'mcp-oauth-missing-pkce');
      assert.ok(rule, 'Rule mcp-oauth-missing-pkce should exist');
      assert.ok(rule.falsePositiveCheck, 'Rule should have falsePositiveCheck');
      const content = 'authorizationUrl = "https://auth.example.com/oauth/authorize?response_type=code&client_id=abc&code_challenge=abc123&code_challenge_method=S256"';
      rule.pattern.lastIndex = 0;
      const match = content.match(rule.pattern);
      assert.ok(match, 'Pattern should match the content');
      assert.strictEqual(rule.falsePositiveCheck(match, content, 'test.ts'), true, 'Should be a false positive when code_challenge is present');
    });
  });

  // ============================================
  // Missing code_verifier
  // ============================================
  describe('Missing code_verifier (mcp-oauth-missing-code-verifier)', () => {
    it('should detect token exchange without code_verifier', () => {
      testPattern(
        'mcp-oauth-missing-code-verifier',
        'body: { grant_type: "authorization_code", code: authCode, redirect_uri: callbackUrl }',
        true
      );
    });

    it('should detect JSON token exchange without code_verifier', () => {
      testPattern(
        'mcp-oauth-missing-code-verifier',
        '"grant_type": "authorization_code", "code": "abc123", "client_id": "myapp"',
        true
      );
    });

    it('should not flag token exchange with code_verifier', () => {
      testPattern(
        'mcp-oauth-missing-code-verifier',
        'body: { grant_type: "authorization_code", code: authCode, code_verifier: pkceVerifier }',
        false
      );
    });
  });

  // ============================================
  // Missing State Parameter (CSRF)
  // ============================================
  describe('Missing state parameter (mcp-oauth-missing-state)', () => {
    it('should detect authorization request without state', () => {
      testPattern(
        'mcp-oauth-missing-state',
        'response_type=code&client_id=abc&redirect_uri=https://example.com/callback',
        true
      );
    });

    it('should detect token response_type without state', () => {
      testPattern(
        'mcp-oauth-missing-state',
        'response_type=token&redirect_uri=https://example.com/callback&client_id=abc',
        true
      );
    });

    it('should mark as false positive when state parameter is present', () => {
      const rule = rules.find(r => r.id === 'mcp-oauth-missing-state');
      assert.ok(rule, 'Rule mcp-oauth-missing-state should exist');
      assert.ok(rule.falsePositiveCheck, 'Rule should have falsePositiveCheck');
      const content = 'response_type=code&client_id=abc&redirect_uri=https://example.com/callback&state=randomcryptovalue';
      rule.pattern.lastIndex = 0;
      const match = content.match(rule.pattern);
      assert.ok(match, 'Pattern should match the content');
      assert.strictEqual(rule.falsePositiveCheck(match, content, 'test.ts'), true, 'Should be a false positive when state= is present');
    });
  });

  // ============================================
  // Open Redirect
  // ============================================
  describe('Open redirect in OAuth callback (mcp-oauth-open-redirect)', () => {
    it('should detect redirect_uri from request query', () => {
      testPattern(
        'mcp-oauth-open-redirect',
        'redirect_uri = req.query["redirect"]',
        true
      );
    });

    it('should detect callback_url from request body', () => {
      testPattern(
        'mcp-oauth-open-redirect',
        'callback_url = req.body["url"]',
        true
      );
    });

    it('should detect return_url from params', () => {
      testPattern(
        'mcp-oauth-open-redirect',
        'return_url = request.args["next"]',
        true
      );
    });

    it('should not flag hardcoded redirect URI', () => {
      testPattern(
        'mcp-oauth-open-redirect',
        'redirect_uri = "https://myapp.example.com/oauth/callback"',
        false
      );
    });
  });

  // ============================================
  // Wildcard Redirect URI
  // ============================================
  describe('Wildcard redirect URI (mcp-oauth-wildcard-redirect)', () => {
    it('should detect wildcard redirect URI', () => {
      testPattern(
        'mcp-oauth-wildcard-redirect',
        'redirect_uri = "https://*.example.com/callback"',
        true
      );
    });

    it('should detect localhost wildcard', () => {
      testPattern(
        'mcp-oauth-wildcard-redirect',
        'redirect_uri = "http://localhost/*"',
        true
      );
    });

    it('should not flag exact redirect URI', () => {
      testPattern(
        'mcp-oauth-wildcard-redirect',
        'redirect_uri = "https://app.example.com/oauth/callback"',
        false
      );
    });
  });

  // ============================================
  // Token Logging
  // ============================================
  describe('OAuth token logging (mcp-oauth-token-logging)', () => {
    it('should detect console.log of access_token', () => {
      testPattern(
        'mcp-oauth-token-logging',
        'console.log("Token received:", access_token)',
        true
      );
    });

    it('should detect logger.info of refresh_token', () => {
      testPattern(
        'mcp-oauth-token-logging',
        'logger.info("Refresh token:", refresh_token)',
        true
      );
    });

    it('should detect logger.debug of bearer_token', () => {
      testPattern(
        'mcp-oauth-token-logging',
        'logger.debug("Bearer:", bearer_token)',
        true
      );
    });

    it('should detect print of oauth_token', () => {
      testPattern(
        'mcp-oauth-token-logging',
        'print("Got oauth_token from server")',
        true
      );
    });

    it('should not flag logging token type without value', () => {
      testPattern(
        'mcp-oauth-token-logging',
        'console.log("Token type: Bearer")',
        false
      );
    });
  });

  // ============================================
  // Token in URL
  // ============================================
  describe('Token in URL query param (mcp-oauth-token-in-url)', () => {
    it('should detect access_token in URL', () => {
      testPattern(
        'mcp-oauth-token-in-url',
        'https://api.example.com/resource?access_token=eyJhbGciOiJSUzI1NiJ9',
        true
      );
    });

    it('should detect bearer token in URL', () => {
      testPattern(
        'mcp-oauth-token-in-url',
        'https://mcp.example.com/api?bearer=abc123xyz',
        true
      );
    });

    it('should not flag Authorization header usage', () => {
      testPattern(
        'mcp-oauth-token-in-url',
        'headers: { Authorization: "Bearer " + access_token }',
        false
      );
    });
  });

  // ============================================
  // localStorage Token Storage
  // ============================================
  describe('Token in localStorage (mcp-oauth-localstorage-token)', () => {
    it('should detect access_token stored in localStorage', () => {
      testPattern(
        'mcp-oauth-localstorage-token',
        'localStorage.setItem("mcp_token", access_token)',
        true
      );
    });

    it('should detect auth token stored in localStorage', () => {
      testPattern(
        'mcp-oauth-localstorage-token',
        'localStorage.setItem("auth_token", refresh_token)',
        true
      );
    });

    it('should not flag non-token data in localStorage', () => {
      testPattern(
        'mcp-oauth-localstorage-token',
        'localStorage.setItem("user_theme", "dark")',
        false
      );
    });
  });

  // ============================================
  // Hardcoded Client Secret
  // ============================================
  describe('Hardcoded OAuth client secret (mcp-oauth-hardcoded-secret)', () => {
    it('should detect hardcoded client_secret', () => {
      testPattern(
        'mcp-oauth-hardcoded-secret',
        'client_secret = "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6"',
        true
      );
    });

    it('should detect hardcoded clientSecret in JSON', () => {
      testPattern(
        'mcp-oauth-hardcoded-secret',
        '"clientSecret": "supersecretvalue1234567890abcdef"',
        true
      );
    });

    it('should detect hardcoded CLIENT_SECRET', () => {
      testPattern(
        'mcp-oauth-hardcoded-secret',
        'CLIENT_SECRET = "my-oauth-client-secret-abc123xyz"',
        true
      );
    });

    it('should not flag short placeholder value', () => {
      testPattern(
        'mcp-oauth-hardcoded-secret',
        'client_secret = "xxx"',
        false
      );
    });
  });

  // ============================================
  // Wildcard OAuth Scope
  // ============================================
  describe('Wildcard OAuth scope (mcp-oauth-wildcard-scope)', () => {
    it('should detect wildcard scope', () => {
      testPattern(
        'mcp-oauth-wildcard-scope',
        'scope = "*"',
        true
      );
    });

    it('should detect admin scope', () => {
      testPattern(
        'mcp-oauth-wildcard-scope',
        'scopes: "admin"',
        true
      );
    });

    it('should detect full_access scope', () => {
      testPattern(
        'mcp-oauth-wildcard-scope',
        'scope: "full_access"',
        true
      );
    });

    it('should not flag specific scopes', () => {
      testPattern(
        'mcp-oauth-wildcard-scope',
        'scope = "read:tools write:results"',
        false
      );
    });
  });

  // ============================================
  // HTTP OAuth Endpoint
  // ============================================
  describe('HTTP OAuth endpoint (mcp-oauth-http-endpoint)', () => {
    it('should detect HTTP token_endpoint', () => {
      testPattern(
        'mcp-oauth-http-endpoint',
        'token_endpoint = "http://auth.example.com/oauth/token"',
        true
      );
    });

    it('should detect HTTP authorization_endpoint', () => {
      testPattern(
        'mcp-oauth-http-endpoint',
        'authorization_endpoint: "http://remote-mcp.example.com/auth"',
        true
      );
    });

    it('should not flag HTTPS endpoints', () => {
      testPattern(
        'mcp-oauth-http-endpoint',
        'token_endpoint = "https://auth.example.com/oauth/token"',
        false
      );
    });

    it('should not flag localhost HTTP (development)', () => {
      testPattern(
        'mcp-oauth-http-endpoint',
        'token_endpoint = "http://localhost:3000/oauth/token"',
        false
      );
    });

    it('should not flag 127.0.0.1 HTTP (loopback)', () => {
      testPattern(
        'mcp-oauth-http-endpoint',
        'token_url = "http://127.0.0.1:8080/token"',
        false
      );
    });
  });

  // ============================================
  // Dynamic Client Registration without Auth
  // ============================================
  describe('Dynamic registration without auth (mcp-oauth-dynamic-registration-no-auth)', () => {
    it('should detect open /register endpoint', () => {
      testPattern(
        'mcp-oauth-dynamic-registration-no-auth',
        'app.post("/register", async (req, res) => { const client = await registerClient(req.body); })',
        true
      );
    });

    it('should detect open /clients endpoint', () => {
      testPattern(
        'mcp-oauth-dynamic-registration-no-auth',
        'router.post("/clients", (req, res) => { createOAuthClient(req.body); })',
        true
      );
    });
  });
});
