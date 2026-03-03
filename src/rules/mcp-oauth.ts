import type { Rule } from "../types.js";

/**
 * MCP OAuth 2.0 Security Rules
 * Detects OAuth/PKCE misconfigurations introduced with the MCP 2025-03-26 spec,
 * which mandates OAuth 2.0 for remote MCP server authentication.
 *
 * Attack vectors:
 * - Missing PKCE allows authorization code interception (MITM)
 * - Open redirect in callback URI exposes authorization codes
 * - Missing/predictable state parameter enables CSRF attacks
 * - Token leakage via logging or insecure storage
 * - Overly broad scopes grant excessive permissions
 *
 * References:
 * - MCP Specification 2025-03-26: Authorization (OAuth 2.0 mandatory for HTTP)
 * - RFC 7636: PKCE for OAuth 2.0 Public Clients
 * - RFC 6749: The OAuth 2.0 Authorization Framework
 * - OWASP Top 10 2025 - LLM09: Supply Chain Vulnerabilities
 */

export const rules: Rule[] = [
  // ============================================
  // Missing PKCE (Authorization Code Interception)
  // ============================================
  {
    id: 'mcp-oauth-missing-pkce',
    severity: 'high',
    description: 'OAuth authorization request missing PKCE code_challenge (interception risk)',
    pattern: /(?:authorizationUrl|authorization_url|auth_url|oauth2?_url|oauth_endpoint)\s*[=:]\s*["'][^"']*[?&](?:response_type=code|client_id=)[^"']*["']/gi,
    recommendation: 'MCP spec requires PKCE for all OAuth flows. Add code_challenge and code_challenge_method=S256 to authorization requests to prevent authorization code interception.',
    cwe: 'CWE-345',
    falsePositiveCheck: (match) => /code_challenge/.test(match[0]),
  },

  // OAuth token request without code_verifier (PKCE incomplete)
  {
    id: 'mcp-oauth-missing-code-verifier',
    severity: 'high',
    description: 'OAuth token exchange missing PKCE code_verifier',
    pattern: /(?:grant_type\s*[:=]\s*["']authorization_code["']|"grant_type"\s*:\s*"authorization_code")(?![\s\S]{0,300}code_verifier)/gi,
    recommendation: 'Complete PKCE by sending code_verifier in the token exchange request. Without it, a stolen authorization code can be exchanged for tokens.',
    cwe: 'CWE-345',
  },

  // ============================================
  // Missing State Parameter (CSRF)
  // ============================================
  {
    id: 'mcp-oauth-missing-state',
    severity: 'high',
    description: 'OAuth authorization flow without state parameter (CSRF vulnerability)',
    pattern: /response_type=(?:code|token)[^"'\s]*(?:client_id|redirect_uri)[^"'\s]*/gi,
    recommendation: 'Always include a cryptographically random state parameter in OAuth authorization requests to prevent Cross-Site Request Forgery attacks.',
    cwe: 'CWE-352',
    falsePositiveCheck: (match) => /[&?]state=/.test(match[0]),
  },

  // ============================================
  // Open Redirect in OAuth Callback
  // ============================================
  {
    id: 'mcp-oauth-open-redirect',
    severity: 'critical',
    description: 'OAuth callback redirect URI derived from user input (open redirect risk)',
    pattern: /(?:redirect_uri|callback_url|return_url)\s*[=:]\s*(?:req\.(?:query|body|params)|request\.(?:args|form|data)|params\[|query\[|getParam|getQueryParam)\s*[\[.(]["']?(?:redirect|return|next|url|to|callback|dest)/gi,
    recommendation: 'CRITICAL: redirect_uri must be a pre-registered static value, never derived from user input. An attacker can redirect the authorization code to their server.',
    cwe: 'CWE-601',
  },

  // Wildcard or overly broad redirect URI
  {
    id: 'mcp-oauth-wildcard-redirect',
    severity: 'critical',
    description: 'OAuth redirect URI uses wildcard or accepts any origin',
    pattern: /redirect_uri\s*[=:]\s*["'][^"']*(?:\*|localhost(?::\d+)?\/?\*|0\.0\.0\.0)[^"']*["']/gi,
    recommendation: 'Wildcard redirect URIs allow attackers to redirect authorization codes to any subdomain. Register exact redirect URIs only.',
    cwe: 'CWE-183',
  },

  // ============================================
  // Token Logging and Leakage
  // ============================================
  {
    id: 'mcp-oauth-token-logging',
    severity: 'critical',
    description: 'OAuth access token or refresh token logged to console or file',
    pattern: /(?:(?:console|logger|log|logging)\s*[.]\s*(?:log|info|debug|warn|error|write)|print(?:ln)?\s*)\s*\([^)]*(?:access_token|refresh_token|bearer_token|id_token|mcp_token|oauth_token)/gi,
    recommendation: 'CRITICAL: Never log OAuth tokens. Tokens in logs can be stolen from log files, aggregators, or monitoring systems.',
    cwe: 'CWE-532',
  },

  // Token in URL query parameter (referer leakage)
  {
    id: 'mcp-oauth-token-in-url',
    severity: 'high',
    description: 'OAuth token passed as URL query parameter (Referer header leakage risk)',
    pattern: /[?&](?:access_token|token|bearer|auth_token|mcp_token)=[^&\s"']+/gi,
    recommendation: 'Tokens in URLs leak via Referer headers, browser history, and server logs. Pass tokens in Authorization headers instead.',
    cwe: 'CWE-200',
    falsePositiveCheck: (_match, _content, filePath) => /(?:test|spec|fixture|mock|example)/i.test(filePath),
  },

  // ============================================
  // Insecure Token Storage
  // ============================================
  {
    id: 'mcp-oauth-localstorage-token',
    severity: 'high',
    description: 'OAuth token stored in localStorage (XSS-accessible)',
    pattern: /localStorage\.setItem\s*\(\s*["'][^"']*(?:token|auth|bearer|access|refresh|mcp)[^"']*["']\s*,\s*(?:access_token|refresh_token|token|authToken)/gi,
    recommendation: 'localStorage is accessible to any JavaScript on the page. Store tokens in httpOnly cookies or secure in-memory storage.',
    cwe: 'CWE-312',
  },

  // Hardcoded OAuth client secret
  {
    id: 'mcp-oauth-hardcoded-secret',
    severity: 'critical',
    description: 'OAuth client_secret hardcoded in source code',
    pattern: /["']?(?:client_secret|clientSecret|CLIENT_SECRET)["']?\s*[=:]\s*["'][a-zA-Z0-9+/\-_]{16,}["']/g,
    recommendation: 'CRITICAL: OAuth client secrets must never be hardcoded. Use environment variables or a secrets manager.',
    cwe: 'CWE-798',
    falsePositiveCheck: (match, content) => { const idx = content.indexOf(match[0]); return /(?:process\.env|os\.environ|getenv|secrets\.|vault\.)/.test(content.substring(Math.max(0, idx - 100), idx)); },
  },

  // ============================================
  // Overly Broad OAuth Scopes
  // ============================================
  {
    id: 'mcp-oauth-wildcard-scope',
    severity: 'high',
    description: 'OAuth scope requests all permissions (wildcard scope)',
    pattern: /(?:scope|scopes)\s*[=:]\s*["'][^"']*(?:\*|all|admin|\ball\b|full_access|superuser)[^"']*["']/gi,
    recommendation: 'Request only the minimum scopes needed (principle of least privilege). Wildcard or admin scopes grant excessive access.',
    cwe: 'CWE-250',
  },

  // ============================================
  // HTTP (non-HTTPS) OAuth Endpoints
  // ============================================
  {
    id: 'mcp-oauth-http-endpoint',
    severity: 'critical',
    description: 'MCP OAuth token endpoint uses HTTP instead of HTTPS (token interception risk)',
    pattern: /(?:token_endpoint|tokenUrl|token_url|authorization_endpoint|auth_endpoint)\s*[=:]\s*["']http:\/\/(?!localhost|127\.0\.0\.1|::1)/gi,
    recommendation: 'CRITICAL: OAuth endpoints must use HTTPS to prevent token interception. HTTP transmits tokens in plaintext.',
    cwe: 'CWE-319',
  },

  // ============================================
  // MCP Dynamic Client Registration (RFC 7591) misuse
  // ============================================
  {
    id: 'mcp-oauth-dynamic-registration-no-auth',
    severity: 'high',
    description: 'MCP dynamic client registration endpoint without authentication (RFC 7591 abuse risk)',
    pattern: /(?:app|router)\s*\.\s*(?:post|put|patch)\s*\(\s*["']\/(?:register|clients?)["']/gi,
    recommendation: 'Dynamic client registration endpoints should require an initial access token (RFC 7591 §3.1) to prevent unauthorized client registration.',
    cwe: 'CWE-306',
  },

  // ============================================
  // Token Expiry Not Checked
  // ============================================
  {
    id: 'mcp-oauth-no-expiry-check',
    severity: 'medium',
    description: 'OAuth token used without checking expiry (stale token risk)',
    pattern: /(?:access_token|bearer_token|mcp_token)\s*[=:][^;{]+(?:fetch|axios|request|http\.get|got)\s*\((?![\s\S]{0,500}(?:expires_in|expires_at|token_expiry|isExpired|refresh_token|tokenExpired))/gi,
    recommendation: 'Check token expiry before each use and refresh proactively. Using expired tokens can cause silent failures or security issues if token validation is inconsistent.',
    cwe: 'CWE-613',
  },
];

// CommonJS compatibility
module.exports = { rules };
