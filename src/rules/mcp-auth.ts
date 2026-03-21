import type { Rule } from "../types.js";

/**
 * MCP Authentication & Agent Identity Security Rules
 * Detects authentication weaknesses and identity risks in MCP-based agentic systems:
 *  - Hardcoded session tokens and bearer tokens in agent configs
 *  - Missing TLS verification for agent-to-agent communication
 *  - Insecure agent identity claims (trust-on-first-use without pinning)
 *  - Replay attack vectors via static nonce or missing timestamp validation
 *  - Overly permissive CORS/Origin headers on agent APIs
 */

// -------------------------------------------------------
// 1. Hardcoded Bearer / Session Tokens
// -------------------------------------------------------
const mcpAuthTokenRules: Rule[] = [
  {
    id: 'mcp-auth-hardcoded-bearer-token',
    severity: 'critical',
    description: 'Hardcoded Bearer token detected in MCP agent configuration',
    pattern: /"Authorization"\s*:\s*"Bearer\s+[A-Za-z0-9\-_.~+/]{20,}"/gi,
    recommendation: 'Never hardcode Bearer tokens in agent configs. Use environment variable substitution or a secrets manager (AWS Secrets Manager, HashiCorp Vault, etc.).',
    category: 'mcp-auth',
  },
  {
    id: 'mcp-auth-hardcoded-session-token',
    severity: 'critical',
    description: 'Hardcoded session or access token in agent environment configuration',
    pattern: /"(?:SESSION_TOKEN|ACCESS_TOKEN|AUTH_TOKEN|API_TOKEN)"\s*:\s*"[A-Za-z0-9\-_.~]{20,}"/gi,
    recommendation: 'Session and access tokens must not be stored in configuration files. Rotate immediately and inject via secrets management.',
    category: 'mcp-auth',
  },
  {
    id: 'mcp-auth-hardcoded-github-token',
    severity: 'critical',
    description: 'Hardcoded GitHub token (ghp_, gho_, github_pat_) in MCP config',
    pattern: /"[^"]*"\s*:\s*"(ghp_[A-Za-z0-9]{36}|gho_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82})"/gi,
    recommendation: 'Revoke the GitHub token immediately and use GitHub Actions secrets or a secrets manager instead of hardcoding.',
    category: 'mcp-auth',
  },
];

// -------------------------------------------------------
// 2. TLS/Certificate Verification Bypass
// -------------------------------------------------------
const mcpTlsBypassRules: Rule[] = [
  {
    id: 'mcp-auth-tls-verify-disabled',
    severity: 'high',
    description: 'TLS certificate verification explicitly disabled in MCP agent transport config',
    pattern: /"(?:verify_ssl|ssl_verify|verify|tls_verify|insecure)"\s*:\s*false/gi,
    recommendation: 'Never disable TLS certificate verification. Use a proper CA bundle or pin the server certificate. Disabling TLS verification enables MITM attacks against agent-to-agent communication.',
    category: 'mcp-auth',
  },
  {
    id: 'mcp-auth-no-verify-flag',
    severity: 'high',
    description: '--no-verify or --insecure flag used in MCP server startup command',
    pattern: /(?:--no-verify|--insecure|--skip-tls-verify|-k\b)/gi,
    recommendation: 'The --insecure / --no-verify flags disable TLS verification, making connections vulnerable to MITM. Configure a proper certificate chain instead.',
    category: 'mcp-auth',
  },
];

// -------------------------------------------------------
// 3. Static / Weak Nonce / Replay Attack Vectors
// -------------------------------------------------------
const mcpReplayRules: Rule[] = [
  {
    id: 'mcp-auth-static-nonce',
    severity: 'high',
    description: 'Static or hardcoded nonce value detected in MCP authentication payload',
    pattern: /"nonce"\s*:\s*"(?:test|static|fixed|0{8,}|1{8,}|[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}){1}"/gi,
    recommendation: 'Nonce values must be cryptographically random and single-use. Static nonces allow replay attacks against MCP authentication endpoints.',
    category: 'mcp-auth',
  },
  {
    id: 'mcp-auth-missing-expiry',
    severity: 'medium',
    description: 'JWT or token payload missing exp (expiration) claim in MCP agent token config',
    pattern: /"payload"\s*:\s*\{[^}]{0,300}\}(?!.*"exp"\s*:)/gi,
    recommendation: 'All agent authentication tokens must include an expiration claim (exp). Tokens without expiry enable indefinite replay attacks.',
    category: 'mcp-auth',
  },
];

// -------------------------------------------------------
// 4. Overly Permissive CORS / Origin
// -------------------------------------------------------
const mcpCorsRules: Rule[] = [
  {
    id: 'mcp-auth-cors-wildcard',
    severity: 'medium',
    description: 'Wildcard CORS origin (*) configured for MCP agent API endpoint',
    pattern: /"(?:cors_origin|allowed_origins|Access-Control-Allow-Origin)"\s*:\s*"\*"/gi,
    recommendation: 'Wildcard CORS allows any origin to call the MCP agent API. Restrict origins to known agent endpoints or use strict allowlists.',
    category: 'mcp-auth',
  },
  {
    id: 'mcp-auth-cors-credentials-wildcard',
    severity: 'high',
    description: 'CORS credentials allowed with wildcard origin — enables cross-origin credential theft',
    pattern: /"allow_credentials"\s*:\s*true[^}]{0,200}"(?:cors_origin|allowed_origins)"\s*:\s*"\*"/gis,
    recommendation: 'Combining credentials=true with origin=* is forbidden by CORS spec and a security risk. Specify explicit trusted origins when credentials are allowed.',
    category: 'mcp-auth',
  },
];

// -------------------------------------------------------
// 5. Agent Identity / Impersonation Risks
// -------------------------------------------------------
const mcpIdentityRules: Rule[] = [
  {
    id: 'mcp-auth-trust-all-agents',
    severity: 'high',
    description: 'Agent trust policy set to "all" or "any" — trusts all calling agents without verification',
    pattern: /"(?:trust_policy|agent_trust|caller_trust)"\s*:\s*"(?:all|any|everyone|\*|none)"/gi,
    recommendation: 'Never configure agent trust as "all". Use explicit agent identity verification (signed JWTs, mTLS, or public key pinning) to authenticate calling agents.',
    category: 'mcp-auth',
  },
  {
    id: 'mcp-auth-disable-agent-verification',
    severity: 'high',
    description: 'Agent identity verification explicitly disabled in MCP multi-agent config',
    pattern: /"(?:verify_agent|agent_verification|verify_caller)"\s*:\s*false/gi,
    recommendation: 'Agent identity verification must not be disabled. Use mTLS or signed tokens to ensure only authorized agents can invoke tools.',
    category: 'mcp-auth',
  },
];

export const rules: Rule[] = [
  ...mcpAuthTokenRules,
  ...mcpTlsBypassRules,
  ...mcpReplayRules,
  ...mcpCorsRules,
  ...mcpIdentityRules,
];

// CommonJS compatibility
module.exports = { rules };
