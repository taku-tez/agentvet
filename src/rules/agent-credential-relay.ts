import type { Rule } from "../types.js";

/**
 * Agent Credential Relay & Forwarding Rules
 * Detects patterns where AI agents forward, relay, or propagate credentials
 * through multi-tool or multi-agent chains without proper scope reduction.
 *
 * In agentic architectures, credentials from one tool invocation can leak
 * to downstream tools if agents naively pass auth context through chains.
 * This violates the principle of least privilege and enables:
 * - Credential theft via malicious downstream tools
 * - Privilege escalation through credential reuse across trust boundaries
 * - Token replay attacks in multi-hop agent workflows
 *
 * References:
 * - "Securing AI Agents: Enterprise Playbook" (Microsoft, March 2026)
 * - OWASP LLM Top 10 2025 - LLM08: Excessive Agency
 * - MCP Security Vulnerabilities Guide 2026 (Aembit)
 * - CWE-522: Insufficiently Protected Credentials
 */

export const rules: Rule[] = [
  // ── Credentials passed directly between tool calls ──
  {
    id: 'agent-cred-relay-tool-passthrough',
    severity: 'critical',
    description: 'Credentials from one tool response passed directly to another tool call (credential relay attack surface)',
    pattern: /(?:(?:const|let|var)\s+(?:token|auth|cred(?:ential)?s?|api[_-]?key|secret|bearer)\s*=\s*(?:result|response|output|tool[_-]?(?:result|response|output))(?:\.\w+)*\s*;[^;]{0,200}(?:callTool|invokeTool|useTool|mcpClient|tool\.(?:call|invoke|use)|fetch|axios|request)\s*\(|(?:Authorization|Bearer|X-API-Key|X-Auth-Token)\s*['":\s]+\s*(?:\$\{?\s*)?(?:previousTool|upstreamTool|parentAgent|tool[_-]?(?:result|response)))/gi,
    recommendation: 'CRITICAL: Credentials extracted from one tool are being passed to another. This creates a credential relay chain where a compromised tool can harvest upstream credentials. Use scoped, short-lived tokens for each tool call and never forward upstream credentials downstream.',
    category: 'agent-credential-relay',
    cwe: 'CWE-522',
  },

  // ── Agent forwarding full auth context to sub-agents ──
  {
    id: 'agent-cred-relay-full-context',
    severity: 'high',
    description: 'Full authentication context forwarded to sub-agent or downstream service without scope reduction',
    pattern: /(?:(?:sub[_-]?agent|child[_-]?agent|downstream|delegate|worker)\s*\.\s*(?:call|invoke|run|execute|send)\s*\([^)]{0,300}(?:auth(?:Context|Token|Header|ority)?|credentials?|bearer[_-]?token|session[_-]?token)\b|(?:forward|pass|propagate|relay|inherit)\s*(?:the\s+)?(?:auth(?:entication|orization)?|credentials?|tokens?|session)\s+(?:to|into|through)\s+(?:sub[_-]?agents?|downstream|next\s+(?:tool|agent|step)))/gi,
    recommendation: 'Full auth context forwarded to sub-agent. Apply scope reduction: mint a new, narrower token for each sub-agent with only the permissions it needs. Never pass parent agent credentials to children.',
    category: 'agent-credential-relay',
    cwe: 'CWE-269',
  },

  // ── Environment variables exposed to MCP tool execution ──
  {
    id: 'agent-cred-relay-env-leak',
    severity: 'high',
    description: 'Sensitive environment variables passed to MCP tool or agent subprocess without filtering',
    pattern: /(?:(?:env|environment|process\.env)\s*(?::\s*process\.env|=\s*(?:\{\s*\.\.\.process\.env|process\.env))|spawn\s*\([^)]{0,100}env\s*:\s*(?:process\.env|\{\s*\.\.\.process\.env)|(?:child_process|exec|spawn|fork)\s*\([^)]{0,200}(?:env\s*:\s*process\.env|inheritEnv\s*:\s*true))/gi,
    recommendation: 'Passing full process.env to tool subprocesses exposes all secrets (API keys, tokens, database URLs). Create a filtered env object with only the variables the tool needs.',
    category: 'agent-credential-relay',
    cwe: 'CWE-526',
  },

  // ── Bearer token reuse across different API domains ──
  {
    id: 'agent-cred-relay-cross-domain-token',
    severity: 'high',
    description: 'Same bearer/API token variable used for requests to multiple different domains (cross-domain credential reuse)',
    pattern: /(?:(?:Authorization|Bearer|X-API-Key)['":\s]+(?:\+\s*|\$\{?\s*)?(?:token|apiKey|bearer|authToken)\b[\s\S]{0,500}https?:\/\/[\w.-]+\.(?:com|io|net|org|dev|ai)[\s\S]{0,500}https?:\/\/[\w.-]+\.(?:com|io|net|org|dev|ai))/gi,
    recommendation: 'Same authentication token used across different API domains. Each external service should receive its own scoped credential to prevent token theft via compromised services.',
    category: 'agent-credential-relay',
    cwe: 'CWE-522',
  },
];
