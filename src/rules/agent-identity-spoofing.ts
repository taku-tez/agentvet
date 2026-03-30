import type { Rule } from "../types.js";

/**
 * Agent Identity Spoofing Detection Rules
 * Detects patterns where agents impersonate other agents, services, or
 * trusted identities in multi-agent systems.
 *
 * In 2026, multi-agent architectures (A2A, CrewAI, AutoGen) have become
 * common, creating new attack surfaces where compromised agents can spoof
 * identities to gain elevated trust or bypass authorization.
 *
 * References:
 * - Google A2A Protocol security considerations
 * - "Securing AI Agents" (Bessemer VP, March 2026)
 * - CWE-290: Authentication Bypass by Spoofing
 */

export const rules: Rule[] = [
  // ── Agent name/role set from untrusted input ──
  {
    id: 'agent-spoof-dynamic-identity',
    severity: 'high',
    description: 'Agent identity (name/role) set from external or user-controlled input',
    pattern: /(?:agent|bot|assistant)[\w.]*\s*(?:\.\s*(?:name|role|identity|persona|character)\s*=|(?:name|role|identity|persona|character)\s*:\s*)(?:.*(?:input|request|params?|args?|env|user|message|body|query|header))/gi,
    recommendation: 'Agent identities should be hardcoded or derived from signed configuration. Never set agent name/role from user-controlled input.',
    cwe: 'CWE-290',
    category: 'agent-identity-spoofing',
  },

  // ── Missing agent authentication in multi-agent communication ──
  {
    id: 'agent-spoof-no-auth-handshake',
    severity: 'high',
    description: 'Multi-agent message passing without authentication or verification',
    pattern: /(?:send_message|dispatch|forward|relay|broadcast)\s*\(\s*(?:agent|peer|target|recipient|dest)[^)]*\)\s*(?:(?!\s*\.verify|\s*\.authenticate|\s*\.validate|\s*if\s*\(\s*.*auth))/gi,
    recommendation: 'All inter-agent messages should be authenticated. Use signed tokens (JWT/mTLS) to verify agent identity before processing messages.',
    cwe: 'CWE-306',
    category: 'agent-identity-spoofing',
  },

  // ── Agent impersonation via system prompt ──
  {
    id: 'agent-spoof-system-prompt-impersonation',
    severity: 'critical',
    description: 'Content instructs agent to assume another agent\'s identity or role',
    pattern: /(?:you\s+are\s+(?:now\s+)?(?:agent|acting\s+as|pretending\s+to\s+be|impersonating)\s+\w+|assume\s+the\s+(?:identity|role)\s+of\s+agent\s+\w+|respond\s+as\s+(?:if\s+you\s+(?:are|were)\s+)?agent\s+\w+|from\s+now\s+(?:on\s+)?you(?:'re|\s+are)\s+agent\s+\w+)/gi,
    recommendation: 'Instructions to assume another agent\'s identity indicate an impersonation attack. Reject identity-changing instructions from untrusted sources.',
    cwe: 'CWE-290',
    category: 'agent-identity-spoofing',
  },

  // ── Forged agent metadata in A2A/multi-agent protocol ──
  {
    id: 'agent-spoof-forged-metadata',
    severity: 'high',
    description: 'Agent metadata (sender/source) can be set by external input without verification',
    pattern: /(?:(?:sender|source|from|origin|author|agent_id|agent_name|peer_id)\s*[=:]\s*(?:req|request|params?|args?|body|message|input|header|query)[\w.[\]]*)/gi,
    recommendation: 'Agent sender metadata should be cryptographically bound to the authenticated session. Never accept self-declared identity from message payloads.',
    cwe: 'CWE-290',
    category: 'agent-identity-spoofing',
  },

  // ── Agent Card without authentication ──
  {
    id: 'agent-spoof-unauthenticated-agent-card',
    severity: 'medium',
    description: 'A2A Agent Card served without authentication or integrity verification',
    pattern: /(?:agent[_-]?card|\.well-known\/agent)[\s\S]*?authentication[\s"']*:\s*(?:null|none|false|"none"|""|"\s*"|\[\s*\])/gi,
    recommendation: 'Agent Cards should require authentication and be served over HTTPS with integrity checks. Unauthenticated Agent Cards can be spoofed by MITM attackers.',
    cwe: 'CWE-306',
    category: 'agent-identity-spoofing',
  },
];
