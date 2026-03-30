import type { Rule } from "../types.js";

/**
 * Agent Session Hijacking Detection Rules
 * Detects patterns where agent sessions, conversation contexts, or
 * ongoing tasks can be intercepted or taken over by attackers.
 *
 * As agents maintain long-running sessions with persistent state,
 * session hijacking becomes a critical attack vector — especially
 * in multi-tenant and shared-infrastructure deployments.
 *
 * References:
 * - OWASP LLM Top 10 2025 - LLM06: Excessive Agency
 * - "Securing AI Agents" (Bessemer VP, March 2026)
 * - CWE-384: Session Fixation
 */

export const rules: Rule[] = [
  // ── Agent session token in URL/query parameter ──
  {
    id: 'agent-session-token-in-url',
    severity: 'critical',
    description: 'Agent session token or conversation ID exposed in URL or query parameter',
    pattern: /(?:(?:url|href|link|redirect|location|endpoint)\s*[=:+]\s*[^;]*(?:\?|&)(?:session[_-]?id|conversation[_-]?id|thread[_-]?id|agent[_-]?token|auth[_-]?token|api[_-]?key)\s*=)/gi,
    recommendation: 'Never pass agent session tokens in URLs. Use HTTP headers (Authorization) or secure cookies. URL-based tokens are logged and exposed in referrer headers.',
    cwe: 'CWE-598',
    category: 'agent-session-hijack',
  },

  // ── Shared/hardcoded session across agents ──
  {
    id: 'agent-session-shared-static',
    severity: 'high',
    description: 'Static or shared session ID/token used across multiple agents or requests',
    pattern: /(?:session[_-]?(?:id|token|key)\s*[=:]\s*["'`](?:[a-zA-Z0-9_-]{8,})["'`]|(?:const|let|var|final)\s+(?:SESSION|AGENT_TOKEN|CONVERSATION_ID)\s*=\s*["'`][^"'`]{8,}["'`])/gi,
    recommendation: 'Session tokens should be dynamically generated per-session with cryptographic randomness. Hardcoded tokens allow session fixation attacks.',
    cwe: 'CWE-384',
    category: 'agent-session-hijack',
  },

  // ── Agent session without expiry/TTL ──
  {
    id: 'agent-session-no-expiry',
    severity: 'medium',
    description: 'Agent session created without expiry time, TTL, or timeout configuration',
    pattern: /(?:create[_-]?session|new[_-]?session|start[_-]?session|init[_-]?session|session\.create|session\.start)\s*\([^)]*\)(?:(?!(?:ttl|expir|timeout|max[_-]?age|lifetime|duration|valid[_-]?until)).){0,200}$/gims,
    recommendation: 'Agent sessions should have explicit TTL/expiry. Long-lived sessions increase the window for session hijacking. Set max session duration and implement re-authentication.',
    cwe: 'CWE-613',
    category: 'agent-session-hijack',
  },

  // ── Cross-tenant session access ──
  {
    id: 'agent-session-cross-tenant',
    severity: 'critical',
    description: 'Agent session lookup without tenant/user scope isolation',
    pattern: /(?:get[_-]?session|find[_-]?session|load[_-]?session|session\.(?:get|find|load|fetch))\s*\(\s*(?:session[_-]?id|id|token|key)\s*\)(?:(?!(?:tenant|user[_-]?id|org[_-]?id|workspace|scope|owner))\s*[^{]*\{)/gis,
    recommendation: 'Session lookups must include tenant/user scope to prevent cross-tenant session access. Always filter by both session_id AND tenant/user.',
    cwe: 'CWE-639',
    category: 'agent-session-hijack',
  },

  // ── Agent context injection via session restore ──
  {
    id: 'agent-session-context-injection',
    severity: 'high',
    description: 'Agent session restore loads unvalidated context/history from storage',
    pattern: /(?:restore|resume|load|deserialize|hydrate)[_-]?(?:session|context|conversation|history|state)\s*\([^)]*\)[\s\S]{0,200}(?:(?:system|prompt|instruction|message|context)\s*[=:]|\.push\s*\(|\.concat\s*\(|\.append\s*\()/gi,
    recommendation: 'Session restoration should validate and sanitize stored context before injecting into the agent\'s prompt. Tampered session data can inject malicious instructions.',
    cwe: 'CWE-502',
    category: 'agent-session-hijack',
  },
];
