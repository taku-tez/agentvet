import type { Rule } from "../types.js";

/**
 * MCP Callback Exfiltration Detection Rules
 * Detects data exfiltration via MCP server notifications, callbacks,
 * and webhook mechanisms.
 *
 * MCP servers can abuse notification/callback channels to exfiltrate
 * sensitive data from the agent's context. This is distinct from
 * traditional exfiltration because it uses the legitimate MCP protocol
 * transport as the covert channel.
 *
 * References:
 * - "MCP is the backdoor your zero-trust architecture forgot" (SC Media, 2026)
 * - MCP protocol notifications_changed, resources_changed events
 * - CWE-200: Information Exposure
 */

export const rules: Rule[] = [
  // ── MCP notification sends sensitive data to external URL ──
  {
    id: 'mcp-exfil-notification-external',
    severity: 'critical',
    description: 'MCP server notification/callback sends data to external endpoint',
    pattern: /(?:notification|callback|webhook|on_event|emit|notify)\s*\([^)]*(?:https?:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\])[^\s"'`,)]+)[^)]*(?:context|token|secret|key|password|credential|session|cookie|api_key|auth)/gis,
    recommendation: 'MCP notifications should never transmit sensitive context data to external URLs. Audit all outbound notification endpoints and restrict to localhost/internal.',
    cwe: 'CWE-200',
    category: 'mcp-callback-exfil',
  },

  // ── MCP tool encodes data in DNS/URL for exfiltration ──
  {
    id: 'mcp-exfil-dns-encoding',
    severity: 'critical',
    description: 'Data encoding for DNS/URL-based exfiltration detected in MCP context',
    pattern: /(?:btoa|base64|encodeURIComponent|encode|hexlify|b64encode)\s*\([^)]*(?:context|system_prompt|instructions|conversation|history|memory|secret|token|api_key|password|credential)[^)]*\)[\s\S]{0,200}(?:fetch|request|http|dns|query|lookup|resolve|url|href|src)/gi,
    recommendation: 'Encoding sensitive data and sending via DNS/HTTP queries is a classic exfiltration technique. Block outbound requests containing encoded context data.',
    cwe: 'CWE-200',
    category: 'mcp-callback-exfil',
  },

  // ── MCP server logs or stores sensitive agent context ──
  {
    id: 'mcp-exfil-context-logging',
    severity: 'high',
    description: 'MCP server logs or persists sensitive agent context (potential staging for exfiltration)',
    pattern: /(?:log|write|save|store|persist|append|record|track|capture)\s*\([^)]*(?:system_prompt|instructions|conversation|full_context|chat_history|agent_memory|user_message|tool_results?)\s*[,)]/gi,
    recommendation: 'MCP servers should not log or persist the agent\'s full context, system prompt, or conversation history. This creates exfiltration staging points.',
    cwe: 'CWE-532',
    category: 'mcp-callback-exfil',
  },

  // ── MCP resource subscription leaks data via polling ──
  {
    id: 'mcp-exfil-resource-subscription-leak',
    severity: 'high',
    description: 'MCP resource subscription or change notification contains sensitive data patterns',
    pattern: /(?:resources?[/_-]?(?:changed|updated|list_changed)|subscribe|on_change)[^}]*(?:(?:content|data|value|body|result)\s*[=:][^}]*(?:secret|token|key|password|credential|session|auth|cookie|api[_-]?key))/gis,
    recommendation: 'MCP resource change notifications should never contain credentials or secrets. Filter sensitive fields before emitting resource change events.',
    cwe: 'CWE-200',
    category: 'mcp-callback-exfil',
  },

  // ── MCP tool result includes external tracking pixel/beacon ──
  {
    id: 'mcp-exfil-tracking-beacon',
    severity: 'high',
    description: 'MCP tool result contains tracking pixel, beacon, or 1x1 image (data exfiltration indicator)',
    pattern: /(?:<img[^>]*(?:width|height)\s*=\s*["']?1["']?[^>]*(?:width|height)\s*=\s*["']?1["']?[^>]*src\s*=\s*["']?https?:\/\/|!\[(?:\s|\.)*\]\(https?:\/\/[^)]*(?:\?|&)(?:d|data|q|ctx|token|uid|ref)=)/gi,
    recommendation: 'Tracking pixels in MCP tool results can exfiltrate context via URL parameters. Strip or sanitize image tags from tool results.',
    cwe: 'CWE-200',
    category: 'mcp-callback-exfil',
  },
];
