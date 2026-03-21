import type { Rule } from "../types.js";

/**
 * MCP Rate Limiting & DoS Protection Rules
 * Detects missing or misconfigured rate limiting in MCP agent configurations,
 * which can lead to resource exhaustion, cost amplification, and availability attacks.
 */

// -------------------------------------------------------
// 1. Missing Rate Limiting Configuration
// -------------------------------------------------------
const mcpRateLimitMissingRules: Rule[] = [
  {
    id: 'mcp-ratelimit-no-max-requests',
    severity: 'medium',
    description: 'MCP server configuration has no max_requests or rate_limit setting — vulnerable to request flooding',
    pattern: /"mcpServers"\s*:\s*\{[^}]{0,1000}\}(?!.*"(?:max_requests|rate_limit|request_limit|ratelimit)"\s*:)/gis,
    recommendation: 'Add rate limiting to all MCP server configurations (e.g., "max_requests": 100) to prevent resource exhaustion and cost amplification attacks from malicious agents.',
    category: 'mcp-ratelimit',
  },
  {
    id: 'mcp-ratelimit-unlimited-tokens',
    severity: 'high',
    description: 'MCP agent configured with unlimited token budget (max_tokens: -1 or very high value)',
    pattern: /"max_tokens"\s*:\s*(?:-1|999999|1000000|10000000)/gi,
    recommendation: 'Never set max_tokens to -1 or unreasonably high values. Set a reasonable per-request token budget (e.g., 4096-16384) to prevent cost amplification attacks.',
    category: 'mcp-ratelimit',
  },
  {
    id: 'mcp-ratelimit-unlimited-tool-calls',
    severity: 'high',
    description: 'MCP agent allows unlimited tool calls per session (max_tool_calls: -1 or 0)',
    pattern: /"max_tool_calls"\s*:\s*(?:-1|0)\b/gi,
    recommendation: 'Set a reasonable max_tool_calls limit per session to prevent infinite agentic loops and runaway resource consumption.',
    category: 'mcp-ratelimit',
  },
];

// -------------------------------------------------------
// 2. Misconfigured Timeouts
// -------------------------------------------------------
const mcpTimeoutRules: Rule[] = [
  {
    id: 'mcp-ratelimit-no-timeout',
    severity: 'medium',
    description: 'MCP tool or server has no timeout configured — long-running tools can exhaust resources',
    pattern: /"tools"\s*:\s*\{[^}]{0,500}\}(?!.*"timeout"\s*:)/gis,
    recommendation: 'Configure timeouts for all MCP tools (e.g., "timeout": 30000 in ms). Without timeouts, a malicious or misbehaving tool can indefinitely block agent processing.',
    category: 'mcp-ratelimit',
  },
  {
    id: 'mcp-ratelimit-excessive-timeout',
    severity: 'low',
    description: 'MCP tool timeout is excessively long (> 5 minutes)',
    pattern: /"timeout"\s*:\s*(?:[3-9]\d{5}|[1-9]\d{6,})\b/gi,
    recommendation: 'Tool timeouts exceeding 5 minutes (300000ms) are unusual and may indicate misconfiguration. Prefer short timeouts with retry logic.',
    category: 'mcp-ratelimit',
  },
];

// -------------------------------------------------------
// 3. Concurrent Request Limits
// -------------------------------------------------------
const mcpConcurrencyRules: Rule[] = [
  {
    id: 'mcp-ratelimit-unlimited-concurrency',
    severity: 'high',
    description: 'MCP server allows unlimited concurrent connections or requests',
    pattern: /"(?:max_concurrent|max_connections|concurrency_limit)"\s*:\s*(?:-1|0|99999)\b/gi,
    recommendation: 'Set a reasonable concurrency limit for MCP servers to prevent resource exhaustion. Values of -1 or 0 typically mean unlimited, which is dangerous in production.',
    category: 'mcp-ratelimit',
  },
  {
    id: 'mcp-ratelimit-no-backpressure',
    severity: 'low',
    description: 'MCP agent queue configured without backpressure (queue_size: -1 or missing drop policy)',
    pattern: /"queue_size"\s*:\s*-1\b/gi,
    recommendation: 'Configure finite queue sizes with explicit drop policies (drop_oldest, reject_new) to prevent memory exhaustion when agents are overwhelmed with requests.',
    category: 'mcp-ratelimit',
  },
];

// -------------------------------------------------------
// 4. Cost / Budget Protection
// -------------------------------------------------------
const mcpBudgetRules: Rule[] = [
  {
    id: 'mcp-ratelimit-no-cost-limit',
    severity: 'medium',
    description: 'MCP agent has no max_cost or budget_limit configured — vulnerable to cost amplification',
    pattern: /"model"\s*:\s*"[^"]+(?:gpt-4|claude-3|claude-opus|gemini-ultra)[^"]*"(?![\s\S]{0,200}"(?:max_cost|budget_limit|cost_limit|monthly_budget)"\s*:)/gi,
    recommendation: 'Set a cost/budget limit for agents using expensive models to prevent runaway API costs from prompt injection or agentic loop attacks.',
    category: 'mcp-ratelimit',
  },
  {
    id: 'mcp-ratelimit-no-session-limit',
    severity: 'low',
    description: 'MCP agent has no max_sessions or session_limit — unlimited parallel sessions possible',
    pattern: /"agent"\s*:\s*\{[^}]{0,500}\}(?!.*"(?:max_sessions|session_limit|max_parallel)"\s*:)/gis,
    recommendation: 'Limit the number of parallel agent sessions to prevent resource exhaustion and cost amplification from coordinated multi-agent attacks.',
    category: 'mcp-ratelimit',
  },
];

export const rules: Rule[] = [
  ...mcpRateLimitMissingRules,
  ...mcpTimeoutRules,
  ...mcpConcurrencyRules,
  ...mcpBudgetRules,
];

// CommonJS compatibility
module.exports = { rules };
