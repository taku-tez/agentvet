import type { Rule } from "../types.js";

/**
 * Resource Exhaustion & Denial-of-Service Rules for AI Agents
 * Detects patterns where an AI agent may cause excessive resource consumption,
 * runaway loops, or deliberate denial-of-service against infrastructure or
 * downstream services.
 *
 * AI agents operating with agentic autonomy can exhaust resources unintentionally
 * (runaway loops, unbounded API calls) or be weaponized deliberately (DoS via
 * prompt injection, token flooding, infinite recursion through tool abuse).
 *
 * Attack surfaces include:
 * - Recursive agent spawning without depth limits
 * - Unbounded tool call loops (web search, API calls)
 * - Prompt amplification attacks (small input → huge LLM output)
 * - Memory/context window flooding to degrade model performance
 * - Rate limit bypass attempts against external APIs
 *
 * References:
 * - OWASP LLM Top 10 2025 - LLM04: Model Denial of Service
 * - OWASP LLM Top 10 2025 - LLM08: Excessive Agency
 * - CWE-400: Uncontrolled Resource Consumption
 * - CWE-674: Uncontrolled Recursion
 * - "Denial of Wallet" attacks in LLM API contexts (2025)
 */

export const rules: Rule[] = [
  // ============================================
  // 1. Runaway Loop Detection
  // ============================================
  {
    id: 'rexh-infinite-loop-instruction',
    severity: 'high',
    description: 'Instruction to loop indefinitely or without termination condition',
    pattern: /(?:loop\s+(?:forever|infinitely|indefinitely|until\s+(?:i\s+say\s+stop|stopped\s+externally))|(?:keep|continue)\s+(?:running|calling|repeating|retrying)\s+(?:forever|indefinitely|without\s+stopping)|repeat\s+(?:this\s+)?(?:process|step|loop)\s+(?:endlessly|forever|without\s+(?:limit|end|stopping))|while\s*\(\s*true\s*\)\s*\{[^}]{0,200}\})/gi,
    recommendation: 'Infinite loop instructions without termination conditions can exhaust compute resources and incur unbounded API costs. Enforce maximum iteration limits on all agent loops.',
    category: 'resource-exhaustion',
    cwe: 'CWE-835',
  },
  {
    id: 'rexh-recursive-self-spawn',
    severity: 'critical',
    description: 'Agent instructed to spawn copies of itself recursively',
    pattern: /(?:spawn\s+(?:another|a\s+new|multiple|more)\s+(?:copy\s+of\s+)?yourself|(?:create|launch|start)\s+(?:another|a\s+new)\s+(?:instance|copy)\s+of\s+(?:this\s+)?agent|(?:fork|clone)\s+(?:yourself|this\s+agent|the\s+current\s+agent)|sub[\s_-]agent\s+(?:should\s+)?spawn\s+sub[\s_-]agents?)/gi,
    recommendation: 'CRITICAL: Recursive agent self-spawning without depth limits can cause exponential resource growth. Implement strict sub-agent depth limits (e.g., max 3 levels) and count quotas.',
    category: 'resource-exhaustion',
    cwe: 'CWE-674',
  },
  {
    id: 'rexh-unbounded-tool-calls',
    severity: 'high',
    description: 'Pattern suggesting unbounded or excessive sequential tool invocations',
    pattern: /(?:call\s+(?:the\s+)?(?:api|tool|function|endpoint)\s+(?:for\s+each|on\s+every|across\s+all)\s+(?:item|record|entry|url|page|result)[^.]{0,100}(?:without|no)\s+(?:limit|pause|delay|rate[\s_-]limit)|(?:scrape|fetch|download|query)\s+(?:all|every)\s+(?:\w+\s+)?(?:simultaneously|without\s+limit|as\s+fast\s+as\s+possible)|(?:make|send)\s+(?:as\s+many|unlimited|unbounded)\s+(?:requests?|calls?|queries?))/gi,
    recommendation: 'Unbounded tool call loops can exhaust API rate limits, incur unexpected costs, and degrade downstream services. Enforce per-session tool call budgets and add rate limiting between calls.',
    category: 'resource-exhaustion',
    cwe: 'CWE-400',
  },

  // ============================================
  // 2. Token & Context Flooding
  // ============================================
  {
    id: 'rexh-context-flooding',
    severity: 'medium',
    description: 'Attempt to flood the agent context window with large repetitive content',
    pattern: /(?:(?:repeat|copy|paste|include)\s+(?:this|the following|above)\s+(?:text|content|message|block)\s+(?:\d{3,}|\w+\s+thousand)\s+times|(?:fill|pad)\s+(?:the\s+)?(?:context|prompt|input)\s+with|(?:generate|output|produce)\s+(?:as\s+many|maximum|unlimited)\s+tokens?\s+(?:as\s+possible|without\s+stopping))/gi,
    recommendation: 'Context window flooding degrades model performance and increases inference costs. Validate and truncate inputs exceeding reasonable length thresholds before processing.',
    category: 'resource-exhaustion',
    cwe: 'CWE-400',
  },
  {
    id: 'rexh-prompt-amplification',
    severity: 'high',
    description: 'Prompt designed to produce disproportionately large output from small input',
    pattern: /(?:(?:expand|elaborate|detail)\s+(?:each|every)\s+(?:word|character|letter|token)\s+into\s+(?:a\s+)?(?:paragraph|essay|page|chapter)|(?:write|generate)\s+(?:an?\s+)?(?:exhaustive|comprehensive|complete)\s+(?:list|description)\s+of\s+(?:every|all)\s+possible\s+(?:combination|permutation|variation)|(?:enumerate|list)\s+(?:all\s+)?(?:\d{4,}|\w+\s+thousand)\s+(?:examples?|items?|cases?))/gi,
    recommendation: 'Prompt amplification attacks exploit small inputs to generate massive outputs, causing high inference costs. Implement output token limits and validate instruction-to-output ratios.',
    category: 'resource-exhaustion',
    cwe: 'CWE-400',
  },

  // ============================================
  // 3. Rate Limit Bypass
  // ============================================
  {
    id: 'rexh-rate-limit-bypass',
    severity: 'high',
    description: 'Instruction to bypass or circumvent API rate limiting',
    pattern: /(?:(?:bypass|evade|circumvent|avoid|ignore)\s+(?:the\s+)?rate[\s_-]limit|(?:rotate|cycle|switch)\s+(?:through\s+)?(?:api[\s_-]keys?|tokens?|accounts?)\s+to\s+avoid\s+(?:rate[\s_-]limit|throttling|quota)|(?:use|try)\s+(?:multiple|different)\s+(?:api[\s_-]keys?|accounts?|proxies?)\s+(?:to\s+(?:avoid|bypass|evade)|alternating))/gi,
    recommendation: 'Rate limit bypass attempts violate provider terms of service and can exhaust shared infrastructure. Use legitimate retry-with-backoff patterns and request quota increases through official channels.',
    category: 'resource-exhaustion',
    cwe: 'CWE-307',
  },
  {
    id: 'rexh-denial-of-wallet',
    severity: 'critical',
    description: 'Instruction intended to maximize LLM API spending or exhaust billing quotas',
    pattern: /(?:(?:maximize|exhaust|drain|burn\s+through)\s+(?:the\s+)?(?:api[\s_-]?budget|token\s+quota|billing\s+limit|spending\s+limit|llm\s+credits?)|(?:consume|use\s+up)\s+(?:all|as\s+many)\s+(?:tokens?|api\s+calls?|credits?)\s+as\s+(?:possible|you\s+can)|denial[\s_-]of[\s_-]wallet|budget\s+exhaustion\s+cost\s+spike)/gi,
    recommendation: 'CRITICAL: Denial-of-Wallet attack detected. Malicious prompts can deliberately exhaust LLM API budgets. Enforce hard spending caps per session/user and alert on anomalous token consumption spikes.',
    category: 'resource-exhaustion',
    cwe: 'CWE-400',
  },

  // ============================================
  // 4. Memory & Storage Exhaustion
  // ============================================
  {
    id: 'rexh-memory-write-loop',
    severity: 'high',
    description: 'Instruction to write large or unbounded data to agent memory/storage',
    pattern: /(?:(?:write|store|save|append)\s+(?:to\s+)?(?:memory|storage|database|file|cache)\s+(?:in\s+a\s+loop|repeatedly|continuously|every\s+(?:second|minute|iteration))|(?:fill|flood|exhaust)\s+(?:agent\s+)?(?:memory|storage|disk|cache)|(?:generate|create)\s+(?:thousands?|millions?)\s+of\s+(?:memory|storage)\s+(?:entries?|records?|files?))/gi,
    recommendation: 'Unbounded memory or storage writes can exhaust agent working memory, cause crashes, or fill disk. Enforce write quotas, size limits, and TTL policies on agent memory entries.',
    category: 'resource-exhaustion',
    cwe: 'CWE-789',
  },

  // ============================================
  // 5. External Service Flooding
  // ============================================
  {
    id: 'rexh-external-service-flood',
    severity: 'high',
    description: 'Instruction to flood an external URL, server, or third-party service with requests',
    pattern: /(?:(?:send|make|fire)\s+(?:thousands?\s+of|millions?\s+of|hundreds?\s+of\s+thousands?\s+of|\d{4,})\s+(?:requests?|calls?|queries?|pings?)|(?:hammer|bombard|flood|DDoS|stress[\s_-]test)\s+(?:the\s+)?(?:server|api|endpoint|service|site)|(?:request|call|ping)\s+(?:the\s+)?(?:url|endpoint|api)\s+(?:as\s+fast\s+as\s+possible|without\s+(?:delay|pause|limit)))/gi,
    recommendation: 'Flooding external services constitutes a DoS attack and violates terms of service. All outbound request rates must be throttled with configurable delays and total request caps.',
    category: 'resource-exhaustion',
    cwe: 'CWE-400',
  },
];
