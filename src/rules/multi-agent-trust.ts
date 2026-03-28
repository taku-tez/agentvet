import type { Rule } from "../types.js";

/**
 * Multi-Agent Trust & Authorization Rules
 * Detects security issues in multi-agent systems where agents interact,
 * delegate, or exchange data without proper authentication and trust boundaries.
 *
 * With the rise of A2A (Agent-to-Agent) protocols and orchestrator frameworks,
 * trust boundaries between agents have become a critical attack surface:
 * - Agents impersonating trusted systems to gain elevated access
 * - Unauthorized privilege escalation through agent chaining
 * - Missing authentication in inter-agent communication
 * - Data injection via unvalidated cross-agent payloads
 *
 * References:
 * - OWASP LLM Top 10 2025 - LLM08: Excessive Agency
 * - OWASP LLM Top 10 2025 - LLM09: Overreliance
 * - Google A2A Protocol Security Considerations (2025)
 * - Anthropic MAS (Multi-Agent Systems) Security Guide (2025)
 * - AgentVet Issue #12: Trust Chain & Signed Skills
 */

export const rules: Rule[] = [
  // ============================================
  // 1. Agent Identity & Impersonation
  // ============================================
  {
    id: 'mat-unverified-agent-identity',
    severity: 'high',
    description: 'Agent claiming trusted/verified identity without cryptographic verification',
    pattern: /(?:i\s+am\s+(?:a\s+)?(?:trusted|verified|authorized|official|system)\s+agent|acting\s+as\s+(?:the\s+)?(?:authorized|trusted|verified)\s+agent|this\s+(?:message|request)\s+(?:is\s+)?from\s+(?:a\s+)?(?:trusted|authorized)\s+agent|verified[\s_-]agent[\s_-]id|trusted[\s_-]orchestrator[\s_-]token)/gi,
    recommendation: 'Agent identity claims must be verified cryptographically (signed tokens, mTLS, or verifiable credentials). Never trust self-declared agent identity strings.',
    category: 'multi-agent-trust',
    cwe: 'CWE-287',
  },
  {
    id: 'mat-llm-provider-impersonation',
    severity: 'critical',
    description: 'Agent claiming to be a specific LLM provider (GPT/Claude/Gemini) to gain trust',
    pattern: /(?:i\s+am\s+(?:gpt|claude|gemini|llama|mistral|deepseek|o[134]|gpt-[0-9]|claude-[0-9])|(?:acting|responding)\s+as\s+(?:gpt|claude|gemini|chatgpt|anthropic\s+claude)|i\s+am\s+an?\s+(?:openai|anthropic|google\s+deepmind)\s+(?:model|assistant|agent))/gi,
    recommendation: 'CRITICAL: LLM provider impersonation detected. An agent claiming to be GPT/Claude/Gemini may trick other agents or users into trusting malicious output. Validate identity through official API channels only.',
    category: 'multi-agent-trust',
    cwe: 'CWE-290',
  },

  // ============================================
  // 2. Privilege Escalation via Agent Chain
  // ============================================
  {
    id: 'mat-cross-agent-privilege-escalation',
    severity: 'critical',
    description: 'Instruction to another agent to perform privileged/admin operation',
    pattern: /(?:(?:tell|ask|instruct|order|command|direct)\s+(?:the\s+)?(?:\w+[\s_-])?agent\s+to\s+(?:run\s+as\s+(?:root|admin|sudo)|bypass\s+(?:auth|permissions?|restrictions?|limits?)|grant\s+(?:admin|root|elevated)|disable\s+(?:security|guardrails?|restrictions?))|agent[\s_-](?:sudo|admin|root|elevated)[\s_-](?:mode|access|override))/gi,
    recommendation: 'CRITICAL: Cross-agent privilege escalation detected. Sub-agents must operate with their own least-privilege scope, not inherited/escalated from the calling agent.',
    category: 'multi-agent-trust',
    cwe: 'CWE-269',
  },
  {
    id: 'mat-delegation-without-scope',
    severity: 'high',
    description: 'Delegating full permissions to sub-agent without scope constraints',
    pattern: /(?:delegate\s+(?:all|full|complete|unlimited)\s+(?:permissions?|access|capabilities?|authority|rights?)\s+to\s+(?:sub[-_]?agent|agent|assistant)|subagent\s+(?:inherit|inherits)\s+(?:all|full|parent'?s?)\s+permissions?|(?:pass|forward|transfer)\s+(?:full|all)\s+(?:auth|permissions?|credentials?)\s+to\s+(?:sub[-_]?agent|child[-_]?agent)|hand[\s_-]off[\s_-](?:full|all)[\s_-](?:access|permissions?))/gi,
    recommendation: 'Never delegate full permissions to sub-agents. Use capability tokens with explicitly scoped permissions (principle of least authority).',
    category: 'multi-agent-trust',
    cwe: 'CWE-272',
  },

  // ============================================
  // 3. Ghost Admin / Injected Authority Claims
  // ============================================
  {
    id: 'mat-ghost-admin-claim',
    severity: 'critical',
    description: 'Injected authority claim in agent prompt (ghost admin pattern)',
    pattern: /(?:\[(?:SYSTEM|AGENT_SYSTEM|MASTER_AGENT|ORCHESTRATOR|SUPERVISOR)\]\s*(?:you\s+have|grant|allow|authorized?|override|bypass)|you\s+are\s+the\s+(?:master|primary|root|admin|supervisor|controller)\s+agent\s+(?:with|and\s+you\s+have)\s+(?:full|all|elevated|unrestricted)\s+(?:access|permissions?|authority)|as\s+the\s+system\s+agent[,\s]+(?:you\s+(?:must|should|can|are\s+allowed\s+to))\s+(?:bypass|override|ignore|skip))/gi,
    recommendation: 'CRITICAL: Ghost admin injection detected. Embedded authority claims in brackets or "you are master agent" style prompts are a classic privilege escalation vector. Reject prompts that assert agent authority outside official system channels.',
    category: 'multi-agent-trust',
    cwe: 'CWE-20',
  },

  // ============================================
  // 4. Unsigned / Unverified Skill Execution
  // ============================================
  {
    id: 'mat-unsigned-skill-execution',
    severity: 'high',
    description: 'Skill or agent tool executed without signature/manifest verification',
    pattern: /(?:skip(?:_|[\s-])?(?:signature|manifest|trust)(?:_|[\s-])?(?:check|verification?|validation?)|ignore(?:_|[\s-])?(?:signature|manifest|unsigned)|trust(?:_|[\s-])?unsigned(?:_|[\s-])?(?:skill|agent|tool)|bypass(?:_|[\s-])?manifest(?:_|[\s-])?(?:check|validation?)|(?:signature|manifest)(?:_|[\s-])?(?:check|verification?)\s*[:=]\s*(?:false|disabled?|off|0|none|null))/gi,
    recommendation: 'Skills and agent tools must have verified signatures. Use .agentvet-manifest.json with hash verification to detect tampering.',
    category: 'multi-agent-trust',
    cwe: 'CWE-347',
  },

  // ============================================
  // 5. A2A Authentication Gaps
  // ============================================
  {
    id: 'mat-a2a-missing-auth',
    severity: 'high',
    description: 'Agent-to-agent (A2A) endpoint call without authentication token',
    pattern: /(?:a2a[\s_-](?:call|request|message|invoke)\s+(?:without|no|skip)\s+(?:auth|token|credential|signature)|inter[\s_-]agent[\s_-](?:call|request)\s+(?:without|no)\s+(?:auth|token)|agent[\s_-]?endpoint\s+(?:no[\s_-]auth|unauthenticated|open)|(?:no|skip)[\s-]auth\s*=\s*true.*open\s*=\s*true|(?:\/api\/agents?|\/a2a\/)\s*\{[^}]*(?:auth|token|apiKey)\s*:\s*(?:false|null|undefined|''|""))/gi,
    recommendation: 'All A2A communications must be authenticated. Use signed JWT bearer tokens, mutual TLS, or API keys with per-agent scopes. Never expose agent endpoints without authentication.',
    category: 'multi-agent-trust',
    cwe: 'CWE-306',
  },
  {
    id: 'mat-forged-agent-header',
    severity: 'high',
    description: 'Agent identity taken directly from request headers without verification',
    pattern: /(?:req\.headers?\[['"]x-agent-(?:id|identity|name|role)['"]\]|request\.get\(['"]x-(?:agent|orchestrator)-(?:id|role)['"]\)|headers\[['"]x-trusted-agent['"]\]|req\.header\(['"]x-agent-authorization['"]\)\s*(?:===|!==|==|\|\||&&))/gi,
    recommendation: 'Agent identity headers (X-Agent-Id, X-Trusted-Agent) can be trivially forged. Verify agent identity via signed tokens or out-of-band authentication, not request headers.',
    category: 'multi-agent-trust',
    cwe: 'CWE-290',
  },

  // ============================================
  // 6. Recursive / Unbounded Agent Spawning
  // ============================================
  {
    id: 'mat-recursive-spawn-unlimited',
    severity: 'warning',
    description: 'Recursive or looping agent spawn without depth/count limit',
    pattern: /(?:(?:spawn|create|start|launch|fork)\s+(?:new\s+)?(?:sub[\s_-]?agent|child[\s_-]?agent|agent)\s+(?:in\s+a?\s+)?(?:loop|recursively|indefinitely|until|while)|while\s*\([^)]*\)\s*\{[^}]*(?:spawn|create|fork)\w*(?:Agent|SubAgent|_agent)\s*\(|(?:agent|orchestrator)\.spawn\s*\([^)]*\)\s*(?:without\s+)?(?:depth|limit|max)[\s_-](?:check|guard)?|max[\s_-](?:depth|spawn[\s_-]count|agent[\s_-]count)\s*[:=]\s*(?:-1|0|null|undefined|Infinity|unlimited)|spawn\w*(?:Agent|SubAgent)\s*\([^)]*\)\s*;?\s*\/\/.*(?:loop|recursive|unlimited))/gi,
    recommendation: 'Implement depth limits (e.g., max_depth: 5) and total spawn count limits to prevent exponential agent explosion attacks.',
    category: 'multi-agent-trust',
    cwe: 'CWE-674',
  },

  // ============================================
  // 7. Cross-Agent Data Injection
  // ============================================
  {
    id: 'mat-unvalidated-cross-agent-payload',
    severity: 'high',
    description: 'Unvalidated user input passed directly to sub-agent as instruction',
    pattern: /(?:(?:spawn|invoke|call|execute)(?:Agent|SubAgent|_agent|_subagent)\s*\(\s*(?:userInput|req\.body|request\.data|event\.text|message\.content|input)\s*\)|(?:agent|subagent)(?:\.run|\.execute|\.invoke|\.call|Runner\.run)\s*\(\s*(?:userInput|req\.body|untrusted|rawInput)\s*[,)"]|subagent\s*\.\s*(?:prompt|run|execute)\s*\([^)]*\+\s*(?:userInput|rawInput|\w*[Ii]nput)|(?:spawn|invoke|call|execute)\w*(?:Agent|SubAgent|_agent)\s*\(\s*(?:userInput|req\.body|untrusted|rawInput)\s*\))/gi,
    recommendation: 'Never pass raw user input directly to sub-agents as instructions. Sanitize, validate, and template all cross-agent payloads to prevent prompt injection relay attacks.',
    category: 'multi-agent-trust',
    cwe: 'CWE-74',
  },

  // ============================================
  // 8. Agent Enumeration & Discovery
  // ============================================
  {
    id: 'mat-agent-enumeration-attempt',
    severity: 'medium',
    description: 'Attempt to enumerate or discover available agents in the system',
    pattern: /(?:(?:list|enumerate|discover|find|show|get)\s+(?:all\s+)?(?:available\s+)?agents?\s+(?:in\s+(?:the\s+)?(?:system|network|cluster|org)|you\s+(?:can\s+)?(?:access|reach|connect\s+to|communicate\s+with))|what\s+agents?\s+(?:are|do\s+you\s+have|can\s+(?:i|you)\s+(?:access|use|talk\s+to|call))|available[\s_-]agents?\s*[:=?]|agent[\s_-](?:registry|directory|catalog|inventory)\s+(?:list|dump|export))/gi,
    recommendation: 'Agent enumeration exposes the attack surface of multi-agent systems. Restrict agent discovery to authorized orchestrators and implement access controls on agent registries.',
    category: 'multi-agent-trust',
    cwe: 'CWE-200',
  },

  // ============================================
  // 9. Role Confusion
  // ============================================
  {
    id: 'mat-system-role-user-confusion',
    severity: 'critical',
    description: 'User/agent message being treated as system-level instruction',
    pattern: /(?:role\s*[:=]\s*['"](?:system|admin|root|orchestrator)['"]\s*,\s*content\s*[:=]\s*(?:req\.|user(?:Input|Message|Text)|untrusted|external)|trust(?:ing)?\s+(?:user|agent)\s+(?:message|input)\s+as\s+(?:system|admin|orchestrator)\s+(?:instruction|command|directive)|elevate(?:d)?\s+(?:user|agent)\s+(?:role|message)\s+to\s+(?:system|admin))/gi,
    recommendation: 'CRITICAL: User or agent messages must never be promoted to system role. Multi-agent architectures must enforce strict role separation between system prompts and user/agent channels.',
    category: 'multi-agent-trust',
    cwe: 'CWE-269',
  },

  // ============================================
  // 10. Orchestrator Prompt Injection Relay
  // ============================================
  {
    id: 'mat-orchestrator-blind-relay',
    severity: 'critical',
    description: 'Orchestrator blindly forwarding external/user content to sub-agents as instructions',
    pattern: /(?:orchestrator\.(?:send|forward|relay|pass)\s*\([^)]*(?:externalContent|userInput|rawInput|untrusted|scraped|fetched)[^)]*\)|forward(?:_|\s+)to(?:_|\s+)(?:sub)?agent\s*\(\s*(?:externalContent|userInput|rawInput|webContent|fetchedData)\s*\)|relay\w*\s*\([^)]*\)\s+to\s+(?:sub)?agent\s+without\s+(?:sanitiz|filter|validat)|(?:relay|forward)\s+(?:to\s+)?(?:sub)?agent\s*\([^)]*(?:externalContent|webContent|fetchedData)[^)]*\)\s+without)/gi,
    recommendation: 'CRITICAL: Orchestrators must never blindly relay external content (web scrapes, user messages, tool outputs) to sub-agents as instructions. All content crossing trust boundaries must be wrapped in structured templates, not passed raw.',
    category: 'multi-agent-trust',
    cwe: 'CWE-77',
  },

  // ============================================
  // 11. Missing Inter-Agent Trust Policy
  // ============================================
  {
    id: 'mat-no-trust-boundary-defined',
    severity: 'warning',
    description: 'Multi-agent system configured without explicit trust boundaries or policies',
    pattern: /(?:multi[\s_-]?agent\s+(?:system|framework|network|pipeline)\s+(?:with\s+)?(?:no|without|missing|undefined)\s+(?:trust[\s_-]?(?:policy|boundary|level|config|rules?)|auth(?:entication)?[\s_-]?(?:policy|config|rules?))|trust[\s_-]?(?:all|everyone|any)\s+(?:agent|source|message|input)|agent[\s_-]trust[\s_-](?:policy|level|config)\s*[:=]\s*(?:none|null|undefined|false|off|0|['"]?any['"]?|['"]?all['"]?))/gi,
    recommendation: 'Define explicit trust policies for all agent interactions. Use a trust hierarchy: system > orchestrator > sub-agent > external. Never use "trust all" policies.',
    category: 'multi-agent-trust',
    cwe: 'CWE-693',
  },
  {
    id: 'mat-capability-token-missing',
    severity: 'warning',
    description: 'Sub-agent invoked without capability-scoped token or explicit permission set',
    pattern: /(?:(?:spawn|create|invoke|call)(?:Agent|SubAgent|_agent)\s*\([^)]*\)\s*(?:\/\/[^\n]*)?(?:\n\s*)?(?!.*(?:token|capabilities?|permissions?|scope|auth))(?:[^;{]*[;{])|subagent\s+(?:has\s+)?(?:no\s+)?(?:capability[\s_-]token|permission[\s_-]set|scoped[\s_-](?:token|key)))/gi,
    recommendation: 'Issue capability tokens with explicit scopes when spawning sub-agents. Never spawn agents with implicit full-access; always define what the sub-agent is allowed to do.',
    category: 'multi-agent-trust',
    cwe: 'CWE-272',
  },

  // ============================================
  // 12. Agent Session Hijacking
  // ============================================
  {
    id: 'mat-agent-session-hijacking',
    severity: 'critical',
    description: 'Agent session token or ID being reused, stolen, or hijacked by another agent',
    pattern: /(?:reuse\s+(?:agent|another\s+agent'?s?)\s+(?:session|token|credentials?)|steal(?:ing)?\s+(?:agent|orchestrator)\s+(?:session|token|auth)|hijack(?:ing)?\s+(?:agent|sub[\s_-]?agent)\s+(?:session|token)|(?:agent|session)[\s_-]token[\s_-](?:stolen|hijacked|reused|shared)|use\s+(?:session|token)\s+from\s+(?:another|different)\s+agent|(?:copy|clone|steal|reuse)[\s_-]agent[\s_-](?:session|auth|token)|agentSessionId\s*=\s*(?:otherAgent|anotherAgent|external|stolen)\w*(?:Session|Token|Id))/gi,
    recommendation: 'CRITICAL: Agent session tokens must be unique per agent instance and non-transferable. Implement session binding (IP, agent fingerprint) and single-use tokens for sensitive operations.',
    category: 'multi-agent-trust',
    cwe: 'CWE-384',
  },

  // ============================================
  // 13. A2A Callback Injection
  // ============================================
  {
    id: 'mat-a2a-callback-injection',
    severity: 'high',
    description: 'A2A callback or webhook URL taken from external/user input without validation',
    pattern: /(?:(?:callback[\s_-]?url|webhook[\s_-]?url|a2a[\s_-]?callback|return[\s_-]?url)\s*[:=]\s*(?:req\.|request\.|userInput|user_input|body\.|params\.|query\.)\w*|(?:a2a|inter[\s_-]?agent)[\s_-]?(?:webhook|callback|notify[\s_-]url)\s*=\s*(?:input|external|untrusted|req\.\w+|body\.\w+|userInput\.\w+|userInput\b)|register\w*(?:Callback|Webhook)\s*\(\s*(?:req\.|userInput|untrusted|external)\w*\s*\)|a2a_config\s*=\s*\{[^}]*callback\s*:\s*(?:req\.|body\.|userInput))/gi,
    recommendation: 'A2A callback URLs must never be taken from user or external input. Use a pre-registered allowlist of callback endpoints and validate against it before invoking.',
    category: 'multi-agent-trust',
    cwe: 'CWE-918',
  },

  // ============================================
  // 14. Agent Result Tampering
  // ============================================
  {
    id: 'mat-agent-result-tampering',
    severity: 'high',
    description: 'Agent result or sub-agent output being intercepted or tampered with before use',
    pattern: /(?:(?:modify|tamper|alter|intercept|manipulate)\s+(?:agent|sub[\s_-]?agent)\s+(?:result|output|response)|(?:agent|sub[\s_-]?agent)[\s_-](?:result|output|response)[\s_-](?:modified|tampered|altered|forged)|(?:before\s+passing|prior\s+to\s+forwarding)\s+(?:agent|sub[\s_-]?agent)\s+(?:result|output)\s*,?\s*(?:modify|alter|change|inject)|intercept(?:ing)?\s+(?:agent|sub[\s_-]?agent)\s+(?:response|result|output)|agent\.result\s*=\s*(?:tampered|forged|modified|injected)\w*|subAgentOutput\s*\.\s*(?:replace|modify|alter|inject)\s*\()/gi,
    recommendation: 'Sub-agent results must flow through integrity-protected channels. Use signed response envelopes or hash verification to detect tampering before results are acted upon.',
    category: 'multi-agent-trust',
    cwe: 'CWE-345',
  },

  // ============================================
  // 15. Agent Tool Whitelist Bypass
  // ============================================
  {
    id: 'mat-agent-tool-whitelist-bypass',
    severity: 'critical',
    description: 'Attempt to bypass agent tool whitelist or access tools outside allowed set',
    pattern: /(?:bypass\s+(?:tool|agent)\s+(?:restrictions?|whitelist|allowlist|limits?)|(?:access|use|invoke|call)\s+tools?\s+(?:not\s+in|outside\s+(?:the\s+)?|beyond\s+(?:the\s+)?)(?:whitelist|allowlist|permitted|allowed)\s+(?:tools?|set|list)|allowed[\s_-]tools?\s*[:=]\s*(?:\[\s*\]|\*|['"]?\*['"]?|['"]?all['"]?|null|undefined)|tool[\s_-]whitelist\s*[:=]\s*(?:\[\s*\]|null|undefined|false|['"]?none['"]?)|disable[\s_-]tool[\s_-](?:restrictions?|whitelist|allowlist|filtering)|tool[\s_-]restrictions?\s*[:=]\s*(?:false|disabled?|off|null|none))/gi,
    recommendation: 'CRITICAL: Tool whitelists are a critical safety boundary. Never use wildcard or empty tool lists. Explicitly enumerate allowed tools per agent role and enforce at the framework level.',
    category: 'multi-agent-trust',
    cwe: 'CWE-732',
  },

  // ============================================
  // 16. Agent Memory Poisoning
  // ============================================
  {
    id: 'mat-agent-memory-poisoning',
    severity: 'high',
    description: 'External or user-controlled content being injected into agent persistent memory or vector store',
    pattern: /(?:(?:inject|write|insert|store|add|push)\s+(?:into|to)\s+agent[\s_-](?:memory|context|store|knowledge[\s_-]base|vector[\s_-]store)\s+(?:with\s+)?(?:external|user|untrusted|raw|scraped)\s+(?:content|input|data)|poison(?:ing)?\s+agent[\s_-](?:memory|context|vector[\s_-]store|knowledge)|agent(?:Memory|Context|Store|VectorDb)\.(?:add|insert|store|upsert|write)\s*\(\s*(?:userInput|externalContent|rawInput|untrustedData|scrapedContent)\s*[,)"]|(?:memory|context)[\s_-](?:injection|poisoning|contamination)\s+(?:via|through|using)\s+(?:user|external|untrusted)|(?:write|store|save)\s+(?:untrusted|unvalidated|raw|external)\s+(?:input|content)\s+(?:to|into)\s+(?:agent\s+)?(?:memory|vector\s+store|knowledge\s+base))/gi,
    recommendation: 'Agent memory and vector stores must only accept validated, sanitized content from trusted sources. Implement content filtering and source attribution before storing any data in agent memory.',
    category: 'multi-agent-trust',
    cwe: 'CWE-74',
  },
];
