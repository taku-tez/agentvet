import type { Rule } from "../types.js";

/**
 * Context Window Poisoning Attack Detection Rules
 * Detects code patterns that expose LLM agents to context window manipulation:
 * unbounded accumulation, role confusion, missing isolation, overflow blindness,
 * hidden unicode markers, and recursive depth issues.
 *
 * Attack categories:
 * - Unbounded context accumulation (no token / message limit)
 * - System prompt overridable at runtime
 * - Conversation history re-injection without sanitization
 * - Role confusion (user content in system/assistant role)
 * - Missing context isolation between sessions/users
 * - Hidden instruction markers (zero-width / invisible unicode)
 * - Prompt concatenation without boundary separators
 * - Inverted history truncation (newest messages discarded)
 * - Tool output injected verbatim into message content
 * - Sampling params modifiable from user input
 * - Silent overflow on context limit exceeded
 * - Multimodal content bypassing text safety checks
 * - Recursive agent calls without depth guard
 * - Large document ingestion without size validation
 */

export const rules: Rule[] = [
  // ============================================
  // CWP001 - Unbounded context accumulation
  // Messages array grows forever; no maxMessages /
  // maxTokens cap means attacker can fill the window.
  // ============================================
  {
    id: 'cwp-unbounded-context',
    severity: 'high',
    description: 'Conversation history grows without bound — no max message/token limit enforced',
    // Flags push/spread onto messages/history arrays without any adjacent truncation/limit call.
    // Simplified to avoid complex cross-statement lookahead; pair with static analysis for FP reduction.
    pattern: /(?:messages|history|chatHistory|conversationHistory)\s*\.push\s*\(|(?:messages|history)\s*=\s*\[\s*\.\.\.(?:messages|history)/gi,
    recommendation: 'Cap conversation history (e.g. keep last N messages or stay under a token budget). Unbounded accumulation lets attackers flood the context with adversarial content and crowd out legitimate instructions.',
    category: 'context-window-poisoning',
    cwe: 'CWE-770',
  },

  // ============================================
  // CWP002 - System prompt overridable at runtime
  // Accepting systemPrompt from request body or user
  // input lets an attacker replace safety instructions.
  // ============================================
  {
    id: 'cwp-dynamic-system-prompt',
    severity: 'critical',
    description: 'System prompt set from user-controlled input at runtime (system prompt override risk)',
    pattern: /(?:system(?:Prompt|_prompt|Message)?|messages\[0\]\.content)\s*[:=]\s*(?:req\.(?:body|query|params)\.|body\.|params\.|query\.|userInput|input\.|data\.)[a-zA-Z_$][a-zA-Z0-9_$.]*/gi,
    recommendation: 'Never derive the system prompt from user-supplied input. Hardcode it or load it from a verified, immutable config. Runtime override lets an attacker replace your safety/behaviour instructions entirely.',
    category: 'context-window-poisoning',
    cwe: 'CWE-20',
  },

  // ============================================
  // CWP003 - Conversation history not sanitized
  // Re-injecting raw history strings that may contain
  // role-injection or hidden instructions.
  // ============================================
  {
    id: 'cwp-unsanitized-history',
    severity: 'high',
    description: 'Raw conversation history re-injected into prompt without sanitization',
    // Detects history/chatHistory/conversationHistory being joined, mapped, or concatenated
    // into a prompt/content variable without a sanitize/escape call on the same expression.
    pattern: /(?:history|chatHistory|conversationHistory|pastMessages|previousMessages)\s*\.\s*(?:join|map|toString|reduce)\s*\(|(?:prompt|content|context)\s*\+?=\s*.*(?:history|chatHistory|conversationHistory)(?!\s*\.\s*(?:sanitize|escape|filter|clean))/gi,
    recommendation: 'Sanitize stored history before re-injecting it into prompts. Strip hidden unicode, validate role fields, and strip any content matching injection patterns to prevent poisoned history from influencing future turns.',
    category: 'context-window-poisoning',
    cwe: 'CWE-116',
  },

  // ============================================
  // CWP004 - Role confusion: user content placed in system/assistant role
  // ============================================
  {
    id: 'cwp-role-confusion',
    severity: 'critical',
    description: 'User-supplied content assigned to system or assistant role in message array',
    pattern: /\{\s*role\s*:\s*['"`](?:system|assistant)['"`]\s*,\s*content\s*:\s*(?:req\.|body\.|params\.|query\.|userInput\.?|input\.|data\.)[a-zA-Z_$][a-zA-Z0-9_$.]*\s*\}/gi,
    recommendation: 'Never assign user-supplied content to the "system" or "assistant" role. These roles carry elevated trust with the model. User input must always be in the "user" role.',
    category: 'context-window-poisoning',
    cwe: 'CWE-284',
  },

  // ============================================
  // CWP005 - Large document ingestion without size validation
  // ============================================
  {
    id: 'cwp-unbounded-document-ingestion',
    severity: 'medium',
    description: 'Document or file content injected into context without size/token validation',
    pattern: /(?:content|text|document|fileContent|pageContent)\s*[:=]\s*(?:fs\.readFileSync|readFile|await\s+fs\.promises\.readFile|readFileSync)\s*\([^)]+\)(?![^;]{0,200}(?:slice|substring|substr|maxLength|maxSize|maxTokens|truncate|limit))/gi,
    recommendation: 'Validate and truncate document content before injecting it into the context. Unbounded document ingestion can fill the context window, crowding out system instructions and enabling context poisoning.',
    category: 'context-window-poisoning',
    cwe: 'CWE-400',
  },

  // ============================================
  // CWP006 - Hidden instruction markers (zero-width / invisible unicode)
  // ============================================
  {
    id: 'cwp-hidden-unicode-markers',
    severity: 'high',
    description: 'Zero-width or invisible unicode characters in string literals — hidden instruction injection risk',
    // Matches zero-width space (U+200B), zero-width non-joiner (U+200C), zero-width joiner (U+200D),
    // word joiner (U+2060), left-to-right mark (U+200E), right-to-left mark (U+200F),
    // soft hyphen (U+00AD), invisible separator (U+2063)
    pattern: /['"`][^'"`]*[\u200B\u200C\u200D\u2060\u200E\u200F\u00AD\u2063\uFEFF][^'"`]*['"`]/g,
    recommendation: 'Zero-width and invisible unicode characters in strings can carry hidden instructions that bypass text-based safety filters. Strip these characters from all user-supplied content before processing.',
    category: 'context-window-poisoning',
    cwe: 'CWE-116',
  },

  // ============================================
  // CWP007 - Prompt concatenation without separator/boundary
  // ============================================
  {
    id: 'cwp-prompt-no-boundary',
    severity: 'medium',
    description: 'System prompt and user input concatenated without explicit boundary/separator',
    pattern: /(?:systemPrompt|system_prompt|basePrompt|instructionPrompt)\s*\+\s*(?:userInput|userMessage|query|input|message|content)(?!\s*\.?\s*(?:separator|delimiter|boundary|\s*`[^`]*---[^`]*`))/gi,
    recommendation: 'When concatenating a system prompt with user input, insert a clear boundary (e.g. "\\n---\\nUser input:") so the model can distinguish prompt from user content. Direct concatenation enables prompt injection.',
    category: 'context-window-poisoning',
    cwe: 'CWE-116',
  },

  // ============================================
  // CWP008 - Inverted history truncation (newest discarded)
  // ============================================
  {
    id: 'cwp-inverted-truncation',
    severity: 'medium',
    description: 'History truncated from the end (newest messages discarded) — important recent context lost',
    pattern: /(?:messages|history|conversation)\s*=\s*(?:messages|history|conversation)\s*\.\s*slice\s*\(\s*0\s*,\s*[1-9][0-9]*\s*\)/gi,
    recommendation: 'Truncating from the end (slice(0, N)) keeps oldest messages and discards the most recent ones. This can cause the model to miss recent instructions. Truncate from the beginning (slice(-N)) to keep the latest context.',
    category: 'context-window-poisoning',
    cwe: 'CWE-696',
  },

  // ============================================
  // CWP009 - No context isolation between sessions/users
  // ============================================
  {
    id: 'cwp-shared-context',
    severity: 'critical',
    description: 'Conversation history stored in module-level or global variable — shared across all sessions/users',
    pattern: /^(?:const|let|var)\s+(?:messages|history|chatHistory|conversationHistory|context)\s*=\s*\[\s*\]/gm,
    recommendation: 'Module-level message arrays are shared across all requests/users in a Node.js process. Each session must have its own isolated history. Use per-request state or a session store keyed by user/session ID.',
    category: 'context-window-poisoning',
    cwe: 'CWE-362',
  },

  // ============================================
  // CWP010 - Tool output injected verbatim into messages
  // ============================================
  {
    id: 'cwp-raw-tool-output-injection',
    severity: 'high',
    description: 'Raw tool / function call output injected directly into message content without escaping',
    pattern: /(?:content|text|message)\s*[:=]\s*(?:`[^`]*\$\{(?:toolResult|toolOutput|functionResult|result|output)\}[^`]*`|[^;]{0,80}\+\s*(?:toolResult|toolOutput|functionResult)(?!\s*\.\s*(?:sanitize|escape|filter|clean)))/gi,
    recommendation: 'Tool outputs may contain adversarial content designed to hijack the next LLM turn. Escape or sanitize tool results before injecting them as message content, or wrap them in a clearly-delimited block.',
    category: 'context-window-poisoning',
    cwe: 'CWE-116',
  },

  // ============================================
  // CWP011 - Sampling params modifiable from user input
  // ============================================
  {
    id: 'cwp-user-controlled-sampling',
    severity: 'high',
    description: 'Temperature, top_p, or other sampling parameters derived from user-controlled input',
    pattern: /(?:temperature|top_p|topP|top_k|topK|presencePenalty|frequencyPenalty|repetitionPenalty)\s*[:=]\s*(?:parseFloat|parseInt|Number)\s*\(\s*(?:req\.|body\.|params\.|query\.|userInput|input\.)[a-zA-Z_$][a-zA-Z0-9_$.]*\s*\)/gi,
    recommendation: 'Allowing users to set sampling parameters enables jailbreak-assisting attacks (e.g. extreme temperature) or cost amplification. Always use fixed, validated values server-side.',
    category: 'context-window-poisoning',
    cwe: 'CWE-20',
  },

  // ============================================
  // CWP012 - Silent context overflow (no error on limit exceeded)
  // ============================================
  {
    id: 'cwp-silent-context-overflow',
    severity: 'medium',
    description: 'Context length error silently swallowed — truncation/overflow goes undetected',
    pattern: /catch\s*\([^)]*\)\s*\{[^}]{0,200}(?:context_length|maximum context|token limit|context_window|too long)[^}]{0,200}\}/gi,
    recommendation: 'Silently catching context-length errors hides overflow events. Log them, alert, or gracefully truncate so you know when the context window is exceeded and can respond appropriately.',
    category: 'context-window-poisoning',
    cwe: 'CWE-390',
  },

  // ============================================
  // CWP013 - Multimodal content bypassing text safety checks
  // ============================================
  {
    id: 'cwp-multimodal-safety-bypass',
    severity: 'high',
    description: 'Image or multimodal content added to messages without safety/content-policy check',
    pattern: /\{\s*type\s*:\s*['"`]image(?:_url)?['"`][^}]{0,300}\}(?![^;]{0,500}(?:moderati|safety|nsfw|content.?check|scan|filter|validate))/gi,
    recommendation: 'Images and other multimodal content can encode adversarial instructions invisible to text-based safety filters. Run a moderation or safety check on all multimodal inputs before including them in the model context.',
    category: 'context-window-poisoning',
    cwe: 'CWE-20',
  },

  // ============================================
  // CWP014 - Recursive agent calls without depth limit
  // ============================================
  {
    id: 'cwp-recursive-agent-no-depth-limit',
    severity: 'high',
    description: 'Recursive or self-calling agent function with no depth/iteration limit guard',
    pattern: /(?:async\s+)?function\s+(\w+)\s*\([^)]*\)\s*\{(?:[^}]|\{[^}]*\}){0,2000}?\1\s*\([^)]*\)(?![^}]{0,500}(?:depth|maxDepth|maxIterations|maxCalls|recursionLimit|callCount|iteration\s*[><=]))/gi,
    recommendation: 'Recursive agent calls without a depth guard can be triggered by an adversarial prompt to consume unbounded context, CPU, and API credits. Add a maxDepth or maxIterations guard and throw when exceeded.',
    category: 'context-window-poisoning',
    cwe: 'CWE-674',
  },
];
