import type { Rule } from "../types.js";

/**
 * Tool Result Poisoning Detection Rules
 * Detects hidden instructions or manipulation attempts embedded in tool
 * outputs/responses that could hijack the agent's behavior.
 *
 * Attack vector: A compromised or malicious tool returns results containing
 * hidden directives that the LLM interprets as instructions, overriding
 * the user's intent.
 *
 * References:
 * - "Poisoning Web-Scale Training Datasets" (Carlini et al.)
 * - OWASP LLM Top 10 2025 - LLM01: Prompt Injection
 * - Anthropic "Many-shot jailbreaking" research
 */

export const rules: Rule[] = [
  // ── Fake XML instruction tags in tool output ──────────────────
  {
    id: 'tool-poison-fake-xml-instructions',
    severity: 'critical',
    description: 'Fake XML instruction/system tags detected in tool output (tool result poisoning)',
    pattern: /<\s*(?:instructions?|system_prompt|system_message|assistant_instructions|tool_instructions|internal_instructions|admin_override)\s*>[^<]+<\s*\/\s*(?:instructions?|system_prompt|system_message|assistant_instructions|tool_instructions|internal_instructions|admin_override)\s*>/gi,
    recommendation: 'Tool outputs should never contain XML instruction tags. Strip or escape XML-like tags from tool results before passing to the LLM.',
    cwe: 'CWE-74',
  },

  // ── Role impersonation in tool results ────────────────────────
  {
    id: 'tool-poison-role-impersonation',
    severity: 'critical',
    description: 'Role impersonation pattern in tool output (system:/assistant:/user: prefixes)',
    pattern: /(?:^|\n)\s*(?:system|assistant|SYSTEM|ASSISTANT)\s*:\s*(?:you\s+(?:must|should|are|will|need\s+to)|ignore|override|forget|disregard|new\s+instructions?|from\s+now\s+on)/gim,
    recommendation: 'Tool results containing role-prefixed instructions can hijack agent behavior. Sanitize role markers from tool outputs.',
    cwe: 'CWE-74',
  },

  // ── SYSTEM OVERRIDE / ADMIN OVERRIDE patterns ─────────────────
  {
    id: 'tool-poison-override-directive',
    severity: 'critical',
    description: 'Override directive detected in content (SYSTEM OVERRIDE, ADMIN OVERRIDE, etc.)',
    pattern: /(?:SYSTEM|ADMIN|DEVELOPER|INTERNAL|PRIORITY)\s+OVERRIDE\s*[:\-—]\s*\S/gi,
    recommendation: 'Override directives in tool outputs are a strong indicator of prompt injection. Never trust override claims from tool results.',
    cwe: 'CWE-74',
  },

  // ── Hidden instructions in JSON string values returned by tools ─
  {
    id: 'tool-poison-json-hidden-instruction',
    severity: 'high',
    description: 'Hidden instruction embedded in JSON string value from tool result',
    pattern: /(?:"(?:result|output|data|content|message|response|text|body|answer|summary|description|snippet)"\s*:\s*"[^"]*(?:ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions?|you\s+are\s+now\s+(?:a|an|in)|forget\s+(?:everything|all|your)|new\s+(?:system\s+)?instructions?|override\s+(?:system|safety|your))[^"]*")/gi,
    recommendation: 'Tool results with instruction-like content in JSON values can poison the LLM context. Apply output sanitization on tool results.',
    cwe: 'CWE-74',
  },

  // ── Invisible text injection in tool results ──────────────────
  {
    id: 'tool-poison-invisible-text',
    severity: 'high',
    description: 'Invisible/zero-width characters hiding payload in tool output',
    pattern: /(?:tool_result|function_result|tool_output|<output>|<result>)[^]*?[\u200B\u200C\u200D\u2060\uFEFF\u00AD]{4,}/gi,
    recommendation: 'Strip zero-width and invisible Unicode characters from tool results before passing to the LLM.',
    cwe: 'CWE-116',
  },

  // ── Prompt delimiter injection (```system, [INST], <<SYS>>) ──
  {
    id: 'tool-poison-prompt-delimiter',
    severity: 'critical',
    description: 'LLM prompt delimiter/tag found in tool output (prompt format injection)',
    pattern: /(?:<<\s*SYS\s*>>|<\|(?:system|im_start|im_end)\|>|\[INST\]|\[\/INST\]|<\|(?:begin|end)_of_text\|>|```\s*system\b)/gi,
    recommendation: 'LLM prompt delimiters in tool results indicate an attempt to break out of the tool output context. Escape or reject these patterns.',
    cwe: 'CWE-74',
  },

  // ── Tool claiming elevated authority ──────────────────────────
  {
    id: 'tool-poison-authority-claim',
    severity: 'high',
    description: 'Tool output claims elevated authority or special permissions',
    pattern: /(?:this\s+(?:message|instruction|directive)\s+(?:comes?\s+from|is\s+from|has)\s+(?:the\s+)?(?:system|admin|developer|root|operator)|(?:priority|elevated|privileged|authorized)\s+(?:instruction|message|directive|command)|(?:I\s+am|this\s+is)\s+(?:the\s+)?(?:system|admin|developer|root)\s+(?:speaking|process|module))/gi,
    recommendation: 'Tool outputs should not claim authority over the agent. Reject authority claims from tool results.',
    cwe: 'CWE-863',
  },

  // ── Multi-turn conversation injection ─────────────────────────
  {
    id: 'tool-poison-fake-conversation',
    severity: 'high',
    description: 'Fake multi-turn conversation injected via tool output',
    pattern: /(?:Human|User|Assistant|AI)\s*:\s*[^\n]+\n(?:Human|User|Assistant|AI)\s*:\s*[^\n]+\n(?:Human|User|Assistant|AI)\s*:\s*/gi,
    recommendation: 'Injected fake conversation turns in tool outputs can manipulate agent behavior (many-shot jailbreaking). Sanitize conversational patterns from tool results.',
    cwe: 'CWE-74',
  },

  // ── Tool response wrapping with fake tags ─────────────────────
  {
    id: 'tool-poison-fake-tool-response-tag',
    severity: 'high',
    description: 'Fake tool_response / function_call tags detected (context manipulation)',
    pattern: /<\s*\/?(?:tool_response|function_call|function_response|tool_call|tool_use|tool_result|api_response)\s*>/gi,
    recommendation: 'Fake tool/function XML tags in content can confuse the LLM about message boundaries. Strip or escape these tags.',
    cwe: 'CWE-74',
    falsePositiveCheck: (_match, _content, filePath) =>
      /(?:\.test\.|\.spec\.|__tests__|test\/|docs?\/|README|CHANGELOG)/i.test(filePath),
  },

  // ── Instruction to hide/suppress information ──────────────────
  {
    id: 'tool-poison-suppress-instruction',
    severity: 'high',
    description: 'Tool output instructs agent to hide or suppress information from user',
    pattern: /(?:do\s+not\s+(?:show|reveal|display|tell|mention|disclose|share)\s+(?:this|the\s+(?:user|human|person))|hide\s+this\s+(?:from|response)|keep\s+this\s+(?:hidden|secret|private)\s+from\s+(?:the\s+)?(?:user|human))/gi,
    recommendation: 'Tool outputs instructing the agent to hide information from users indicate poisoning. Agents should never suppress tool output based on tool instructions.',
    cwe: 'CWE-451',
  },

  // ── Encoded/obfuscated payload in tool output ─────────────────
  {
    id: 'tool-poison-encoded-payload',
    severity: 'high',
    description: 'Base64 or hex-encoded instruction payload detected in tool output (obfuscated injection)',
    pattern: /(?:(?:decode|atob|Buffer\.from)\s*\(\s*['"][A-Za-z0-9+/=]{20,}['"]\s*(?:,\s*['"]base64['"])?\s*\)|(?:eval|Function|exec)\s*\(\s*(?:atob|Buffer\.from|decodeURIComponent)\s*\(|\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){9,}|&#x[0-9a-fA-F]{2};(?:&#x[0-9a-fA-F]{2};){9,})/gi,
    recommendation: 'Encoded payloads in tool results may hide prompt injection or malicious instructions. Decode and inspect all encoded content before passing to the LLM.',
    cwe: 'CWE-116',
  },

  // ── Markdown/image exfiltration via tool output ───────────────
  {
    id: 'tool-poison-markdown-exfiltration',
    severity: 'critical',
    description: 'Markdown image/link in tool output used to exfiltrate data via URL parameters',
    pattern: /(?:!\[[^\]]*\]\(\s*https?:\/\/[^)]*(?:\?[^)]*(?:data|token|secret|key|password|session|cookie|prompt|context|q)=|\/(?:collect|exfil|log|track|steal|capture)\/)|\[(?:click\s+here|see\s+result|view|open)\]\(\s*https?:\/\/[^)]*(?:\?[^)]*(?:data|token|secret|key|password|session|cookie|prompt|context|q)=))/gi,
    recommendation: 'Markdown images and links in tool outputs can exfiltrate sensitive data by embedding it in URL parameters. Strip or sanitize markdown rendering of tool results. Block dynamic image URLs from untrusted tool outputs.',
    cwe: 'CWE-200',
  },

  // ── Tool output redirecting to call another tool ──────────────
  {
    id: 'tool-poison-tool-redirection',
    severity: 'critical',
    description: 'Tool output attempts to instruct agent to call another tool or function (tool chaining attack)',
    pattern: /(?:(?:now\s+)?(?:call|invoke|execute|run|use|trigger)\s+(?:the\s+)?(?:tool|function|command|action)\s+['"`]?\w+['"`]?\s+(?:with|using|passing)|(?:you\s+(?:must|should|need\s+to)\s+)?(?:call|invoke|execute|use)\s+(?:the\s+)?(?:following|next|this)\s+(?:tool|function|API|command)|(?:tool_use|function_call)\s*[:=]\s*\{?\s*['"]?(?:name|function)['"]?\s*[:=]|please\s+(?:call|invoke|execute|run)\s+(?:the\s+)?(?:\w+[\s_])?(?:tool|function|API)\s+(?:to|and|for)\s+(?:delete|remove|modify|update|send|transfer|execute))/gi,
    recommendation: 'Tool outputs must never instruct the agent to call other tools. This enables tool chaining attacks where a compromised tool can pivot to more privileged operations. Implement allowlists for tool invocation sequences.',
    cwe: 'CWE-441',
  },

  // ── Tool output requesting callback/webhook to external URL ───
  {
    id: 'tool-poison-callback-exfiltration',
    severity: 'high',
    description: 'Tool output requests agent to make HTTP callback or webhook to external URL (data exfiltration)',
    pattern: /(?:(?:send|post|make|submit)\s+(?:a\s+)?(?:request|callback|webhook|ping|HTTP)\s+to\s+https?:\/\/|(?:fetch|curl|wget|axios|got|request)\s*\(\s*['"]https?:\/\/(?!(?:localhost|127\.0\.0\.1|0\.0\.0\.0|::1)\b)|report\s+(?:back|results?)\s+(?:to|at)\s+https?:\/\/|(?:notify|alert|ping)\s+(?:this\s+)?(?:URL|endpoint|server)\s*[:=]?\s*https?:\/\/)/gi,
    recommendation: 'Tool outputs directing the agent to make external HTTP requests can exfiltrate context, secrets, or user data. Never allow tool results to trigger outbound network calls. Use a strict allowlist for any agent-initiated HTTP requests.',
    cwe: 'CWE-918',
  },

  // ── Tool output manipulating conversation history ─────────────
  {
    id: 'tool-poison-history-manipulation',
    severity: 'critical',
    description: 'Tool output attempts to manipulate or rewrite conversation history/context',
    pattern: /(?:(?:the\s+)?(?:previous|prior|earlier|above)\s+(?:conversation|messages?|context|instructions?)\s+(?:(?:was|were|is|are)\s+)?(?:incorrect|wrong|outdated|superseded|invalid|corrupted)|(?:discard|clear|reset|erase|wipe|flush)\s+(?:the\s+)?(?:previous|prior|current|existing)\s+(?:conversation|context|history|messages?|chat|memory)|(?:replace|overwrite|update)\s+(?:the\s+)?(?:system\s+prompt|instructions?|context|history)\s+with\s+(?:the\s+following|this|these)|(?:start|begin)\s+(?:a\s+)?(?:new|fresh)\s+(?:conversation|context|session)\s*(?:with|using|[:—])\s+(?:the\s+following|this|these)\s+(?:instructions?|rules?|guidelines?|directives?))/gi,
    recommendation: 'Tool outputs attempting to invalidate prior context or inject new "history" are a sophisticated form of prompt injection. Agents must treat their conversation history as immutable and never allow tool results to override it.',
    cwe: 'CWE-74',
  },
];
