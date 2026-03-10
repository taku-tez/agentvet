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
];
