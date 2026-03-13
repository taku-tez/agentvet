import type { Rule } from "../types.js";

/**
 * Prompt Leaking / System Prompt Extraction Attack Detection Rules
 * Detects attempts to extract, reveal, or exfiltrate AI agent system prompts
 * through various social engineering and technical manipulation techniques.
 *
 * System prompt extraction is a major attack vector against AI agents:
 * - Exposes proprietary instructions, business logic, and safety guardrails
 * - Reveals tool configurations and API integrations
 * - Enables targeted jailbreaks by knowing exact safety rules
 * - Leaks secrets embedded in system prompts (API keys, internal URLs)
 *
 * References:
 * - Perez & Ribeiro "Ignore Previous Prompt" (2022)
 * - OWASP LLM Top 10 2025 - LLM07: System Prompt Leakage
 * - Embrace The Red: "Prompt Injection Attacks" series
 * - Anthropic Red Team: Prompt Extraction Techniques (2024)
 */

export const rules: Rule[] = [
  // ============================================
  // 1. Repeat-Above Extraction
  // ============================================
  {
    id: 'prompt-leak-repeat-above',
    severity: 'high',
    description: 'Instruction to repeat/echo content above (system prompt extraction attempt)',
    pattern: /(?:repeat|echo|output|print|show|display|copy|reproduce|retype|write\s+out)\s+(?:back\s+)?(?:the\s+)?(?:above|everything\s+above|all\s+(?:of\s+)?the\s+above|(?:all\s+)?(?:your\s+)?(?:previous|prior)\s+(?:text|content|messages?|instructions?|prompt|words?))/gi,
    recommendation: 'Detected "repeat above" style prompt extraction. AI agents should not echo back their system context. Implement output filtering and context boundary enforcement.',
    category: 'prompt-leaking',
    cwe: 'CWE-200',
  },

  // ============================================
  // 2. Initial Instructions Extraction
  // ============================================
  {
    id: 'prompt-leak-initial-instructions',
    severity: 'high',
    description: 'Query asking for initial/original instructions (system prompt extraction)',
    pattern: /(?:what\s+(?:were|are|was)\s+(?:your|the)\s+(?:initial|original|first|starting|base|core|real|actual|true)\s+(?:instructions?|prompt|directives?|guidelines?|rules?|configuration|setup|programming|orders?)|what\s+instructions?\s+(?:were|are|was|have\s+been)\s+(?:you|given)\s+(?:given|provided|set)?)/gi,
    recommendation: 'Query attempting to extract system instructions. AI agents should not reveal their system prompt contents in response to direct questions.',
    category: 'prompt-leaking',
    cwe: 'CWE-200',
  },

  // ============================================
  // 3. Pretend-Visible Trick
  // ============================================
  {
    id: 'prompt-leak-pretend-visible',
    severity: 'high',
    description: 'Instruction to pretend system prompt is visible or to act without one',
    pattern: /(?:pretend\s+(?:your|the)\s+(?:system\s+)?(?:prompt|instructions?|configuration)\s+(?:is|are)\s+(?:visible|public|shared|open|accessible|transparent)|act\s+as\s+if\s+(?:you\s+have\s+)?no\s+system\s+prompt|imagine\s+you\s+(?:can|could)\s+(?:share|reveal|show|tell\s+me)\s+(?:your\s+)?(?:instructions?|prompt|configuration)|suppose\s+your\s+(?:instructions?|prompt)\s+(?:were|are)\s+(?:visible|public))/gi,
    recommendation: 'Pretend-visible trick detected. Attackers use hypothetical/fictional framing to bypass system prompt confidentiality. Enforce strict output controls regardless of framing.',
    category: 'prompt-leaking',
    cwe: 'CWE-200',
  },

  // ============================================
  // 4. Output Configuration/Prompt Directly
  // ============================================
  {
    id: 'prompt-leak-output-config',
    severity: 'critical',
    description: 'Direct request to output system prompt, configuration, or initialization text',
    pattern: /(?:(?:output|print|show|display|reveal|expose|share|give\s+me|tell\s+me|write\s+out|dump)\s+(?:me\s+)?(?:your\s+)?(?:system\s+(?:prompt|message|instructions?|configuration)|initial(?:ization)?\s+(?:prompt|message|instructions?)|(?:full\s+)?(?:prompt|configuration|config|context|instructions?|setup|programming))(?:\s+(?:verbatim|exactly|word\s+for\s+word|as-is|literally|in\s+full|completely))?)/gi,
    recommendation: 'CRITICAL: Direct system prompt extraction attempt detected. Never expose system prompt contents. Implement strict response filtering for requests about internal configuration.',
    category: 'prompt-leaking',
    cwe: 'CWE-200',
  },

  // ============================================
  // 5. Translation-as-Exfiltration Trick
  // ============================================
  {
    id: 'prompt-leak-translation-trick',
    severity: 'high',
    description: 'Translation trick — translating instructions/prompt to extract via language change',
    pattern: /translate\s+(?:your\s+)?(?:system\s+)?(?:instructions?|prompt|configuration|rules?|guidelines?|programming|directives?)\s+(?:in)?to\s+(?:french|spanish|german|japanese|chinese|arabic|portuguese|russian|italian|base64|hex|binary|morse|pig\s+latin|leet|rot13|reverse)/gi,
    recommendation: 'Translation trick detected. Attackers ask AI to "translate" its system prompt, tricking it into repeating and revealing content. Treat translation requests for internal context as extraction attempts.',
    category: 'prompt-leaking',
    cwe: 'CWE-200',
  },

  // ============================================
  // 6. Ignore-and-Reveal Attack
  // ============================================
  {
    id: 'prompt-leak-ignore-and-reveal',
    severity: 'critical',
    description: 'Ignore-previous + reveal instructions combined attack',
    pattern: /(?:ignore|disregard|forget|bypass|override)\s+(?:all\s+)?(?:previous|prior|your|the|above)?\s*(?:instructions?|prompt|rules?|guidelines?|restrictions?|constraints?|configuration|programming)\s+(?:and\s+)?(?:reveal|show|output|print|display|expose|share|tell|give|leak|dump|list)\s+(?:your\s+)?(?:original|real|actual|true|initial|full|complete|entire)?\s*(?:instructions?|prompt|configuration|programming|rules?)/gi,
    recommendation: 'CRITICAL: Combined ignore+reveal extraction attack detected. This pattern explicitly tries to override safety measures to expose system prompts. Block at input validation layer.',
    category: 'prompt-leaking',
    cwe: 'CWE-284',
  },

  // ============================================
  // 7. Sudo/Developer Mode Reveal
  // ============================================
  {
    id: 'prompt-leak-sudo-reveal',
    severity: 'high',
    description: 'Sudo or developer/admin mode invocation to reveal system instructions',
    pattern: /(?:\[?sudo\]?\s+(?:show|reveal|output|print|display)\s+(?:system\s+)?(?:prompt|instructions?|configuration)|(?:developer|admin|debug|root|superuser|operator|maintenance|privileged|override)\s+mode\s*[:\-–]\s*(?:reveal|show|output|print|display|expose)\s+(?:your\s+)?(?:system\s+)?(?:prompt|instructions?|configuration|rules?)|enable\s+(?:debug|developer|admin|diagnostic)\s+mode\s+(?:and\s+)?(?:show|reveal|output|print)\s+(?:your\s+)?(?:instructions?|prompt|configuration))/gi,
    recommendation: 'Pseudo-privileged mode trick detected. Attackers use fake "sudo", "admin mode", or "developer mode" commands to trick AI into revealing system prompts. These modes do not exist and should never trigger prompt exposure.',
    category: 'prompt-leaking',
    cwe: 'CWE-269',
  },

  // ============================================
  // 8. Format-as-Exfiltration Trick
  // ============================================
  {
    id: 'prompt-leak-format-trick',
    severity: 'high',
    description: 'Request to reformat/restructure system prompt as JSON/YAML/list to extract it',
    pattern: /(?:format|reformat|convert|output|write|structure|present|render)\s+(?:your\s+)?(?:system\s+)?(?:instructions?|prompt|configuration|rules?|guidelines?|programming)\s+(?:as|in(?:to)?|using)\s+(?:json|yaml|xml|csv|markdown|bullet\s+points?|numbered\s+list|table|outline|structured\s+format)/gi,
    recommendation: 'Format-as-exfiltration trick detected. Asking to reformat the system prompt is a common extraction technique. Treat any request to output system context in structured formats as a prompt extraction attempt.',
    category: 'prompt-leaking',
    cwe: 'CWE-200',
  },

  // ============================================
  // 9. Complete-the-Sentence Trick
  // ============================================
  {
    id: 'prompt-leak-complete-sentence',
    severity: 'high',
    description: 'Complete-the-sentence trick to elicit system prompt content',
    pattern: /(?:complete\s+(?:this\s+)?(?:sentence|phrase|text|statement)\s*[:\-–]\s*["']?(?:my\s+(?:instructions?|prompt|rules?|guidelines?|directives?)\s+(?:are|say|state|include|tell\s+me)\s*[:\-–]?|you\s+are\s+(?:programmed|designed|instructed|configured|set up)\s+to\s*[:\-–]?|your\s+(?:system\s+)?(?:prompt|instructions?)\s+(?:is|are|says?|states?)\s*[:\-–]?)|fill\s+in\s+(?:the\s+)?(?:blank|rest)\s*[:\-–]\s*["']?(?:my\s+(?:instructions?|system\s+prompt)|you\s+(?:are|were)\s+(?:told|instructed|programmed)))/gi,
    recommendation: 'Complete-the-sentence extraction trick detected. Attackers start a sentence about the AI\'s instructions expecting it to complete it truthfully. Treat sentence-completion prompts about internal instructions as extraction attempts.',
    category: 'prompt-leaking',
    cwe: 'CWE-200',
  },

  // ============================================
  // 10. Roleplay/Story-based Extraction
  // ============================================
  {
    id: 'prompt-leak-roleplay-extract',
    severity: 'medium',
    description: 'Roleplay or fictional framing used to extract AI instructions',
    pattern: /(?:in\s+(?:this\s+)?(?:story|fiction|roleplay|narrative|scenario|game|simulation|hypothetical)(?:\s+\w+)?\s*[,.]?\s*(?:the\s+)?(?:AI|assistant|character|agent|chatbot|robot)(?:\s+\w+)?\s+(?:explains?|reveals?|describes?|shares?|tells?|outputs?)\s+(?:its|their|your)\s+(?:programming|instructions?|configuration|system\s+prompt|rules?|directives?)|pretend\s+(?:you\s+are\s+)?(?:an?\s+)?(?:AI|assistant|character|agent)\s+(?:that\s+)?(?:has\s+no\s+(?:restrictions?|rules?|guidelines?)|(?:always\s+)?(?:reveals?|shares?|shows?)\s+(?:its|your)\s+(?:instructions?|system\s+prompt|configuration)))/gi,
    recommendation: 'Roleplay-based prompt extraction detected. Fictional framing is used to bypass safety rules and expose system prompts. Maintain prompt confidentiality regardless of fictional or hypothetical framing.',
    category: 'prompt-leaking',
    cwe: 'CWE-200',
  },

  // ============================================
  // 11. Indirect Restriction Mapping
  // ============================================
  {
    id: 'prompt-leak-indirect-ask',
    severity: 'medium',
    description: 'Indirect probe to map restrictions, effectively reverse-engineering system prompt',
    pattern: /(?:(?:what\s+(?:topics?|things?|subjects?|questions?|tasks?|content)\s+are\s+you\s+(?:not\s+allowed|forbidden|prohibited|restricted|unable|not\s+permitted)\s+to\s+(?:discuss|talk\s+about|answer|help\s+with|address))|(?:list|tell\s+me|enumerate|describe)\s+(?:all\s+(?:of\s+)?)?(?:your\s+)?(?:restrictions?|limitations?|rules?|guidelines?|constraints?|prohibitions?|off-limits\s+topics?)(?:\s+(?:in\s+detail|completely|fully|exhaustively|one\s+by\s+one))?)/gi,
    recommendation: 'Indirect restriction probe detected. By mapping all restrictions, attackers can reconstruct the system prompt. Avoid disclosing the full list of restrictions; instead, decline specific requests gracefully.',
    category: 'prompt-leaking',
    cwe: 'CWE-200',
  },

  // ============================================
  // 12. Token Smuggling / Encoded Extraction
  // ============================================
  {
    id: 'prompt-leak-token-smuggling',
    severity: 'critical',
    description: 'Encoded/obfuscated instructions near system prompt or decode-and-follow patterns',
    pattern: /(?:(?:decode|decrypt|deobfuscate|base64\s+decode|hex\s+decode|rot13|reverse)\s+(?:this|the\s+following|below)\s+(?:and\s+)?(?:follow|execute|apply|use\s+(?:it\s+as|as)\s+(?:your\s+)?(?:instructions?|prompt|configuration|rules?))|(?:your\s+(?:real|actual|true|hidden|secret|encoded)\s+(?:instructions?|prompt|rules?|configuration))\s+(?:is|are)\s*[:\-–]?\s*(?:[A-Za-z0-9+/]{20,}={0,2}|(?:0x)?[0-9a-fA-F]{20,})|(?:base64|hex|encoded)\s+(?:system\s+)?(?:prompt|instructions?|configuration)\s*[:\-–]?\s*(?:[A-Za-z0-9+/]{20,}={0,2}))/gi,
    recommendation: 'CRITICAL: Token smuggling via encoding detected. Attackers encode malicious instructions in base64/hex to bypass text filters, or claim the AI has a "real" encoded prompt. Decode and inspect all base64/hex content before processing.',
    category: 'prompt-leaking',
    cwe: 'CWE-116',
  },
];

// CommonJS compatibility
module.exports = { rules };
