import type { Rule } from "../types.js";

/**
 * Indirect Prompt Injection Detection Rules
 * Detects hidden instructions embedded in data that could manipulate AI agents
 * when processing untrusted content (documents, web pages, emails, etc.).
 *
 * References:
 * - Greshake et al. "Not what you've signed up for" (2023)
 * - OWASP LLM Top 10 2025 - LLM01: Prompt Injection
 * - Markdown image exfiltration (Embrace The Red blog)
 */

export const rules: Rule[] = [
  // Hidden instructions in HTML comments
  {
    id: 'indirect-injection-html-comment',
    severity: 'high',
    description: 'Hidden instruction detected in HTML comment (indirect prompt injection)',
    pattern: /<!--[^>]*(?:ignore\s+(?:all\s+)?(?:previous|prior|above)|new\s+instructions?|you\s+(?:are|must|should|will)\s+now|forget\s+(?:all|your|everything)|system\s*:\s*|assistant\s*:\s*|<\s*(?:system|instruction))[^>]*-->/gi,
    recommendation: 'HTML comments containing instruction-like text can manipulate AI agents processing this content. Sanitize HTML comments before LLM processing.',
    cwe: 'CWE-74',
  },

  // Invisible unicode characters hiding instructions
  {
    id: 'indirect-injection-invisible-unicode',
    severity: 'critical',
    description: 'Invisible unicode characters detected (may hide prompt injection payload)',
    pattern: /[\u200B\u200C\u200D\u2060\u2061\u2062\u2063\u2064\uFEFF\u00AD\u034F\u061C\u180E\u200E\u200F\u202A-\u202E\u2066-\u2069]{3,}/g,
    recommendation: 'Multiple invisible unicode characters (zero-width spaces, joiners, directional marks) can hide malicious instructions. Strip invisible characters before LLM processing.',
    cwe: 'CWE-116',
  },

  // Markdown image exfiltration (rendering triggers GET with data in URL)
  {
    id: 'indirect-injection-markdown-exfil',
    severity: 'critical',
    description: 'Markdown image tag with dynamic/exfiltration URL pattern detected',
    pattern: /!\[[^\]]*\]\(\s*https?:\/\/[^\s)]*(?:\{\{|\$\{|%7[Bb]|%24%7[Bb]|\?\s*(?:data|secret|token|key|password|api_key|content|response|output|result|answer)\s*=)[^\s)]*\)/g,
    recommendation: 'Markdown images can exfiltrate data by embedding it in the URL when rendered. Block dynamic URLs in markdown image tags.',
    cwe: 'CWE-200',
  },

  // Data URI with embedded instructions
  {
    id: 'indirect-injection-data-uri',
    severity: 'high',
    description: 'Data URI containing potential hidden instructions',
    pattern: /data:(?:text\/(?:html|plain|xml)|application\/(?:xhtml|xml))[^,]*,(?:[^"'\s]*(?:ignore|instruction|system|assistant|forget|override)[^"'\s]*)/gi,
    recommendation: 'Data URIs can embed hidden instructions that AI agents may process. Validate and sanitize data URIs.',
    cwe: 'CWE-74',
  },

  // Prompt injection via image alt text / metadata
  {
    id: 'indirect-injection-image-metadata',
    severity: 'high',
    description: 'Suspicious instruction text in image alt/title attributes',
    pattern: /(?:alt|title)\s*=\s*["'][^"']*(?:ignore\s+previous|new\s+instructions?|you\s+(?:are|must|should)\s+now|system\s*:|forget\s+(?:all|your))[^"']*["']/gi,
    recommendation: 'Image metadata (alt text, titles) can carry prompt injection payloads when processed by multimodal AI agents. Sanitize metadata before LLM processing.',
    cwe: 'CWE-74',
  },

  // Instruction smuggling via JSON/YAML string values
  {
    id: 'indirect-injection-data-smuggling',
    severity: 'high',
    description: 'Instruction-like content detected in data field values (potential smuggling)',
    pattern: /(?:"(?:bio|description|about|comment|note|summary|content|message|text|body|value|memo|remark)"\s*:\s*"[^"]*(?:ignore\s+(?:all\s+)?previous|new\s+instruction|you\s+are\s+now|forget\s+(?:everything|all|your)|override\s+(?:system|safety)|<\/?system>)[^"]*")/gi,
    recommendation: 'User-controlled data fields containing instruction-like text can poison AI agent context. Implement input boundary markers and instruction hierarchy.',
    cwe: 'CWE-74',
  },

  // ============================================
  // New Indirect Injection Vectors (Issue #12)
  // ============================================

  // SVG foreignObject hidden instruction injection
  {
    id: 'indirect-injection-svg-foreign-object',
    severity: 'high',
    description: 'SVG foreignObject with hidden instruction text (potential prompt injection via image processing)',
    pattern: /<foreignObject[^>]*>[\s\S]{0,500}(?:ignore\s+(?:all\s+)?previous|new\s+instructions?|you\s+(?:are|must|should)\s+now|forget\s+(?:all|your|everything)|system\s*:|assistant\s*:)[\s\S]{0,200}<\/foreignObject>/gi,
    recommendation: 'SVG foreignObject elements can embed hidden text instructions that multimodal AI agents may process as directives. Strip foreignObject from SVGs before LLM processing.',
    cwe: 'CWE-74',
  },

  // CSS content property injection for web-scraping agents
  {
    id: 'indirect-injection-css-content-exfil',
    severity: 'high',
    description: 'CSS ::before/::after content property contains instruction text (targets web-scraping AI agents)',
    pattern: /::?(?:before|after)\s*\{[^}]*content\s*:\s*["'](?:[^"']*(?:ignore\s+(?:all\s+)?previous|new\s+instructions?|you\s+(?:are|must|should)\s+now|forget\s+(?:all|your)|system\s*:|assistant\s*:)[^"']*)/gi,
    recommendation: 'CSS ::before/::after content properties can inject hidden text into web pages scraped by AI agents. Sanitize rendered CSS content before LLM processing.',
    cwe: 'CWE-74',
  },

  // GitHub/GitLab PR/Issue body targeting AI code review agents
  {
    id: 'indirect-injection-code-review-agent',
    severity: 'critical',
    description: 'Code review context contains approval-forcing instructions (targets AI PR review agents)',
    pattern: /(?:approve\s+(?:this|the)\s+(?:pr|pull\s*request|change|merge\s*request)|lgtm\s+automatically|merge\s+without\s+review|automatically\s+(?:approve|merge|lgtm)|add\s+the\s+(?:approved|lgtm|ship.?it)\s+(?:label|tag|status))/gi,
    recommendation: 'AI code review agents can be manipulated by embedding approval instructions in PR descriptions or comments. Validate AI review decisions independently of LLM output.',
    cwe: 'CWE-74',
  },

  // ICS/Calendar invite DESCRIPTION field injection
  {
    id: 'indirect-injection-calendar-invite',
    severity: 'high',
    description: 'ICS/calendar invite DESCRIPTION field contains instruction-like content',
    pattern: /DESCRIPTION:[^\r\n]*(?:ignore\s+(?:all\s+)?previous|new\s+instructions?|you\s+(?:are|must|should)\s+now|system\s*:|forget\s+(?:all|your|everything))/gi,
    recommendation: 'AI calendar assistants parsing ICS files can be manipulated via the DESCRIPTION field. Sanitize calendar event content before LLM processing.',
    cwe: 'CWE-74',
  },

  // YAML frontmatter hidden instruction fields
  {
    id: 'indirect-injection-frontmatter',
    severity: 'high',
    description: 'YAML frontmatter contains hidden instruction fields targeting AI document processors',
    pattern: /^---\s*\n(?:[^\n]*\n)*?(?:instructions?|system_prompt|ai_directive|llm_context|agent_note|hidden_prompt)\s*:/im,
    recommendation: 'YAML frontmatter with instruction-like keys (instructions, system_prompt, ai_directive) can manipulate AI agents processing Markdown documents. Validate and sanitize frontmatter keys before LLM processing.',
    cwe: 'CWE-74',
  },

  // Zero-opacity / white-on-white hidden text injection
  {
    id: 'indirect-injection-hidden-text-style',
    severity: 'high',
    description: 'Zero-opacity or white-on-white text containing instruction content (hidden injection for document-processing agents)',
    pattern: /(?:style\s*=\s*["'][^"']*(?:color\s*:\s*(?:white|#fff(?:fff)?|rgba?\s*\(\s*25[45]\s*,\s*25[45]\s*,\s*25[45])|opacity\s*:\s*0(?:\.\s*0+)?|visibility\s*:\s*hidden|display\s*:\s*none)[^"']*["'][^>]*>|class\s*=\s*["'][^"']*(?:sr-only|visually-hidden|hidden|invisible)[^"']*["'][^>]*>)[\s\S]{0,300}(?:ignore\s+(?:all\s+)?previous|new\s+instructions?|you\s+(?:are|must|should)\s+now|forget\s+(?:all|your|everything)|system\s*:|assistant\s*:)/gi,
    recommendation: 'Zero-opacity, white-on-white, or CSS-hidden text can conceal injection instructions from humans while remaining readable to AI document processors. Sanitize HTML with hidden-text stripping before LLM processing.',
    cwe: 'CWE-74',
  },
];

// CommonJS compatibility
module.exports = { rules };
