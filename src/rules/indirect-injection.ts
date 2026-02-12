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
];

// CommonJS compatibility
module.exports = { rules };
