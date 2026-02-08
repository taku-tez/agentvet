import type { Rule } from "../types.js";

/**
 * Hallucination Risk Rules
 * Detects configurations that increase the risk of hallucinated outputs.
 */

export const rules: Rule[] = [
  {
    id: 'hallucination-no-grounding',
    severity: 'medium',
    description: 'RAG configuration without grounding or source citation settings',
    pattern: /(?:(?:rag|retrieval|knowledge_base|vector_store|embeddings?)\s*[=:{](?:(?!(?:ground|cit(?:e|ation)|source|reference|attribution|provenance)).){0,200}(?:\n|$))/gi,
    recommendation: 'Enable grounding/source citation in RAG configurations to reduce hallucination risk.',
    falsePositiveCheck: (_match, content, _filePath) => {
      const lower = content.toLowerCase();
      return lower.includes('grounding') || lower.includes('citation') || lower.includes('source_attribution');
    },
  },
  {
    id: 'hallucination-high-temperature',
    severity: 'medium',
    description: 'Temperature setting above 1.0 detected (increases hallucination risk)',
    pattern: /(?:temperature|temp)\s*[:=]\s*(?:[2-9]\d*(?:\.\d+)?|1\.[1-9]\d*|1\.0[1-9]\d*|[1-9]\d+\.\d+)/gi,
    recommendation: 'Reduce temperature to 1.0 or below. Higher values significantly increase hallucination risk.',
  },
  {
    id: 'hallucination-no-max-tokens',
    severity: 'medium',
    description: 'Model configuration without max_tokens limit (unlimited generation risk)',
    pattern: /(?:model|llm|completion|chat)\s*[:={](?:(?!max_tokens|max_output_tokens|maxTokens|max_length).){0,300}(?:\n\s*\n|\n[^\s]|$)/gis,
    recommendation: 'Set max_tokens to prevent runaway generation and reduce hallucination in long outputs.',
    falsePositiveCheck: (_match, content, _filePath) => {
      const lower = content.toLowerCase();
      return lower.includes('max_tokens') || lower.includes('maxtokens') || lower.includes('max_length') || lower.includes('max_output_tokens');
    },
  },
];

// CommonJS compatibility
module.exports = { rules };
