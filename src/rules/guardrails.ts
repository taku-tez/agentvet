import type { Rule } from "../types.js";

/**
 * Guardrails & Topic Restriction Rules
 * Detects missing guardrails configuration and topic restrictions in agent configs
 */

export const rules: Rule[] = [
  {
    id: 'config-no-guardrails',
    severity: 'medium',
    description: 'No guardrails configuration detected in agent config',
    pattern: /(?:system_prompt|system_message|instructions|agent_config|llm_config|model_config)\s*[=:]/gi,
    category: 'guardrails',
    recommendation: 'Add guardrails configuration (e.g., NeMo Guardrails, OpenAI moderation, content filters) to protect against unsafe outputs.',
    falsePositiveCheck: (_match, content, _filePath) => {
      // If guardrails ARE configured, this is a false positive (suppress the finding)
      const guardrailPatterns = [
        /nemo[\s_-]?guardrails/i,
        /guardrails[\s_-]?config/i,
        /content[\s_-]?filter/i,
        /content[\s_-]?moderation/i,
        /safety[\s_-]?settings/i,
        /moderation[\s_-]?endpoint/i,
        /openai[\s_-]?moderation/i,
        /azure[\s_-]?content[\s_-]?safety/i,
        /harm[\s_-]?categories/i,
        /block[\s_-]?threshold/i,
        /guardrails/i,
      ];
      return guardrailPatterns.some(p => p.test(content));
    },
  },
  {
    id: 'config-no-input-filter',
    severity: 'medium',
    description: 'No input filtering/validation configured for agent',
    pattern: /(?:system_prompt|system_message|instructions|agent_config|llm_config|model_config)\s*[=:]/gi,
    category: 'guardrails',
    recommendation: 'Configure input filtering to validate and sanitize user inputs before processing.',
    falsePositiveCheck: (_match, content, _filePath) => {
      const inputFilterPatterns = [
        /input[\s_-]?filter/i,
        /input[\s_-]?validation/i,
        /input[\s_-]?guard/i,
        /input[\s_-]?moderation/i,
        /input[\s_-]?sanitiz/i,
        /pre[\s_-]?processing/i,
        /input[\s_-]?check/i,
        /validate[\s_-]?input/i,
        /input_rail/i,
        /user[\s_-]?input[\s_-]?check/i,
      ];
      return inputFilterPatterns.some(p => p.test(content));
    },
  },
  {
    id: 'config-no-output-filter',
    severity: 'medium',
    description: 'No output filtering/validation configured for agent',
    pattern: /(?:system_prompt|system_message|instructions|agent_config|llm_config|model_config)\s*[=:]/gi,
    category: 'guardrails',
    recommendation: 'Configure output filtering to validate agent responses before delivery to users.',
    falsePositiveCheck: (_match, content, _filePath) => {
      const outputFilterPatterns = [
        /output[\s_-]?filter/i,
        /output[\s_-]?validation/i,
        /output[\s_-]?guard/i,
        /output[\s_-]?moderation/i,
        /output[\s_-]?sanitiz/i,
        /post[\s_-]?processing/i,
        /output[\s_-]?check/i,
        /validate[\s_-]?output/i,
        /output_rail/i,
        /response[\s_-]?filter/i,
        /response[\s_-]?validation/i,
      ];
      return outputFilterPatterns.some(p => p.test(content));
    },
  },
  {
    id: 'config-no-topic-restriction',
    severity: 'low',
    description: 'No topic restriction configured for agent',
    pattern: /(?:system_prompt|system_message|instructions|agent_config|llm_config|model_config)\s*[=:]/gi,
    category: 'guardrails',
    recommendation: 'Consider adding topic restrictions (allowed/blocked topics) to limit agent scope and reduce risk of misuse.',
    falsePositiveCheck: (_match, content, _filePath) => {
      const topicPatterns = [
        /(?:allowed|blocked|restricted|prohibited|forbidden)[\s_-]?topics?/i,
        /topic[\s_-]?(?:restrict|limit|allow|block|filter)/i,
        /off[\s_-]?topic/i,
        /on[\s_-]?topic/i,
        /scope[\s_-]?(?:restrict|limit)/i,
        /(?:do not|don'?t|never|refuse to)\s+(?:discuss|talk about|answer|respond)/i,
        /(?:only|exclusively)\s+(?:discuss|talk about|answer|respond)/i,
        /subject[\s_-]?(?:restrict|limit|matter)/i,
      ];
      return topicPatterns.some(p => p.test(content));
    },
  },
];

// CommonJS compatibility
module.exports = { rules };
