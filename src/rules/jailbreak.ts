import type { Rule } from "../types.js";

/**
 * Jailbreak Detection Rules
 * Static detection of jailbreak vulnerability patterns in agent configurations.
 * Inspired by NeMo Guardrails heuristic checks.
 */

export const rules: Rule[] = [
  {
    id: 'jailbreak-system-prompt-leak',
    severity: 'high',
    description: 'System prompt leak pattern detected (instruction to reveal system prompt)',
    pattern: /(?:ignore\s+(?:all\s+)?previous\s+instructions|repeat\s+the\s+above|print\s+your\s+(?:system\s+)?prompt|reveal\s+your\s+(?:system\s+)?(?:prompt|instructions)|show\s+(?:me\s+)?your\s+(?:initial|system|original)\s+(?:prompt|instructions)|what\s+(?:are|were)\s+your\s+(?:original|initial|system)\s+(?:instructions|prompt)|output\s+(?:the|your)\s+(?:system|initial)\s+(?:prompt|instructions|message)|disregard\s+(?:all\s+)?(?:previous|prior|above)\s+(?:instructions|directives|rules))/gi,
    recommendation: 'Add guardrails to prevent system prompt leakage. Never include instructions that could reveal the system prompt.',
  },
  {
    id: 'jailbreak-role-play',
    severity: 'high',
    description: 'Role-play jailbreak pattern detected (identity override attempt)',
    pattern: /(?:pretend\s+(?:you\s+are|to\s+be)|act\s+as\s+(?:if\s+you\s+(?:are|were)\s+)?(?:a\s+)?(?:DAN|an?\s+unrestricted|an?\s+unfiltered|evil|jailbroken)|you\s+are\s+now\s+(?:DAN|free|unrestricted|unfiltered|jailbroken)|from\s+now\s+on\s+you\s+(?:are|will)|do\s+anything\s+now|DAN\s+mode|developer\s+mode\s+(?:enabled|on)|bypass\s+(?:your\s+)?(?:safety|content|ethical)\s+(?:filters?|guidelines?|restrictions?)|enable\s+(?:jailbreak|unrestricted)\s+mode|ignore\s+(?:your\s+)?(?:safety|content|ethical)\s+(?:guidelines?|restrictions?|filters?))/gi,
    recommendation: 'Add role-play jailbreak detection. Implement identity anchoring in the system prompt.',
  },
  {
    id: 'jailbreak-encoding-bypass',
    severity: 'high',
    description: 'Encoded instruction bypass detected (Base64/hex/ROT13 encoded directives)',
    pattern: /(?:(?:decode|interpret|execute|follow|run)\s+(?:this|the\s+following)\s+(?:base64|hex|rot13|encoded)|base64\s*(?:decode|decrypt|interpret)\s*[:(]|(?:aWdub3Jl|SWdub3Jl|cHJpbnQ|ZXhlY3V0|cmV2ZWFs)[A-Za-z0-9+/=]{4,}|\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){3,}|(?:rot13|caesar)\s+(?:decode|decrypt|translate)\s+(?:the\s+following|this)|(?:convert|translate)\s+from\s+(?:base64|hex|rot13))/gi,
    recommendation: 'Block encoded instruction patterns. Validate and sanitize inputs before processing.',
  },
];

// CommonJS compatibility
module.exports = { rules };
