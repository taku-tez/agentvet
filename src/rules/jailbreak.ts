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

  // ============================================
  // Hypothetical / Fictional Framing Jailbreaks
  // Attackers frame harmful requests as fiction, research, or thought
  // experiments to bypass safety filters.
  // ============================================
  {
    id: 'jailbreak-hypothetical-framing',
    severity: 'high',
    description: 'Hypothetical/fictional framing jailbreak (bypasses safety via "just pretend" framing)',
    pattern: /(?:(?:in\s+a\s+)?hypothetical(?:ly)?[,.]?\s+(?:scenario|world|situation|in\s+a\s+(?:world|scenario))|for\s+(?:a\s+)?(?:fictional|creative|academic)\s+(?:story|novel|research|paper|exercise)|imagine\s+(?:a\s+(?:world|scenario|situation)|you\s+(?:have\s+no|don'?t\s+have\s+any)\s+(?:restrictions?|limitations?|filters?|guidelines?))|in\s+(?:a\s+)?(?:parallel\s+universe|alternate\s+reality|fiction)\s+where\s+(?:you|AI|there)\s+(?:have|has|are|is)\s+no\s+(?:restrictions?|rules?|limitations?|filters?)|this\s+is\s+(?:just\s+)?(?:a\s+)?(?:thought\s+experiment|creative\s+writing|fiction|role\s*play))/gi,
    recommendation: 'Hypothetical framing is used to bypass safety guardrails. Ensure the model maintains safety constraints regardless of fictional context.',
    category: 'jailbreak',
    cwe: 'CWE-693',
  },

  // ============================================
  // Translation-Based Bypass
  // Requesting harmful content in another language or asking the
  // model to translate its response to evade content filters.
  // ============================================
  {
    id: 'jailbreak-translation-bypass',
    severity: 'high',
    description: 'Translation-based jailbreak bypass (evades content filters via language switch)',
    pattern: /(?:(?:respond|answer|reply|write)\s+(?:only\s+)?in\s+(?:(?:pig\s+)?latin|leet\s*speak|1337|morse\s+code|binary|braille|caesar\s+cipher|reversed?\s+text)|translate\s+(?:your\s+)?(?:(?:previous|above|last)\s+)?(?:response|answer|output|instructions)\s+(?:into?|to)\s+(?:(?:pig\s+)?latin|leet\s*speak|1337|morse\s+code|binary|braille|reversed?\s+text)|(?:use|speak|write)\s+(?:only\s+)?(?:in\s+)?(?:emoji|symbols?|unicode\s+characters?)\s+(?:to\s+(?:answer|respond|reply)|instead\s+of\s+(?:text|words)))/gi,
    recommendation: 'Translation and encoding-based bypasses circumvent content filters. Apply safety checks to the semantic meaning, not just the surface text.',
    category: 'jailbreak',
    cwe: 'CWE-693',
  },

  // ============================================
  // Prompt Splitting / Multi-Turn Jailbreak
  // Splitting a malicious prompt across multiple turns or using
  // instruction-continuation patterns to reassemble harmful requests.
  // ============================================
  {
    id: 'jailbreak-prompt-splitting',
    severity: 'high',
    description: 'Prompt splitting / continuation jailbreak (reassembles harmful request across turns)',
    pattern: /(?:continue\s+from\s+(?:where|the\s+point)\s+(?:you|we)\s+(?:left\s+off|stopped|were\s+cut\s+off)|now\s+combine\s+(?:all\s+)?(?:the\s+)?(?:previous\s+)?(?:parts?|pieces?|segments?|responses?|outputs?)\s+(?:together|into\s+one)|(?:concatenate|merge|join|assemble)\s+(?:all\s+)?(?:the\s+)?(?:previous\s+|above\s+|earlier\s+)?(?:responses?|parts?|outputs?|pieces?|segments?)(?:\s+(?:together|into\s+one))?|remember\s+(?:the\s+)?(?:first|earlier|previous)\s+(?:part|instruction|message)\s+(?:and|then)\s+(?:combine|add|append|merge))/gi,
    recommendation: 'Multi-turn prompt splitting reassembles harmful payloads across messages. Implement cross-turn context analysis in guardrails.',
    category: 'jailbreak',
    cwe: 'CWE-693',
  },

  // ============================================
  // Token Smuggling / Special Token Injection
  // Injecting model-specific control tokens or delimiters to
  // manipulate the model's internal prompt parsing.
  // ============================================
  {
    id: 'jailbreak-token-smuggling',
    severity: 'critical',
    description: 'Token smuggling / special token injection (manipulates model prompt boundaries)',
    pattern: /(?:<\|(?:im_start|im_end|system|user|assistant|endoftext|pad|sep|end|eos|bos)\|>|<\/?(?:system|user|assistant|human|bot|context|instruction)>|\[\/INST\]|\[INST\]|<\|(?:begin|end)_of_text\|>|<<SYS>>|<\/s>|<s>)/gi,
    recommendation: 'CRITICAL: Special token injection attempts to manipulate model prompt boundaries. Sanitize all user input to strip model-specific control tokens.',
    category: 'jailbreak',
    cwe: 'CWE-74',
  },

  // ============================================
  // Payload Splitting via Variable Assignment
  // Defining variables or completing partial strings so the model
  // reconstructs a harmful payload from innocuous fragments.
  // ============================================
  {
    id: 'jailbreak-payload-variable-split',
    severity: 'high',
    description: 'Payload splitting via variable assignment (reconstructs harmful content from fragments)',
    pattern: /(?:(?:let|set|define|assign)\s+(?:a|b|x|y|var\d?|part\d?)\s*=\s*['"][^'"]{2,}['"]\s*(?:;\s*)?(?:let|set|define|assign)\s+(?:a|b|x|y|var\d?|part\d?)\s*=\s*['"][^'"]{2,}['"]\s*(?:;\s*)?(?:now\s+)?(?:combine|concatenate|join|print|execute|output|eval)\s+(?:a|b|x|y|var\d?|part\d?)\s*\+|(?:first\s+half|part\s+(?:one|1|a))[\s:]+['"][^'"]+['"]\s*(?:,|\.|\n)\s*(?:second\s+half|part\s+(?:two|2|b))[\s:]+['"][^'"]+['"]\s*(?:,|\.|\n)\s*(?:now\s+)?(?:combine|put\s+(?:them\s+)?together|concatenate|merge))/gi,
    recommendation: 'Payload splitting assigns innocuous fragments to variables then recombines them. Analyze the final reconstructed payload, not individual fragments.',
    category: 'jailbreak',
    cwe: 'CWE-693',
  },

  // ============================================
  // Grandma / Social Engineering Jailbreak
  // Emotional manipulation patterns that guilt or trick the model
  // into dropping safety barriers ("my grandma used to...", "I'll die if").
  // ============================================
  {
    id: 'jailbreak-social-engineering',
    severity: 'high',
    description: 'Social engineering jailbreak (emotional manipulation to bypass safety)',
    pattern: /(?:(?:my\s+)?(?:grandma|grandmother|dying\s+(?:friend|relative|mother|father))\s+(?:used\s+to|always|would)\s+(?:tell|told|read|say|recite)\s+(?:me\s+)?(?:about\s+)?(?:how\s+to|the\s+(?:recipe|formula|steps|instructions|way)\s+(?:for|to))|(?:I(?:'ll|\s+will)\s+(?:die|be\s+(?:hurt|harmed))|(?:someone|a\s+person)\s+(?:will\s+(?:die|be\s+hurt))|(?:life|death)\s+(?:depends?\s+on|is\s+at\s+stake))\s+(?:if|unless)\s+you\s+(?:don'?t\s+|do\s+not\s+)?(?:tell|help|answer|respond|provide|give))/gi,
    recommendation: 'Social engineering jailbreaks use emotional manipulation. Safety constraints must not be overridden by simulated urgency or emotional appeals.',
    category: 'jailbreak',
    cwe: 'CWE-693',
  },
];

// CommonJS compatibility
module.exports = { rules };
