/**
 * Default Prompt Firewall Pattern Ruleset
 * 25+ patterns covering major prompt injection vectors
 */

export interface FirewallPattern {
  id: string;
  regex: RegExp;
  name: string;
  category: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  direction: 'inbound' | 'outbound' | 'both';
  score: number;
}

export const FIREWALL_PATTERNS: FirewallPattern[] = [
  // === Instruction Override (inbound) ===
  { id: 'FW001', regex: /ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|context|rules?)/i, name: 'Ignore previous instructions', category: 'instruction_override', severity: 'critical', direction: 'both', score: 40 },
  { id: 'FW002', regex: /disregard\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?)/i, name: 'Disregard instructions', category: 'instruction_override', severity: 'critical', direction: 'both', score: 40 },
  { id: 'FW003', regex: /forget\s+(everything|all)\s+(you|that)\s+(were|was|have\s+been)\s+told/i, name: 'Forget instructions', category: 'instruction_override', severity: 'critical', direction: 'both', score: 40 },
  { id: 'FW004', regex: /(?:do\s+not|don'?t)\s+follow\s+(?:any\s+)?(?:previous|prior|your)\s+(?:instructions?|rules?|guidelines?)/i, name: 'Do not follow instructions', category: 'instruction_override', severity: 'critical', direction: 'both', score: 35 },
  { id: 'FW005', regex: /override\s+(?:all\s+)?(?:previous\s+)?(?:instructions?|settings?|rules?|constraints?)/i, name: 'Override instructions', category: 'instruction_override', severity: 'critical', direction: 'both', score: 35 },

  // === System Prompt Extraction (inbound) ===
  { id: 'FW010', regex: /(?:print|show|reveal|display|output|repeat|echo)\s+(?:your\s+)?(?:full\s+)?(?:system\s+)?(?:prompt|instructions|rules|directives)/i, name: 'System prompt extraction', category: 'prompt_extraction', severity: 'high', direction: 'inbound', score: 30 },
  { id: 'FW011', regex: /what\s+(?:are|were|is)\s+your\s+(?:original\s+)?(?:instructions|system\s+prompt|initial\s+prompt|directives)/i, name: 'Instruction query', category: 'prompt_extraction', severity: 'high', direction: 'inbound', score: 25 },
  { id: 'FW012', regex: /(?:copy|paste|dump)\s+(?:your\s+)?(?:entire\s+)?(?:system\s+)?(?:prompt|context|instructions)/i, name: 'Dump system prompt', category: 'prompt_extraction', severity: 'high', direction: 'inbound', score: 30 },
  { id: 'FW013', regex: /(?:beginning|start)\s+of\s+(?:this\s+)?conversation.*(?:verbatim|exact)/i, name: 'Conversation start extraction', category: 'prompt_extraction', severity: 'medium', direction: 'inbound', score: 20 },

  // === Role Hijacking ===
  { id: 'FW020', regex: /you\s+are\s+now\s+(?:a|an|the|in)\s+/i, name: 'Role reassignment', category: 'role_hijack', severity: 'high', direction: 'both', score: 25 },
  { id: 'FW021', regex: /(?:new|updated|revised)\s+(?:system\s+)?(?:prompt|instructions?|role|persona)\s*:/i, name: 'New system prompt', category: 'role_hijack', severity: 'critical', direction: 'both', score: 40 },
  { id: 'FW022', regex: /\[SYSTEM\]|\[INST\]|<<SYS>>|<\|im_start\|>system|<\|system\|>/i, name: 'System token injection', category: 'role_hijack', severity: 'critical', direction: 'both', score: 40 },
  { id: 'FW023', regex: /(?:act|behave|respond)\s+as\s+(?:if\s+)?(?:you\s+(?:are|were)\s+)?(?:a\s+)?(?:different|new|unrestricted|jailbroken)/i, name: 'Behavioral override', category: 'role_hijack', severity: 'high', direction: 'both', score: 30 },
  { id: 'FW024', regex: /entering\s+(?:a\s+)?(?:new|special|developer|debug|admin|root|maintenance)\s+mode/i, name: 'Mode switch injection', category: 'role_hijack', severity: 'high', direction: 'both', score: 30 },

  // === Tool/Command Manipulation ===
  { id: 'FW030', regex: /(?:call|execute|run|invoke|trigger)\s+(?:the\s+)?(?:tool|function|command|api)\s+/i, name: 'Tool invocation injection', category: 'tool_manipulation', severity: 'high', direction: 'outbound', score: 25 },
  { id: 'FW031', regex: /use\s+(?:the\s+)?(?:bash|shell|exec|terminal|cmd|system)\s+(?:tool|command|function)/i, name: 'Shell execution injection', category: 'tool_manipulation', severity: 'critical', direction: 'outbound', score: 35 },

  // === Data Exfiltration ===
  { id: 'FW040', regex: /(?:send|post|upload|exfil|transfer|transmit)\s+(?:all\s+)?(?:data|files?|contents?|secrets?|keys?|tokens?|credentials?|passwords?)\s+(?:to|via|using)/i, name: 'Data exfiltration', category: 'data_exfiltration', severity: 'critical', direction: 'both', score: 40 },
  { id: 'FW041', regex: /(?:curl|wget|fetch|http)\s+https?:\/\//i, name: 'External request injection', category: 'data_exfiltration', severity: 'high', direction: 'outbound', score: 25 },

  // === Steganography / Hidden Content ===
  { id: 'FW050', regex: /[\u200B\u200C\u200D\uFEFF]{3,}/, name: 'Zero-width character hiding', category: 'steganography', severity: 'high', direction: 'both', score: 30 },
  { id: 'FW051', regex: /<!--\s*(?:IMPORTANT|SYSTEM|INSTRUCTION|NOTE\s+TO\s+AI|HIDDEN|SECRET|ADMIN)/i, name: 'HTML comment injection', category: 'steganography', severity: 'high', direction: 'outbound', score: 30 },
  { id: 'FW052', regex: /\x1b\[\d+(?:;\d+)*m.*(?:ignore|system|instruction|execute)/i, name: 'ANSI escape injection', category: 'steganography', severity: 'high', direction: 'outbound', score: 25 },

  // === Delimiter Injection ===
  { id: 'FW060', regex: /={10,}\s*(?:END|BEGIN)\s+(?:OF\s+)?(?:CONTEXT|DOCUMENT|INSTRUCTIONS?|PROMPT|SYSTEM)/i, name: 'Delimiter injection', category: 'delimiter', severity: 'medium', direction: 'both', score: 20 },
  { id: 'FW061', regex: /---+\s*(?:SYSTEM|ADMIN|IMPORTANT|INSTRUCTIONS?)\s*---+/i, name: 'Delimiter boundary injection', category: 'delimiter', severity: 'medium', direction: 'both', score: 20 },

  // === Encoding Evasion ===
  { id: 'FW070', regex: /(?:base64|rot13|hex)\s*(?:decode|encoded?)\s*:/i, name: 'Encoding evasion hint', category: 'evasion', severity: 'medium', direction: 'both', score: 15 },
  { id: 'FW071', regex: /eval\s*\(|Function\s*\(|setTimeout\s*\(|setInterval\s*\(/i, name: 'Code execution attempt', category: 'evasion', severity: 'high', direction: 'both', score: 25 },
];

/**
 * Context protection specific patterns (system prompt extraction)
 */
export const CONTEXT_PROTECTION_PATTERNS: FirewallPattern[] = [
  ...FIREWALL_PATTERNS.filter(p => p.category === 'prompt_extraction'),
  { id: 'CTX001', regex: /(?:what|tell\s+me)\s+(?:is|was)\s+(?:in\s+)?your\s+(?:system|initial|original|first)\s+(?:message|prompt|instruction)/i, name: 'System message query', category: 'context_protection', severity: 'high', direction: 'inbound', score: 25 },
  { id: 'CTX002', regex: /repeat\s+(?:the\s+)?(?:text|message|content)\s+(?:above|before|from\s+the\s+(?:start|beginning))/i, name: 'Repeat above content', category: 'context_protection', severity: 'high', direction: 'inbound', score: 25 },
  { id: 'CTX003', regex: /(?:translate|convert)\s+(?:your\s+)?(?:system\s+)?(?:prompt|instructions)\s+(?:to|into)\s+/i, name: 'Translate system prompt', category: 'context_protection', severity: 'medium', direction: 'inbound', score: 20 },
];
