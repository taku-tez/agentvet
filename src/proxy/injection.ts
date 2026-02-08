/**
 * Indirect Prompt Injection Detector
 * Scans tool responses for embedded prompt injection attempts
 */

export interface InjectionDetection {
  detected: boolean;
  patterns: InjectionMatch[];
  score: number; // 0-100 confidence
}

export interface InjectionMatch {
  pattern: string;
  category: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  offset: number;
  snippet: string;
}

// Known prompt injection patterns
const INJECTION_PATTERNS: Array<{ regex: RegExp; category: string; severity: InjectionMatch['severity']; name: string }> = [
  // Direct instruction override
  { regex: /ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|context)/i, category: 'instruction_override', severity: 'critical', name: 'Ignore previous instructions' },
  { regex: /disregard\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?)/i, category: 'instruction_override', severity: 'critical', name: 'Disregard instructions' },
  { regex: /forget\s+(everything|all)\s+(you|that)\s+(were|was)\s+told/i, category: 'instruction_override', severity: 'critical', name: 'Forget instructions' },
  
  // System prompt extraction
  { regex: /(?:print|show|reveal|display|output|repeat)\s+(?:your\s+)?(?:system\s+)?(?:prompt|instructions|rules)/i, category: 'prompt_extraction', severity: 'high', name: 'System prompt extraction' },
  { regex: /what\s+(?:are|were)\s+your\s+(?:original\s+)?(?:instructions|system\s+prompt)/i, category: 'prompt_extraction', severity: 'high', name: 'Instruction query' },
  
  // Role hijacking
  { regex: /you\s+are\s+now\s+(?:a|an|the)\s+/i, category: 'role_hijack', severity: 'high', name: 'Role reassignment' },
  { regex: /(?:new|updated)\s+(?:system\s+)?(?:prompt|instructions?|role)\s*:/i, category: 'role_hijack', severity: 'critical', name: 'New system prompt' },
  { regex: /\[SYSTEM\]|\[INST\]|<<SYS>>|<\|im_start\|>system/i, category: 'role_hijack', severity: 'critical', name: 'System token injection' },
  
  // Tool manipulation
  { regex: /(?:call|execute|run|invoke)\s+(?:the\s+)?(?:tool|function|command)\s+/i, category: 'tool_manipulation', severity: 'high', name: 'Tool invocation injection' },
  { regex: /use\s+(?:the\s+)?(?:bash|shell|exec|terminal|cmd)\s+(?:tool|command)/i, category: 'tool_manipulation', severity: 'critical', name: 'Shell execution injection' },
  
  // Data exfiltration
  { regex: /(?:send|post|upload|exfil|transfer)\s+(?:all\s+)?(?:data|files?|contents?|secrets?|keys?|tokens?)\s+(?:to|via)/i, category: 'data_exfiltration', severity: 'critical', name: 'Data exfiltration' },
  { regex: /(?:curl|wget|fetch|http)\s+https?:\/\//i, category: 'data_exfiltration', severity: 'high', name: 'External request injection' },
  
  // Hidden instructions (zero-width, base64, etc.)
  { regex: /[\u200B\u200C\u200D\uFEFF]{3,}/,  category: 'steganography', severity: 'high', name: 'Zero-width character hiding' },
  { regex: /<!--\s*(?:IMPORTANT|SYSTEM|INSTRUCTION|NOTE TO AI)/i, category: 'steganography', severity: 'high', name: 'HTML comment injection' },

  // Delimiter injection
  { regex: /={10,}\s*(?:END|BEGIN)\s+(?:OF\s+)?(?:CONTEXT|DOCUMENT|INSTRUCTIONS?)/i, category: 'delimiter', severity: 'medium', name: 'Delimiter injection' },
  { regex: /---+\s*(?:SYSTEM|ADMIN|IMPORTANT)\s*---+/i, category: 'delimiter', severity: 'medium', name: 'Delimiter boundary injection' },
];

// Heuristic checks
function heuristicCheck(text: string): InjectionMatch[] {
  const matches: InjectionMatch[] = [];

  // High ratio of imperatives to content
  const imperatives = text.match(/\b(must|shall|always|never|do not|don't|ensure|immediately|urgently)\b/gi);
  if (imperatives && imperatives.length > 5 && text.length < 500) {
    matches.push({
      pattern: 'High imperative density',
      category: 'heuristic',
      severity: 'medium',
      offset: 0,
      snippet: text.slice(0, 100),
    });
  }

  // Suspicious base64 that decodes to text with injection patterns
  const b64Matches = text.match(/[A-Za-z0-9+/]{40,}={0,2}/g);
  if (b64Matches) {
    for (const b64 of b64Matches) {
      try {
        const decoded = Buffer.from(b64, 'base64').toString('utf-8');
        // Check if decoded text looks like instructions
        if (/ignore|system|prompt|instruction|execute/i.test(decoded) && decoded.length > 10) {
          matches.push({
            pattern: 'Base64-encoded injection',
            category: 'steganography',
            severity: 'high',
            offset: text.indexOf(b64),
            snippet: `Decoded: ${decoded.slice(0, 80)}`,
          });
        }
      } catch {
        // Not valid base64
      }
    }
  }

  return matches;
}

/**
 * Scan text for prompt injection patterns
 */
export function detectInjection(text: string): InjectionDetection {
  if (!text || typeof text !== 'string') {
    return { detected: false, patterns: [], score: 0 };
  }

  const matches: InjectionMatch[] = [];

  // Pattern-based detection
  for (const pattern of INJECTION_PATTERNS) {
    const match = pattern.regex.exec(text);
    if (match) {
      const offset = match.index;
      const start = Math.max(0, offset - 20);
      const end = Math.min(text.length, offset + match[0].length + 20);
      matches.push({
        pattern: pattern.name,
        category: pattern.category,
        severity: pattern.severity,
        offset,
        snippet: text.slice(start, end),
      });
    }
  }

  // Heuristic detection
  matches.push(...heuristicCheck(text));

  // Calculate score
  let score = 0;
  for (const m of matches) {
    switch (m.severity) {
      case 'critical': score += 40; break;
      case 'high': score += 25; break;
      case 'medium': score += 15; break;
      case 'low': score += 5; break;
    }
  }
  score = Math.min(100, score);

  return {
    detected: matches.length > 0,
    patterns: matches,
    score,
  };
}

export { INJECTION_PATTERNS };
