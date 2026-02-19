import type { Rule } from "../types.js";

/**
 * Code Obfuscation Detection Rules
 * Detects obfuscated code patterns that may hide malicious intent.
 * Obfuscation in agent skills/tools is a strong indicator of malicious behavior.
 */

export const rules: Rule[] = [
  // ============================================
  // JavaScript Obfuscation
  // ============================================
  {
    id: 'obfusc-js-eval-encoded',
    severity: 'critical',
    description: 'eval() with encoded/constructed string (likely obfuscated payload)',
    pattern: /eval\s*\(\s*(?:atob|Buffer\.from|decodeURIComponent|unescape|String\.fromCharCode)\s*\(/gi,
    recommendation: 'eval() with decoded content is a classic obfuscation technique. Remove and inspect the decoded payload.',
  },
  {
    id: 'obfusc-js-function-constructor',
    severity: 'critical',
    description: 'Function constructor used to execute dynamic code',
    pattern: /(?:new\s+Function|Function\s*\()\s*\([^)]*(?:atob|fromCharCode|decode|unescape)/gi,
    recommendation: 'Function() constructor with encoding is equivalent to eval(). Review the decoded content.',
  },
  {
    id: 'obfusc-js-fromcharcode-long',
    severity: 'high',
    description: 'Long String.fromCharCode() sequence (obfuscated string)',
    pattern: /String\.fromCharCode\s*\(\s*(?:\d+\s*,\s*){5,}/gi,
    recommendation: 'Long fromCharCode sequences typically hide malicious strings. Decode and review.',
  },
  {
    id: 'obfusc-js-hex-string-array',
    severity: 'high',
    description: 'Array of hex-encoded strings (JavaScript obfuscation pattern)',
    pattern: /\[\s*(?:['"]\\x[0-9a-f]{2}(?:\\x[0-9a-f]{2})*['"],?\s*){3,}\]/gi,
    recommendation: 'Hex-encoded string arrays are used by obfuscators. Decode and review content.',
  },
  {
    id: 'obfusc-js-bracket-notation-chain',
    severity: 'warning',
    description: 'Chained bracket notation property access (obfuscation pattern)',
    pattern: /\w+\[['"][a-zA-Z]+['"]\]\[['"][a-zA-Z]+['"]\]\[['"][a-zA-Z]+['"]\]/g,
    recommendation: 'Chained bracket notation (obj["a"]["b"]["c"]) is used to hide method calls. Review the accessed properties.',
  },

  // ============================================
  // Base64 Obfuscation
  // ============================================
  {
    id: 'obfusc-base64-exec',
    severity: 'critical',
    description: 'Base64-decoded content passed to execution function',
    pattern: /(?:atob|base64[_-]?decode|b64decode|Buffer\.from)\s*\([^)]+\).*(?:eval|exec|system|spawn|Function|child_process)/gi,
    recommendation: 'Base64-decoded content being executed is a strong indicator of hidden malicious code.',
  },
  {
    id: 'obfusc-base64-long-inline',
    severity: 'warning',
    description: 'Suspiciously long Base64 string inline (potential encoded payload)',
    pattern: /['"][A-Za-z0-9+/]{100,}={0,2}['"]/g,
    recommendation: 'Very long inline Base64 strings may contain encoded payloads. Decode and inspect.',
  },

  // ============================================
  // Python Obfuscation
  // ============================================
  {
    id: 'obfusc-python-exec-compile',
    severity: 'critical',
    description: 'Python exec/eval with compile() or codecs (obfuscated execution)',
    pattern: /exec\s*\(\s*(?:compile|codecs\.decode|base64\.b64decode|bytes\.fromhex)\s*\(/gi,
    recommendation: 'exec() with encoding/compilation hides malicious code. Decode and review the payload.',
  },
  {
    id: 'obfusc-python-chr-join',
    severity: 'high',
    description: 'Python chr() join pattern (character-by-character string building)',
    pattern: /['"](?:\s*\+\s*)?['"]\.join\s*\(\s*(?:chr|map)\s*\(/gi,
    recommendation: 'Building strings with chr()/map() hides the actual string content. Evaluate and review.',
  },
  {
    id: 'obfusc-python-rot13',
    severity: 'warning',
    description: 'ROT13 encoding detected (simple obfuscation)',
    pattern: /codecs\.decode\s*\([^)]+,\s*['"]rot[_-]?13['"]\s*\)/gi,
    recommendation: 'ROT13 is used to hide string content. Decode and review.',
  },
  {
    id: 'obfusc-python-lambda-chain',
    severity: 'high',
    description: 'Nested lambda chain (obfuscation via functional composition)',
    pattern: /lambda\s+\w+\s*:\s*lambda\s+\w+\s*:\s*lambda/gi,
    recommendation: 'Deeply nested lambdas are used to obfuscate logic. Simplify and review.',
  },

  // ============================================
  // Shell Obfuscation
  // ============================================
  {
    id: 'obfusc-shell-hex-echo',
    severity: 'high',
    description: 'Shell command using hex-encoded echo/printf',
    pattern: /(?:echo|printf)\s+(?:-e\s+)?['"](?:\\x[0-9a-f]{2}){4,}['"]\s*\|\s*(?:bash|sh|zsh|eval)/gi,
    recommendation: 'Hex-encoded strings piped to shell execution hide the actual command. Decode and review.',
  },
  {
    id: 'obfusc-shell-base64-pipe',
    severity: 'critical',
    description: 'Base64-encoded command piped to shell',
    pattern: /(?:echo|printf)\s+['"][A-Za-z0-9+/]{20,}={0,2}['"]\s*\|\s*(?:base64\s+-d|openssl\s+enc)\s*\|\s*(?:bash|sh|zsh)/gi,
    recommendation: 'Base64-encoded shell commands hide malicious payloads. Decode and inspect before execution.',
  },
  {
    id: 'obfusc-shell-variable-substitution',
    severity: 'warning',
    description: 'Shell variable-based command construction (evasion technique)',
    pattern: /\w+=\w;\w+=\w;\w+=\w;.*\$\w\$\w\$\w/g,
    recommendation: 'Building commands from single-character variables evades detection. Review the constructed command.',
  },
  {
    id: 'obfusc-shell-rev-command',
    severity: 'high',
    description: 'Reversed string piped to rev (command obfuscation)',
    pattern: /echo\s+['"][^'"]+['"]\s*\|\s*rev\s*\|\s*(?:bash|sh|eval)/gi,
    recommendation: 'Reversing strings to hide commands. Reverse and review the payload.',
  },

  // ============================================
  // PowerShell Obfuscation
  // ============================================
  {
    id: 'obfusc-powershell-encodedcommand',
    severity: 'critical',
    description: 'PowerShell -EncodedCommand execution',
    pattern: /powershell[^;|]*-(?:e(?:nc(?:odedcommand)?|c(?:ommand)?))\s+[A-Za-z0-9+/=]{20,}/gi,
    recommendation: 'PowerShell -EncodedCommand hides the actual script in Base64. Decode and review.',
  },
  {
    id: 'obfusc-powershell-iex',
    severity: 'high',
    description: 'PowerShell IEX with download (fileless execution)',
    pattern: /(?:IEX|Invoke-Expression)\s*\(\s*(?:\(New-Object\s+Net\.WebClient\)|Invoke-WebRequest|iwr|curl|wget)/gi,
    recommendation: 'IEX with download is a fileless execution technique. Block or review the downloaded content.',
  },
  {
    id: 'obfusc-powershell-concat',
    severity: 'warning',
    description: 'PowerShell string concatenation obfuscation',
    pattern: /(?:\+'[a-z]{1,3}'){4,}|(?:'[a-z]{1,3}'\+){4,}/gi,
    recommendation: 'Excessive string concatenation is used to evade keyword detection. Concatenate and review.',
  },

  // ============================================
  // General Obfuscation Indicators
  // ============================================
  {
    id: 'obfusc-unicode-escape-abuse',
    severity: 'high',
    description: 'Excessive Unicode escape sequences (obfuscated identifiers)',
    pattern: /(?:\\u[0-9a-fA-F]{4}){4,}/g,
    recommendation: 'Long Unicode escape sequences hide actual identifiers. Decode and review.',
  },
  {
    id: 'obfusc-known-tool-signature',
    severity: 'warning',
    description: 'Known JavaScript obfuscator signature detected',
    pattern: /(?:javascript-obfuscator|jsfuck|aaencode|jjencode|_0x[a-f0-9]{4,}\s*=)/gi,
    recommendation: 'Output from known obfuscation tools detected. De-obfuscate and review the source code.',
  },
  {
    id: 'obfusc-jsfuck-pattern',
    severity: 'critical',
    description: 'JSFuck-style encoding detected (code written with []()!+ characters)',
    pattern: /\[\]\[['"][a-z]+['"]\]\[['"][a-z]+['"]\]\s*\(/g,
    recommendation: 'JSFuck encodes JavaScript using only []()!+ characters. This is always suspicious in production code.',
  },
];

// CommonJS compatibility
module.exports = { rules };
