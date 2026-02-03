import type { Rule } from "../types.js";

/**
 * Dangerous Command and Code Pattern Detection Rules
 * Detects potentially dangerous shell commands, code patterns, and security issues
 */

export const rules: Rule[] = [
  // ============================================
  // Dangerous Shell Commands
  // ============================================
  {
    id: 'command-rm-rf',
    severity: 'critical',
    description: 'Dangerous rm -rf command with root or home path',
    pattern: /rm\s+(?:-[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*|-[a-zA-Z]*f[a-zA-Z]*r[a-zA-Z]*)\s+[\/~\$]/g,
    recommendation: 'Avoid recursive force delete on system paths. Use safer alternatives like trash-cli.',
  },
  {
    id: 'command-rm-system',
    severity: 'critical',
    description: 'Deletion of system directories',
    pattern: /rm\s+[^#\n]*(?:\/bin|\/sbin|\/usr|\/etc|\/var|\/boot|\/lib)/g,
    recommendation: 'Never delete system directories.',
  },
  {
    id: 'command-curl-bash',
    severity: 'critical',
    description: 'Curl piped to shell execution detected',
    pattern: /curl\s+[^|]*\|\s*(?:ba)?sh/gi,
    recommendation: 'Download scripts first, review them, then execute. Never pipe directly to shell.',
  },
  {
    id: 'command-wget-bash',
    severity: 'critical',
    description: 'Wget piped to shell execution detected',
    pattern: /wget\s+[^|]*\|\s*(?:ba)?sh/gi,
    recommendation: 'Download scripts first, review them, then execute.',
  },
  {
    id: 'command-chmod-777',
    severity: 'warning',
    description: 'chmod 777 (world-writable) detected',
    pattern: /chmod\s+(?:777|\+rwx|a\+rwx|-R\s+777)/g,
    recommendation: 'Avoid world-writable permissions. Use minimal required permissions.',
  },
  {
    id: 'command-chmod-setuid',
    severity: 'critical',
    description: 'SetUID/SetGID permission change',
    pattern: /chmod\s+[^#\n]*[4267][0-7]{3}|chmod\s+[^#\n]*[ug]\+s/g,
    recommendation: 'SetUID/SetGID is dangerous. Review necessity carefully.',
  },
  {
    id: 'command-sudo-nopasswd',
    severity: 'critical',
    description: 'NOPASSWD sudo configuration detected',
    pattern: /NOPASSWD/g,
    recommendation: 'Avoid NOPASSWD in sudo configurations. Require password for security.',
  },
  {
    id: 'command-dd-disk',
    severity: 'critical',
    description: 'dd command writing to disk device',
    pattern: /dd\s+[^#\n]*of=\/dev\/(?:sd|hd|nvme|vd)/g,
    recommendation: 'dd to disk devices can cause data loss. Verify target carefully.',
  },
  {
    id: 'command-mkfs',
    severity: 'critical',
    description: 'Filesystem format command detected',
    pattern: /mkfs(?:\.[a-z0-9]+)?\s+\/dev\//g,
    recommendation: 'Filesystem formatting will destroy data. Verify necessity.',
  },

  // ============================================
  // Shell Injection Patterns
  // ============================================
  {
    id: 'command-shell-injection-js',
    severity: 'critical',
    description: 'Potential shell injection in JavaScript',
    pattern: /(?:exec|execSync|spawn|spawnSync)\s*\([^)]*(?:\$\{|` ?\$|\+ *(?:req|user|input|param))/gi,
    recommendation: 'Sanitize user input before shell execution. Use parameterized commands.',
  },
  {
    id: 'command-shell-injection-py',
    severity: 'critical',
    description: 'Potential shell injection in Python',
    pattern: /(?:subprocess|os\.system|os\.popen|commands\.getoutput)\s*\([^)]*(?:\+|%|\.format|f['"])/gi,
    recommendation: 'Use subprocess with list arguments and shell=False.',
  },
  {
    id: 'command-backtick-injection',
    severity: 'warning',
    description: 'Command substitution with user input',
    pattern: /`[^`]*\$\{?(?:req|user|input|param|query)/gi,
    recommendation: 'Avoid command substitution with user input.',
  },

  // ============================================
  // Code Execution
  // ============================================
  {
    id: 'command-eval-js',
    severity: 'warning',
    description: 'Use of eval() with dynamic input',
    pattern: /\beval\s*\([^)]*(?:\$|req\.|user|input|param|query)/gi,
    recommendation: 'Avoid eval() with user input. It enables code injection.',
  },
  {
    id: 'command-function-constructor',
    severity: 'warning',
    description: 'Function constructor with dynamic input',
    pattern: /new\s+Function\s*\([^)]*(?:\$|req\.|user|input)/gi,
    recommendation: 'Avoid Function constructor with user input.',
  },
  {
    id: 'command-python-exec',
    severity: 'warning',
    description: 'Python exec() or compile() with dynamic input',
    pattern: /(?:exec|compile)\s*\([^)]*(?:input|request|argv|environ|open)/gi,
    recommendation: 'Avoid executing dynamic code from user input.',
  },
  {
    id: 'command-python-pickle',
    severity: 'warning',
    description: 'Pickle deserialization detected',
    pattern: /pickle\.(?:load|loads)\s*\(/g,
    recommendation: 'Pickle deserialization is unsafe with untrusted data. Use JSON instead.',
  },
  {
    id: 'command-base64-exec',
    severity: 'critical',
    description: 'Base64 decode piped to execution',
    pattern: /base64\s+(?:-d|--decode)[^|]*\|\s*(?:ba)?sh/gi,
    recommendation: 'Review base64-encoded content before execution.',
  },
  {
    id: 'command-vm-runin',
    severity: 'warning',
    description: 'Node.js vm module with untrusted code',
    pattern: /vm\.(?:runInContext|runInNewContext|runInThisContext|Script)\s*\(/g,
    recommendation: 'vm module is not a security sandbox. Do not use with untrusted code.',
  },

  // ============================================
  // SQL Injection
  // ============================================
  {
    id: 'command-sql-injection',
    severity: 'critical',
    description: 'Potential SQL injection pattern',
    pattern: /(?:query|execute)\s*\([^)]*(?:\+|`|\$\{)[^)]*(?:SELECT|INSERT|UPDATE|DELETE|DROP)/gi,
    recommendation: 'Use parameterized queries to prevent SQL injection.',
  },
  {
    id: 'command-sql-string-concat',
    severity: 'warning',
    description: 'SQL string concatenation',
    pattern: /["'](?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)[^"']*["']\s*\+/gi,
    recommendation: 'Avoid string concatenation in SQL. Use parameterized queries.',
  },
  {
    id: 'command-nosql-injection',
    severity: 'warning',
    description: 'Potential NoSQL injection pattern',
    pattern: /\$(?:where|regex|ne|gt|lt|gte|lte|in|nin|or|and)\s*:/gi,
    recommendation: 'Sanitize MongoDB query operators from user input.',
  },

  // ============================================
  // XSS Patterns
  // ============================================
  {
    id: 'command-xss-innerhtml',
    severity: 'warning',
    description: 'innerHTML with user input',
    pattern: /\.innerHTML\s*=\s*(?:.*(?:req|user|input|param|query)|`)/gi,
    recommendation: 'Use textContent or sanitize HTML to prevent XSS.',
  },
  {
    id: 'command-xss-document-write',
    severity: 'warning',
    description: 'document.write with dynamic content',
    pattern: /document\.write\s*\([^)]*(?:\+|`|\$\{)/gi,
    recommendation: 'Avoid document.write with dynamic content.',
  },
  {
    id: 'command-xss-dangerously-set',
    severity: 'warning',
    description: 'React dangerouslySetInnerHTML',
    pattern: /dangerouslySetInnerHTML\s*=\s*\{\s*\{/g,
    recommendation: 'Sanitize content before using dangerouslySetInnerHTML.',
  },

  // ============================================
  // Path Traversal
  // ============================================
  {
    id: 'command-path-traversal',
    severity: 'warning',
    description: 'Potential path traversal pattern',
    pattern: /(?:readFile|createReadStream|open|include|require)\s*\([^)]*(?:\+|`|\$\{)[^)]*(?:\.\.\/|\.\.\\)/gi,
    recommendation: 'Validate and sanitize file paths to prevent directory traversal.',
  },
  {
    id: 'command-hardcoded-path',
    severity: 'info',
    description: 'Hardcoded sensitive path',
    pattern: /["'](?:\/etc\/(?:passwd|shadow|hosts|sudoers)|\/root\/|C:\\Windows\\System32)/g,
    recommendation: 'Avoid hardcoding sensitive system paths.',
  },

  // ============================================
  // Network Security
  // ============================================
  {
    id: 'command-disable-ssl',
    severity: 'critical',
    description: 'SSL/TLS verification disabled',
    pattern: /(?:verify\s*=\s*False|rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0)/gi,
    recommendation: 'Never disable SSL/TLS verification in production.',
  },
  {
    id: 'command-insecure-http',
    severity: 'warning',
    description: 'Insecure HTTP request with credentials',
    pattern: /http:\/\/[^\/]*(?:@|:.*@|token=|key=|password=)/gi,
    recommendation: 'Use HTTPS for requests containing credentials.',
  },
  {
    id: 'command-ssrf-pattern',
    severity: 'warning',
    description: 'Potential SSRF pattern',
    pattern: /(?:fetch|axios|request|http\.get)\s*\([^)]*(?:req\.|user\.|param|query)/gi,
    recommendation: 'Validate and whitelist URLs to prevent SSRF.',
  },

  // ============================================
  // Insecure Randomness
  // ============================================
  {
    id: 'command-math-random',
    severity: 'warning',
    description: 'Math.random() used for security',
    pattern: /Math\.random\s*\(\s*\)[^;]*(?:token|secret|key|password|salt|nonce|iv)/gi,
    recommendation: 'Use crypto.randomBytes() for security-sensitive randomness.',
  },
  {
    id: 'command-weak-random-py',
    severity: 'warning',
    description: 'Python random module used for security',
    pattern: /random\.(?:random|randint|choice)\s*\([^)]*\)[^;]*(?:token|secret|key|password)/gi,
    recommendation: 'Use secrets module for security-sensitive randomness.',
  },

  // ============================================
  // Cryptography Issues
  // ============================================
  {
    id: 'command-weak-crypto',
    severity: 'warning',
    description: 'Weak cryptographic algorithm',
    // Use word boundaries to avoid matching "des" in "description"
    pattern: /\b(?:MD5|SHA-?1|DES|RC4|3DES|Triple-?DES)\b|createCipher\(/gi,
    recommendation: 'Use modern algorithms: SHA-256+, AES-256-GCM, etc.',
  },
  {
    id: 'command-hardcoded-iv',
    severity: 'critical',
    description: 'Hardcoded initialization vector',
    pattern: /(?:iv|IV|nonce)\s*[:=]\s*["'][a-fA-F0-9]{16,}["']/g,
    recommendation: 'Generate random IVs for each encryption operation.',
  },
  {
    id: 'command-ecb-mode',
    severity: 'warning',
    description: 'ECB encryption mode detected',
    pattern: /(?:AES|DES).*ECB|ECB.*(?:AES|DES)|MODE_ECB/gi,
    recommendation: 'ECB mode is insecure. Use CBC, GCM, or CTR mode.',
  },

  // ============================================
  // Deserialization
  // ============================================
  {
    id: 'command-yaml-load',
    severity: 'warning',
    description: 'Unsafe YAML load',
    pattern: /yaml\.load\s*\([^)]*\)(?!\s*,\s*Loader)/g,
    recommendation: 'Use yaml.safe_load() to prevent code execution.',
  },
  {
    id: 'command-json-parse-eval',
    severity: 'warning',
    description: 'JSON parsing with eval',
    pattern: /eval\s*\([^)]*JSON/gi,
    recommendation: 'Use JSON.parse() instead of eval for JSON.',
  },

  // ============================================
  // Reverse Shell Patterns
  // ============================================
  {
    id: 'command-reverse-shell',
    severity: 'critical',
    description: 'Potential reverse shell pattern',
    pattern: /(?:\/dev\/tcp\/|nc\s+-[a-z]*e|bash\s+-i\s+>&|python.*socket.*connect|php\s+-r.*fsockopen)/gi,
    recommendation: 'Remove reverse shell code patterns.',
  },
  {
    id: 'command-netcat-shell',
    severity: 'critical',
    description: 'Netcat shell command',
    pattern: /nc\s+(?:-[a-z]+\s+)*(?:\d{1,3}\.){3}\d{1,3}\s+\d+\s*(?:-e|<|>|\|)/gi,
    recommendation: 'Review netcat usage for potential backdoor.',
  },

  // ============================================
  // Other Dangerous Patterns
  // ============================================
  {
    id: 'command-format-string',
    severity: 'warning',
    description: 'Format string vulnerability pattern',
    pattern: /printf\s*\([^,)]*(?:argv|user|input|param|query)/gi,
    recommendation: 'Use format specifiers, not user input as format string.',
  },
  {
    id: 'command-unvalidated-redirect',
    severity: 'warning',
    description: 'Unvalidated redirect pattern',
    pattern: /(?:redirect|location\.href|window\.location)\s*=\s*(?:req\.|user\.|param|query)/gi,
    recommendation: 'Validate redirect URLs against a whitelist.',
  },
  {
    id: 'command-debug-enabled',
    severity: 'warning',
    description: 'Debug mode enabled',
    pattern: /(?:DEBUG\s*=\s*True|debug:\s*true|\.enableDebug\(\))/gi,
    recommendation: 'Disable debug mode in production.',
  },

  // ============================================
  // Obfuscation Detection
  // ============================================
  {
    id: 'obfuscation-eval-base64',
    severity: 'critical',
    description: 'Base64 decoded string passed to eval',
    pattern: /eval\s*\(\s*(?:atob|Buffer\.from|base64[_-]?decode)\s*\(/gi,
    recommendation: 'Remove obfuscated code execution. Review the decoded content.',
  },
  {
    id: 'obfuscation-fromcharcode',
    severity: 'critical',
    description: 'String.fromCharCode obfuscation detected',
    pattern: /String\.fromCharCode\s*\(\s*(?:\d+\s*,?\s*){5,}/gi,
    recommendation: 'Remove character code obfuscation. Review the decoded content.',
  },
  {
    id: 'obfuscation-hex-escape',
    severity: 'warning',
    description: 'Heavy hex escape sequence usage',
    pattern: /(?:\\x[0-9a-f]{2}){10,}/gi,
    recommendation: 'Review hex-escaped strings for hidden content.',
  },
  {
    id: 'obfuscation-unicode-escape',
    severity: 'warning',
    description: 'Heavy unicode escape sequence usage',
    pattern: /(?:\\u[0-9a-f]{4}){10,}/gi,
    recommendation: 'Review unicode-escaped strings for hidden content.',
  },
  {
    id: 'obfuscation-constructor-call',
    severity: 'critical',
    description: 'Function constructor for code execution',
    pattern: /(?:new\s+)?Function\s*\(\s*['"`][\s\S]*?['"`]\s*\)/gi,
    recommendation: 'Avoid dynamic function construction. Use static code.',
  },
  {
    id: 'obfuscation-array-reverse',
    severity: 'warning',
    description: 'Reversed string obfuscation',
    pattern: /\.split\s*\(\s*['"`]['"`]\s*\)\s*\.reverse\s*\(\s*\)\s*\.join/gi,
    recommendation: 'Review reversed string patterns for hidden content.',
  },
  {
    id: 'obfuscation-bracket-notation',
    severity: 'warning',
    description: 'Heavy bracket notation (potential obfuscation)',
    pattern: /(?:\[['"]\w+['"]\]){5,}/g,
    recommendation: 'Review bracket notation for obfuscation.',
  },
  {
    id: 'obfuscation-packed-code',
    severity: 'critical',
    description: 'Packed/minified obfuscated code pattern',
    pattern: /eval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e\s*,/gi,
    recommendation: 'Remove packed/obfuscated code. Use unpacked source.',
  },
  {
    id: 'obfuscation-jsfuck',
    severity: 'critical',
    description: 'JSFuck-style obfuscation detected',
    pattern: /\(\s*!\s*\[\s*\]\s*\+\s*\[\s*\]\s*\)|(\[\s*\]\s*\[\s*['"!+\[\]]+\s*\])/g,
    recommendation: 'Remove JSFuck obfuscation. Review the decoded content.',
  },
  {
    id: 'obfuscation-concat-split',
    severity: 'warning',
    description: 'Concatenation/split obfuscation pattern',
    pattern: /(?:['"`][a-z]['"`]\s*\+\s*){10,}/gi,
    recommendation: 'Review character-by-character concatenation for hidden strings.',
  },
  {
    id: 'obfuscation-computed-property',
    severity: 'warning',
    description: 'Computed property access for obfuscation',
    pattern: /\w+\[\s*['"`](?:e|ev|eva|eval|exe|exec)['"]+\s*\+/gi,
    recommendation: 'Review computed property access for hidden function calls.',
  },
  {
    id: 'obfuscation-base64-long',
    severity: 'warning',
    description: 'Long Base64 string (potential encoded payload)',
    pattern: /['"`][A-Za-z0-9+\/=]{100,}['"`]/g,
    recommendation: 'Review long Base64 strings. Decode and inspect content.',
  },
  {
    id: 'obfuscation-double-encoding',
    severity: 'warning',
    description: 'Double URL encoding detected',
    pattern: /%25[0-9a-f]{2}/gi,
    recommendation: 'Review double-encoded strings for bypass attempts.',
  },
];


// CommonJS compatibility
module.exports = { rules };
