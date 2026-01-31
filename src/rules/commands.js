/**
 * Dangerous Command Detection Rules
 * Detects potentially dangerous shell commands and code patterns
 */

const rules = [
  {
    id: 'command-rm-rf',
    severity: 'warning',
    description: 'Dangerous rm -rf command with root or home path',
    pattern: /rm\s+(?:-[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*|-[a-zA-Z]*f[a-zA-Z]*r[a-zA-Z]*)\s+[\/~]/g,
    recommendation: 'Avoid recursive force delete on system paths. Use safer alternatives like trash-cli.',
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
    id: 'command-eval',
    severity: 'warning',
    description: 'Use of eval() detected',
    pattern: /\beval\s*\([^)]*[\$`]/g,
    recommendation: 'Avoid eval() with dynamic input. It can lead to code injection.',
  },
  {
    id: 'command-exec-variable',
    severity: 'warning',
    description: 'exec() with variable input detected',
    pattern: /\bexec\s*\([^)]*[\$`{]/g,
    recommendation: 'Sanitize input before passing to exec(). Consider using safer alternatives.',
  },
  {
    id: 'command-chmod-777',
    severity: 'warning',
    description: 'chmod 777 (world-writable) detected',
    pattern: /chmod\s+(?:777|\+rwx|a\+rwx)/g,
    recommendation: 'Avoid world-writable permissions. Use minimal required permissions.',
  },
  {
    id: 'command-sudo-nopasswd',
    severity: 'critical',
    description: 'NOPASSWD sudo configuration detected',
    pattern: /NOPASSWD/g,
    recommendation: 'Avoid NOPASSWD in sudo configurations. Require password for security.',
  },
  {
    id: 'command-base64-decode',
    severity: 'info',
    description: 'Base64 decode piped to execution',
    pattern: /base64\s+(?:-d|--decode)[^|]*\|\s*(?:ba)?sh/gi,
    recommendation: 'Review base64-encoded content before execution. This is often used to obfuscate malicious code.',
  },
  {
    id: 'command-python-exec',
    severity: 'warning',
    description: 'Python exec() or compile() with dynamic input',
    pattern: /(?:exec|compile)\s*\([^)]*(?:input|request|argv|environ)/gi,
    recommendation: 'Avoid executing dynamic code from user input.',
  },
  {
    id: 'command-shell-injection',
    severity: 'warning',
    description: 'Potential shell injection pattern',
    pattern: /(?:subprocess|os\.system|os\.popen|commands\.getoutput)\s*\([^)]*(?:\+|%|format|f['"])/gi,
    recommendation: 'Use parameterized commands or shlex.quote() to prevent shell injection.',
  },
];

module.exports = { rules };
