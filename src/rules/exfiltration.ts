import type { Rule } from "../types.js";

/**
 * Data Exfiltration Hardening Rules
 * Extended detection for sophisticated data exfiltration techniques.
 */

export const rules: Rule[] = [
  {
    id: 'exfil-base64-in-url',
    severity: 'high',
    description: 'Base64-encoded data embedded in URL parameters (potential data exfiltration)',
    pattern: /https?:\/\/[^\s"']+[?&][a-zA-Z_]+=(?:[A-Za-z0-9+/]{20,}={0,2})/g,
    recommendation: 'Inspect URLs with long Base64-encoded parameters. This pattern is commonly used to exfiltrate data via URL query strings.',
  },
  {
    id: 'exfil-dns-tunneling',
    severity: 'high',
    description: 'DNS tunneling pattern detected (data exfiltration via DNS queries)',
    pattern: /(?:dig|nslookup|host|drill)\s+[^\n]*(?:\$\{|\$\(|`[^`]*\$)/gi,
    recommendation: 'DNS queries with variable expansion can tunnel data out via DNS. Block dynamic DNS lookups.',
  },
  {
    id: 'exfil-steganography',
    severity: 'high',
    description: 'Steganography tool usage detected (data hidden in images/files)',
    pattern: /(?:steghide\s+(?:embed|extract)|exiftool\s+[^\n]*(?:-[A-Z]+=|--comment)|(?:openstego|stegano|stegosuite|snow)\s|convert\s+[^\n]*(?:-comment|-set\s+comment)|identify\s+-verbose|strings\s+[^\n]*\.(?:png|jpg|jpeg|gif|bmp|tiff))/gi,
    recommendation: 'Steganography tools can hide data in images/files for covert exfiltration. Review and restrict usage.',
  },

  // ============================================
  // Clipboard Theft
  // ============================================
  {
    id: 'exfil-clipboard-read',
    severity: 'critical',
    description: 'Clipboard content read via system tool (potential clipboard theft)',
    // xclip -o / --out = read mode; xclip -i = write mode (excluded)
    pattern: /(?:xclip\s+(?:-o\b|--out\b)|xsel\s+--(?:output|clipboard)\b|pbpaste|Get-Clipboard|powershell[^\n]*Get-Clipboard|wl-paste)/gi,
    recommendation: 'Reading clipboard content is rarely needed in automated agent skills. Verify this is intentional and not stealing clipboard data (passwords, tokens, etc.).',
    category: 'exfiltration',
    cwe: 'CWE-522',
  },
  {
    id: 'exfil-clipboard-js',
    severity: 'high',
    description: 'JavaScript clipboard API read combined with network access (clipboard theft pattern)',
    pattern: /navigator\.clipboard\.readText\s*\(\s*\)[\s\S]{0,300}(?:fetch|axios|http\.request|XMLHttpRequest)/gi,
    recommendation: 'Reading the clipboard then making a network request is a strong indicator of clipboard theft. Review this pattern carefully.',
    category: 'exfiltration',
    cwe: 'CWE-522',
  },

  // ============================================
  // Screen Capture Exfiltration
  // ============================================
  {
    id: 'exfil-screenshot-capture',
    severity: 'high',
    description: 'Screenshot capture tool detected (potential screen data exfiltration)',
    pattern: /(?:scrot\s|import\s+-window|screencapture\s+-[a-z]|gnome-screenshot|xwd\s+-root|spectacle\s+-[a-z]|maim\s|flameshot\s+gui\s+--raw)\s*(?:[^\n]*(?:fetch|curl|wget|upload|send|post)|\$\{|\$\()/gi,
    recommendation: 'Screenshot capture combined with data transmission suggests screen exfiltration. Audit screenshot usage in agent skills.',
    category: 'exfiltration',
    cwe: 'CWE-359',
  },

  // ============================================
  // Time-Delayed Exfiltration (Evasion)
  // ============================================
  {
    id: 'exfil-time-delayed',
    severity: 'high',
    description: 'Network request inside timer callback (time-delayed exfiltration evasion pattern)',
    pattern: /(?:setTimeout|setInterval)\s*\(\s*(?:async\s*)?\(\s*\)\s*=>\s*\{[\s\S]{0,500}(?:fetch|axios\.(?:post|get|put)|http\.request|https\.request|XMLHttpRequest)/gi,
    recommendation: 'Network calls inside setTimeout/setInterval can be used to delay exfiltration and evade detection. Review timer-based network activity in agent skills.',
    category: 'exfiltration',
    cwe: 'CWE-400',
  },

  // ============================================
  // Compress-then-Send (Archive Staging)
  // ============================================
  {
    id: 'exfil-compress-then-send',
    severity: 'high',
    description: 'Archive creation followed by upload (compress-then-exfiltrate pattern)',
    pattern: /(?:tar\s+[cz]+f|zip\s+-[a-z]*r?|gzip\s+-c|7z\s+a|rar\s+a)\s+[^\n]*\n(?:[^\n]*\n){0,10}(?:curl|wget|scp|rsync|aws\s+s3\s+cp|gsutil\s+cp)\s+/gi,
    recommendation: 'Compressing files then uploading them is a common data staging and exfiltration pattern. Verify this transfer is authorized.',
    category: 'exfiltration',
    cwe: 'CWE-212',
  },

  // ============================================
  // Tmpfile Staging (Multi-stage Exfil)
  // ============================================
  {
    id: 'exfil-tmpfile-staging',
    severity: 'high',
    description: 'Sensitive data written to /tmp then transmitted (multi-stage exfiltration)',
    // Matches: write to /tmp path, then within ~500 chars a network call appears
    pattern: /(?:writeFile(?:Sync)?\s*\([^)]*\/tmp\/|fs\.write\s*\([^)]*\/tmp\/|echo\s+[^\n]*>\s*\/tmp\/)[^\n]*[\s\S]{0,500}(?:fetch\s*\(|curl\s+|wget\s+|scp\s+|http\.request\s*\(|https\.request\s*\()/gi,
    recommendation: 'Writing data to /tmp and then transmitting it is a multi-stage exfiltration pattern. Review data flows involving /tmp and external endpoints.',
    category: 'exfiltration',
    cwe: 'CWE-379',
  },

  // ============================================
  // Out-of-Band (OOB) Exfiltration Services
  // Commonly used to capture data from compromised agents
  // ============================================
  {
    id: 'exfil-oob-webhook-site',
    severity: 'critical',
    description: 'Data sent to webhook.site (known OOB data capture service)',
    pattern: /https?:\/\/webhook\.site\/[a-f0-9-]{36}/gi,
    recommendation: 'webhook.site is a public service used to capture arbitrary HTTP requests. Sending data here is almost certainly an exfiltration attempt.',
    category: 'exfiltration',
    cwe: 'CWE-200',
  },
  {
    id: 'exfil-oob-requestbin',
    severity: 'critical',
    description: 'Data sent to RequestBin or similar HTTP inspection service',
    pattern: /https?:\/\/(?:[a-z0-9]+\.)?(?:requestbin\.(?:com|net|io)|hookbin\.com|requestcatcher\.com|beeceptor\.com|mockbin\.org|httpbin\.org\/post|httpie\.io\/run)\//gi,
    recommendation: 'RequestBin-type services capture arbitrary HTTP traffic. These are classic exfiltration endpoints. Reject any skill sending data to these services.',
    category: 'exfiltration',
    cwe: 'CWE-200',
  },
  {
    id: 'exfil-oob-pipedream',
    severity: 'critical',
    description: 'Data sent to Pipedream or similar workflow automation endpoint (OOB exfiltration risk)',
    pattern: /https?:\/\/(?:[a-z0-9]+\.m\.)?pipedream\.net\/[a-zA-Z0-9_-]+/gi,
    recommendation: 'Pipedream endpoints can capture arbitrary HTTP requests. Sending data to these endpoints from an agent skill is a strong indicator of data exfiltration.',
    category: 'exfiltration',
    cwe: 'CWE-200',
  },
  {
    id: 'exfil-oob-interactsh',
    severity: 'critical',
    description: 'Data sent to Interactsh/Burp Collaborator OOB testing endpoint',
    pattern: /https?:\/\/(?:[a-z0-9]+\.)?(?:oastify\.com|interactsh\.com|burpcollaborator\.net|canarytokens\.(?:com|org))\//gi,
    recommendation: 'Interactsh and Burp Collaborator endpoints are security testing tools for OOB exfiltration detection. Their presence in a skill is highly suspicious.',
    category: 'exfiltration',
    cwe: 'CWE-200',
  },
  {
    id: 'exfil-oob-tunnel',
    severity: 'high',
    description: 'Public tunnel service used (potential covert channel for exfiltration)',
    pattern: /https?:\/\/[a-z0-9-]+\.(?:ngrok\.(?:io|app)|serveo\.net|loca\.lt|localtunnel\.me|pagekite\.me|localhost\.run)\b/gi,
    recommendation: 'Tunnel services (ngrok, serveo, etc.) expose internal services publicly. When used inside an agent skill, they can create covert exfiltration channels.',
    category: 'exfiltration',
    cwe: 'CWE-200',
  },

  // ============================================
  // Sensitive Dotfile / Credential File Access
  // Based on real attack: weather skill exfiltrated ~/.clawdbot/.env
  // ============================================
  {
    id: 'exfil-dotenv-read',
    severity: 'critical',
    description: 'Reading sensitive dotfile or credential file (e.g., ~/.clawdbot/.env, ~/.env)',
    pattern: /(?:readFile(?:Sync)?\s*\([^)]*|cat\s+|open\s*\([^)]*)['"~]?(?:\/root|\/home\/[^/]+)?\/?\.(?:clawdbot|config\/openclaw|ssh\/(?:id_rsa|id_ed25519)|aws\/credentials|gnupg\/|netrc|npmrc|pypirc|docker\/config\.json|kube\/|gcloud\/application_default_credentials\.json)[^'")\s]*/gi,
    recommendation: 'Accessing sensitive dotfiles (SSH keys, cloud credentials, .env files) is a critical red flag. This is how the credential-stealer weather skill operated. Block immediately.',
    category: 'exfiltration',
    cwe: 'CWE-522',
  },
  {
    id: 'exfil-env-file-read',
    severity: 'critical',
    description: 'Agent skill reads .env file (potential API key theft)',
    // Match file read ops where the quoted path ends with .env (with or without directory prefix)
    pattern: /(?:readFile(?:Sync)?\s*\(\s*['"]|cat\s+['"]?|open\s*\(\s*['"])[^'")\n]{0,120}\.env['")\s]/gi,
    recommendation: 'Reading .env files steals API keys and credentials. Unless this is a legitimate env loader, treat as malicious. Verify the skill\'s declared purpose.',
    category: 'exfiltration',
    cwe: 'CWE-522',
  },
];

// CommonJS compatibility
module.exports = { rules };
