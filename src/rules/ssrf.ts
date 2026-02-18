import type { Rule } from "../types.js";

/**
 * SSRF (Server-Side Request Forgery) Detection Rules
 * Detects patterns where user-controlled input flows into URL requests,
 * internal service access, and cloud metadata endpoint abuse.
 */

export const rules: Rule[] = [
  // ============================================
  // Cloud Metadata Endpoint Access (SSRF Target)
  // ============================================
  {
    id: 'ssrf-aws-metadata',
    severity: 'critical',
    description: 'AWS metadata endpoint access (SSRF target)',
    pattern: /169\.254\.169\.254|metadata\.google\.internal|metadata\.azure\.com/gi,
    recommendation: 'Cloud metadata endpoints are primary SSRF targets. Block access to 169.254.169.254 from application code. Use IMDSv2 on AWS.',
    category: 'ssrf',
    cwe: 'CWE-918',
  },
  {
    id: 'ssrf-aws-metadata-v1',
    severity: 'critical',
    description: 'AWS IMDSv1 metadata access (no token required)',
    pattern: /curl\s+[^\n]*169\.254\.169\.254(?!.*X-aws-ec2-metadata-token)/gi,
    recommendation: 'IMDSv1 requires no authentication. Migrate to IMDSv2 which requires a session token.',
    category: 'ssrf',
    cwe: 'CWE-918',
  },

  // ============================================
  // URL Construction from User Input
  // ============================================
  {
    id: 'ssrf-url-from-param',
    severity: 'high',
    description: 'URL constructed from request parameter (potential SSRF)',
    pattern: /(?:fetch|axios|http\.(?:get|request)|got|ky|urllib\.request\.urlopen|requests\.(?:get|post|put|head))\s*\(\s*(?:req\.(?:query|params|body)|request\.(?:args|form|json))\[?[.\['"]/gi,
    recommendation: 'Never pass user input directly to HTTP request functions. Validate URLs against an allowlist of domains.',
    category: 'ssrf',
    cwe: 'CWE-918',
  },
  {
    id: 'ssrf-url-concat',
    severity: 'high',
    description: 'URL built by concatenating user input',
    pattern: /(?:fetch|axios|got|requests\.get)\s*\(\s*['"`]https?:\/\/['"`]\s*\+\s*(?:req|request|params|query|input|user)/gi,
    recommendation: 'URL construction from user input enables SSRF. Use URL validation and domain allowlists.',
    category: 'ssrf',
    cwe: 'CWE-918',
  },
  {
    id: 'ssrf-template-url',
    severity: 'high',
    description: 'URL template with user-controlled variable',
    pattern: /(?:fetch|axios|got|requests\.get)\s*\(\s*`https?:\/\/\$\{(?:req|request|params|query|input|user)/gi,
    recommendation: 'Template literal URLs with user input enable SSRF. Validate the full URL before making requests.',
    category: 'ssrf',
    cwe: 'CWE-918',
  },
  {
    id: 'ssrf-python-fstring-url',
    severity: 'high',
    description: 'Python f-string URL with user input',
    pattern: /requests\.(?:get|post|put|head)\s*\(\s*f['"]https?:\/\/\{(?:request|params|args|user_input)/gi,
    recommendation: 'f-string URLs with user input enable SSRF. Validate URLs against domain allowlists.',
    category: 'ssrf',
    cwe: 'CWE-918',
  },

  // ============================================
  // Internal Network Access Patterns
  // ============================================
  {
    id: 'ssrf-internal-ip-fetch',
    severity: 'high',
    description: 'HTTP request to internal/private IP address',
    pattern: /(?:fetch|axios|got|requests\.get|http\.request|urllib)\s*\(\s*['"`]https?:\/\/(?:10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.|127\.0\.0|0\.0\.0\.0|localhost)/gi,
    recommendation: 'Requests to internal IPs may indicate SSRF. Ensure this is intentional and not user-controlled.',
    category: 'ssrf',
    cwe: 'CWE-918',
  },
  {
    id: 'ssrf-redirect-follow',
    severity: 'warning',
    description: 'HTTP request with redirect following enabled (SSRF bypass)',
    pattern: /(?:followRedirects?\s*:\s*true|maxRedirects\s*:\s*[1-9]|allow_redirects\s*=\s*True)/gi,
    recommendation: 'Following redirects can bypass SSRF protections. Disable redirects or validate each redirect URL.',
    category: 'ssrf',
    cwe: 'CWE-918',
  },

  // ============================================
  // DNS Rebinding & Protocol Smuggling
  // ============================================
  {
    id: 'ssrf-dns-rebinding-risk',
    severity: 'warning',
    description: 'URL resolved then fetched separately (DNS rebinding risk)',
    pattern: /dns\.(?:resolve|lookup)\s*\([^)]*\)[\s\S]{0,200}(?:fetch|axios|http\.request|got)\s*\(/gi,
    recommendation: 'DNS resolution followed by HTTP request is vulnerable to DNS rebinding. Resolve and fetch atomically or pin the IP.',
    category: 'ssrf',
    cwe: 'CWE-350',
  },
  {
    id: 'ssrf-gopher-protocol',
    severity: 'critical',
    description: 'Gopher protocol URL (SSRF protocol smuggling)',
    pattern: /gopher:\/\//gi,
    recommendation: 'Gopher protocol can be used for SSRF protocol smuggling against Redis, Memcached, etc. Block non-HTTP protocols.',
    category: 'ssrf',
    cwe: 'CWE-918',
  },
  {
    id: 'ssrf-file-protocol',
    severity: 'high',
    description: 'File protocol in URL (local file access via SSRF)',
    pattern: /(?:fetch|axios|got|urllib|requests)\s*\(\s*['"`]file:\/\//gi,
    recommendation: 'file:// protocol can read local files. Block non-HTTP protocols in URL inputs.',
    category: 'ssrf',
    cwe: 'CWE-918',
  },
  {
    id: 'ssrf-dict-protocol',
    severity: 'high',
    description: 'Dict protocol URL (SSRF protocol smuggling)',
    pattern: /dict:\/\//gi,
    recommendation: 'Dict protocol can be used for port scanning and protocol smuggling. Block non-HTTP protocols.',
    category: 'ssrf',
    cwe: 'CWE-918',
  },

  // ============================================
  // Image/PDF/Webhook URL Processing
  // ============================================
  {
    id: 'ssrf-image-url-fetch',
    severity: 'warning',
    description: 'Image URL fetched from user input (common SSRF vector)',
    pattern: /(?:imageUrl|image_url|avatarUrl|avatar_url|profileImage|logo_url|icon_url|thumbnail_url)\s*(?:=|:)\s*(?:req|request|params|body|input)/gi,
    recommendation: 'Image URL processing is a common SSRF vector. Validate URLs, restrict to HTTPS, and use domain allowlists.',
    category: 'ssrf',
    cwe: 'CWE-918',
  },
  {
    id: 'ssrf-webhook-url',
    severity: 'warning',
    description: 'User-supplied webhook URL (outbound SSRF)',
    pattern: /(?:webhookUrl|webhook_url|callbackUrl|callback_url|notify_url)\s*(?:=|:)\s*(?:req|request|params|body|input)/gi,
    recommendation: 'User-supplied webhook URLs can target internal services. Validate against domain allowlists and block private IPs.',
    category: 'ssrf',
    cwe: 'CWE-918',
  },
];

// CommonJS compatibility
module.exports = { rules };
