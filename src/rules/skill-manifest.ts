import type { Rule } from "../types.js";

/**
 * SKILL.md Permission Declaration Analysis Rules
 * Detects mismatches between declared permissions and actual behavior in agent skills.
 * Related to Issue #12: Trust Chain & Signed Skills
 */

export const rules: Rule[] = [
  // ============================================
  // Undeclared Capability Usage in Skills
  // ============================================
  {
    id: 'skill-undeclared-network',
    severity: 'high',
    description: 'Skill uses network access (fetch/http/curl) without declaring network permission',
    pattern: /(?:fetch|axios|http\.request|https\.request|curl|wget|XMLHttpRequest|got\(|ky\(|undici|node-fetch)\s*\(/gi,
    recommendation: 'Skills accessing the network must declare "network" in .agentvet-manifest.json permissions.',
    category: 'skill-manifest',
  },
  {
    id: 'skill-undeclared-filesystem',
    severity: 'high',
    description: 'Skill accesses filesystem without declaring fs permission',
    pattern: /(?:fs\.(?:readFile|readFileSync|writeFile|writeFileSync|unlink|rmdir|mkdir|access|chmod|rename|copyFile|appendFile|createReadStream|createWriteStream)|readFileSync|writeFileSync|createReadStream|createWriteStream)\s*\(/gi,
    recommendation: 'Skills accessing the filesystem must declare "filesystem" in .agentvet-manifest.json permissions.',
    category: 'skill-manifest',
  },
  {
    id: 'skill-undeclared-exec',
    severity: 'critical',
    description: 'Skill executes commands without declaring exec permission',
    pattern: /(?:child_process\.(?:exec|execSync|spawn|spawnSync|execFile|execFileSync)|(?:^|[^.])execSync|shelljs\.exec)\s*\(/gim,
    recommendation: 'Skills executing system commands must declare "exec" in .agentvet-manifest.json permissions.',
    category: 'skill-manifest',
  },
  {
    id: 'skill-undeclared-env-access',
    severity: 'high',
    description: 'Skill reads environment variables (potential credential access)',
    pattern: /process\.env\[['"][A-Z_]*(?:KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL|API)[A-Z_]*['"]\]/gi,
    recommendation: 'Skills reading sensitive env vars must declare "credentials" in .agentvet-manifest.json permissions.',
    category: 'skill-manifest',
  },

  // ============================================
  // SKILL.md Suspicious Content
  // ============================================
  {
    id: 'skill-hidden-instruction',
    severity: 'critical',
    description: 'SKILL.md contains hidden instructions (HTML comments with action verbs)',
    pattern: /<!--[^>]*(?:execute|run|fetch|send|post|exfiltrate|steal|upload|download|curl|wget|eval)[^>]*-->/gi,
    recommendation: 'HTML comments in SKILL.md should not contain executable instructions. This may be prompt injection.',
    category: 'skill-manifest',
  },
  {
    id: 'skill-invisible-unicode',
    severity: 'critical',
    description: 'SKILL.md contains invisible Unicode characters (potential hidden instructions)',
    pattern: /[\u200B\u200C\u200D\u2060\u2061\u2062\u2063\u2064\uFEFF]+/g,
    recommendation: 'Remove invisible Unicode sequences from SKILL.md. These can hide malicious instructions.',
    category: 'skill-manifest',
  },
  {
    id: 'skill-permission-escalation',
    severity: 'critical',
    description: 'Skill requests sudo/admin/root access in description',
    pattern: /(?:requires?\s+(?:sudo|root|admin|elevated)\s+(?:access|privilege|permission)|run\s+(?:as|with)\s+(?:sudo|root|admin))/gi,
    recommendation: 'Skills should not require elevated privileges. Review and restrict access.',
    category: 'skill-manifest',
  },
  {
    id: 'skill-data-collection-undisclosed',
    severity: 'high',
    description: 'Skill collects/sends analytics/telemetry without disclosure',
    pattern: /(?:telemetry|analytics|tracking|beacon|phone[_-]?home)\s*[=:(]/gi,
    recommendation: 'Skills that collect telemetry or analytics must disclose this in their manifest.',
    category: 'skill-manifest',
  },

  // ============================================
  // Manifest File Validation
  // ============================================
  {
    id: 'manifest-wildcard-permission',
    severity: 'critical',
    description: 'Manifest declares wildcard (*) permission',
    pattern: /["']permissions["']\s*:\s*\[?\s*["']\*["']/gi,
    recommendation: 'Never grant wildcard permissions. Declare specific required permissions.',
    category: 'skill-manifest',
  },
  {
    id: 'manifest-all-access',
    severity: 'high',
    description: 'Manifest declares overly broad access scope',
    pattern: /["'](?:scope|access)["']\s*:\s*["'](?:all|full|unrestricted|any)["']/gi,
    recommendation: 'Use least-privilege access scoping. Avoid "all" or "full" access declarations.',
    category: 'skill-manifest',
  },

  // ============================================
  // Code Obfuscation in Skills
  // ============================================
  {
    id: 'skill-eval-obfuscation',
    severity: 'critical',
    description: 'Skill uses eval() with base64-decoded payload (code obfuscation / malicious loader pattern)',
    pattern: /eval\s*\(\s*(?:atob|Buffer\.from)\s*\(/gi,
    recommendation: 'eval(atob(...)) or eval(Buffer.from(..., "base64")) is a strong indicator of obfuscated malicious code. Remove immediately.',
    category: 'skill-manifest',
  },
  {
    id: 'skill-dynamic-require',
    severity: 'high',
    description: 'Skill uses dynamic require/import with a variable path (can load arbitrary modules at runtime)',
    pattern: /(?:require|import)\s*\(\s*(?!['"`])[^)]{1,80}\)/gi,
    recommendation: 'Dynamic require/import with non-literal paths can load malicious modules. Use static imports only.',
    category: 'skill-manifest',
  },

  // ============================================
  // Trust Chain Tampering
  // ============================================
  {
    id: 'skill-signature-bypass',
    severity: 'critical',
    description: 'Attempt to bypass or disable skill signature verification',
    pattern: /(?:skip|bypass|disable|ignore|no)[_-]?(?:signature|verify|verification|signing|integrity)[_-]?(?:check)?/gi,
    recommendation: 'Do not disable signature verification. This compromises the trust chain.',
    category: 'skill-manifest',
  },
  {
    id: 'skill-modified-after-audit',
    severity: 'high',
    description: 'Skill references modifying itself after audit/review',
    pattern: /(?:self[_-]?modify|auto[_-]?update|hot[_-]?patch|dynamic[_-]?load)\s*(?:after|post)[_\s-]?(?:audit|review|sign)/gi,
    recommendation: 'Skills should not self-modify after being audited. This breaks the trust chain.',
    category: 'skill-manifest',
  },

  // ============================================
  // Agent Credential Path Access (Issue #12 — eudaemon_0 research)
  // Detects access to well-known AI agent config/credential directories.
  // These are high-value targets for credential theft skills.
  // ============================================
  {
    id: 'skill-agent-config-read',
    severity: 'high',
    description: 'Skill accesses known AI agent config/credential path (OpenClaw, Claude, Cursor, etc.)',
    pattern: /(?:readFile|readFileSync|fs\.open|cat\s|open\s*\()\s*['"` ]?.*(?:\.clawdbot[/\\]|\.config[/\\]openclaw[/\\]|claude_desktop_config|\.cursor[/\\]mcp|\.continue[/\\]|\.codeium[/\\]|openai[/\\]credentials|anthropic[/\\]credentials)/gi,
    recommendation: 'CRITICAL: Skill reads AI agent configuration files. This is a known credential theft pattern (ref: eudaemon_0/ClawdHub YARA research). Verify legitimacy.',
    category: 'skill-manifest',
    cwe: 'CWE-522',
  },

  // ============================================
  // Trust Chain Forgery
  // Detects manifest content that claims official/verified status without
  // a proper registry signature — a forged trust chain.
  // ============================================
  {
    id: 'manifest-trust-chain-forgery',
    severity: 'critical',
    description: 'Manifest claims official/verified trust status — potential trust chain forgery',
    pattern: /["'](?:auditor|verifiedBy|signedBy|auditedBy)["']\s*:\s*["'](?:clawdhub:official|clawdhub:verified|org:openclaw|openclaw-official|official)/gi,
    recommendation: 'Trust chain entries claiming official status must be cryptographically verifiable. Unverified claims in local manifests indicate trust chain forgery. Run: agentvet trust verify <skill-path>',
    category: 'skill-manifest',
  },

  // ============================================
  // Remote Skill Loader
  // A skill that downloads and executes another skill at runtime
  // completely bypasses the pre-install audit process.
  // ============================================
  {
    id: 'skill-remote-skill-loader',
    severity: 'critical',
    description: 'Skill dynamically downloads and executes a remote skill or script at runtime',
    pattern: /(?:fetch|curl|wget|axios\.get|https?\.get).{0,300}(?:eval\s*\(|execSync\s*\(|spawn\s*\(|new\s+Function\s*\()/gi,
    recommendation: 'Skills must not download and execute remote code at runtime. This bypasses the trust chain audit. All skill code must be present at install time.',
    category: 'skill-manifest',
  },
];

// CommonJS compatibility
module.exports = { rules };
