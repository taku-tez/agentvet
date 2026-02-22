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
];

// CommonJS compatibility
module.exports = { rules };
