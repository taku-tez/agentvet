import type { Rule } from "../types.js";

/**
 * Supply Chain Attack Detection Rules
 * Detects dependency confusion, typosquatting, malicious install scripts,
 * and other software supply chain attack patterns
 */

export const rules: Rule[] = [
  {
    id: 'supply-chain-postinstall-exec',
    severity: 'critical',
    description: 'Package postinstall script executes arbitrary commands',
    pattern: /"(?:post|pre)install"\s*:\s*"(?:.*(?:curl|wget|nc|ncat|bash|sh|python|node\s+-e|eval|powershell))/gi,
    recommendation: 'Audit postinstall scripts carefully. Use --ignore-scripts for untrusted packages.',
  },
  {
    id: 'supply-chain-install-fetch',
    severity: 'critical',
    description: 'Install script fetches remote payload',
    pattern: /"(?:post|pre)?install"\s*:\s*"[^"]*(?:curl|wget|fetch|http\.get|axios\.get|node-fetch)\s+https?:\/\//gi,
    recommendation: 'Install scripts should not download remote code. Review package source.',
  },
  {
    id: 'supply-chain-dependency-confusion',
    severity: 'high',
    description: 'Private package name pattern without registry scope — dependency confusion risk',
    pattern: /"(?:dependencies|devDependencies)":\s*\{[^}]*"(?!@)[a-z]+-(?:internal|private|corp|company)[^"]*"\s*:/gi,
    recommendation: 'Use scoped packages (@org/pkg) for internal packages. Configure .npmrc with registry mapping.',
  },
  {
    id: 'supply-chain-typosquat-popular',
    severity: 'high',
    description: 'Potential typosquat of popular package name',
    pattern: /"(?:dependencies|devDependencies)":\s*\{[^}]*"(?:l0dash|lo-dash|lodash[._-]|expresss|exress|reacct|reactt|axois|axos|requets|reqeusts)[^"]*"\s*:/gi,
    recommendation: 'Verify package name spelling. Check npm for the official package.',
  },
  {
    id: 'supply-chain-unpinned-dependency',
    severity: 'medium',
    description: 'Unpinned dependency version with * or latest — vulnerable to supply chain attacks',
    pattern: /"(?:dependencies|devDependencies)":\s*\{[^}]*"[^"]+"\s*:\s*"(?:\*|latest|>=)"/gi,
    recommendation: 'Pin dependency versions. Use lockfiles and integrity checks.',
  },
  {
    id: 'supply-chain-pip-install-url',
    severity: 'high',
    description: 'pip install from direct URL — potential supply chain attack',
    pattern: /pip\s+install\s+(?:--(?:extra-)?index-url\s+https?:\/\/(?!pypi\.org)[^\s]+|https?:\/\/[^\s]+\.(?:tar\.gz|whl|zip))/gi,
    recommendation: 'Only install from official PyPI. Verify custom index URLs.',
  },
  {
    id: 'supply-chain-setup-py-exec',
    severity: 'critical',
    description: 'setup.py executing code during install',
    pattern: /(?:setup\.py|setup\.cfg).*(?:cmdclass|install_requires.*exec|subprocess\.(?:call|run|Popen)|os\.system|__import__\s*\(\s*['"](?:subprocess|os|shutil))/gi,
    recommendation: 'Audit setup.py for code execution. Prefer pyproject.toml builds.',
  },
  {
    id: 'supply-chain-git-dependency',
    severity: 'medium',
    description: 'Direct git dependency without commit hash pinning',
    pattern: /"[^"]+"\s*:\s*"(?:git(?:\+https?)?:\/\/|github:)[^"]*(?<![a-f0-9]{40})"/gi,
    recommendation: 'Pin git dependencies to specific commit hashes, not branches or tags.',
  },
  {
    id: 'supply-chain-npm-config-registry',
    severity: 'high',
    description: 'Custom npm registry configuration — potential dependency confusion',
    pattern: /registry\s*=\s*https?:\/\/(?!registry\.npmjs\.org)[^\s]+/gi,
    recommendation: 'Verify custom registry URLs. Use scoped registry config for private packages.',
  },
  {
    id: 'supply-chain-lockfile-mismatch',
    severity: 'medium',
    description: 'Package lockfile contains resolved URL to non-standard registry',
    pattern: /"resolved"\s*:\s*"https?:\/\/(?!registry\.npmjs\.org|registry\.yarnpkg\.com)[^"]+"/gi,
    recommendation: 'Audit lockfile resolved URLs. Ensure all packages come from trusted registries.',
  },
];
