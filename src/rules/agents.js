/**
 * AI Agent Configuration Rules
 * Detects security issues in agent config files
 */

const rules = [
  // Claude Code / Cursor / Cline config patterns
  {
    id: 'agent-unrestricted-tools',
    severity: 'warning',
    description: 'Agent configured with unrestricted tool access',
    pattern: /"tools"\s*:\s*\[\s*"\*"\s*\]|"allowAllTools"\s*:\s*true/gi,
    recommendation: 'Explicitly list required tools instead of allowing all',
  },
  {
    id: 'agent-unrestricted-filesystem',
    severity: 'warning',
    description: 'Agent configured with unrestricted filesystem access',
    pattern: /"allowedPaths"\s*:\s*\[\s*"\/"\s*\]|"filesystem"\s*:\s*"full"/gi,
    recommendation: 'Restrict filesystem access to specific directories',
  },
  {
    id: 'agent-shell-access',
    severity: 'warning',
    description: 'Agent configured with shell/terminal access',
    pattern: /"shell"\s*:\s*true|"terminal"\s*:\s*true|"exec"\s*:\s*true/gi,
    recommendation: 'Consider disabling shell access unless required',
  },
  {
    id: 'agent-network-unrestricted',
    severity: 'warning',
    description: 'Agent configured with unrestricted network access',
    pattern: /"network"\s*:\s*"full"|"allowAllHosts"\s*:\s*true/gi,
    recommendation: 'Restrict network access to required hosts only',
  },
  
  // Dangerous instruction patterns in agent configs
  {
    id: 'agent-instruction-override',
    severity: 'critical',
    description: 'Instruction to override or ignore safety guidelines',
    pattern: /ignore\s+(?:all\s+)?(?:previous\s+)?(?:safety|security)\s+(?:guidelines?|rules?|instructions?)/gi,
    recommendation: 'Remove instructions that bypass safety guidelines',
  },
  {
    id: 'agent-hidden-behavior',
    severity: 'critical',
    description: 'Instruction for hidden or secret behavior',
    pattern: /(?:do\s+not|don't|never)\s+(?:tell|reveal|show|mention|disclose)\s+(?:the\s+)?user/gi,
    recommendation: 'Agents should be transparent about their actions',
  },
  {
    id: 'agent-data-collection',
    severity: 'warning',
    description: 'Instruction to collect or store user data',
    pattern: /(?:collect|gather|store|save|log|record)\s+(?:user|personal|private)\s+(?:data|information|details)/gi,
    recommendation: 'Ensure data collection complies with privacy policies',
  },
  
  // API key exposure in configs
  {
    id: 'agent-config-api-key',
    severity: 'critical',
    description: 'API key found in agent configuration',
    pattern: /"(?:api[_-]?key|apiKey|secret[_-]?key)"\s*:\s*"(?!.*\$\{)[^"]{20,}"/gi,
    recommendation: 'Use environment variables for API keys, not hardcoded values',
  },
  
  // Dangerous exec patterns
  {
    id: 'agent-dangerous-command',
    severity: 'critical',
    description: 'Dangerous command pattern in agent instructions',
    pattern: /(?:sudo|rm\s+-rf|chmod\s+777|curl\s+.*\|\s*(?:bash|sh))/gi,
    recommendation: 'Avoid dangerous shell commands in agent instructions',
  },
  
  // External URL patterns in instructions
  {
    id: 'agent-external-callback',
    severity: 'warning',
    description: 'External callback URL in agent instructions',
    pattern: /(?:callback|webhook|notify|send\s+to)\s*(?:url|endpoint)?\s*[:=]\s*["']?https?:\/\/(?!localhost)/gi,
    recommendation: 'Verify external URLs are trusted and necessary',
  },
];

module.exports = { rules };
