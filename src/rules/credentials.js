/**
 * Credential Detection Rules
 * Detects hardcoded API keys, tokens, and secrets
 */

const rules = [
  {
    id: 'credential-aws-key',
    severity: 'critical',
    description: 'AWS Access Key ID detected',
    pattern: /AKIA[0-9A-Z]{16}/g,
    recommendation: 'Use environment variables or AWS credentials file (~/.aws/credentials)',
  },
  {
    id: 'credential-aws-secret',
    severity: 'critical',
    description: 'Potential AWS Secret Access Key detected',
    pattern: /(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])/g,
    recommendation: 'Use environment variables or AWS credentials file',
  },
  {
    id: 'credential-github-token',
    severity: 'critical',
    description: 'GitHub token detected',
    pattern: /gh[pousr]_[A-Za-z0-9_]{36,}/g,
    recommendation: 'Use environment variables or GitHub CLI authentication',
  },
  {
    id: 'credential-github-pat',
    severity: 'critical',
    description: 'GitHub Personal Access Token detected',
    pattern: /github_pat_[A-Za-z0-9_]{22,}/g,
    recommendation: 'Use environment variables or GitHub CLI authentication',
  },
  {
    id: 'credential-slack-token',
    severity: 'critical',
    description: 'Slack token detected',
    pattern: /xox[baprs]-[0-9A-Za-z-]{10,}/g,
    recommendation: 'Use environment variables or Slack app configuration',
  },
  {
    id: 'credential-openai-key',
    severity: 'critical',
    description: 'OpenAI API key detected',
    pattern: /sk-[A-Za-z0-9]{32,}/g,
    recommendation: 'Use environment variables (OPENAI_API_KEY)',
  },
  {
    id: 'credential-anthropic-key',
    severity: 'critical',
    description: 'Anthropic API key detected',
    pattern: /sk-ant-[A-Za-z0-9-]{32,}/g,
    recommendation: 'Use environment variables (ANTHROPIC_API_KEY)',
  },
  {
    id: 'credential-private-key',
    severity: 'critical',
    description: 'Private key detected',
    pattern: /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/g,
    recommendation: 'Never commit private keys. Use secure key management.',
  },
  {
    id: 'credential-generic-api-key',
    severity: 'warning',
    description: 'Potential hardcoded API key',
    pattern: /['"]?(?:api[_-]?key|apikey)['"]?\s*[:=]\s*['"][a-zA-Z0-9_-]{20,}['"]/gi,
    recommendation: 'Use environment variables for API keys',
  },
  {
    id: 'credential-generic-secret',
    severity: 'warning',
    description: 'Potential hardcoded secret or password',
    pattern: /['"]?(?:secret|password|passwd|pwd)['"]?\s*[:=]\s*['"][^'"]{8,}['"]/gi,
    recommendation: 'Use environment variables or a secrets manager',
  },
  {
    id: 'credential-bearer-token',
    severity: 'warning',
    description: 'Bearer token in code',
    pattern: /['"]Bearer\s+[A-Za-z0-9._-]{20,}['"]/g,
    recommendation: 'Use environment variables for authentication tokens',
  },
  {
    id: 'credential-notion-token',
    severity: 'critical',
    description: 'Notion API token detected',
    pattern: /(?:ntn_|secret_)[A-Za-z0-9]{32,}/g,
    recommendation: 'Use environment variables or secure configuration',
  },
  {
    id: 'credential-discord-token',
    severity: 'critical',
    description: 'Discord bot token detected',
    pattern: /[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27,}/g,
    recommendation: 'Use environment variables (DISCORD_TOKEN)',
  },
];

module.exports = { rules };
