/**
 * Credential Detection Rules
 * Detects hardcoded API keys, tokens, secrets, and sensitive data
 */

const rules = [
  // ============================================
  // Cloud Provider Keys
  // ============================================
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
    id: 'credential-gcp-key',
    severity: 'critical',
    description: 'Google Cloud API key detected',
    pattern: /AIza[0-9A-Za-z_-]{35}/g,
    recommendation: 'Use environment variables or GCP service accounts',
  },
  {
    id: 'credential-gcp-service-account',
    severity: 'critical',
    description: 'GCP service account key file pattern',
    pattern: /"type"\s*:\s*"service_account"[\s\S]*"private_key"/g,
    recommendation: 'Use workload identity or managed service accounts',
  },
  {
    id: 'credential-azure-key',
    severity: 'critical',
    description: 'Azure subscription key detected',
    pattern: /[a-f0-9]{32}/gi,
    recommendation: 'Use Azure Key Vault or managed identities',
    // Note: High false positive rate, combined with context
  },

  // ============================================
  // AI/LLM Provider Keys
  // ============================================
  {
    id: 'credential-openai-key',
    severity: 'critical',
    description: 'OpenAI API key detected',
    pattern: /sk-[A-Za-z0-9]{32,}/g,
    recommendation: 'Use environment variables (OPENAI_API_KEY)',
  },
  {
    id: 'credential-openai-org',
    severity: 'warning',
    description: 'OpenAI organization ID detected',
    pattern: /org-[A-Za-z0-9]{24}/g,
    recommendation: 'Consider using environment variables for org IDs',
  },
  {
    id: 'credential-anthropic-key',
    severity: 'critical',
    description: 'Anthropic API key detected',
    pattern: /sk-ant-[A-Za-z0-9-]{32,}/g,
    recommendation: 'Use environment variables (ANTHROPIC_API_KEY)',
  },
  {
    id: 'credential-cohere-key',
    severity: 'critical',
    description: 'Cohere API key detected',
    pattern: /[a-zA-Z0-9]{40}/g, // Combined with context
    recommendation: 'Use environment variables (COHERE_API_KEY)',
  },
  {
    id: 'credential-huggingface-token',
    severity: 'critical',
    description: 'Hugging Face token detected',
    pattern: /hf_[A-Za-z0-9]{34,}/g,
    recommendation: 'Use environment variables (HF_TOKEN)',
  },
  {
    id: 'credential-replicate-token',
    severity: 'critical',
    description: 'Replicate API token detected',
    pattern: /r8_[A-Za-z0-9]{32,}/g,
    recommendation: 'Use environment variables (REPLICATE_API_TOKEN)',
  },

  // ============================================
  // Version Control & CI/CD
  // ============================================
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
    id: 'credential-gitlab-token',
    severity: 'critical',
    description: 'GitLab token detected',
    pattern: /glpat-[A-Za-z0-9_-]{20,}/g,
    recommendation: 'Use environment variables or GitLab CI variables',
  },
  {
    id: 'credential-bitbucket-token',
    severity: 'critical',
    description: 'Bitbucket app password detected',
    pattern: /ATBB[A-Za-z0-9]{32,}/g,
    recommendation: 'Use environment variables or Bitbucket pipelines variables',
  },
  {
    id: 'credential-circleci-token',
    severity: 'critical',
    description: 'CircleCI token detected',
    pattern: /circle-token-[a-f0-9]{40}/gi,
    recommendation: 'Use CircleCI contexts or project environment variables',
  },
  {
    id: 'credential-travis-token',
    severity: 'critical',
    description: 'Travis CI token detected',
    pattern: /[a-zA-Z0-9]{22}/g, // Combined with "travis" context
    recommendation: 'Use Travis CI encrypted variables',
  },

  // ============================================
  // Communication & Collaboration
  // ============================================
  {
    id: 'credential-slack-token',
    severity: 'critical',
    description: 'Slack token detected',
    pattern: /xox[baprs]-[0-9A-Za-z-]{10,}/g,
    recommendation: 'Use environment variables or Slack app configuration',
  },
  {
    id: 'credential-slack-webhook',
    severity: 'critical',
    description: 'Slack webhook URL detected',
    pattern: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]+/g,
    recommendation: 'Use environment variables (SLACK_WEBHOOK_URL)',
  },
  {
    id: 'credential-discord-token',
    severity: 'critical',
    description: 'Discord bot token detected',
    pattern: /[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27,}/g,
    recommendation: 'Use environment variables (DISCORD_TOKEN)',
  },
  {
    id: 'credential-discord-webhook',
    severity: 'critical',
    description: 'Discord webhook URL detected',
    pattern: /https:\/\/discord\.com\/api\/webhooks\/[0-9]+\/[A-Za-z0-9_-]+/g,
    recommendation: 'Use environment variables (DISCORD_WEBHOOK_URL)',
  },
  {
    id: 'credential-telegram-token',
    severity: 'critical',
    description: 'Telegram bot token detected',
    pattern: /[0-9]{8,10}:[A-Za-z0-9_-]{35}/g,
    recommendation: 'Use environment variables (TELEGRAM_BOT_TOKEN)',
  },
  {
    id: 'credential-teams-webhook',
    severity: 'critical',
    description: 'Microsoft Teams webhook URL detected',
    pattern: /https:\/\/[a-z0-9]+\.webhook\.office\.com\/webhookb2\/[a-f0-9-]+/gi,
    recommendation: 'Use environment variables (TEAMS_WEBHOOK_URL)',
  },

  // ============================================
  // Database & Storage
  // ============================================
  {
    id: 'credential-database-url',
    severity: 'critical',
    description: 'Database connection string with credentials detected',
    pattern: /(?:mysql|postgres|postgresql|mongodb|redis|mssql):\/\/[^:]+:[^@]+@[^\s'"]+/gi,
    recommendation: 'Use environment variables (DATABASE_URL) without inline credentials',
  },
  {
    id: 'credential-mongodb-srv',
    severity: 'critical',
    description: 'MongoDB SRV connection string detected',
    pattern: /mongodb\+srv:\/\/[^:]+:[^@]+@[^\s'"]+/gi,
    recommendation: 'Use environment variables (MONGODB_URI)',
  },
  {
    id: 'credential-redis-url',
    severity: 'critical',
    description: 'Redis connection string with password detected',
    pattern: /redis:\/\/[^:]*:[^@]+@[^\s'"]+/gi,
    recommendation: 'Use environment variables (REDIS_URL)',
  },
  {
    id: 'credential-s3-url',
    severity: 'warning',
    description: 'S3 bucket URL with potential credentials',
    pattern: /s3:\/\/[A-Z0-9]{20}:[A-Za-z0-9/+=]{40}@/g,
    recommendation: 'Use IAM roles or environment variables',
  },

  // ============================================
  // Authentication Tokens
  // ============================================
  {
    id: 'credential-jwt-token',
    severity: 'warning',
    description: 'JWT token detected',
    pattern: /eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*/g,
    recommendation: 'Do not hardcode JWT tokens; generate them dynamically',
  },
  {
    id: 'credential-bearer-token',
    severity: 'warning',
    description: 'Bearer token in code',
    pattern: /['"]Bearer\s+[A-Za-z0-9._-]{20,}['"]/g,
    recommendation: 'Use environment variables for authentication tokens',
  },
  {
    id: 'credential-basic-auth',
    severity: 'critical',
    description: 'Basic authentication credentials detected',
    pattern: /['"]Basic\s+[A-Za-z0-9+/=]{10,}['"]/g,
    recommendation: 'Use environment variables or secure credential storage',
  },
  {
    id: 'credential-oauth-token',
    severity: 'critical',
    description: 'OAuth access token detected',
    pattern: /ya29\.[A-Za-z0-9_-]{50,}/g, // Google OAuth
    recommendation: 'Use OAuth flows to generate tokens dynamically',
  },

  // ============================================
  // SSH & Certificates
  // ============================================
  {
    id: 'credential-private-key',
    severity: 'critical',
    description: 'Private key detected',
    pattern: /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/g,
    recommendation: 'Never commit private keys. Use secure key management.',
  },
  {
    id: 'credential-ssh-private-key',
    severity: 'critical',
    description: 'SSH private key content detected',
    pattern: /-----BEGIN OPENSSH PRIVATE KEY-----[\s\S]*?-----END OPENSSH PRIVATE KEY-----/g,
    recommendation: 'Use SSH agent or secure key storage, never commit keys',
  },
  {
    id: 'credential-pgp-private',
    severity: 'critical',
    description: 'PGP private key detected',
    pattern: /-----BEGIN PGP PRIVATE KEY BLOCK-----/g,
    recommendation: 'Never commit PGP private keys',
  },
  {
    id: 'credential-certificate',
    severity: 'warning',
    description: 'Certificate file content detected',
    pattern: /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g,
    recommendation: 'Review if this certificate should be public',
  },

  // ============================================
  // SaaS & Third-Party Services
  // ============================================
  {
    id: 'credential-notion-token',
    severity: 'critical',
    description: 'Notion API token detected',
    pattern: /(?:ntn_|secret_)[A-Za-z0-9]{32,}/g,
    recommendation: 'Use environment variables (NOTION_TOKEN)',
  },
  {
    id: 'credential-stripe-key',
    severity: 'critical',
    description: 'Stripe API key detected',
    pattern: /sk_(?:live|test)_[A-Za-z0-9]{24,}/g,
    recommendation: 'Use environment variables (STRIPE_SECRET_KEY)',
  },
  {
    id: 'credential-stripe-publishable',
    severity: 'warning',
    description: 'Stripe publishable key detected',
    pattern: /pk_(?:live|test)_[A-Za-z0-9]{24,}/g,
    recommendation: 'Publishable keys are okay in frontend code, but verify scope',
  },
  {
    id: 'credential-twilio-key',
    severity: 'critical',
    description: 'Twilio API key or auth token detected',
    pattern: /SK[a-f0-9]{32}/g,
    recommendation: 'Use environment variables (TWILIO_API_KEY)',
  },
  {
    id: 'credential-sendgrid-key',
    severity: 'critical',
    description: 'SendGrid API key detected',
    pattern: /SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}/g,
    recommendation: 'Use environment variables (SENDGRID_API_KEY)',
  },
  {
    id: 'credential-mailchimp-key',
    severity: 'critical',
    description: 'Mailchimp API key detected',
    pattern: /[a-f0-9]{32}-us[0-9]{1,2}/g,
    recommendation: 'Use environment variables (MAILCHIMP_API_KEY)',
  },
  {
    id: 'credential-firebase-key',
    severity: 'critical',
    description: 'Firebase API key detected',
    pattern: /AIza[0-9A-Za-z_-]{35}/g,
    recommendation: 'Use environment variables or Firebase app configuration',
  },
  {
    id: 'credential-algolia-key',
    severity: 'critical',
    description: 'Algolia API key detected',
    pattern: /[a-f0-9]{32}/g, // Combined with "algolia" context
    recommendation: 'Use search-only keys in frontend, admin keys in environment',
  },
  {
    id: 'credential-npm-token',
    severity: 'critical',
    description: 'npm authentication token detected',
    pattern: /npm_[A-Za-z0-9]{36}/g,
    recommendation: 'Use npm login or environment variables (NPM_TOKEN)',
  },
  {
    id: 'credential-pypi-token',
    severity: 'critical',
    description: 'PyPI API token detected',
    pattern: /pypi-[A-Za-z0-9_-]{50,}/g,
    recommendation: 'Use environment variables (PYPI_TOKEN)',
  },
  {
    id: 'credential-dockerhub-token',
    severity: 'critical',
    description: 'Docker Hub access token detected',
    pattern: /dckr_pat_[A-Za-z0-9_-]{28,}/g,
    recommendation: 'Use environment variables (DOCKER_TOKEN)',
  },
  {
    id: 'credential-heroku-key',
    severity: 'critical',
    description: 'Heroku API key detected',
    pattern: /[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}/g,
    recommendation: 'Use Heroku CLI authentication or environment variables',
  },
  {
    id: 'credential-vercel-token',
    severity: 'critical',
    description: 'Vercel token detected',
    pattern: /[A-Za-z0-9]{24}/g, // Combined with "vercel" context
    recommendation: 'Use environment variables (VERCEL_TOKEN)',
  },
  {
    id: 'credential-netlify-token',
    severity: 'critical',
    description: 'Netlify access token detected',
    pattern: /[a-f0-9]{64}/g, // Combined with "netlify" context
    recommendation: 'Use environment variables (NETLIFY_AUTH_TOKEN)',
  },
  {
    id: 'credential-shopify-key',
    severity: 'critical',
    description: 'Shopify API key detected',
    pattern: /shpat_[a-fA-F0-9]{32}/g,
    recommendation: 'Use environment variables or Shopify app credentials',
  },
  {
    id: 'credential-square-token',
    severity: 'critical',
    description: 'Square access token detected',
    pattern: /sq0[a-z]{3}-[A-Za-z0-9_-]{22,}/g,
    recommendation: 'Use environment variables (SQUARE_ACCESS_TOKEN)',
  },

  // ============================================
  // Generic Patterns
  // ============================================
  {
    id: 'credential-generic-api-key',
    severity: 'warning',
    description: 'Potential hardcoded API key',
    pattern: /['"]?(?:api[_-]?key|apikey|api_token)['"]?\s*[:=]\s*['"][a-zA-Z0-9_-]{20,}['"]/gi,
    recommendation: 'Use environment variables for API keys',
  },
  {
    id: 'credential-generic-secret',
    severity: 'warning',
    description: 'Potential hardcoded secret or password',
    pattern: /['"]?(?:secret|password|passwd|pwd|token)['"]?\s*[:=]\s*['"][^'"]{8,}['"]/gi,
    recommendation: 'Use environment variables or a secrets manager',
  },
  {
    id: 'credential-generic-auth',
    severity: 'warning',
    description: 'Potential hardcoded authentication credential',
    pattern: /['"]?(?:auth|authorization|credential)['"]?\s*[:=]\s*['"][^'"]{10,}['"]/gi,
    recommendation: 'Use secure credential storage',
  },
  {
    id: 'credential-connection-string',
    severity: 'critical',
    description: 'Connection string with embedded credentials',
    pattern: /(?:Server|Data Source|Host)=[^;]+;.*(?:Password|Pwd)=[^;]+/gi,
    recommendation: 'Use environment variables for connection strings',
  },
];

module.exports = { rules };
