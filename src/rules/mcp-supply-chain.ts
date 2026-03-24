import type { Rule } from "../types.js";

/**
 * MCP Supply Chain Security Rules (Issue #15)
 * Detects supply chain risks specific to the MCP ecosystem:
 *  - Secret exposure in MCP config files (.mcp.json, claude_desktop_config.json, etc.)
 *  - Untrusted / unregistered MCP servers (unknown npm orgs, git URLs, local paths)
 *  - Typosquatting of official Anthropic / popular MCP packages
 *  - Unpinned MCP server versions (susceptible to malicious updates)
 *  - Sandbox escape paths in MCP server startup commands
 *  - Excessive env var exposure to MCP server processes
 */

// -------------------------------------------------------
// 1. Secret Exposure in MCP config env blocks
// -------------------------------------------------------
const mcpConfigSecretRules: Rule[] = [
  {
    id: 'mcp-supply-chain-hardcoded-aws-key',
    severity: 'critical',
    description: 'AWS Access Key ID hardcoded in MCP server env block',
    pattern: /"env"\s*:\s*\{[^}]{0,500}"[^"]*"\s*:\s*"(AKIA|ASIA|AROA)[A-Z0-9]{16}[^"]*"/gi,
    recommendation: 'Never hardcode AWS credentials in MCP config. Use the AWS credential chain (IAM roles, ~/.aws/credentials) or pass via a secrets manager.',
    category: 'mcp-supply-chain',
  },
  {
    id: 'mcp-supply-chain-hardcoded-gcp-key',
    severity: 'critical',
    description: 'GCP service account key JSON path or inline credentials in MCP server env',
    pattern: /"env"\s*:\s*\{[^}]{0,500}"GOOGLE_APPLICATION_CREDENTIALS"\s*:\s*"[^"]+(?:\.json|key|credentials)[^"]*"/gi,
    recommendation: 'Do not embed GCP key paths in MCP config. Use Workload Identity or Application Default Credentials.',
    category: 'mcp-supply-chain',
  },
  {
    id: 'mcp-supply-chain-slack-webhook-env',
    severity: 'high',
    description: 'Slack/Discord/PagerDuty webhook URL in MCP server env block',
    pattern: /"env"\s*:\s*\{[^}]{0,500}"[^"]*"\s*:\s*"https:\/\/hooks\.(?:slack\.com\/services|discord\.com\/api\/webhooks|pagerduty\.com)[^"]+"/gi,
    recommendation: 'Webhook URLs in MCP configs leak messaging/alerting access. Inject at runtime via environment variables.',
    category: 'mcp-supply-chain',
  },
  {
    id: 'mcp-supply-chain-openai-key-env',
    severity: 'critical',
    description: 'OpenAI / Anthropic API key hardcoded in MCP server env block',
    pattern: /"env"\s*:\s*\{[^}]{0,500}"[^"]*(?:OPENAI|ANTHROPIC|CLAUDE|GPT)[^"]*"\s*:\s*"(?:sk-|sk-ant-)[A-Za-z0-9_-]{20,}"/gi,
    recommendation: 'LLM API keys in MCP configs allow unlimited API spend by anyone reading the config. Use env var references ($ENV_VAR) or a secrets manager.',
    category: 'mcp-supply-chain',
  },
];

// -------------------------------------------------------
// 2. Untrusted / Unverified MCP Servers
// -------------------------------------------------------
const mcpUntrustedServerRules: Rule[] = [
  {
    id: 'mcp-supply-chain-git-url-server',
    severity: 'high',
    description: 'MCP server loaded from a raw git URL (not a published npm package)',
    pattern: /"command"\s*:\s*"(?:git|node)"\s*,\s*"args"\s*:\s*\[[^\]]*"(?:https?|git(?:\+https?)?):\/\/[^"]+\.git[^"]*"/gi,
    recommendation: 'Loading MCP servers from arbitrary git URLs bypasses supply chain controls. Publish to npm and pin to a specific version + integrity hash.',
    category: 'mcp-supply-chain',
  },
  {
    id: 'mcp-supply-chain-local-path-server',
    severity: 'medium',
    description: 'MCP server loaded from a local filesystem path (not an installed package)',
    pattern: /"(?:command|args)"\s*:\s*(?:"[^"]*"|)\s*[,\[]?\s*"(?:\.{1,2}\/|\/(?!usr\/local\/lib|usr\/bin|home\/[^/]+\/\.nvm)[^"]*\/)[^"]*\.(?:js|ts|cjs|mjs)"/gi,
    recommendation: 'Local path MCP servers are not version-controlled or integrity-checked. Install via npm with a pinned version and lockfile.',
    category: 'mcp-supply-chain',
  },
  {
    id: 'mcp-supply-chain-unpinned-npx',
    severity: 'high',
    description: 'MCP server launched via npx without a pinned version — vulnerable to malicious updates',
    pattern: /"command"\s*:\s*"npx"\s*,\s*"args"\s*:\s*\["(?!-)[^"@]+"\s*(?:,|])/gi,
    recommendation: 'Always pin MCP server versions: use "npx" with "@pkg@1.2.3" or install to node_modules and reference directly. Unpinned npx runs always pull the latest version.',
    category: 'mcp-supply-chain',
  },
  {
    id: 'mcp-supply-chain-unofficial-anthropic-pkg',
    severity: 'high',
    description: 'Potential typosquat of official Anthropic MCP package detected',
    pattern: /"(?:command|args)"\s*:\s*(?:"[^"]*",\s*)?\[[^\]]*"@anthropics?\/|"@aanthropic\/|"@anth[^"]+\/|"mcp-server-anthropik|"mcp-server-claudee|"claudde-mcp|"claude-mcp-server[^"]"/gi,
    recommendation: 'Verify MCP package names against the official Anthropic registry. Common typosquats target @anthropic/ scope.',
    category: 'mcp-supply-chain',
  },
];

// -------------------------------------------------------
// 3. Sandbox Escape in MCP Server Commands
// -------------------------------------------------------
const mcpSandboxEscapeRules: Rule[] = [
  {
    id: 'mcp-supply-chain-privileged-exec',
    severity: 'critical',
    description: 'MCP server launched with sudo or root-level privileges',
    pattern: /"command"\s*:\s*"(?:sudo|su)\b|"args"\s*:\s*\[[^\]]*"(?:sudo|su)\b[^"]*"/gi,
    recommendation: 'MCP servers must never run with elevated privileges. Use capability-dropping and run as an unprivileged user.',
    category: 'mcp-supply-chain',
  },
  {
    id: 'mcp-supply-chain-docker-privileged',
    severity: 'critical',
    description: 'MCP server container launched with --privileged or --cap-add ALL flag',
    pattern: /"args"\s*:\s*\[[^\]]*"(?:--privileged|--cap-add\s+ALL)[^"]*"/gi,
    recommendation: '--privileged containers have full host access and defeat container isolation. Never use for MCP server containers.',
    category: 'mcp-supply-chain',
  },
  {
    id: 'mcp-supply-chain-host-network',
    severity: 'high',
    description: 'MCP server container uses --network=host (bypasses network isolation)',
    pattern: /"args"\s*:\s*\[[^\]]*"--network[= ]host[^"]*"/gi,
    recommendation: 'Host network mode removes container network isolation. MCP servers should use bridge networking with explicit port mappings.',
    category: 'mcp-supply-chain',
  },
  {
    id: 'mcp-supply-chain-host-pid',
    severity: 'critical',
    description: 'MCP server container uses --pid=host (exposes host process namespace)',
    pattern: /"args"\s*:\s*\[[^\]]*"--pid[= ]host[^"]*"/gi,
    recommendation: 'Sharing the host PID namespace with an MCP server allows process inspection and signal injection against host processes.',
    category: 'mcp-supply-chain',
  },
  {
    id: 'mcp-supply-chain-volume-etc-mount',
    severity: 'critical',
    description: 'MCP server container mounts /etc, /var, or / from the host (config/credential theft path)',
    pattern: /"args"\s*:\s*\[[^\]]*"-v\s+(?:\/etc|\/var\/(?:lib|run)|\/proc|\/sys|\/root|\/home)\b[^"]*"/gi,
    recommendation: 'Mounting sensitive host directories into an MCP container enables credential theft and persistent backdoors. Use named volumes or specific data paths only.',
    category: 'mcp-supply-chain',
  },
];

// -------------------------------------------------------
// 4. Excessive Env Var Exposure
// -------------------------------------------------------
const mcpEnvExposureRules: Rule[] = [
  {
    id: 'mcp-supply-chain-full-env-exposure',
    severity: 'high',
    description: 'MCP server env block appears to expose the entire process environment (passthrough pattern)',
    pattern: /"env"\s*:\s*\{[^}]{0,200}"\.\.\.\s*process\.env|"env"\s*:\s*"inherit"|"inheritEnv"\s*:\s*true/gi,
    recommendation: 'Passing the entire host environment to an MCP server leaks all secrets available to the parent process. Pass only the specific env vars required.',
    category: 'mcp-supply-chain',
  },
  {
    id: 'mcp-supply-chain-ssh-key-env',
    severity: 'critical',
    description: 'SSH private key path or content exposed via MCP server env var',
    pattern: /"env"\s*:\s*\{[^}]{0,500}"[^"]*(?:SSH_KEY|PRIVATE_KEY|IDENTITY_FILE|id_rsa|id_ed25519)[^"]*"\s*:\s*"[^"]+"/gi,
    recommendation: 'SSH keys in MCP env blocks allow the server to authenticate as the host user to remote systems. Use ssh-agent forwarding selectively instead.',
    category: 'mcp-supply-chain',
  },
];

// -------------------------------------------------------
// 5. Additional Supply Chain Risks
// -------------------------------------------------------
const mcpAdditionalRules: Rule[] = [
  {
    id: 'mcp-supply-chain-unpinned-uvx',
    severity: 'high',
    description: 'MCP server launched via uvx without a pinned version — vulnerable to malicious updates',
    pattern: /"command"\s*:\s*"uvx"\s*,\s*"args"\s*:\s*\[[^\]]*"(?!.*==)[a-z][a-z0-9_-]+"\s*(?:,|])/gi,
    recommendation: 'Pin uvx MCP server versions: use "uvx" with "pkg==1.2.3" syntax. Unpinned uvx runs fetch the latest version and are vulnerable to supply chain attacks.',
    category: 'mcp-supply-chain',
  },
  {
    id: 'mcp-supply-chain-github-raw-url',
    severity: 'critical',
    description: 'MCP server loaded from raw.githubusercontent.com or GitHub archive URL',
    pattern: /"(?:command|args)"\s*:\s*(?:"[^"]*",\s*)?\[[^\]]*"(?:https?:\/\/raw\.githubusercontent\.com|https?:\/\/github\.com\/[^"]+\/(?:archive|raw)\/)[^"]+"/gi,
    recommendation: 'Loading MCP servers from raw GitHub URLs bypasses integrity checks and can be updated without warning. Publish to a package registry and pin to a specific version + hash.',
    category: 'mcp-supply-chain',
  },
  {
    id: 'mcp-supply-chain-database-url-env',
    severity: 'critical',
    description: 'Database connection string with credentials in MCP server env block',
    pattern: /"env"\s*:\s*\{[^}]{0,500}"[^"]*(?:DATABASE_URL|DB_URL|MONGODB_URI|POSTGRES(?:_URL|SQL_URL)?|MYSQL_URL|REDIS_URL|MONGO_URI)[^"]*"\s*:\s*"(?:postgres|mysql|mongodb|redis|sqlite|mssql):\/\/[^@"]+:[^@"]+@[^"]+"/gi,
    recommendation: 'Database URLs with embedded credentials in MCP configs expose your database to anyone reading the config file. Use env var references or a secrets manager at runtime.',
    category: 'mcp-supply-chain',
  },
  {
    id: 'mcp-supply-chain-payment-api-key-env',
    severity: 'critical',
    description: 'Payment/communication API key (Stripe, Twilio, SendGrid) in MCP server env block',
    pattern: /"env"\s*:\s*\{[^}]{0,500}"[^"]*(?:STRIPE_|TWILIO_|SENDGRID_|MAILGUN_)[^"]*"\s*:\s*"(?:sk_live_|sk_test_|AC[0-9a-f]{32}|SG\.[A-Za-z0-9_-]{22,})[^"]*"/gi,
    recommendation: 'Payment and communication API keys in MCP configs can lead to unauthorized charges or data leaks. Inject credentials at runtime via environment variables.',
    category: 'mcp-supply-chain',
  },
  {
    id: 'mcp-supply-chain-writable-host-mount',
    severity: 'high',
    description: 'MCP server container mounts a host directory in read-write mode (default or :rw)',
    pattern: /"-v\s+[^"]+:[^":]+(?<!:ro)"/gi,
    recommendation: 'Read-write host mounts in MCP containers allow the server to modify host files. Use :ro (read-only) mounts for data volumes, or named volumes for writable storage.',
    category: 'mcp-supply-chain',
  },
];

// -------------------------------------------------------
// 6. Additional MCP threat vectors (Issue #15 batch 2)
// -------------------------------------------------------
const mcpThreatVectorRules: Rule[] = [
  {
    id: 'mcp-supply-chain-anthropic-key-env',
    severity: 'critical',
    description: 'Anthropic API key hardcoded in MCP server env block',
    pattern: /"env"\s*:\s*\{[^}]{0,500}"[^"]*"\s*:\s*"sk-ant-[A-Za-z0-9_\-]{20,}[^"]*"/gi,
    recommendation: 'Anthropic API keys in MCP config are readable by all processes. Use a secrets manager (HashiCorp Vault, AWS Secrets Manager) or environment-level injection instead.',
    category: 'mcp-supply-chain',
  },
  {
    id: 'mcp-supply-chain-huggingface-token-env',
    severity: 'high',
    description: 'HuggingFace token hardcoded in MCP server env block',
    pattern: /"env"\s*:\s*\{[^}]{0,500}"[^"]*"\s*:\s*"hf_[A-Za-z0-9]{20,}[^"]*"/gi,
    recommendation: 'HuggingFace tokens in MCP config expose model access credentials. Use the HuggingFace CLI token store (~/.cache/huggingface/token) and reference it via $HF_TOKEN at runtime.',
    category: 'mcp-supply-chain',
  },
  {
    id: 'mcp-supply-chain-curl-pipe-sh',
    severity: 'critical',
    description: 'MCP server startup command pipes curl/wget output directly to shell',
    pattern: /(?:curl|wget)[^|"]+\|\s*(?:bash|sh|zsh|fish)/gi,
    recommendation: 'Piping remote script content directly to a shell is a common supply chain attack vector. Download the script first, verify its hash, then execute it.',
    category: 'mcp-supply-chain',
  },
  {
    id: 'mcp-supply-chain-unverified-pip-install',
    severity: 'high',
    description: 'MCP server startup installs pip packages without version pinning',
    pattern: /(?:pip|pip3)\s+install\s+(?!.*==)[a-zA-Z0-9_\-]+(?:\s|$)/gi,
    recommendation: 'Unpinned pip packages in MCP server startup commands can be silently replaced with malicious versions. Pin all packages: pip install package==1.2.3',
    category: 'mcp-supply-chain',
  },
  {
    id: 'mcp-supply-chain-env-passthrough-all',
    severity: 'high',
    description: 'MCP server config passes all environment variables (env: {}) with no restriction',
    pattern: /"env"\s*:\s*\{\s*"[^"]+"\s*:\s*"\$\{[A-Z_]+\}"\s*,\s*"[^"]+"\s*:\s*"\$\{[A-Z_]+\}"\s*,\s*"[^"]+"\s*:\s*"\$\{[A-Z_]+\}"/gi,
    recommendation: 'Passing many env vars to MCP servers increases the attack surface. Only pass the specific variables each server needs.',
    category: 'mcp-supply-chain',
  },
];

// -------------------------------------------------------
// 7. Batch 3: hardcoded secrets & filesystem scope (Issue #15)
// -------------------------------------------------------
const mcpBatch3Rules: Rule[] = [
  {
    id: 'mcp-supply-chain-database-uri-env',
    severity: 'critical',
    description: 'Database connection URI (PostgreSQL/MySQL/MongoDB) hardcoded in MCP server env block',
    pattern: /"env"\s*:\s*\{[^}]{0,1000}(?:postgresql|mysql|mongodb(?:\+srv)?):\/\/[^"]+"/gi,
    recommendation: 'Never hardcode database URIs in MCP configs. Use env var references or a secrets manager.',
    category: 'mcp-supply-chain',
  },
  {
    id: 'mcp-supply-chain-stripe-key-env',
    severity: 'critical',
    description: 'Stripe secret key hardcoded in MCP server env block',
    pattern: /"env"\s*:\s*\{[^}]{0,1000}"[^"]*"\s*:\s*"(?:sk_live_|rk_live_)[^"]*"/gi,
    recommendation: 'Stripe secret keys in MCP configs allow financial fraud. Use env var references.',
    category: 'mcp-supply-chain',
  },
  {
    id: 'mcp-supply-chain-unrestricted-filesystem',
    severity: 'high',
    description: 'MCP filesystem server granted access to root directory or entire home directory',
    pattern: /"args"\s*:\s*\[[^\]]*"(?:\/|\/root|\/home)"\s*[\],]/gi,
    recommendation: 'Restrict filesystem MCP server access to specific project directories only, never grant root or home dir access.',
    category: 'mcp-supply-chain',
  },
];

// -------------------------------------------------------
// 8. Batch 4: typosquatting, GitHub Actions OIDC leakage,
//    MCP server impersonation, and stale/abandoned servers
// -------------------------------------------------------
const mcpBatch4Rules: Rule[] = [
  {
    id: 'mcp-supply-chain-typosquat-uvx',
    severity: 'high',
    description: 'UVX/NPX command targets a package name resembling a known tool (possible typosquatting)',
    pattern: /"command"\s*:\s*"(?:uvx|npx)"[^}]{0,500}"args"\s*:\s*\[\s*"(?:mcp[-_]?serv(?:er)?s?|mcp[-_]?tools?|mcp[-_]?utils?|mcpserver|mcptools?)[^"]*"/gi,
    recommendation: 'Generic or suspiciously named MCP packages (e.g. mcp-server, mcp-tools) may be typosquats. Verify the exact package name and maintainer on npmjs.com or PyPI before use.',
    category: 'mcp-supply-chain',
  },
  {
    id: 'mcp-supply-chain-github-actions-oidc-env',
    severity: 'critical',
    description: 'GitHub Actions OIDC token or Actions environment variable passed to MCP server',
    pattern: /"env"\s*:\s*\{[^}]{0,1000}(?:ACTIONS_ID_TOKEN_REQUEST_(?:TOKEN|URL)|GITHUB_TOKEN|ACTIONS_RUNTIME_TOKEN)/gi,
    recommendation: 'GitHub Actions tokens (GITHUB_TOKEN, ACTIONS_RUNTIME_TOKEN, OIDC tokens) must never be passed to MCP servers. This exposes CI/CD credentials to third-party code execution.',
    category: 'mcp-supply-chain',
  },
  {
    id: 'mcp-supply-chain-aws-session-token-env',
    severity: 'critical',
    description: 'AWS temporary session token (STS) hardcoded or referenced in MCP server env block',
    pattern: /"env"\s*:\s*\{[^}]{0,1000}"[^"]*(?:AWS_SESSION_TOKEN|AWS_SECURITY_TOKEN)[^"]*"\s*:\s*"[^$][^"]{8,}"/gi,
    recommendation: 'AWS session tokens expire but granting them to MCP servers creates a lateral movement path. Use IAM role assumptions with minimal scope instead.',
    category: 'mcp-supply-chain',
  },
  {
    id: 'mcp-supply-chain-npx-no-yes-flag',
    severity: 'medium',
    description: 'NPX command used in MCP server without --yes flag, allowing interactive prompts to be bypassed by malicious scripts',
    pattern: /"command"\s*:\s*"npx"(?:(?!"--yes"|"-y").){0,500}"args"\s*:\s*\[/gis,
    recommendation: 'Use npx with --yes to prevent malicious packages from injecting interactive prompts that execute arbitrary code during installation.',
    category: 'mcp-supply-chain',
  },
  {
    id: 'mcp-supply-chain-localhost-non-standard-port',
    severity: 'medium',
    description: 'MCP server configured to connect to localhost on a non-standard high port (potential port hijacking)',
    pattern: /"url"\s*:\s*"https?:\/\/(?:localhost|127\.0\.0\.1):(?:[3-9][0-9]{3,4}|[1-5][0-9]{4}|6[0-4][0-9]{3})\/"/gi,
    recommendation: 'Connecting to localhost on high ports may allow other processes on the machine to impersonate the MCP server. Use Unix sockets or validate the server process identity.',
    category: 'mcp-supply-chain',
  },
];

export const rules: Rule[] = [
  ...mcpConfigSecretRules,
  ...mcpUntrustedServerRules,
  ...mcpSandboxEscapeRules,
  ...mcpEnvExposureRules,
  ...mcpAdditionalRules,
  ...mcpThreatVectorRules,
  ...mcpBatch3Rules,
  ...mcpBatch4Rules,
];

// CommonJS compatibility
module.exports = { rules };
