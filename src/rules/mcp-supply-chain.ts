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

export const rules: Rule[] = [
  ...mcpConfigSecretRules,
  ...mcpUntrustedServerRules,
  ...mcpSandboxEscapeRules,
  ...mcpEnvExposureRules,
];

// CommonJS compatibility
module.exports = { rules };
