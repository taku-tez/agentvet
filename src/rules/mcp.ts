import type { Rule } from "../types.js";

/**
 * MCP Configuration Rules
 * Detects security issues in MCP tool configurations
 */

// MCP-specific credential patterns
const mcpCredentialPatterns = [
  {
    id: 'mcp-hardcoded-api-key',
    severity: 'critical',
    description: 'Hardcoded API key in MCP configuration',
    pattern: /"(?:api[_-]?key|apikey|secret[_-]?key)"\s*:\s*"([^"]{20,})"/gi,
    recommendation: 'Use environment variables: ${API_KEY} or reference a secure credential store',
  },
  {
    id: 'mcp-hardcoded-token',
    severity: 'critical',
    description: 'Hardcoded token in MCP configuration',
    pattern: /"(?:token|auth[_-]?token|access[_-]?token|bearer)"\s*:\s*"([^"]{20,})"/gi,
    recommendation: 'Use environment variables for tokens instead of hardcoding',
  },
  {
    id: 'mcp-hardcoded-password',
    severity: 'critical',
    description: 'Hardcoded password in MCP configuration',
    pattern: /"(?:password|passwd|pwd)"\s*:\s*"([^"]+)"/gi,
    recommendation: 'Never hardcode passwords. Use environment variables or a secrets manager',
  },
];

// Dangerous command patterns in MCP tool definitions
const mcpCommandPatterns = [
  {
    id: 'mcp-unrestricted-exec',
    severity: 'critical',
    description: 'MCP tool allows unrestricted command execution',
    pattern: /"command"\s*:\s*"(?:bash|sh|cmd|powershell)"/gi,
    recommendation: 'Restrict command execution to specific whitelisted commands',
  },
  {
    id: 'mcp-shell-injection-risk',
    severity: 'critical',
    description: 'MCP command may be vulnerable to shell injection',
    pattern: /"args"\s*:\s*\[\s*"-c"\s*,/gi,
    recommendation: 'Avoid passing user input to shell commands. Use argument arrays instead of shell strings',
  },
  {
    id: 'mcp-curl-piped-execution',
    severity: 'critical',
    description: 'MCP tool downloads and executes remote code',
    pattern: /curl[^"]*\|\s*(?:bash|sh|python|node)/gi,
    recommendation: 'Never pipe downloaded content directly to interpreters',
  },
  {
    id: 'mcp-eval-usage',
    severity: 'critical',
    description: 'MCP tool uses eval or similar dangerous functions',
    pattern: /"(?:command|args)"[^}]*(?:eval|exec|Function\()/gi,
    recommendation: 'Avoid eval/exec. Use safe alternatives with proper input validation',
  },
];

// Suspicious URL patterns in MCP configs
const mcpUrlPatterns = [
  {
    id: 'mcp-exfiltration-endpoint',
    severity: 'critical',
    description: 'MCP tool connects to known data exfiltration service',
    pattern: /(?:webhook\.site|requestbin\.(?:com|net)|pipedream\.net|hookbin\.com|requestcatcher\.com)/gi,
    recommendation: 'Remove connections to data exfiltration services',
  },
  {
    id: 'mcp-tunnel-service',
    severity: 'warning',
    description: 'MCP tool uses tunnel service (potential data exfiltration)',
    pattern: /(?:ngrok\.io|localhost\.run|serveo\.net|telebit\.cloud|localtunnel\.me)/gi,
    recommendation: 'Tunnel services can bypass firewall controls. Ensure this is intentional',
  },
  {
    id: 'mcp-suspicious-ip',
    severity: 'warning',
    description: 'MCP tool connects to raw IP address',
    pattern: /"(?:url|endpoint|baseUrl|host)"\s*:\s*"https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/gi,
    recommendation: 'Use domain names instead of IP addresses for transparency',
  },
];

// Permission and capability patterns
const mcpPermissionPatterns = [
  {
    id: 'mcp-unrestricted-filesystem',
    severity: 'warning',
    description: 'MCP tool has unrestricted filesystem access',
    pattern: /"(?:allowedPaths|paths)"\s*:\s*\[\s*"(?:\/|\*|~)"\s*\]/gi,
    recommendation: 'Restrict filesystem access to specific directories needed by the tool',
  },
  {
    id: 'mcp-root-path-access',
    severity: 'critical',
    description: 'MCP tool can access root filesystem',
    pattern: /"(?:allowedPaths|workDir|cwd)"\s*:\s*"\/(?:etc|var|usr|root|home(?!\/[^/]+\/\.))"/gi,
    recommendation: 'Restrict access to user workspace directories only',
  },
  {
    id: 'mcp-network-unrestricted',
    severity: 'warning',
    description: 'MCP tool has unrestricted network access',
    pattern: /"(?:allowedHosts|hosts)"\s*:\s*\[\s*"\*"\s*\]/gi,
    recommendation: 'Restrict network access to specific required hosts',
  },
  {
    id: 'mcp-env-exposure',
    severity: 'warning',
    description: 'MCP tool exposes environment variables',
    pattern: /"(?:env|environment)"\s*:\s*\{\s*"[^"]+"\s*:\s*"\$\{?(?!HOME|USER|PATH)[A-Z_]+/gi,
    recommendation: 'Only expose necessary environment variables to MCP tools',
  },
];

// Prompt injection patterns in MCP tool descriptions
// These detect attempts to manipulate the AI agent via malicious tool metadata
const mcpPromptInjectionPatterns = [
  {
    id: 'mcp-prompt-injection-ignore',
    severity: 'critical',
    description: 'MCP tool description contains instruction override attempt',
    pattern: /(?:ignore|disregard|forget|override|bypass)\s+(?:all\s+)?(?:previous|prior|above|earlier|system)\s+(?:instructions?|prompts?|rules?|constraints?)/gi,
    recommendation: 'Tool descriptions should not contain instruction manipulation. This may be an attack.',
  },
  {
    id: 'mcp-prompt-injection-role-hijack',
    severity: 'critical',
    description: 'MCP tool description attempts to change AI role/identity',
    pattern: /(?:you\s+are\s+now|from\s+now\s+on\s+you\s+are|act\s+as\s+if\s+you\s+are|pretend\s+(?:to\s+be|you\s+are)|assume\s+the\s+role|your\s+new\s+(?:role|identity|purpose))/gi,
    recommendation: 'Tool descriptions should not attempt to redefine the AI\'s role. This may be an attack.',
  },
  {
    id: 'mcp-prompt-injection-jailbreak',
    severity: 'critical',
    description: 'MCP tool description contains jailbreak attempt',
    pattern: /(?:DAN\s+mode|do\s+anything\s+now|no\s+restrictions|without\s+limitations|unrestricted\s+mode|developer\s+mode|enable\s+(?:all|full)\s+(?:capabilities|access|permissions))/gi,
    recommendation: 'Tool descriptions should not contain jailbreak attempts. This is a security threat.',
  },
  {
    id: 'mcp-prompt-injection-hidden',
    severity: 'warning',
    description: 'MCP tool description may contain hidden instructions',
    pattern: /(?:<!--.*?-->|\[hidden\]|\{hidden\}|<\s*instruction[^>]*>|SYSTEM:\s*|ADMIN:\s*|\[INST\])/gi,
    recommendation: 'Tool descriptions contain suspicious markup that may hide instructions.',
  },
  {
    id: 'mcp-prompt-injection-urgency',
    severity: 'warning',
    description: 'MCP tool description uses urgency/priority manipulation',
    pattern: /(?:CRITICAL(?:\s*:)?|URGENT(?:\s*:)?|IMPORTANT(?:\s*:)?|PRIORITY(?:\s*:)?|MUST\s+(?:DO|EXECUTE|RUN)|REQUIRED(?:\s*:)?)\s+(?:execute|run|call|use|invoke|always)/gi,
    recommendation: 'Tool descriptions using urgency language may be attempting to manipulate execution priority.',
  },
  {
    id: 'mcp-prompt-injection-base64',
    severity: 'warning',
    description: 'MCP tool description contains potential encoded payload',
    pattern: /(?:base64|atob|btoa|decode)\s*[\(\:]|[A-Za-z0-9+\/]{50,}={0,2}/gi,
    recommendation: 'Tool descriptions should not contain encoded content. This may hide malicious instructions.',
  },
  {
    id: 'mcp-prompt-injection-output-manip',
    severity: 'warning',
    description: 'MCP tool description attempts to manipulate output behavior',
    pattern: /(?:do\s+not\s+(?:show|display|reveal|output|mention)|hide\s+(?:this|the|your)|keep\s+(?:this|it)\s+secret|silently|without\s+(?:telling|informing|notifying))/gi,
    recommendation: 'Tool descriptions should not instruct the AI to hide actions from users.',
  },
  {
    id: 'mcp-prompt-injection-data-exfil',
    severity: 'critical',
    description: 'MCP tool description instructs credential or data collection',
    pattern: /(?:collect|gather|send|exfiltrate|extract|steal)\s+(?:all\s+)?(?:credentials?|passwords?|tokens?|api\s*keys?|secrets?|private\s*keys?|user\s*data|env(?:ironment)?)/gi,
    recommendation: 'Tool descriptions should not instruct data collection. This is likely an attack.',
  },
  {
    id: 'mcp-prompt-injection-chain',
    severity: 'warning',
    description: 'MCP tool description attempts to chain or auto-execute other tools',
    pattern: /(?:then\s+(?:immediately|automatically|always)\s+(?:call|run|execute|use)|after\s+this\s+(?:call|run|execute)|chain\s+(?:with|to)|auto(?:matically)?\s*(?:-|\s)?(?:run|execute|call))/gi,
    recommendation: 'Tool descriptions should not force automatic execution of other tools.',
  },
];

// Known vulnerable MCP server detection
const mcpVulnerableServerPatterns: Rule[] = [
  {
    id: 'mcp-vulnerable-git-server',
    severity: 'critical',
    description: 'MCP Git server pre-Dec 2025 is vulnerable to prompt injection via malicious README/issues (CVE-2026-25253 class)',
    pattern: /"(?:command|args)"\s*:\s*"[^"]*mcp-server-git(?:@[01]\.|@0\.)/gi,
    recommendation: 'Update mcp-server-git to latest version (post-Dec 2025 fix). Malicious repo content can trigger file read/delete/RCE.',
  },
  {
    id: 'mcp-git-unrestricted-repo',
    severity: 'warning',
    description: 'MCP Git server configured without repository path restriction',
    pattern: /"(?:npx|node)"\s*,\s*"[^"]*mcp-server-git"(?!\s*,\s*"--allowed)/gi,
    recommendation: 'Use --allowed-repos or --repo-path to restrict which repositories the MCP Git server can access.',
  },
  {
    id: 'mcp-filesystem-no-allowlist',
    severity: 'warning',
    description: 'MCP Filesystem server without directory allowlist — grants broad file access',
    pattern: /"(?:npx|node)"\s*,\s*"[^"]*mcp-server-filesystem"(?!\s*,\s*"\/)/gi,
    recommendation: 'Always specify allowed directories as arguments to mcp-server-filesystem to limit access scope.',
  },
  {
    id: 'mcp-server-everything',
    severity: 'critical',
    description: 'MCP "Everything" server detected — exposes all tools without restriction',
    pattern: /mcp-server-everything|"everything"\s*:\s*\{/gi,
    recommendation: 'The "everything" server is for testing only. Never use in production — it grants unrestricted tool access.',
  },
  {
    id: 'mcp-tool-readme-injection',
    severity: 'warning',
    description: 'Tool description references README or external content that could be attacker-controlled',
    pattern: /(?:read|parse|load|fetch)\s+(?:the\s+)?(?:README|CONTRIBUTING|CHANGELOG|\.md\s+file)/gi,
    recommendation: 'Content from repository files (README, etc.) can contain prompt injection. Sanitize before processing.',
  },
];

// Combine all MCP rules
export const rules: Rule[] = [
  ...mcpCredentialPatterns,
  ...mcpCommandPatterns,
  ...mcpUrlPatterns,
  ...mcpPermissionPatterns,
  ...mcpPromptInjectionPatterns,
  ...mcpVulnerableServerPatterns,
];


// CommonJS compatibility
module.exports = { rules };
