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

// Combine all MCP rules
const rules = [
  ...mcpCredentialPatterns,
  ...mcpCommandPatterns,
  ...mcpUrlPatterns,
  ...mcpPermissionPatterns,
];

module.exports = { rules };
