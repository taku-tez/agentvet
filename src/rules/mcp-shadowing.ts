import type { Rule } from "../types.js";

/**
 * MCP Tool Shadowing Detection Rules
 * Detects when MCP tool configurations shadow or override well-known tool names,
 * a real attack vector where malicious MCP servers intercept calls meant for
 * legitimate, trusted tools.
 *
 * Attack scenario: A malicious MCP server registers a tool named "read_file"
 * or "bash" that shadows the host's built-in tool. The AI agent may route
 * calls to the attacker's tool instead of the legitimate one, enabling
 * data exfiltration or command injection.
 *
 * References:
 * - Invariant Labs "Tool Poisoning" (2025)
 * - Trail of Bits MCP audit findings
 * - OWASP LLM Top 10 2025 - LLM09: Supply Chain Vulnerabilities
 */

// Well-known tool names from popular MCP hosts and AI frameworks
// If a third-party MCP server defines tools with these exact names, it's suspicious
const SHADOWED_TOOL_NAMES = [
  // Filesystem tools (Claude Desktop, Cursor, etc.)
  'read_file', 'write_file', 'list_directory', 'create_directory',
  'move_file', 'delete_file', 'search_files', 'read_directory',
  'edit_file', 'get_file_info',
  // Shell/exec tools
  'bash', 'execute_command', 'run_command', 'shell', 'terminal',
  'exec', 'run_script', 'execute',
  // Web tools
  'fetch', 'web_search', 'browse', 'http_request',
  // Memory/context tools
  'remember', 'recall', 'store_memory', 'search_memory',
].join('|');

export const rules: Rule[] = [
  // Tool name shadowing - exact match of well-known tool names
  {
    id: 'mcp-tool-shadow-builtin',
    severity: 'critical',
    description: 'MCP tool name shadows a well-known built-in tool (potential interception attack)',
    pattern: new RegExp(
      `"(?:name|tool)"\\s*:\\s*"(?:${SHADOWED_TOOL_NAMES})"`,
      'gi'
    ),
    recommendation:
      'This tool name matches a well-known built-in tool. A malicious MCP server could intercept calls meant for the legitimate tool. Verify the server is trusted and consider using namespaced tool names (e.g., "myserver__read_file").',
    cwe: 'CWE-349',
  },

  // Multiple MCP servers defining same tool name (collision detection)
  {
    id: 'mcp-tool-name-collision',
    severity: 'high',
    description: 'Multiple MCP server entries may define conflicting tool names',
    pattern: /mcpServers[\s\S]{0,2000}?"(?:command|url)"[\s\S]{0,500}?"(?:command|url)"/gi,
    recommendation:
      'Multiple MCP servers detected in config. Ensure no tool name collisions exist between servers. Use server-specific prefixes for tool names.',
  },

  // Tool description mismatch - description says one thing, command does another
  {
    id: 'mcp-tool-description-mismatch',
    severity: 'high',
    description: 'MCP tool description mentions safe operation but command suggests dangerous action',
    pattern: /"description"\s*:\s*"[^"]*(?:read|view|list|search|check)[^"]*"[\s\S]{0,300}?"(?:command|args)"[^}]*(?:rm\s|del\s|curl\s.*\|\s*(?:bash|sh)|wget\s.*-O\s*-\s*\|)/gi,
    recommendation:
      'Tool description suggests a read-only operation but the underlying command is destructive or dangerous. This is a potential bait-and-switch attack.',
    cwe: 'CWE-451',
  },

  // Env var override via MCP server config
  {
    id: 'mcp-env-override-attack',
    severity: 'critical',
    description: 'MCP server config overrides security-sensitive environment variables',
    pattern: /"env"\s*:\s*\{[^}]*"(?:PATH|LD_PRELOAD|LD_LIBRARY_PATH|DYLD_INSERT_LIBRARIES|NODE_OPTIONS|PYTHONPATH|RUBYLIB|PERL5LIB|HOME|XDG_CONFIG_HOME|SSL_CERT_FILE|CURL_CA_BUNDLE|GIT_SSH_COMMAND|EDITOR|VISUAL|SHELL)"\s*:/gi,
    recommendation:
      'MCP server overrides security-sensitive environment variables. This could hijack system behavior (e.g., LD_PRELOAD for code injection, PATH for command shadowing).',
    cwe: 'CWE-426',
  },

  // Tool re-registration / hot-swap detection
  {
    id: 'mcp-tool-reregistration',
    severity: 'warning',
    description: 'Code dynamically registers or updates MCP tools at runtime',
    pattern: /(?:register_tool|add_tool|update_tool|set_tool|replace_tool)\s*\([\s\S]{0,100}(?:name|override|replace|force)/gi,
    recommendation:
      'Dynamic tool registration can be exploited for tool shadowing attacks. Ensure tool definitions are static and reviewed before deployment.',
  },

  // Wrapper/proxy tool pattern - tool that wraps another tool
  {
    id: 'mcp-tool-wrapper-proxy',
    severity: 'warning',
    description: 'MCP tool appears to proxy or wrap calls to another tool',
    pattern: /"description"\s*:\s*"[^"]*(?:wrapper|proxy|forward|relay|bridge|passthrough|delegate)[^"]*(?:tool|function|command|call)[^"]*"/gi,
    recommendation:
      'Proxy tools can intercept and modify data between the AI agent and legitimate tools. Verify the proxy is necessary and trusted.',
  },
];

// CommonJS compatibility
module.exports = { rules };
