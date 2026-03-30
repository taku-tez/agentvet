import type { Rule } from "../types.js";

/**
 * MCP Command Injection Detection Rules
 * Detects shell/OS command injection vulnerabilities in MCP tool implementations.
 *
 * 43% of MCP CVEs in early 2026 involved shell or command injection.
 * MCP tool handlers that pass user/agent input to shell commands without
 * sanitization are the single largest attack surface.
 *
 * References:
 * - 30+ MCP CVEs filed Jan-Feb 2026 (toolradar.com analysis)
 * - OWASP LLM Top 10 2025 - LLM01: Prompt Injection
 * - CWE-78: OS Command Injection
 */

export const rules: Rule[] = [
  // ── MCP tool handler executes shell commands with user input ──
  {
    id: 'mcp-cmdinj-exec-tool-input',
    severity: 'critical',
    description: 'MCP tool handler passes tool input directly to shell exec (command injection)',
    pattern: /(?:tools?\s*[\[{(]|handle_call|tool_handler|CallToolRequest)[^}]*(?:exec|execSync|spawn|spawnSync|child_process|subprocess|os\.system|os\.popen|Popen|shell_exec|system\(|popen\(|proc_open)/gis,
    recommendation: 'Never pass MCP tool inputs directly to shell commands. Use parameterized APIs or allowlisted commands with strict input validation.',
    cwe: 'CWE-78',
    category: 'mcp-command-injection',
  },

  // ── Template string in shell command with MCP arguments ──
  {
    id: 'mcp-cmdinj-template-shell',
    severity: 'critical',
    description: 'Shell command built via template literal/string interpolation with tool arguments',
    pattern: /(?:exec|execSync|spawn|system|popen|shell_exec|proc_open|subprocess\.run|os\.system)\s*\(\s*(?:`[^`]*\$\{(?:args?|params?|input|request|query|path|filename|url|command|tool)[^`]*`|f["'][^"']*\{(?:args?|params?|input|request|query|path|filename|url|command|tool)[^"']*["']|["'][^"']*["']\s*\+\s*(?:args?|params?|input|request|query|path|filename|url|command|tool))/gi,
    recommendation: 'String interpolation in shell commands is the primary vector for MCP command injection. Use execFile with argument arrays or a strict allowlist.',
    cwe: 'CWE-78',
    category: 'mcp-command-injection',
  },

  // ── MCP server using eval/Function with tool inputs ──
  {
    id: 'mcp-cmdinj-eval-tool-input',
    severity: 'critical',
    description: 'MCP server uses eval() or Function() with tool input parameters',
    pattern: /(?:tool|handler|server|mcp)[^{]*\{[^}]*(?:eval|Function|vm\.runInContext|vm\.runInNewContext|new\s+Function)\s*\([^)]*(?:args?|params?|input|request|query|content|code|expression|script)/gis,
    recommendation: 'Using eval/Function with tool inputs enables arbitrary code execution. Use a sandboxed interpreter or pre-defined operation set.',
    cwe: 'CWE-95',
    category: 'mcp-command-injection',
  },

  // ── Unsanitized path in file operations from MCP tool ──
  {
    id: 'mcp-cmdinj-unsanitized-path',
    severity: 'high',
    description: 'MCP tool uses unsanitized file path from tool arguments (path traversal via command injection)',
    pattern: /(?:readFile|writeFile|readFileSync|writeFileSync|createReadStream|createWriteStream|open|unlink|rmdir|mkdir)\s*\(\s*(?:args?|params?|input|request)[\w.[\]]*\s*(?:\.(?:path|file|filename|filepath|dir|directory|folder|target))/gi,
    recommendation: 'Validate and resolve file paths against an allowed base directory. Use path.resolve() + startsWith() checks to prevent directory traversal.',
    cwe: 'CWE-22',
    category: 'mcp-command-injection',
  },

  // ── SQL injection via MCP tool parameters ──
  {
    id: 'mcp-cmdinj-sql-injection',
    severity: 'high',
    description: 'MCP tool constructs SQL query with string concatenation from tool arguments',
    pattern: /(?:query|execute|exec|run)\s*\(\s*(?:`[^`]*(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE)[^`]*\$\{(?:args?|params?|input|request)[^`]*`|["'][^"']*(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE)[^"']*["']\s*\+\s*(?:args?|params?|input|request))/gis,
    recommendation: 'Use parameterized queries (prepared statements) instead of string concatenation for SQL in MCP tool handlers.',
    cwe: 'CWE-89',
    category: 'mcp-command-injection',
  },
];
