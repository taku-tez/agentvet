import type { Rule } from "../types.js";

/**
 * Unsafe LLM Output Handling Rules
 * Detects patterns where LLM/agent output is used in dangerous sinks
 * without sanitization — e.g. eval(), SQL, shell commands, innerHTML, etc.
 *
 * This is a critical attack surface: if an attacker controls LLM input
 * (via prompt injection or RAG poisoning), unsanitized output becomes
 * a code execution / injection vector.
 *
 * References:
 * - OWASP LLM Top 10 2025 - LLM02: Insecure Output Handling
 * - CWE-94: Improper Control of Generation of Code
 * - CWE-79: Cross-site Scripting (XSS)
 * - CWE-89: SQL Injection
 * - CWE-78: OS Command Injection
 */

export const rules: Rule[] = [
  // ── Code Execution via eval / exec ────────────────────────────
  {
    id: 'unsafe-output-eval-llm',
    severity: 'critical',
    description: 'LLM/agent output passed directly to eval() or exec()',
    pattern: /(?:eval|exec|execSync|Function)\s*\(\s*(?:response|result|output|completion|answer|reply|generated|llm_output|ai_output|chat_response|agent_output|model_output)[\w.[\]]*\s*\)/gi,
    recommendation: 'Never pass LLM output to eval/exec. Use a sandboxed code runner (e.g. E2B, Pyodide, VM2) with strict resource limits and allowlisted APIs.',
    cwe: 'CWE-94',
    category: 'unsafe-output',
  },
  {
    id: 'unsafe-output-new-function',
    severity: 'critical',
    description: 'LLM output used to construct a new Function()',
    pattern: /new\s+Function\s*\([^)]*(?:response|result|output|completion|answer|generated|llm_output|ai_output|agent_output|model_output)[\w.[\]]*[^)]*\)/gi,
    recommendation: 'new Function() with LLM-generated strings is equivalent to eval(). Use a sandboxed execution environment instead.',
    cwe: 'CWE-94',
    category: 'unsafe-output',
  },
  {
    id: 'unsafe-output-python-exec',
    severity: 'critical',
    description: 'LLM output passed to Python exec() or compile()',
    pattern: /(?:exec|compile)\s*\(\s*(?:response|result|output|completion|answer|generated|llm_output|ai_output|agent_output|model_output)[\w.\[\]]*(?:\s*,|\s*\))/gi,
    recommendation: 'Never execute LLM-generated Python code via exec/compile. Use RestrictedPython or a sandboxed subprocess with seccomp/AppArmor.',
    cwe: 'CWE-94',
    category: 'unsafe-output',
  },

  // ── Shell Command Injection ───────────────────────────────────
  {
    id: 'unsafe-output-shell-injection',
    severity: 'critical',
    description: 'LLM output interpolated into shell command execution',
    pattern: /(?:child_process|subprocess|os\.system|os\.popen|Popen|execSync|spawnSync|exec)\s*\([^)]*(?:\$\{|`|\+\s*|f["']|\.format\()[^)]*(?:response|result|output|completion|answer|generated|llm_output|ai_output|agent_output|model_output)/gi,
    recommendation: 'LLM output in shell commands enables arbitrary command execution via prompt injection. Use parameterized commands or an allow-list of permitted operations.',
    cwe: 'CWE-78',
    category: 'unsafe-output',
  },
  {
    id: 'unsafe-output-shell-template',
    severity: 'critical',
    description: 'LLM output used in template literal shell command',
    pattern: /(?:execSync|exec|spawn)\s*\(\s*`[^`]*\$\{[^}]*(?:response|result|output|completion|answer|generated|llm_output|ai_output|agent_output|model_output)[^}]*\}[^`]*`/gi,
    recommendation: 'Template literal shell commands with LLM output are vulnerable to injection. Use execFile() with argument arrays instead of string interpolation.',
    cwe: 'CWE-78',
    category: 'unsafe-output',
  },

  // ── SQL Injection ─────────────────────────────────────────────
  {
    id: 'unsafe-output-sql-injection',
    severity: 'critical',
    description: 'LLM output directly interpolated into SQL query string',
    pattern: /(?:query|execute|raw|sql)\s*\(\s*(?:`[^`]*\$\{|f["'][^)]*(?:response|result|output|completion|answer|generated|llm_output|ai_output|agent_output|model_output)|["'][^"']*(?:\+|\.format|%s)[^)]*(?:response|result|output|completion|answer|generated|llm_output|ai_output|agent_output|model_output))/gi,
    recommendation: 'LLM-generated text in SQL queries enables SQL injection. Always use parameterized queries / prepared statements, even for AI-generated content.',
    cwe: 'CWE-89',
    category: 'unsafe-output',
  },
  {
    id: 'unsafe-output-sql-concat',
    severity: 'high',
    description: 'SQL query concatenated with LLM/agent output variable',
    pattern: /(?:SELECT|INSERT|UPDATE|DELETE|CREATE|DROP|ALTER)\b[^"'`]*(?:\+|\.concat\()\s*(?:response|result|output|completion|answer|generated|llm_output|ai_output|agent_output|model_output)|["'](?:SELECT|INSERT|UPDATE|DELETE|CREATE|DROP|ALTER)\b[^"']*["']\s*\+\s*(?:response|result|output|completion|answer|generated|llm_output|ai_output|agent_output|model_output)/gi,
    recommendation: 'String concatenation of SQL with LLM output is a classic injection vector. Use parameterized queries or an ORM.',
    cwe: 'CWE-89',
    category: 'unsafe-output',
  },

  // ── XSS / HTML Injection ──────────────────────────────────────
  {
    id: 'unsafe-output-innerhtml',
    severity: 'high',
    description: 'LLM output assigned to innerHTML or outerHTML (XSS risk)',
    pattern: /(?:innerHTML|outerHTML)\s*(?:=|\+=)\s*(?:response|result|output|completion|answer|generated|llm_output|ai_output|agent_output|model_output|chat_response)[\w.\[\]]*/gi,
    recommendation: 'Setting innerHTML with LLM output enables XSS. Use textContent for plain text, or sanitize with DOMPurify before rendering HTML.',
    cwe: 'CWE-79',
    category: 'unsafe-output',
  },
  {
    id: 'unsafe-output-dangerously-set',
    severity: 'high',
    description: 'LLM output passed to React dangerouslySetInnerHTML',
    pattern: /dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:\s*(?:response|result|output|completion|answer|generated|llm_output|ai_output|agent_output|model_output|chat_response)[\w.\[\]]*/gi,
    recommendation: 'dangerouslySetInnerHTML with LLM output is a direct XSS vector. Sanitize with DOMPurify or render as plain text/markdown with a safe renderer.',
    cwe: 'CWE-79',
    category: 'unsafe-output',
  },
  {
    id: 'unsafe-output-v-html',
    severity: 'high',
    description: 'LLM output bound to Vue v-html directive (XSS risk)',
    pattern: /v-html\s*=\s*["'](?:response|result|output|completion|answer|generated|llmOutput|aiOutput|agentOutput|modelOutput|chatResponse)[\w.\[\]]*["']/gi,
    recommendation: 'v-html with LLM output enables XSS in Vue applications. Use v-text or sanitize the output before rendering.',
    cwe: 'CWE-79',
    category: 'unsafe-output',
  },

  // ── Deserialization of LLM Output ─────────────────────────────
  {
    id: 'unsafe-output-json-parse-unvalidated',
    severity: 'medium',
    description: 'LLM output parsed as JSON without schema validation',
    pattern: /JSON\.parse\s*\(\s*(?:response|result|output|completion|answer|generated|llm_output|ai_output|agent_output|model_output)[\w.\[\]]*\s*\)(?!\s*(?:;?\s*(?:const|let|var)\s+\w+\s*=\s*\w+Schema|;\s*\w+\.validate|;\s*validate))/gi,
    recommendation: 'JSON.parse on LLM output without schema validation risks prototype pollution or unexpected data shapes. Validate against a JSON schema (Zod, Ajv, etc.) after parsing.',
    cwe: 'CWE-502',
    category: 'unsafe-output',
  },
  {
    id: 'unsafe-output-yaml-load',
    severity: 'critical',
    description: 'LLM output loaded via unsafe YAML parser (yaml.load / yaml.unsafe_load)',
    pattern: /yaml\.(?:load|unsafe_load)\s*\(\s*(?:response|result|output|completion|answer|generated|llm_output|ai_output|agent_output|model_output)[\w.\[\]]*/gi,
    recommendation: 'yaml.load with LLM output can execute arbitrary Python objects. Use yaml.safe_load() and validate the structure afterward.',
    cwe: 'CWE-502',
    category: 'unsafe-output',
  },

  // ── File Write with LLM Content ───────────────────────────────
  {
    id: 'unsafe-output-file-write',
    severity: 'high',
    description: 'LLM output written to filesystem without sanitization or path validation',
    pattern: /(?:writeFile|writeFileSync|write|appendFile)\s*\([^,]*,\s*(?:response|result|output|completion|answer|generated|llm_output|ai_output|agent_output|model_output)[\w.\[\]]*/gi,
    recommendation: 'Writing LLM output to files can lead to code injection (if the file is later executed) or path traversal. Validate content type and destination path before writing.',
    cwe: 'CWE-73',
    category: 'unsafe-output',
  },
  {
    id: 'unsafe-output-path-from-llm',
    severity: 'critical',
    description: 'File path derived from LLM output (path traversal risk)',
    pattern: /(?:readFile|writeFile|open|unlink|access|stat|mkdir|rmdir|createReadStream|createWriteStream)\s*\(\s*(?:response|result|output|completion|answer|generated|llm_output|ai_output|agent_output|model_output)[\w.\[\]]*/gi,
    recommendation: 'File paths from LLM output enable path traversal attacks (e.g. ../../etc/passwd). Resolve paths against a safe base directory and validate with path.resolve() + startsWith() check.',
    cwe: 'CWE-22',
    category: 'unsafe-output',
  },

  // ── HTTP Request with LLM-Controlled URL ──────────────────────
  {
    id: 'unsafe-output-ssrf-url',
    severity: 'high',
    description: 'HTTP request URL derived from LLM output (SSRF risk)',
    pattern: /(?:fetch|axios|got|request|http\.get|urllib\.request|requests\.get|requests\.post)\s*\(\s*(?:response|result|output|completion|answer|generated|llm_output|ai_output|agent_output|model_output)[\w.\[\]]*/gi,
    recommendation: 'URLs from LLM output can target internal services (SSRF). Validate against an allowlist of domains and block private IP ranges before making requests.',
    cwe: 'CWE-918',
    category: 'unsafe-output',
  },

  // ── Dynamic import / require with LLM content ─────────────────
  {
    id: 'unsafe-output-dynamic-import',
    severity: 'critical',
    description: 'Dynamic import() or require() with LLM-generated module path',
    pattern: /(?:import|require)\s*\(\s*(?:response|result|output|completion|answer|generated|llm_output|ai_output|agent_output|model_output)[\w.\[\]]*/gi,
    recommendation: 'Dynamic imports with LLM-controlled paths allow loading arbitrary modules — effectively remote code execution. Use a static allowlist of importable modules.',
    cwe: 'CWE-94',
    category: 'unsafe-output',
  },

  // ── Regex from LLM output (ReDoS) ────────────────────────────
  {
    id: 'unsafe-output-regex-injection',
    severity: 'medium',
    description: 'Regular expression constructed from LLM output (ReDoS risk)',
    pattern: /new\s+RegExp\s*\(\s*(?:response|result|output|completion|answer|generated|llm_output|ai_output|agent_output|model_output)[\w.\[\]]*/gi,
    recommendation: 'LLM-generated regex patterns can cause catastrophic backtracking (ReDoS). Use a regex sanitizer or set a timeout on regex execution.',
    cwe: 'CWE-1333',
    category: 'unsafe-output',
  },
];

// CommonJS compatibility
module.exports = { rules };
