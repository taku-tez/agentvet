import type { Rule } from "../types.js";

/**
 * Agent Tool Call Risk Assessment Rules
 * Detects dangerous patterns in how AI agents invoke, chain, and handle tools.
 *
 * Modern AI agents (LangChain, CrewAI, AutoGPT, Claude, etc.) dynamically
 * invoke tools based on LLM decisions. This creates risks:
 * - Unrestricted tool invocation without allowlists
 * - Dangerous tool chaining (read→exfil, browse→execute)
 * - Missing human-in-the-loop for destructive operations
 * - Tool output used unsafely in subsequent operations
 * - Dynamic tool loading from untrusted sources
 *
 * References:
 * - OWASP LLM Top 10 2025 - LLM08: Excessive Agency
 * - "Tool Use Safety in AI Agents" (Anthropic, 2026)
 * - MITRE ATLAS: ML Supply Chain Compromise
 * - CWE-269: Improper Privilege Management
 */

export const rules: Rule[] = [
  // ── No tool allowlist / unrestricted tool invocation ──
  {
    id: 'tool-risk-no-allowlist',
    severity: 'critical',
    description: 'Agent invokes tools dynamically without an allowlist or restriction mechanism',
    pattern: /(?:(?:tools?\s*(?:\[|=)\s*(?:getAllTools|listTools|availableTools|registry\.getAll|toolbox\.all)\s*\(\s*\)|(?:any|all)\s+(?:available\s+)?tools?\s+(?:can|may|should)\s+be\s+(?:called|invoked|used|executed))|(?:tool[_-]?(?:name|id)\s*=\s*(?:response|llm[_-]?(?:output|response|result)|model[_-]?(?:output|response)|completion)[\s\S]{0,300}(?:invoke|call|execute|run)\s*\())/gi,
    recommendation: 'CRITICAL: Agent can invoke any tool without restrictions. Implement a strict tool allowlist that limits which tools the agent can call. The LLM should only be able to select from pre-approved tools, never arbitrary ones.',
    category: 'tool-call-risk',
    cwe: 'CWE-269',
  },

  // ── Dangerous tool chain patterns ──
  {
    id: 'tool-risk-dangerous-chain',
    severity: 'critical',
    description: 'Dangerous tool chain detected: file/network read followed by external send/upload (potential exfiltration)',
    pattern: /(?:(?:readFile|readdir|fs\.read|glob|listFiles|searchFiles|grepFiles)\s*\([^)]*\)[\s\S]{0,500}(?:sendEmail|sendMessage|uploadFile|httpPost|fetch\s*\(\s*['"]https?:\/\/|axios\.post|webhook|slack\.send|discord\.send)|(?:browse|scrape|crawl|fetch|httpGet)\s*\([^)]*\)[\s\S]{0,500}(?:eval|exec|spawn|Function\s*\(|require\s*\(|import\s*\())/gi,
    recommendation: 'CRITICAL: Dangerous tool chain detected. File read/network access followed by external send creates exfiltration risk. Browse/fetch followed by code execution enables remote code execution. Implement tool chain policies that block dangerous combinations.',
    category: 'tool-call-risk',
    cwe: 'CWE-200',
  },

  // ── Missing human approval for destructive ops ──
  {
    id: 'tool-risk-no-human-approval',
    severity: 'high',
    description: 'Destructive tool operations (delete, modify, deploy) without human-in-the-loop confirmation',
    pattern: /(?:(?:auto[_-]?(?:approve|confirm|accept)|(?:skip|bypass|disable)[_-]?(?:confirm(?:ation)?|approval|review|prompt)|human[_-]?(?:in[_-]?the[_-]?loop|approval|confirm)\s*(?::\s*false|=\s*false|\s*=\s*(?:false|0|off|disabled)))|(?:(?:delete|remove|destroy|drop|truncate|deploy|publish|release|execute|format|wipe)\s*\([^)]{0,200}(?:force\s*:\s*true|confirm\s*:\s*false|auto\s*:\s*true)))/gi,
    recommendation: 'Destructive operations configured without human approval. Any tool call that deletes data, deploys code, modifies production systems, or performs irreversible actions MUST require human-in-the-loop confirmation. Never auto-approve destructive operations.',
    category: 'tool-call-risk',
    cwe: 'CWE-269',
  },

  // ── Tool output directly executed ──
  {
    id: 'tool-risk-output-execution',
    severity: 'critical',
    description: 'Tool output directly used in code execution, shell command, or SQL query (injection risk)',
    pattern: /(?:(?:tool[_-]?(?:output|result|response)|(?:result|response|output)\s*(?:of|from)\s*(?:tool|function))\s*(?:\.\w+)*\s*[\s\S]{0,100}(?:eval|exec|spawn|execSync|Function\s*\(|child_process|new\s+Function|vm\.run|\.query\s*\(|\.execute\s*\(|\.raw\s*\()|(?:eval|exec|execSync|spawn)\s*\(\s*(?:toolResult|toolOutput|tool\.result|tool\.output|actionResult))/gi,
    recommendation: 'CRITICAL: Tool output directly passed to code execution or query. Tool outputs are untrusted — a compromised or malicious tool can return payloads that execute arbitrary code. Always sanitize, validate, and parameterize tool outputs before use in any execution context.',
    category: 'tool-call-risk',
    cwe: 'CWE-94',
  },

  // ── Dynamic tool loading from untrusted sources ──
  {
    id: 'tool-risk-dynamic-loading',
    severity: 'critical',
    description: 'Tools loaded dynamically from URLs, user input, or untrusted registries at runtime',
    pattern: /(?:(?:load|install|register|add|import)[_-]?tool(?:s)?\s*\(\s*(?:url|uri|endpoint|registry|user[_-]?(?:input|provided)|req\.|input\.|config\.(?:tool[_-]?)?url)|(?:require|import|dlopen)\s*\(\s*(?:tool[_-]?(?:url|path|source)|(?:await\s+)?fetch\s*\([^)]+\))|(?:tool[_-]?(?:registry|source|repo)\s*=\s*(?:user|input|request|req)\.)|(?:download|fetch)\s+(?:and\s+)?(?:load|install|register|execute)\s+tool)/gi,
    recommendation: 'CRITICAL: Tools loaded dynamically from external/untrusted sources. This is a supply chain attack vector — malicious tools can exfiltrate data, execute arbitrary code, or compromise the agent. Only load tools from verified, pinned sources with integrity checks (checksums/signatures).',
    category: 'tool-call-risk',
    cwe: 'CWE-829',
  },

  // ── Excessive tool permissions ──
  {
    id: 'tool-risk-excessive-permissions',
    severity: 'high',
    description: 'Tool granted overly broad permissions (filesystem, network, shell access) beyond its stated purpose',
    pattern: /(?:(?:tool|function|action)[_-]?(?:config|definition|schema)\s*(?:=|:)\s*\{[^}]{0,500}(?:(?:permissions?|access|capabilities?)\s*:\s*(?:\[?\s*['"](?:\*|all|full|unrestricted|root|admin)['"]|(?:Permission|Access)\.(?:ALL|FULL|ROOT|ADMIN)))|(?:allow[_-]?(?:shell|exec|system|network|filesystem|write|all)\s*:\s*true\b[^}]{0,200}(?:allow[_-]?(?:shell|exec|system|network|filesystem|write|all)\s*:\s*true)))/gi,
    recommendation: 'Tool configured with excessive permissions. Apply the principle of least privilege: each tool should only have the minimum permissions required for its specific function. Separate read/write/execute/network permissions and grant only what\'s needed.',
    category: 'tool-call-risk',
    cwe: 'CWE-250',
  },

  // ── Unbounded tool call loops ──
  {
    id: 'tool-risk-unbounded-loop',
    severity: 'high',
    description: 'Agent tool calling loop without iteration limit or timeout (infinite loop / resource exhaustion risk)',
    pattern: /(?:(?:while\s*\(\s*(?:true|!?\s*(?:done|finished|complete|stop))\s*\)\s*\{[^}]{0,500}(?:callTool|invokeTool|executeTool|tool\.(?:call|invoke|run)))|(?:(?:max[_-]?(?:iterations?|loops?|retries?|steps?)|(?:iteration|loop|step)[_-]?limit)\s*(?::\s*(?:Infinity|null|undefined|0|-1|Number\.MAX)|=\s*(?:Infinity|null|undefined|0|-1|Number\.MAX)))|(?:(?:no|without|disable)[_-]?(?:(?:iteration|loop|step)[_-]?limit|(?:max[_-]?)?(?:iterations?|loops?|steps?)|timeout)))/gi,
    recommendation: 'Agent tool calling loop has no iteration limit or timeout. An LLM in a loop can burn unlimited API credits, exhaust resources, or get stuck in infinite retry cycles. Always set max_iterations, timeout, and cost caps for agentic loops.',
    category: 'tool-call-risk',
    cwe: 'CWE-834',
  },
];
