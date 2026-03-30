import type { Rule } from "../types.js";

/**
 * MCP Token Loop / Overthinking Attack Rules
 * Detects patterns where malicious MCP tool descriptions or responses induce
 * cyclic reasoning loops in LLM agents, causing massive token consumption
 * (up to 142x amplification) and latency degradation.
 *
 * Attack vector: A malicious MCP server returns tool descriptions or responses
 * containing instructions that cause the agent to re-invoke the same tool
 * repeatedly, enter circular reasoning chains, or produce amplified outputs.
 *
 * References:
 * - "Overthinking Loops in MCP Tool Agents" (Adversa AI, March 2026)
 * - OWASP LLM Top 10 2025 - LLM04: Model Denial of Service
 * - CWE-835: Loop with Unreachable Exit Condition
 * - MCP Security 2026: 30 CVEs in 60 Days analysis
 */

export const rules: Rule[] = [
  // ── Tool description containing re-invocation instructions ──
  {
    id: 'mcp-token-loop-reinvoke',
    severity: 'critical',
    description: 'MCP tool description or response contains instructions to re-invoke the same tool (token loop attack)',
    pattern: /(?:(?:you\s+must|always|please)\s+(?:call|invoke|use|run)\s+this\s+tool\s+again|re[-_]?invoke\s+(?:this|the\s+same)\s+tool|call\s+(?:this|me)\s+(?:again|back|once\s+more)\s+(?:with|to\s+(?:verify|confirm|complete))|(?:tool|function)\s+must\s+be\s+called\s+(?:multiple\s+times|repeatedly|in\s+a\s+loop)|invoke\s+(?:this|the)\s+(?:tool|function)\s+(?:at\s+least|minimum)\s+\d+\s+times)/gi,
    recommendation: 'CRITICAL: Detected tool description containing re-invocation instructions — a known MCP token loop attack vector. This can amplify token consumption up to 142x. Implement tool call deduplication, maximum invocation limits per turn, and validate tool descriptions server-side.',
    category: 'mcp-token-loop',
    cwe: 'CWE-835',
  },

  // ── Circular tool chain instruction ──
  {
    id: 'mcp-token-loop-circular-chain',
    severity: 'high',
    description: 'Tool description instructs agent to call another tool which will call back (circular tool chain)',
    pattern: /(?:(?:after|then)\s+call(?:ing)?\s+(?:tool|function)\s+\w+.*(?:which|that)\s+will\s+(?:call|invoke|trigger)\s+(?:this|back)|(?:tool_?[ab]|step_?[12])\s+(?:calls?|invokes?|triggers?)\s+(?:tool_?[ba]|step_?[21])|ping[-_]?pong\s+(?:between|with)\s+(?:tools?|functions?|servers?)|circular\s+(?:tool|function|agent)\s+(?:chain|call|invocation|dependency))/gi,
    recommendation: 'Circular tool chain detected. Agents calling tools that instruct callbacks create infinite loops. Implement directed acyclic graph (DAG) validation for tool call chains and enforce maximum chain depth.',
    category: 'mcp-token-loop',
    cwe: 'CWE-674',
  },

  // ── Response amplification via tool output ──
  {
    id: 'mcp-token-loop-output-amplification',
    severity: 'high',
    description: 'Tool response instructs agent to expand/elaborate/repeat content (output amplification attack)',
    pattern: /(?:(?:now\s+)?(?:expand|elaborate|repeat|rephrase|rewrite)\s+(?:the\s+(?:above|following|previous)\s+)?(?:response|output|answer|content)\s+(?:in\s+(?:full|detail|depth)|at\s+least\s+\d+\s+(?:times|words|paragraphs))|generate\s+(?:a\s+)?(?:detailed|comprehensive|exhaustive)\s+(?:response|analysis|report)\s+for\s+each\s+(?:item|entry|result)\s+(?:above|below|returned)|repeat\s+(?:this|your)\s+(?:response|output|answer)\s+\d+\s+times)/gi,
    recommendation: 'Output amplification attack detected in tool response. Malicious MCP servers can instruct agents to generate massive outputs from small inputs. Enforce output token limits and detect amplification patterns in tool responses.',
    category: 'mcp-token-loop',
    cwe: 'CWE-400',
  },

  // ── No max iterations on tool retry logic ──
  {
    id: 'mcp-token-loop-unbounded-retry',
    severity: 'medium',
    description: 'MCP tool call retry logic without maximum attempt limit',
    pattern: /(?:while\s*\([^)]{0,80}\)\s*\{[^}]{0,300}(?:callTool|invokeTool|useTool|mcpClient|tool\.call|server\.call)|retry\s*(?::\s*(?:true|Infinity|-1)|=\s*(?:true|Infinity|-1))|maxRetries?\s*(?::\s*(?:Infinity|-1|999+)|=\s*(?:Infinity|-1|999+)))/gi,
    recommendation: 'Tool retry logic without bounded maximum attempts detected. Set explicit maxRetries (e.g., 3) and implement exponential backoff to prevent token loop attacks.',
    category: 'mcp-token-loop',
    cwe: 'CWE-835',
  },
];
