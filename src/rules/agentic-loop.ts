import type { Rule } from "../types.js";

/**
 * Agentic Loop & Recursion Detection Rules
 * Detects patterns that can cause agents to enter infinite loops,
 * recursive self-invocation, or unbounded iteration without safeguards.
 *
 * References:
 * - OWASP LLM Top 10 2025 - LLM09: Misinformation (hallucination loops)
 * - AgentVet research: Autonomous agent safety
 */

export const rules: Rule[] = [
  // Self-invocation without termination condition
  {
    id: 'agentic-loop-self-invoke',
    severity: 'high',
    description: 'Agent self-invocation without clear termination condition detected',
    pattern: /(?:agent|assistant|llm|model)[\w.]*\s*\.\s*(?:run|invoke|execute|call|chat|complete|ask)\s*\([^)]*(?:agent|assistant|self|this|recursiv)[^)]*\)/gi,
    recommendation: 'Agent self-invocation can cause infinite loops. Add explicit max_iterations, recursion_depth, or loop_limit guards.',
    cwe: 'CWE-674',
  },

  // Missing iteration limit in agentic loops
  {
    id: 'agentic-loop-no-iteration-limit',
    severity: 'medium',
    description: 'Agentic loop without iteration/step limit',
    pattern: /(?:while\s*\(\s*(?:true|1|!done|running|active|loop)\s*\)|for\s*\(\s*;[^;]*;\s*\))[^{]*\{[^}]*(?:agent|llm|model|assistant|invoke|run_agent|step)[^}]*\}/gi,
    recommendation: 'Unbounded loops invoking LLMs or agents can exhaust resources. Add a max_steps or max_iterations counter with early exit.',
    cwe: 'CWE-835',
  },

  // Recursive agent calls with no depth guard
  {
    id: 'agentic-loop-recursive-no-depth',
    severity: 'high',
    description: 'Recursive agent function without depth/guard parameter',
    pattern: /(?:def|function|async\s+function|const\s+\w+\s*=\s*(?:async\s+)?\()\s*(?:run|step|loop|iterate|think|reflect)\w*[^)]*\)[^{]*\{(?:(?!(?:depth|recursion|max_depth|counter|limit|guard)\s*(?:[><=!]|>=|<=)).)*?\b(?:run|step|loop|iterate|think|reflect)\w*\s*\(/gis,
    recommendation: 'Recursive agent functions must include a depth parameter and base case. Add: if depth >= MAX_DEPTH: return.',
    cwe: 'CWE-674',
  },

  // Retry loop without max retry cap
  {
    id: 'agentic-loop-unlimited-retry',
    severity: 'medium',
    description: 'Agent retry loop without maximum retry count',
    pattern: /(?:retry|retries|attempt)\s*(?:=\s*0\s*;?\s*while\s*\(|loop|forever|unlimited)(?!(?:[^}]*max_retr|[^}]*max_attempt|[^}]*retry_limit))/gi,
    recommendation: 'Agent retry loops without limits can cause infinite retries on persistent failures. Add max_retries (recommended: 3-5).',
    cwe: 'CWE-835',
  },

  // Agent thought loop (ReAct/CoT spin without stop condition)
  {
    id: 'agentic-loop-thought-without-stop',
    severity: 'info',
    description: 'ReAct/thought-action loop without explicit stop token or condition',
    pattern: /(?:thought|action|observation)\s*=\s*(?:agent|llm|model)[\w.]*\s*\.\s*(?:run|generate|complete|predict)\([^)]*\)(?:[^;{]*\n){0,10}(?:thought|action|observation)\s*=/gi,
    recommendation: 'ReAct-style thought-action loops should include a FINAL_ANSWER or STOP token check to prevent unbounded iteration.',
    cwe: 'CWE-835',
  },
];
