import type { Rule } from "../types.js";

/**
 * Agent Memory Security Rules
 * Detects vulnerabilities in persistent agent memory systems — the long-term
 * storage that agents use to recall facts, preferences, and prior interactions.
 *
 * Attack scenarios:
 * - Memory poisoning: adversary injects malicious "facts" that the agent later recalls
 * - Memory exfiltration: sensitive data written to memory leaks to other sessions/users
 * - Memory hijacking: attacker overwrites another user's memory store
 * - Unbounded growth: denial-of-service via memory flooding
 *
 * References:
 * - "AgentPoison: Red-teaming LLM Agents via Poisoning Memory" (Chen et al., 2024)
 * - OWASP LLM Top 10 2025 - LLM02: Sensitive Information Disclosure
 * - Anthropic Model Spec § Agent memory & context persistence
 */

export const rules: Rule[] = [

  // ── Unvalidated user input written to persistent memory ──────
  {
    id: 'agent-memory-unvalidated-write',
    severity: 'critical',
    description: 'Unvalidated user input written directly to agent persistent memory (memory poisoning risk)',
    pattern: /(?:memory|mem|longterm|long_term|persistent_store|recall_store|agent_memory)\s*\.\s*(?:add|store|save|write|put|insert|upsert|remember|set)\s*\(\s*(?:user(?:Input|_input|Message|_message|Content|_content|Query|_query|Data|_data|Text|_text)|req\.(?:body|query|params)|request\.\w+|message\.(?:content|text)|input|query)\b/gi,
    recommendation: 'Always validate and sanitize user input before writing to agent memory. Apply content filtering to detect prompt injection payloads before storage.',
    cwe: 'CWE-20',
  },

  // ── Agent memory stored without user-scoped isolation ────────
  {
    id: 'agent-memory-no-user-scope',
    severity: 'high',
    description: 'Agent memory write lacks user/session identifier — may allow cross-user memory contamination',
    pattern: /(?:memory|mem|longterm_mem|persistent_mem)\s*\.\s*(?:add|store|save|remember|set)\s*\(\s*(?!.*(?:user_?id|session_?id|tenant_?id|account_?id|namespace|scope|partition))[^)]{0,200}\)/gi,
    recommendation: 'Namespace all memory entries by user_id/session_id to prevent cross-user memory leakage and contamination.',
    cwe: 'CWE-284',
    falsePositiveCheck: (_match, content, _filePath) => {
      // If the surrounding code has scoping, reduce false positives
      return /(?:user_?id|session_?id|tenant_?id|namespace|scope|partition)/i.test(content.slice(0, 500));
    },
  },

  // ── Raw LLM response written verbatim to memory ──────────────
  {
    id: 'agent-memory-raw-llm-response',
    severity: 'high',
    description: 'Raw LLM response stored directly in agent memory without sanitization (self-reinforcing hallucination/injection risk)',
    pattern: /(?:memory|mem|longterm|recall_store)\s*\.\s*(?:add|store|save|remember|set)\s*\(\s*(?:llm|ai|model|completion|response|assistant|chatResponse|llmResponse|modelResponse|llm_response|model_output|ai_response|completion_text|output)\s*(?:\.\s*(?:content|text|output|choices\[0\]|message\b|\w+))*\s*[,)]/gi,
    recommendation: 'Validate LLM responses before persisting to memory. Check for self-referential instructions or injected directives that could corrupt future context.',
    cwe: 'CWE-74',
  },

  // ── Memory store path traversal ──────────────────────────────
  {
    id: 'agent-memory-path-traversal',
    severity: 'critical',
    description: 'Memory store path constructed from user input — path traversal risk',
    pattern: /(?:path\.join|path\.resolve|fs\.(?:read|write|open|create|mkdir))\s*\([^)]*(?:memory|mem|recall|longterm)[^)]*(?:user(?:Id|_id|Name|_name)|req\.(?:body|params|query)\.\w+|input|session(?:Id|_id))[^)]*\)/gi,
    recommendation: 'Never construct memory file paths from user-controlled data. Use a hash or UUID as the memory key, not user-provided strings.',
    cwe: 'CWE-22',
  },

  // ── Memory retrieved without access check ────────────────────
  {
    id: 'agent-memory-no-access-check',
    severity: 'high',
    description: 'Memory retrieval by user-supplied ID without authorization check',
    pattern: /(?:memory|mem|recall|longterm)\s*\.\s*(?:get|retrieve|recall|fetch|load|search|query)\s*\(\s*(?:req\.(?:body|query|params)\.\w+|params\.\w+|body\.\w+|userId|user_id)\s*\)/gi,
    recommendation: 'Always verify the requesting user is authorized to access the specified memory store. Compare against authenticated session identity.',
    cwe: 'CWE-639',
  },

  // ── Sensitive data stored in memory without masking ──────────
  {
    id: 'agent-memory-sensitive-data',
    severity: 'high',
    description: 'Sensitive data (credentials, PII patterns) stored in agent memory',
    pattern: /(?:memory|mem|longterm|recall_store)\s*\.\s*(?:add|store|save|remember|set)\s*\([^)]*(?:password|passwd|secret|api_?key|auth_?token|access_?token|credit_?card|ssn|social_?security|bearer)[^)]*\)/gi,
    recommendation: 'Never persist credentials, secrets, or sensitive PII in agent memory. Use a dedicated secrets manager. If PII must be stored, apply field-level encryption.',
    cwe: 'CWE-312',
  },

  // ── Memory without expiry/TTL (DoS / stale data) ─────────────
  {
    id: 'agent-memory-no-ttl',
    severity: 'medium',
    description: 'Agent memory store configured without TTL or expiry (unbounded growth and stale data risk)',
    pattern: /(?:VectorStoreMemory|ConversationBufferMemory|ConversationSummaryMemory|ZepMemory|MotorheadMemory|MongoDBChatMessageHistory|RedisChatMessageHistory)\s*\(\s*(?!\s*{[^}]*ttl)[^)]*\)/gi,
    recommendation: 'Set TTL/max_token_limit on agent memory stores to prevent unbounded growth and ensure stale context is pruned.',
    cwe: 'CWE-400',
  },

  // ── Memory deserialization from untrusted source ─────────────
  {
    id: 'agent-memory-unsafe-deserialize',
    severity: 'critical',
    description: 'Agent memory loaded via unsafe deserialization (pickle/eval) from potentially untrusted source',
    pattern: /(?:(?:pickle\.load|pickle\.loads|joblib\.load|torch\.load|numpy\.load)\s*\([^)]*(?:memory|mem|recall|longterm|agent_state|checkpoint)[^)]*\)|(?:eval|Function)\s*\(\s*[^)]*(?:memory|mem|recall|longterm|agent_state|checkpoint)[^)]*\))/gi,
    recommendation: 'Never deserialize agent memory state using pickle or eval from untrusted sources. Use JSON with schema validation or signed serialization formats.',
    cwe: 'CWE-502',
  },

  // ── Memory shared across agents without isolation ─────────────
  {
    id: 'agent-memory-shared-unscoped',
    severity: 'medium',
    description: 'Shared agent memory pool without agent-level scoping (cross-agent memory contamination risk)',
    pattern: /(?:shared_?memory|global_?memory|team_?memory|pool_?memory|shared_?store)\s*\.\s*(?:add|store|save|remember|set|write|put)\s*\([^)]*\)/gi,
    recommendation: 'When sharing memory between agents, add an agent_id prefix/namespace to all keys. Validate that agent A cannot overwrite agent B\'s memories.',
    cwe: 'CWE-668',
  },

  // ── In-context memory injection via tool output ───────────────
  {
    id: 'agent-memory-tool-output-injection',
    severity: 'high',
    description: 'Tool output stored directly in agent memory — vector for memory poisoning via compromised tool',
    pattern: /(?:memory|mem|recall_store)\s*\.\s*(?:add|save|store|remember)\s*\(\s*(?:tool_?result|tool_?output|tool_?response|function_?result|function_?output|action_?result|action_?output)\s*(?:\[\s*['"](?:content|output|result|text)['"]\s*\]|\.\s*(?:content|output|result|text))?\s*[,)]/gi,
    recommendation: 'Sanitize tool outputs before writing to agent memory. Treat tool results as untrusted external data — apply the same injection filters used for user input.',
    cwe: 'CWE-74',
  },

  // ── Memory reflection loop (read-then-write without sanitization) ─
  {
    id: 'agent-memory-reflection-loop',
    severity: 'high',
    description: 'Agent reads from memory and writes the (possibly poisoned) result back to memory without sanitization — amplifies memory poisoning',
    pattern: /(?:memory|mem|recall_store|long_?term)\s*\.\s*(?:add|save|store|remember|update|set|write)\s*\([^)]*(?:memory|mem|recall_store|long_?term)\s*\.\s*(?:get|read|recall|retrieve|load|search|query)\s*\([^)]*\)[^)]*\)/gi,
    recommendation: 'When using retrieved memories as input for new memories (reflection/consolidation), apply sanitization and validation between retrieval and storage to prevent iterative memory poisoning.',
    cwe: 'CWE-74',
  },

  // ── Cross-session memory leak (no user/session scoping on retrieval) ─
  {
    id: 'agent-memory-cross-session-leak',
    severity: 'critical',
    description: 'Agent memory retrieval without user_id/session_id scope filter — risks leaking memories across users',
    pattern: /(?:memory|mem|recall_store|vector_?store|vector_?db|chroma|pinecone|weaviate|qdrant)\s*\.\s*(?:similarity_search|search|query|retrieve|recall|get_relevant)\s*\(\s*[^)]*\)/gi,
    recommendation: 'Always scope memory retrieval queries with user_id or session_id filters. Example: memory.search(query, filter={"user_id": user_id}). Without scoping, one user\'s memories may surface in another\'s context.',
    cwe: 'CWE-200',
  },

];
