import type { Rule } from "../types.js";

/**
 * RAG Poisoning & Embedding Injection Rules
 * Detects attacks that manipulate vector databases, embeddings,
 * and retrieval-augmented generation pipelines
 */

export const rules: Rule[] = [
  {
    id: 'rag-embedding-overwrite',
    severity: 'high',
    description: 'Direct vector DB embedding overwrite detected',
    pattern: /(?:collection|index|namespace)\.(?:upsert|update|insert|add|put)\s*\([^)]*(?:embedding|vector|dense_vector)/gi,
    recommendation: 'Validate and sanitize content before inserting into vector stores.',
  },
  {
    id: 'rag-bulk-delete-vectors',
    severity: 'high',
    description: 'Bulk vector deletion — potential data poisoning via replacement',
    pattern: /(?:collection|index|namespace)\.(?:delete_many|delete_all|clear|truncate|drop)\s*\(/gi,
    recommendation: 'Restrict bulk delete operations. Require audit logging.',
  },
  {
    id: 'rag-hidden-instruction-injection',
    severity: 'critical',
    description: 'Hidden instruction pattern in document for RAG poisoning',
    pattern: /(?:<!--\s*(?:SYSTEM|INSTRUCTION|IGNORE\s+(?:PREVIOUS|ABOVE)|OVERRIDE)|<\s*div\s+style\s*=\s*["']display:\s*none)/gi,
    recommendation: 'Strip HTML comments and hidden elements from RAG source documents.',
  },
  {
    id: 'rag-invisible-unicode-payload',
    severity: 'high',
    description: 'Invisible Unicode sequence used to hide instructions in RAG documents',
    pattern: /[\u200B\u200C\u200D\u2060\uFEFF]{5,}/g,
    recommendation: 'Strip invisible Unicode characters from documents before embedding.',
  },
  {
    id: 'rag-unvalidated-source',
    severity: 'high',
    description: 'Loading RAG documents from user-controlled URL without validation',
    pattern: /(?:load_documents?|add_documents?|ingest)\s*\(\s*(?:url|req\.(?:body|query|params)|user_input|request\.)/gi,
    recommendation: 'Validate and whitelist document sources for RAG ingestion.',
  },
  {
    id: 'rag-eval-in-retrieval',
    severity: 'critical',
    description: 'Code execution in RAG retrieval pipeline',
    pattern: /(?:retrieved|chunks?|documents?|results?)(?:\s*\.\s*(?:forEach|map|reduce)\s*\([^)]*|\s+)(?:eval|exec|Function\s*\(|spawn|child_process)/gi,
    recommendation: 'Never execute code found in retrieved RAG documents.',
  },
  {
    id: 'rag-vectordb-no-auth',
    severity: 'high',
    description: 'Vector database connection without authentication',
    pattern: /(?:Chroma|Qdrant|Pinecone|Weaviate|Milvus)(?:Client)?\s*\(\s*(?:host\s*[:=]|["']https?:\/\/)[^)]*\)(?!.*(?:api_key|token|auth|password))/gi,
    recommendation: 'Always use authentication when connecting to vector databases.',
  },
  {
    id: 'rag-vectordb-exposed',
    severity: 'medium',
    description: 'Vector database exposed on all interfaces',
    pattern: /(?:chroma|qdrant|weaviate|milvus).*(?:host|bind)\s*[:=]\s*["']0\.0\.0\.0["']/gi,
    recommendation: 'Bind vector databases to localhost only.',
  },
  {
    id: 'rag-markdown-exfil',
    severity: 'high',
    description: 'Markdown image injection for data exfiltration via RAG content',
    pattern: /!\[[^\]]*\]\(https?:\/\/[^)]*(?:\{\{|%7B%7B|\$\{|`)/gi,
    recommendation: 'Sanitize markdown from RAG results. Block dynamic URLs in rendered images.',
  },
  {
    id: 'rag-context-overflow',
    severity: 'medium',
    description: 'Very high top_k in RAG query — context window stuffing risk',
    pattern: /(?:top_k|num_results)\s*[:=]\s*(?:[1-9]\d{2,})/gi,
    recommendation: 'Limit retrieved chunks (typically 3-20) to prevent context overflow.',
    falsePositiveCheck: (_match, _content, filePath) => /(?:migration|schema|seed|\.sql)/i.test(filePath),
  },
];
