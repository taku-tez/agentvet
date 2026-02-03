/**
 * AgentVet Type Definitions
 */

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info' | 'warning';

export interface Rule {
  id: string;
  name?: string;
  description: string;
  severity: Severity | string;
  pattern: RegExp;
  category?: string;
  tags?: string[];
  cwe?: string;
  recommendation?: string;
  falsePositiveCheck?: (match: RegExpMatchArray, content: string, filePath: string) => boolean;
}

export interface Finding {
  id: string;
  rule: string;
  name: string;
  description: string;
  severity: Severity;
  file: string;
  line: number;
  column?: number;
  match: string;
  context?: string;
  category?: string;
  cwe?: string;
  recommendation?: string;
  // Reporter aliases (for backwards compatibility)
  ruleId?: string;
  title?: string;
  snippet?: string;
  evidence?: string;
  attackScenario?: string;
}

export interface ScanOptions {
  /** Paths to ignore */
  ignore?: string[];
  /** Maximum file size in bytes */
  maxFileSize?: number;
  /** Custom rules to include */
  customRules?: Rule[];
  /** Output format */
  format?: 'text' | 'json' | 'sarif';
  /** Enable YARA scanning */
  yara?: boolean;
  /** Enable dependency scanning */
  deps?: boolean;
  /** Enable LLM analysis */
  llm?: boolean;
  /** LLM model to use */
  llmModel?: string;
  /** Enable URL/IP reputation checking */
  reputation?: boolean;
  /** Verbose output */
  verbose?: boolean;
  /** Minimum severity to report */
  minSeverity?: Severity;
  /** Enable parallel scanning */
  parallel?: boolean;
  /** Number of parallel workers */
  workers?: number;
}

export interface ScanResult {
  /** Target path that was scanned */
  target: string;
  /** Scan timestamp */
  timestamp: string;
  /** Duration in milliseconds */
  duration: number;
  /** Number of files scanned */
  filesScanned: number;
  /** Number of files skipped */
  filesSkipped: number;
  /** Total findings */
  findings: Finding[];
  /** Findings by severity */
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
    total: number;
  };
  /** Scanner version */
  version: string;
  /** Errors encountered during scan */
  errors?: ScanError[];
}

export interface ScanError {
  file: string;
  error: string;
}

export interface MCPConfig {
  mcpServers?: Record<string, MCPServerConfig>;
}

export interface MCPServerConfig {
  command: string;
  args?: string[];
  env?: Record<string, string>;
  disabled?: boolean;
}

export interface DependencyFinding {
  package: string;
  version: string;
  vulnerability: string;
  severity: Severity;
  cve?: string;
  recommendation?: string;
}

export interface YaraMatch {
  rule: string;
  file: string;
  strings: string[];
  tags?: string[];
}

export interface ReputationResult {
  url: string;
  ip?: string;
  malicious: boolean;
  score?: number;
  sources?: string[];
}
