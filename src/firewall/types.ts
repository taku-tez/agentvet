/**
 * Prompt Firewall Types
 */

export interface FirewallConfig {
  version: string;
  name?: string;
  description?: string;

  /** Inbound filter: detect injection in user/client messages */
  inbound: FilterConfig;

  /** Outbound filter: detect hidden prompts in tool responses */
  outbound: FilterConfig;

  /** Context protection: block system prompt extraction attempts */
  context_protection: ContextProtectionConfig;

  /** Custom allow/deny patterns */
  custom_patterns?: CustomPattern[];

  /** Audit log settings */
  audit: AuditConfig;

  /** Action thresholds */
  thresholds?: {
    /** Score above which to block (default: 30) */
    block: number;
    /** Score above which to warn (default: 15) */
    warn: number;
  };
}

export interface FilterConfig {
  enabled: boolean;
  action: 'block' | 'warn' | 'log';
  /** Additional pattern categories to enable */
  categories?: string[];
}

export interface ContextProtectionConfig {
  enabled: boolean;
  action: 'block' | 'warn' | 'log';
  /** Canary token to detect if system prompt leaks */
  canary_token?: string;
}

export interface CustomPattern {
  id: string;
  description?: string;
  pattern: string; // regex
  category: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  direction: 'inbound' | 'outbound' | 'both';
  action?: 'block' | 'warn' | 'log';
}

export interface AuditConfig {
  enabled: boolean;
  file?: string; // log file path
  format?: 'json' | 'text';
  /** Include full request/response in log */
  include_content?: boolean;
}

export interface FirewallEvent {
  timestamp: string;
  direction: 'inbound' | 'outbound' | 'context';
  method: string;
  toolName?: string;
  action: 'block' | 'warn' | 'log' | 'allow';
  score: number;
  patterns: string[];
  categories: string[];
  requestId?: string | number;
  detail?: string;
}

export interface FirewallStats {
  startTime: string;
  totalRequests: number;
  totalResponses: number;
  inboundBlocked: number;
  inboundWarned: number;
  outboundBlocked: number;
  outboundWarned: number;
  contextBlocked: number;
  topPatterns: Array<{ pattern: string; count: number }>;
}
