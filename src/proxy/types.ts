/**
 * MCP Proxy Types
 */

export interface ProxyPolicy {
  version: string;
  name?: string;
  description?: string;
  rules: PolicyRule[];
  defaults?: {
    action: 'allow' | 'block' | 'warn';
    logLevel?: 'debug' | 'info' | 'warn' | 'error';
  };
  injection?: {
    enabled: boolean;
    action: 'block' | 'warn' | 'log';
    patterns?: string[];
  };
}

export interface PolicyRule {
  id: string;
  description?: string;
  match: PolicyMatch;
  action: 'allow' | 'block' | 'warn';
  reason?: string;
}

export interface PolicyMatch {
  tool?: string | string[];
  toolPattern?: string;
  server?: string | string[];
  args?: Record<string, PolicyArgMatch>;
}

export interface PolicyArgMatch {
  contains?: string | string[];
  matches?: string;
  equals?: string;
  not?: PolicyArgMatch;
}

export interface MCPJsonRpcRequest {
  jsonrpc: '2.0';
  id: number | string;
  method: string;
  params?: Record<string, any>;
}

export interface MCPJsonRpcResponse {
  jsonrpc: '2.0';
  id: number | string;
  result?: any;
  error?: { code: number; message: string; data?: any };
}

export interface ProxyEvent {
  timestamp: string;
  type: 'request' | 'response' | 'block' | 'warn' | 'injection';
  method: string;
  toolName?: string;
  args?: Record<string, any>;
  action: string;
  reason?: string;
  ruleId?: string;
}

export interface ProxyOptions {
  port: number;
  upstream: string;
  policy: ProxyPolicy;
  logFile?: string;
  verbose?: boolean;
  dryRun?: boolean;
}
