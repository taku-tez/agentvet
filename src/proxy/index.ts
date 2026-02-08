/**
 * MCP Proxy Module - Runtime protection for MCP tool calls
 */

export { MCPProxyServer } from './server.js';
export { PolicyEngine } from './policy.js';
export { detectInjection, INJECTION_PATTERNS } from './injection.js';
export type { InjectionDetection, InjectionMatch } from './injection.js';
export type { ProxyPolicy, PolicyRule, PolicyMatch, ProxyOptions, ProxyEvent, MCPJsonRpcRequest, MCPJsonRpcResponse } from './types.js';
