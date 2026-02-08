/**
 * Policy Engine - Evaluates MCP tool calls against policy rules
 */

import type { ProxyPolicy, PolicyRule, PolicyMatch, PolicyArgMatch, MCPJsonRpcRequest, ProxyEvent } from './types.js';

export class PolicyEngine {
  private policy: ProxyPolicy;
  private events: ProxyEvent[] = [];

  constructor(policy: ProxyPolicy) {
    this.policy = policy;
  }

  /**
   * Evaluate a JSON-RPC request against the policy
   */
  evaluate(request: MCPJsonRpcRequest): { action: 'allow' | 'block' | 'warn'; rule?: PolicyRule; reason?: string } {
    // Only intercept tools/call
    if (request.method !== 'tools/call') {
      return { action: 'allow' };
    }

    const toolName = request.params?.name as string;
    const args = request.params?.arguments as Record<string, any> ?? {};

    // Check each rule in order (first match wins)
    for (const rule of this.policy.rules) {
      if (this.matchesRule(rule, toolName, args)) {
        this.logEvent({
          timestamp: new Date().toISOString(),
          type: rule.action === 'block' ? 'block' : rule.action === 'warn' ? 'warn' : 'request',
          method: request.method,
          toolName,
          args,
          action: rule.action,
          reason: rule.reason ?? rule.description,
          ruleId: rule.id,
        });
        return { action: rule.action, rule, reason: rule.reason ?? rule.description };
      }
    }

    // Default action
    const defaultAction = this.policy.defaults?.action ?? 'allow';
    return { action: defaultAction };
  }

  private matchesRule(rule: PolicyRule, toolName: string, args: Record<string, any>): boolean {
    const match = rule.match;

    // Match tool name
    if (match.tool) {
      const tools = Array.isArray(match.tool) ? match.tool : [match.tool];
      if (!tools.includes(toolName)) return false;
    }

    // Match tool pattern (glob-like)
    if (match.toolPattern) {
      const regex = new RegExp('^' + match.toolPattern.replace(/\*/g, '.*').replace(/\?/g, '.') + '$');
      if (!regex.test(toolName)) return false;
    }

    // Match server
    if (match.server) {
      // Server matching would require context from the proxy - skip for now
    }

    // Match arguments
    if (match.args) {
      for (const [key, argMatch] of Object.entries(match.args)) {
        const value = args[key];
        if (!this.matchesArg(value, argMatch)) return false;
      }
    }

    return true;
  }

  private matchesArg(value: any, matcher: PolicyArgMatch): boolean {
    const strValue = String(value ?? '');

    if (matcher.equals !== undefined) {
      if (strValue !== matcher.equals) return false;
    }

    if (matcher.contains) {
      const patterns = Array.isArray(matcher.contains) ? matcher.contains : [matcher.contains];
      if (!patterns.some(p => strValue.includes(p))) return false;
    }

    if (matcher.matches) {
      if (!new RegExp(matcher.matches).test(strValue)) return false;
    }

    if (matcher.not) {
      if (this.matchesArg(value, matcher.not)) return false;
    }

    return true;
  }

  private logEvent(event: ProxyEvent): void {
    this.events.push(event);
  }

  getEvents(): ProxyEvent[] {
    return [...this.events];
  }

  getPolicy(): ProxyPolicy {
    return this.policy;
  }
}
