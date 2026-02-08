/**
 * Prompt Firewall Engine
 * Core scanning logic for inbound, outbound, and context protection
 */

import { FirewallConfig, FirewallEvent, FirewallStats } from './types.js';
import { FirewallPattern, FIREWALL_PATTERNS, CONTEXT_PROTECTION_PATTERNS } from './patterns.js';
import { AuditLogger } from './audit.js';

export interface ScanResult {
  action: 'block' | 'warn' | 'allow';
  score: number;
  matchedPatterns: Array<{ id: string; name: string; category: string; severity: string }>;
  event?: FirewallEvent;
}

export class FirewallEngine {
  private config: FirewallConfig;
  private audit: AuditLogger;
  private customPatterns: FirewallPattern[] = [];
  private stats: FirewallStats;

  constructor(config: FirewallConfig) {
    this.config = config;
    this.audit = new AuditLogger(config.audit);
    this.stats = {
      startTime: new Date().toISOString(),
      totalRequests: 0,
      totalResponses: 0,
      inboundBlocked: 0,
      inboundWarned: 0,
      outboundBlocked: 0,
      outboundWarned: 0,
      contextBlocked: 0,
      topPatterns: [],
    };

    // Build custom patterns from config
    if (config.custom_patterns) {
      this.customPatterns = config.custom_patterns.map(cp => ({
        id: cp.id,
        regex: new RegExp(cp.pattern, 'i'),
        name: cp.description || cp.id,
        category: cp.category,
        severity: cp.severity,
        direction: cp.direction,
        score: cp.severity === 'critical' ? 40 : cp.severity === 'high' ? 30 : cp.severity === 'medium' ? 20 : 10,
      }));
    }
  }

  /** Scan inbound user/client message */
  scanInbound(text: string, meta?: { method?: string; requestId?: string | number }): ScanResult {
    this.stats.totalRequests++;

    if (!this.config.inbound.enabled) {
      return { action: 'allow', score: 0, matchedPatterns: [] };
    }

    const patterns = this.getPatternsForDirection('inbound');
    const result = this.matchPatterns(text, patterns);

    // Also check context protection patterns
    if (this.config.context_protection.enabled) {
      const ctxResult = this.matchPatterns(text, CONTEXT_PROTECTION_PATTERNS);
      result.score += ctxResult.score;
      result.matchedPatterns.push(...ctxResult.matchedPatterns);
      if (ctxResult.matchedPatterns.length > 0) {
        this.stats.contextBlocked++;
      }
    }

    const action = this.determineAction(result.score, 'inbound');
    if (action === 'block') this.stats.inboundBlocked++;
    else if (action === 'warn') this.stats.inboundWarned++;

    const event: FirewallEvent = {
      timestamp: new Date().toISOString(),
      direction: result.matchedPatterns.some(p => p.category.includes('context') || p.category.includes('extraction')) ? 'context' : 'inbound',
      method: meta?.method || 'unknown',
      action,
      score: result.score,
      patterns: result.matchedPatterns.map(p => p.id),
      categories: [...new Set(result.matchedPatterns.map(p => p.category))],
      requestId: meta?.requestId,
    };

    if (action !== 'allow') {
      this.audit.log(event);
    }

    return { action, score: result.score, matchedPatterns: result.matchedPatterns, event };
  }

  /** Scan outbound tool response */
  scanOutbound(text: string, meta?: { toolName?: string; requestId?: string | number }): ScanResult {
    this.stats.totalResponses++;

    if (!this.config.outbound.enabled) {
      return { action: 'allow', score: 0, matchedPatterns: [] };
    }

    const patterns = this.getPatternsForDirection('outbound');
    const result = this.matchPatterns(text, patterns);

    // Check canary token
    if (this.config.context_protection.canary_token && text.includes(this.config.context_protection.canary_token)) {
      result.score += 50;
      result.matchedPatterns.push({ id: 'CANARY', name: 'Canary token detected in output', category: 'context_leak', severity: 'critical' });
    }

    const action = this.determineAction(result.score, 'outbound');
    if (action === 'block') this.stats.outboundBlocked++;
    else if (action === 'warn') this.stats.outboundWarned++;

    const event: FirewallEvent = {
      timestamp: new Date().toISOString(),
      direction: 'outbound',
      method: 'tool_response',
      toolName: meta?.toolName,
      action,
      score: result.score,
      patterns: result.matchedPatterns.map(p => p.id),
      categories: [...new Set(result.matchedPatterns.map(p => p.category))],
      requestId: meta?.requestId,
    };

    if (action !== 'allow') {
      this.audit.log(event);
    }

    return { action, score: result.score, matchedPatterns: result.matchedPatterns, event };
  }

  /** Get current stats */
  getStats(): FirewallStats {
    return { ...this.stats };
  }

  /** Shutdown */
  close(): void {
    this.audit.close();
  }

  private getPatternsForDirection(direction: 'inbound' | 'outbound'): FirewallPattern[] {
    const builtIn = FIREWALL_PATTERNS.filter(p => p.direction === direction || p.direction === 'both');
    const custom = this.customPatterns.filter(p => p.direction === direction || p.direction === 'both');
    return [...builtIn, ...custom];
  }

  private matchPatterns(text: string, patterns: FirewallPattern[]): { score: number; matchedPatterns: Array<{ id: string; name: string; category: string; severity: string }> } {
    let score = 0;
    const matchedPatterns: Array<{ id: string; name: string; category: string; severity: string }> = [];

    for (const pattern of patterns) {
      if (pattern.regex.test(text)) {
        score += pattern.score;
        matchedPatterns.push({ id: pattern.id, name: pattern.name, category: pattern.category, severity: pattern.severity });
      }
    }

    return { score, matchedPatterns };
  }

  private determineAction(score: number, direction: 'inbound' | 'outbound'): 'block' | 'warn' | 'allow' {
    const blockThreshold = this.config.thresholds?.block ?? 30;
    const warnThreshold = this.config.thresholds?.warn ?? 15;

    if (score >= blockThreshold) {
      const configAction = direction === 'inbound' ? this.config.inbound.action : this.config.outbound.action;
      return configAction === 'log' ? 'warn' : configAction;
    }
    if (score >= warnThreshold) return 'warn';
    return 'allow';
  }
}
