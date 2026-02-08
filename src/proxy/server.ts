/**
 * MCP Proxy Server
 * Sits between MCP client and server, intercepting and filtering tool calls
 */

import * as http from 'node:http';
import * as net from 'node:net';
import { PolicyEngine } from './policy.js';
import { detectInjection } from './injection.js';
import type { ProxyPolicy, ProxyOptions, MCPJsonRpcRequest, MCPJsonRpcResponse, ProxyEvent } from './types.js';

export class MCPProxyServer {
  private server: http.Server | null = null;
  private policyEngine: PolicyEngine;
  private options: ProxyOptions;
  private events: ProxyEvent[] = [];

  constructor(options: ProxyOptions) {
    this.options = options;
    this.policyEngine = new PolicyEngine(options.policy);
  }

  /**
   * Start the proxy server (HTTP SSE transport)
   */
  async start(): Promise<void> {
    this.server = http.createServer((req, res) => this.handleRequest(req, res));
    
    return new Promise((resolve, reject) => {
      this.server!.listen(this.options.port, () => {
        this.log('info', `🛡️  AgentVet MCP Proxy listening on port ${this.options.port}`);
        this.log('info', `   Upstream: ${this.options.upstream}`);
        this.log('info', `   Policy: ${this.options.policy.name ?? 'unnamed'} (${this.options.policy.rules.length} rules)`);
        if (this.options.policy.injection?.enabled) {
          this.log('info', `   Injection detection: enabled (action: ${this.options.policy.injection.action})`);
        }
        resolve();
      });
      this.server!.on('error', reject);
    });
  }

  /**
   * Stop the proxy server
   */
  async stop(): Promise<void> {
    return new Promise((resolve) => {
      if (this.server) {
        this.server.close(() => resolve());
      } else {
        resolve();
      }
    });
  }

  private async handleRequest(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    // Health check
    if (req.url === '/health') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ status: 'ok', policy: this.options.policy.name, rules: this.options.policy.rules.length }));
      return;
    }

    // Events/audit log
    if (req.url === '/events') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(this.getAllEvents()));
      return;
    }

    // Stats
    if (req.url === '/stats') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(this.getStats()));
      return;
    }

    // MCP JSON-RPC proxy
    if (req.method === 'POST') {
      await this.handleMCPRequest(req, res);
      return;
    }

    res.writeHead(404);
    res.end('Not Found');
  }

  private async handleMCPRequest(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    try {
      const body = await this.readBody(req);
      const jsonRpc: MCPJsonRpcRequest = JSON.parse(body);

      // Evaluate policy
      const evaluation = this.policyEngine.evaluate(jsonRpc);

      if (evaluation.action === 'block') {
        this.log('warn', `🚫 BLOCKED: ${jsonRpc.method} ${jsonRpc.params?.name ?? ''} - ${evaluation.reason}`);
        const errorResponse: MCPJsonRpcResponse = {
          jsonrpc: '2.0',
          id: jsonRpc.id,
          error: {
            code: -32600,
            message: `Blocked by AgentVet policy: ${evaluation.reason ?? evaluation.rule?.id}`,
            data: { ruleId: evaluation.rule?.id, action: 'block' },
          },
        };
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(errorResponse));
        return;
      }

      if (evaluation.action === 'warn') {
        this.log('warn', `⚠️  WARN: ${jsonRpc.method} ${jsonRpc.params?.name ?? ''} - ${evaluation.reason}`);
      }

      // Forward to upstream
      const upstreamResponse = await this.forwardToUpstream(body);

      // Check response for injection if enabled
      if (this.options.policy.injection?.enabled && jsonRpc.method === 'tools/call') {
        const injectionCheck = this.checkResponseForInjection(upstreamResponse, jsonRpc);
        if (injectionCheck) {
          const injAction = this.options.policy.injection.action;
          if (injAction === 'block') {
            this.log('warn', `🔴 INJECTION BLOCKED in response from ${jsonRpc.params?.name}`);
            const errorResponse: MCPJsonRpcResponse = {
              jsonrpc: '2.0',
              id: jsonRpc.id,
              error: {
                code: -32600,
                message: `Blocked: Prompt injection detected in tool response (score: ${injectionCheck.score})`,
                data: { patterns: injectionCheck.patterns.map(p => p.pattern), score: injectionCheck.score },
              },
            };
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify(errorResponse));
            return;
          }
          // warn/log - forward but log
          this.log('warn', `🟡 INJECTION DETECTED in response from ${jsonRpc.params?.name} (score: ${injectionCheck.score}, action: ${injAction})`);
        }
      }

      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(upstreamResponse);
    } catch (err: any) {
      this.log('error', `Error processing request: ${err.message}`);
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ jsonrpc: '2.0', id: null, error: { code: -32603, message: 'Internal proxy error' } }));
    }
  }

  private checkResponseForInjection(responseBody: string, request: MCPJsonRpcRequest) {
    try {
      const response: MCPJsonRpcResponse = JSON.parse(responseBody);
      if (response.error) return null;

      // Extract text content from MCP response
      const textContent = this.extractTextContent(response.result);
      if (!textContent) return null;

      const detection = detectInjection(textContent);
      if (detection.detected) {
        this.addEvent({
          timestamp: new Date().toISOString(),
          type: 'injection',
          method: request.method,
          toolName: request.params?.name as string,
          action: this.options.policy.injection?.action ?? 'log',
          reason: `Injection detected: ${detection.patterns.map(p => p.pattern).join(', ')} (score: ${detection.score})`,
        });
        return detection;
      }
    } catch {
      // Parse error, skip
    }
    return null;
  }

  private extractTextContent(result: any): string | null {
    if (!result) return null;
    if (typeof result === 'string') return result;
    
    // MCP content array format
    if (result.content && Array.isArray(result.content)) {
      return result.content
        .filter((c: any) => c.type === 'text')
        .map((c: any) => c.text)
        .join('\n');
    }
    
    return JSON.stringify(result);
  }

  private async forwardToUpstream(body: string): Promise<string> {
    const url = new URL(this.options.upstream);
    
    return new Promise((resolve, reject) => {
      const options: http.RequestOptions = {
        hostname: url.hostname,
        port: url.port || (url.protocol === 'https:' ? 443 : 80),
        path: url.pathname,
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) },
      };

      const req = http.request(options, (res) => {
        let data = '';
        res.on('data', (chunk: Buffer) => { data += chunk.toString(); });
        res.on('end', () => resolve(data));
      });

      req.on('error', reject);
      req.write(body);
      req.end();
    });
  }

  private readBody(req: http.IncomingMessage): Promise<string> {
    return new Promise((resolve, reject) => {
      let body = '';
      req.on('data', (chunk: Buffer) => { body += chunk.toString(); });
      req.on('end', () => resolve(body));
      req.on('error', reject);
    });
  }

  private addEvent(event: ProxyEvent): void {
    this.events.push(event);
  }

  private getAllEvents(): ProxyEvent[] {
    return [...this.policyEngine.getEvents(), ...this.events];
  }

  private getStats() {
    const events = this.getAllEvents();
    return {
      totalRequests: events.filter(e => e.type === 'request').length,
      blocked: events.filter(e => e.type === 'block').length,
      warned: events.filter(e => e.type === 'warn').length,
      injections: events.filter(e => e.type === 'injection').length,
      uptime: process.uptime(),
    };
  }

  private log(level: string, message: string): void {
    if (this.options.verbose || level !== 'debug') {
      const prefix = level === 'error' ? '❌' : level === 'warn' ? '⚠️' : 'ℹ️';
      console.error(`[AgentVet Proxy] ${prefix} ${message}`);
    }
  }

  getPolicyEngine(): PolicyEngine {
    return this.policyEngine;
  }
}
