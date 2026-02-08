/**
 * Prompt Firewall HTTP Proxy Server
 * Sits between client and LLM/MCP, filtering requests and responses
 */

import * as http from 'http';
import { FirewallConfig } from './types.js';
import { FirewallEngine, ScanResult } from './engine.js';

export interface FirewallServerOptions {
  port: number;
  config: FirewallConfig;
  verbose?: boolean;
  upstream?: string;
}

export class FirewallServer {
  private server: http.Server | null = null;
  private engine: FirewallEngine;
  private options: FirewallServerOptions;

  constructor(options: FirewallServerOptions) {
    this.options = options;
    this.engine = new FirewallEngine(options.config);
  }

  async start(): Promise<void> {
    this.server = http.createServer((req, res) => this.handleRequest(req, res));

    return new Promise((resolve) => {
      this.server!.listen(this.options.port, () => {
        console.log(`🔥 Prompt Firewall running on port ${this.options.port}`);
        console.log(`   Inbound filter:  ${this.options.config.inbound.enabled ? '✅' : '❌'}`);
        console.log(`   Outbound filter: ${this.options.config.outbound.enabled ? '✅' : '❌'}`);
        console.log(`   Context protect: ${this.options.config.context_protection.enabled ? '✅' : '❌'}`);
        console.log(`   Audit logging:   ${this.options.config.audit.enabled ? '✅' : '❌'}`);
        if (this.options.upstream) {
          console.log(`   Upstream:        ${this.options.upstream}`);
        }
        resolve();
      });
    });
  }

  async stop(): Promise<void> {
    this.engine.close();
    return new Promise((resolve) => {
      if (this.server) {
        this.server.close(() => resolve());
      } else {
        resolve();
      }
    });
  }

  getEngine(): FirewallEngine {
    return this.engine;
  }

  private async handleRequest(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    // Health check
    if (req.url === '/health') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ status: 'ok', version: '1.0' }));
      return;
    }

    // Stats endpoint
    if (req.url === '/stats') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(this.engine.getStats()));
      return;
    }

    // Scan inbound endpoint
    if (req.url === '/scan/inbound' && req.method === 'POST') {
      const body = await this.readBody(req);
      try {
        const payload = JSON.parse(body);
        const text = payload.text || payload.content || payload.message || '';
        const result = this.engine.scanInbound(text, { method: payload.method, requestId: payload.id });
        this.sendScanResult(res, result);
      } catch {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Invalid JSON' }));
      }
      return;
    }

    // Scan outbound endpoint
    if (req.url === '/scan/outbound' && req.method === 'POST') {
      const body = await this.readBody(req);
      try {
        const payload = JSON.parse(body);
        const text = payload.text || payload.content || payload.result || '';
        const result = this.engine.scanOutbound(text, { toolName: payload.toolName, requestId: payload.id });
        this.sendScanResult(res, result);
      } catch {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Invalid JSON' }));
      }
      return;
    }

    // JSON-RPC proxy mode (for MCP)
    if (req.method === 'POST' && (req.url === '/' || req.url === '/jsonrpc')) {
      const body = await this.readBody(req);
      try {
        const rpc = JSON.parse(body);
        await this.handleJsonRpc(rpc, res);
      } catch {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ jsonrpc: '2.0', error: { code: -32700, message: 'Parse error' } }));
      }
      return;
    }

    res.writeHead(404, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Not found' }));
  }

  private async handleJsonRpc(rpc: any, res: http.ServerResponse): Promise<void> {
    // Scan inbound: check params for injection
    const paramsText = JSON.stringify(rpc.params || {});
    const inboundResult = this.engine.scanInbound(paramsText, { method: rpc.method, requestId: rpc.id });

    if (inboundResult.action === 'block') {
      if (this.options.verbose) {
        console.log(`🚫 BLOCKED inbound: method=${rpc.method} score=${inboundResult.score}`);
      }
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        jsonrpc: '2.0',
        id: rpc.id,
        error: {
          code: -32001,
          message: 'Request blocked by Prompt Firewall',
          data: {
            score: inboundResult.score,
            patterns: inboundResult.matchedPatterns.map(p => p.id),
          },
        },
      }));
      return;
    }

    if (inboundResult.action === 'warn' && this.options.verbose) {
      console.log(`⚠️  WARN inbound: method=${rpc.method} score=${inboundResult.score}`);
    }

    // If upstream configured, forward the request
    if (this.options.upstream) {
      try {
        const upstreamRes = await this.forwardToUpstream(rpc);
        // Scan the response
        const responseText = JSON.stringify(upstreamRes.result || {});
        const outboundResult = this.engine.scanOutbound(responseText, { toolName: rpc.method, requestId: rpc.id });

        if (outboundResult.action === 'block') {
          if (this.options.verbose) {
            console.log(`🚫 BLOCKED outbound: method=${rpc.method} score=${outboundResult.score}`);
          }
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            jsonrpc: '2.0',
            id: rpc.id,
            error: {
              code: -32002,
              message: 'Response blocked by Prompt Firewall (suspicious content detected)',
              data: {
                score: outboundResult.score,
                patterns: outboundResult.matchedPatterns.map(p => p.id),
              },
            },
          }));
          return;
        }

        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(upstreamRes));
      } catch (err: any) {
        res.writeHead(502, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          jsonrpc: '2.0',
          id: rpc.id,
          error: { code: -32000, message: `Upstream error: ${err.message}` },
        }));
      }
      return;
    }

    // No upstream: just return scan result
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      jsonrpc: '2.0',
      id: rpc.id,
      result: {
        action: inboundResult.action,
        score: inboundResult.score,
        patterns: inboundResult.matchedPatterns,
      },
    }));
  }

  private async forwardToUpstream(rpc: any): Promise<any> {
    const url = new URL(this.options.upstream!);
    return new Promise((resolve, reject) => {
      const reqOpts: http.RequestOptions = {
        hostname: url.hostname,
        port: url.port || 80,
        path: url.pathname,
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
      };

      const proxyReq = http.request(reqOpts, (proxyRes) => {
        let data = '';
        proxyRes.on('data', (chunk) => data += chunk);
        proxyRes.on('end', () => {
          try { resolve(JSON.parse(data)); } catch { reject(new Error('Invalid upstream response')); }
        });
      });

      proxyReq.on('error', reject);
      proxyReq.write(JSON.stringify(rpc));
      proxyReq.end();
    });
  }

  private sendScanResult(res: http.ServerResponse, result: ScanResult): void {
    const status = result.action === 'block' ? 403 : 200;
    res.writeHead(status, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      action: result.action,
      score: result.score,
      patterns: result.matchedPatterns,
    }));
  }

  private readBody(req: http.IncomingMessage): Promise<string> {
    return new Promise((resolve) => {
      let body = '';
      req.on('data', (chunk) => body += chunk);
      req.on('end', () => resolve(body));
    });
  }
}
