/**
 * Firewall Audit Logger
 * Writes blocked/warned requests to audit log
 */

import * as fs from 'fs';
import * as path from 'path';
import { FirewallEvent, AuditConfig } from './types.js';

export class AuditLogger {
  private config: AuditConfig;
  private stream: fs.WriteStream | null = null;

  constructor(config: AuditConfig) {
    this.config = config;
    if (config.enabled && config.file) {
      const dir = path.dirname(config.file);
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
      this.stream = fs.createWriteStream(config.file, { flags: 'a' });
    }
  }

  log(event: FirewallEvent): void {
    if (!this.config.enabled) return;

    const format = this.config.format || 'json';
    let line: string;

    if (format === 'json') {
      line = JSON.stringify(event);
    } else {
      const icon = event.action === 'block' ? '🚫' : event.action === 'warn' ? '⚠️' : '📝';
      line = `[${event.timestamp}] ${icon} ${event.action.toUpperCase()} ${event.direction} score=${event.score} patterns=[${event.patterns.join(',')}] ${event.detail || ''}`;
    }

    if (this.stream) {
      this.stream.write(line + '\n');
    } else {
      console.error(line);
    }
  }

  close(): void {
    this.stream?.end();
  }
}
