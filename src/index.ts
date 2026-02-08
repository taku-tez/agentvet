/**
 * AgentVet - Main Entry Point
 * Security scanner for AI agent skills, configs, and MCP tools
 */

import { Scanner } from './scanner.js';
import type { Rule, Finding, Severity } from './types.js';

// Re-export types
export type { Rule, Finding, Severity };

/**
 * Scan a directory or file for security issues
 * @param targetPath - Path to scan
 * @param options - Scan options
 * @returns Scan results
 */
export async function scan(targetPath: string, options: Record<string, any> = {}): Promise<any> {
  const scanner = new Scanner(options);
  return scanner.scan(targetPath);
}

/**
 * Get the default rules
 * @returns Array of rule definitions
 */
export function getRules(): Rule[] {
  const credentials = require('./rules/credentials.js');
  const commands = require('./rules/commands.js');
  const urls = require('./rules/urls.js');
  const permissions = require('./rules/permissions.js');
  
  return [
    ...credentials.rules,
    ...commands.rules,
    ...urls.rules,
    ...permissions.rules,
  ];
}

// Export Scanner class
export { Scanner };

// Export Proxy module
export { MCPProxyServer, PolicyEngine, detectInjection } from './proxy/index.js';

// Export A2A module
export { A2AScanner } from './a2a/index.js';

// Export Firewall module
export { FirewallServer, FirewallEngine, FIREWALL_PATTERNS } from './firewall/index.js';

// Default export for CommonJS compatibility
module.exports = {
  scan,
  getRules,
  Scanner,
};
