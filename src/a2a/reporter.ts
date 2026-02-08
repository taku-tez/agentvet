/**
 * A2A Scan Result Reporter
 */

import type { A2AScanResult, A2AFinding } from './types.js';

const SEVERITY_COLORS: Record<string, string> = {
  critical: '\x1b[31m', // red
  high: '\x1b[33m',     // yellow
  medium: '\x1b[36m',   // cyan
  low: '\x1b[34m',      // blue
  info: '\x1b[90m',     // gray
};
const RESET = '\x1b[0m';
const BOLD = '\x1b[1m';

export function printA2AReport(result: A2AScanResult): void {
  console.log(`\n${BOLD}🛡️  AgentVet A2A Protocol Security Scan${RESET}`);
  console.log(`${'─'.repeat(50)}`);
  console.log(`Target:    ${result.target}`);
  console.log(`Timestamp: ${result.timestamp}`);
  console.log(`Duration:  ${result.duration}ms`);

  if (result.agentCard) {
    console.log(`Agent:     ${result.agentCard.name || '(unnamed)'}`);
    if (result.agentCard.version) console.log(`Version:   ${result.agentCard.version}`);
    if (result.agentCard.provider?.organization) console.log(`Provider:  ${result.agentCard.provider.organization}`);
  }

  console.log(`\n${BOLD}Checks Performed:${RESET}`);
  for (const [check, done] of Object.entries(result.checks)) {
    console.log(`  ${done ? '✅' : '⬜'} ${check}`);
  }

  if (result.findings.length === 0) {
    console.log(`\n${BOLD}✅ No security issues found!${RESET}\n`);
    return;
  }

  console.log(`\n${BOLD}Findings (${result.summary.total}):${RESET}`);
  console.log(`${'─'.repeat(50)}`);

  // Group by category
  const byCategory = new Map<string, A2AFinding[]>();
  for (const f of result.findings) {
    const cat = f.category;
    if (!byCategory.has(cat)) byCategory.set(cat, []);
    byCategory.get(cat)!.push(f);
  }

  for (const [category, findings] of byCategory) {
    console.log(`\n${BOLD}📋 ${category}${RESET}`);
    for (const f of findings) {
      const color = SEVERITY_COLORS[f.severity] || '';
      console.log(`  ${color}[${f.severity.toUpperCase()}]${RESET} ${f.title}`);
      console.log(`    ${f.description}`);
      if (f.evidence) console.log(`    Evidence: ${f.evidence}`);
      if (f.cwe) console.log(`    CWE: ${f.cwe}`);
      console.log(`    💡 ${f.recommendation}`);
    }
  }

  console.log(`\n${BOLD}Summary:${RESET}`);
  const { critical, high, medium, low, info } = result.summary;
  console.log(`  🔴 Critical: ${critical}  🟡 High: ${high}  🔵 Medium: ${medium}  ⚪ Low: ${low}  ℹ️  Info: ${info}`);
  console.log();
}

export function printA2AJSON(result: A2AScanResult): void {
  console.log(JSON.stringify(result, null, 2));
}
