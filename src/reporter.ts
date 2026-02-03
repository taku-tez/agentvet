/**
 * AgentVet Reporter (TypeScript)
 */

/**
 * AgentVet Reporter
 * Output formatting for scan results
 */

// ANSI color codes
const colors: Record<string, (s: string) => string> = {
  red: (s) => `\x1b[31m${s}\x1b[0m`,
  green: (s) => `\x1b[32m${s}\x1b[0m`,
  yellow: (s) => `\x1b[33m${s}\x1b[0m`,
  blue: (s) => `\x1b[34m${s}\x1b[0m`,
  gray: (s) => `\x1b[90m${s}\x1b[0m`,
  bold: (s) => `\x1b[1m${s}\x1b[0m`,
  dim: (s) => `\x1b[2m${s}\x1b[0m`,
};

// Severity icons
const icons: Record<string, string> = {
  critical: '🔴',
  high: '🟠',
  warning: '🟡',
  medium: '🟡',
  low: '🔵',
  info: '🔵',
};

/**
 * Print human-readable report
 */
export function printReport(results: any, targetPath: string): string {
  const lines = [];
  
  lines.push('');
  lines.push(colors.bold('🛡️  AgentVet Security Scan Report'));
  lines.push('═'.repeat(50));
  lines.push(`Target: ${targetPath}`);
  lines.push(`Scanned: ${results.scannedFiles} files`);
  if (results.yaraEnabled) {
    lines.push(`YARA: ${colors.green('enabled')} (${results.yaraMode})`);
  } else {
    lines.push(`YARA: ${colors.gray('disabled')}`);
  }
  if (results.depsEnabled) {
    const depsInfo = [];
    if (results.depsResults?.npm?.available) depsInfo.push('npm');
    if (results.depsResults?.pip?.available) depsInfo.push('pip');
    lines.push(`Deps: ${colors.green('enabled')} (${depsInfo.join(', ') || 'no package managers found'})`);
  } else {
    lines.push(`Deps: ${colors.gray('disabled')}`);
  }
  if (results.llmEnabled) {
    lines.push(`LLM: ${colors.green('enabled')} (${results.llmProvider || 'default'})`);
  }
  if (results.customRulesEnabled) {
    lines.push(`Custom Rules: ${colors.green('enabled')} (${results.customRulesCount} rules)`);
  }
  if (results.ignoreSources?.length > 0) {
    lines.push(`Ignore: ${colors.green(results.ignoreSources.join(', '))} (${results.ignorePatterns} patterns)`);
  }
  if (results.reputationEnabled) {
    lines.push(`Reputation: ${colors.green('enabled')} (${results.reputationServices?.join(', ') || 'checking'})`);
  }
  lines.push(`Date: ${new Date().toISOString()}`);
  lines.push('');

  // Group findings by severity
  const critical = results.findings.filter(f => f.severity === 'critical');
  const high = results.findings.filter(f => f.severity === 'high');
  const warning = results.findings.filter(f => f.severity === 'warning' || f.severity === 'medium');
  const info = results.findings.filter(f => f.severity === 'info' || f.severity === 'low');

  // Critical findings
  if (critical.length > 0) {
    lines.push(colors.red(colors.bold(`${icons.critical} CRITICAL (${critical.length})`)));
    lines.push('');
    for (const finding of critical) {
      lines.push(formatFinding(finding, colors.red));
    }
    lines.push('');
  }

  // High findings
  if (high.length > 0) {
    lines.push(colors.red(colors.bold(`${icons.high} HIGH (${high.length})`)));
    lines.push('');
    for (const finding of high) {
      lines.push(formatFinding(finding, colors.red));
    }
    lines.push('');
  }

  // Warning findings
  if (warning.length > 0) {
    lines.push(colors.yellow(colors.bold(`${icons.warning} WARNING (${warning.length})`)));
    lines.push('');
    for (const finding of warning) {
      lines.push(formatFinding(finding, colors.yellow));
    }
    lines.push('');
  }

  // Info findings
  if (info.length > 0) {
    lines.push(colors.blue(colors.bold(`${icons.info} INFO (${info.length})`)));
    lines.push('');
    for (const finding of info) {
      lines.push(formatFinding(finding, colors.blue));
    }
    lines.push('');
  }

  // Summary
  lines.push('─'.repeat(50));
  if (results.summary.total === 0) {
    lines.push(colors.green(colors.bold('✅ No security issues found!')));
  } else {
    lines.push(colors.bold('📊 Summary'));
    if (results.summary.critical > 0) {
      lines.push(colors.red(`   ${icons.critical} Critical: ${results.summary.critical}`));
    }
    if (results.summary.high > 0) {
      lines.push(colors.red(`   ${icons.high} High: ${results.summary.high}`));
    }
    if (results.summary.warning > 0) {
      lines.push(colors.yellow(`   ${icons.warning} Warning: ${results.summary.warning}`));
    }
    if (results.summary.info > 0) {
      lines.push(colors.blue(`   ${icons.info} Info: ${results.summary.info}`));
    }
  }

  // Fixed issues
  if (results.fixedIssues > 0) {
    lines.push('');
    lines.push(colors.green(`🔧 Auto-fixed ${results.fixedIssues} permission issues`));
  }

  // Ignored findings
  if (results.ignoredFindings > 0) {
    lines.push('');
    lines.push(colors.gray(`🔇 ${results.ignoredFindings} findings ignored (via agentvet-ignore comments)`));
  }

  lines.push('');

  return lines.join('\n');
}

/**
 * Format a single finding
 */
function formatFinding(finding: any, colorFn: (s: string) => string): string {
  const lines = [];
  const location = finding.line > 0 
    ? `${finding.file}:${finding.line}` 
    : finding.file;
  
  lines.push(`  ${colorFn('●')} ${finding.description || finding.title || finding.ruleId}`);
  lines.push(colors.dim(`    ${location}`));
  
  if (finding.snippet) {
    lines.push(colors.gray(`    ${finding.snippet}`));
  }
  
  if (finding.recommendation) {
    lines.push(colors.dim(`    💡 ${finding.recommendation}`));
  }
  
  if (finding.fixed) {
    lines.push(colors.green('    ✅ Fixed'));
  }
  
  lines.push('');
  
  return lines.join('\n');
}

/**
 * Print JSON output
 */
export function printJSON(results: any): string {
  return JSON.stringify(results, null, 2);
}

/**
 * Print quiet summary
 */
export function printQuiet(results: any): string {
  const { summary } = results;
  
  if (summary.total === 0) {
    return '✅ No issues found';
  }
  
  const parts = [];
  if (summary.critical > 0) parts.push(`${icons.critical} ${summary.critical} critical`);
  if (summary.high > 0) parts.push(`${icons.high} ${summary.high} high`);
  if (summary.warning > 0) parts.push(`${icons.warning} ${summary.warning} warning`);
  if (summary.info > 0) parts.push(`${icons.info} ${summary.info} info`);
  
  const status = summary.critical > 0 ? '❌' : '⚠️';
  return `${status} ${parts.join(', ')}`;
}

/**
 * Generate HTML report
 */
export function printHTML(results: any, targetPath: string): string {
  const severityColors = {
    critical: '#dc3545',
    high: '#fd7e14',
    warning: '#ffc107',
    medium: '#ffc107',
    low: '#17a2b8',
    info: '#17a2b8',
  };

  const escapeHtml = (str) => {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  };

  const findings = results.findings || [];
  const groupedFindings = {
    critical: findings.filter(f => f.severity === 'critical'),
    high: findings.filter(f => f.severity === 'high'),
    warning: findings.filter(f => f.severity === 'warning' || f.severity === 'medium'),
    info: findings.filter(f => f.severity === 'info' || f.severity === 'low'),
  };

  const renderFinding = (finding) => `
    <div class="finding severity-${finding.severity}">
      <div class="finding-header">
        <span class="severity-badge" style="background-color: ${severityColors[finding.severity] || '#6c757d'}">
          ${escapeHtml(finding.severity?.toUpperCase())}
        </span>
        <span class="rule-id">${escapeHtml(finding.ruleId)}</span>
      </div>
      <div class="finding-body">
        <p class="description">${escapeHtml(finding.description || finding.title)}</p>
        <p class="location">📁 ${escapeHtml(finding.file)}${finding.line ? `:${finding.line}` : ''}</p>
        ${finding.snippet ? `<pre class="snippet">${escapeHtml(finding.snippet)}</pre>` : ''}
        ${finding.evidence ? `<pre class="evidence">${escapeHtml(finding.evidence)}</pre>` : ''}
        ${finding.recommendation ? `<p class="recommendation">💡 ${escapeHtml(finding.recommendation)}</p>` : ''}
        ${finding.attackScenario ? `<p class="attack-scenario">⚠️ Attack: ${escapeHtml(finding.attackScenario)}</p>` : ''}
      </div>
    </div>
  `;

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>AgentVet Security Report</title>
  <style>
    :root {
      --bg-color: #1a1a2e;
      --card-bg: #16213e;
      --text-color: #eee;
      --text-muted: #aaa;
      --border-color: #0f3460;
    }
    * { box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: var(--bg-color);
      color: var(--text-color);
      margin: 0;
      padding: 20px;
      line-height: 1.6;
    }
    .container { max-width: 1200px; margin: 0 auto; }
    header {
      background: var(--card-bg);
      padding: 20px 30px;
      border-radius: 12px;
      margin-bottom: 20px;
      border: 1px solid var(--border-color);
    }
    header h1 { margin: 0 0 10px 0; font-size: 1.8em; }
    header h1::before { content: '🛡️ '; }
    .meta { color: var(--text-muted); font-size: 0.9em; }
    .meta span { margin-right: 20px; }
    .summary {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
      gap: 15px;
      margin-bottom: 20px;
    }
    .stat-card {
      background: var(--card-bg);
      padding: 20px;
      border-radius: 12px;
      text-align: center;
      border: 1px solid var(--border-color);
    }
    .stat-card .number { font-size: 2.5em; font-weight: bold; }
    .stat-card .label { color: var(--text-muted); font-size: 0.9em; }
    .stat-card.critical .number { color: #dc3545; }
    .stat-card.high .number { color: #fd7e14; }
    .stat-card.warning .number { color: #ffc107; }
    .stat-card.info .number { color: #17a2b8; }
    .stat-card.clean .number { color: #28a745; }
    .section { margin-bottom: 30px; }
    .section-title {
      font-size: 1.3em;
      margin-bottom: 15px;
      padding-bottom: 10px;
      border-bottom: 2px solid var(--border-color);
    }
    .finding {
      background: var(--card-bg);
      border-radius: 8px;
      margin-bottom: 15px;
      overflow: hidden;
      border: 1px solid var(--border-color);
    }
    .finding-header {
      padding: 12px 15px;
      background: rgba(0,0,0,0.2);
      display: flex;
      align-items: center;
      gap: 10px;
    }
    .severity-badge {
      padding: 3px 10px;
      border-radius: 4px;
      font-size: 0.75em;
      font-weight: bold;
      color: white;
    }
    .rule-id { font-family: monospace; color: var(--text-muted); }
    .finding-body { padding: 15px; }
    .description { margin: 0 0 10px 0; font-weight: 500; }
    .location { color: var(--text-muted); font-size: 0.9em; margin: 5px 0; }
    .snippet, .evidence {
      background: rgba(0,0,0,0.3);
      padding: 10px;
      border-radius: 4px;
      overflow-x: auto;
      font-size: 0.85em;
      margin: 10px 0;
    }
    .recommendation { color: #28a745; margin: 10px 0 0 0; }
    .attack-scenario { color: #fd7e14; margin: 10px 0 0 0; font-size: 0.9em; }
    .no-findings {
      text-align: center;
      padding: 40px;
      color: #28a745;
      font-size: 1.2em;
    }
    .no-findings::before { content: '✅ '; }
    footer {
      text-align: center;
      color: var(--text-muted);
      font-size: 0.85em;
      margin-top: 30px;
      padding-top: 20px;
      border-top: 1px solid var(--border-color);
    }
    @media (prefers-color-scheme: light) {
      :root {
        --bg-color: #f5f5f5;
        --card-bg: #fff;
        --text-color: #333;
        --text-muted: #666;
        --border-color: #ddd;
      }
    }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <h1>AgentVet Security Report</h1>
      <div class="meta">
        <span>📁 Target: ${escapeHtml(targetPath)}</span>
        <span>📄 Files: ${results.scannedFiles || 0}</span>
        <span>🕐 ${new Date().toISOString()}</span>
      </div>
    </header>

    <div class="summary">
      ${results.summary.total === 0 ? `
        <div class="stat-card clean" style="grid-column: 1 / -1;">
          <div class="number">✓</div>
          <div class="label">No Security Issues Found</div>
        </div>
      ` : `
        <div class="stat-card critical">
          <div class="number">${results.summary.critical || 0}</div>
          <div class="label">Critical</div>
        </div>
        <div class="stat-card high">
          <div class="number">${results.summary.high || 0}</div>
          <div class="label">High</div>
        </div>
        <div class="stat-card warning">
          <div class="number">${results.summary.warning || 0}</div>
          <div class="label">Warning</div>
        </div>
        <div class="stat-card info">
          <div class="number">${results.summary.info || 0}</div>
          <div class="label">Info</div>
        </div>
      `}
    </div>

    ${groupedFindings.critical.length > 0 ? `
      <div class="section">
        <h2 class="section-title">🔴 Critical Issues (${groupedFindings.critical.length})</h2>
        ${groupedFindings.critical.map(renderFinding).join('')}
      </div>
    ` : ''}

    ${groupedFindings.high.length > 0 ? `
      <div class="section">
        <h2 class="section-title">🟠 High Issues (${groupedFindings.high.length})</h2>
        ${groupedFindings.high.map(renderFinding).join('')}
      </div>
    ` : ''}

    ${groupedFindings.warning.length > 0 ? `
      <div class="section">
        <h2 class="section-title">🟡 Warnings (${groupedFindings.warning.length})</h2>
        ${groupedFindings.warning.map(renderFinding).join('')}
      </div>
    ` : ''}

    ${groupedFindings.info.length > 0 ? `
      <div class="section">
        <h2 class="section-title">🔵 Info (${groupedFindings.info.length})</h2>
        ${groupedFindings.info.map(renderFinding).join('')}
      </div>
    ` : ''}

    ${results.summary.total === 0 ? `
      <div class="no-findings">No security issues detected in the scanned files.</div>
    ` : ''}

    <footer>
      Generated by <strong>AgentVet</strong> | 
      <a href="https://github.com/taku-tez/agentvet" style="color: inherit;">GitHub</a>
    </footer>
  </div>
</body>
</html>`;

  return html;
}

/**
 * Generate Markdown report
 */
export function printMarkdown(results: any, targetPath: string): string {
  const lines = [];
  
  lines.push('# 🛡️ AgentVet Security Report\n');
  lines.push(`**Target:** \`${targetPath}\`  `);
  lines.push(`**Files Scanned:** ${results.scannedFiles || 0}  `);
  lines.push(`**Date:** ${new Date().toISOString()}\n`);

  // Summary table
  lines.push('## 📊 Summary\n');
  if (results.summary.total === 0) {
    lines.push('✅ **No security issues found!**\n');
  } else {
    lines.push('| Severity | Count |');
    lines.push('|----------|-------|');
    if (results.summary.critical > 0) lines.push(`| 🔴 Critical | ${results.summary.critical} |`);
    if (results.summary.high > 0) lines.push(`| 🟠 High | ${results.summary.high} |`);
    if (results.summary.warning > 0) lines.push(`| 🟡 Warning | ${results.summary.warning} |`);
    if (results.summary.info > 0) lines.push(`| 🔵 Info | ${results.summary.info} |`);
    lines.push('');
  }

  // Findings
  const groupedFindings = {
    critical: results.findings.filter(f => f.severity === 'critical'),
    high: results.findings.filter(f => f.severity === 'high'),
    warning: results.findings.filter(f => f.severity === 'warning' || f.severity === 'medium'),
    info: results.findings.filter(f => f.severity === 'info' || f.severity === 'low'),
  };

  const renderFinding = (f, index) => {
    const lines = [];
    lines.push(`### ${index + 1}. ${f.ruleId}\n`);
    lines.push(`**File:** \`${f.file}${f.line ? `:${f.line}` : ''}\`\n`);
    if (f.description || f.title) {
      lines.push(`**Description:** ${f.description || f.title}\n`);
    }
    if (f.snippet || f.evidence) {
      lines.push('```');
      lines.push(f.snippet || f.evidence);
      lines.push('```\n');
    }
    if (f.recommendation) {
      lines.push(`💡 **Recommendation:** ${f.recommendation}\n`);
    }
    return lines.join('\n');
  };

  if (groupedFindings.critical.length > 0) {
    lines.push('## 🔴 Critical Issues\n');
    groupedFindings.critical.forEach((f, i) => lines.push(renderFinding(f, i)));
  }

  if (groupedFindings.high.length > 0) {
    lines.push('## 🟠 High Issues\n');
    groupedFindings.high.forEach((f, i) => lines.push(renderFinding(f, i)));
  }

  if (groupedFindings.warning.length > 0) {
    lines.push('## 🟡 Warnings\n');
    groupedFindings.warning.forEach((f, i) => lines.push(renderFinding(f, i)));
  }

  if (groupedFindings.info.length > 0) {
    lines.push('## 🔵 Info\n');
    groupedFindings.info.forEach((f, i) => lines.push(renderFinding(f, i)));
  }

  lines.push('\n---\n*Generated by [AgentVet](https://github.com/taku-tez/agentvet)*');

  return lines.join('\n');
}

// CommonJS compatibility
module.exports = { printReport, printJSON, printQuiet, printHTML, printMarkdown };
