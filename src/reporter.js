/**
 * AgentVet Reporter
 * Output formatting for scan results
 */

// ANSI color codes
const colors = {
  red: (s) => `\x1b[31m${s}\x1b[0m`,
  green: (s) => `\x1b[32m${s}\x1b[0m`,
  yellow: (s) => `\x1b[33m${s}\x1b[0m`,
  blue: (s) => `\x1b[34m${s}\x1b[0m`,
  gray: (s) => `\x1b[90m${s}\x1b[0m`,
  bold: (s) => `\x1b[1m${s}\x1b[0m`,
  dim: (s) => `\x1b[2m${s}\x1b[0m`,
};

// Severity icons
const icons = {
  critical: '🔴',
  warning: '🟡',
  info: '🔵',
};

/**
 * Print human-readable report
 */
function printReport(results, targetPath) {
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
  lines.push(`Date: ${new Date().toISOString()}`);
  lines.push('');

  // Group findings by severity
  const critical = results.findings.filter(f => f.severity === 'critical');
  const warning = results.findings.filter(f => f.severity === 'warning');
  const info = results.findings.filter(f => f.severity === 'info');

  // Critical findings
  if (critical.length > 0) {
    lines.push(colors.red(colors.bold(`${icons.critical} CRITICAL (${critical.length})`)));
    lines.push('');
    for (const finding of critical) {
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

  lines.push('');

  return lines.join('\n');
}

/**
 * Format a single finding
 */
function formatFinding(finding, colorFn) {
  const lines = [];
  const location = finding.line > 0 
    ? `${finding.file}:${finding.line}` 
    : finding.file;
  
  lines.push(`  ${colorFn('●')} ${finding.description}`);
  lines.push(colors.dim(`    ${location}`));
  
  if (finding.snippet) {
    lines.push(colors.gray(`    ${finding.snippet}`));
  }
  
  if (finding.recommendation) {
    lines.push(colors.dim(`    💡 ${finding.recommendation}`));
  }
  
  if (finding.fixed) {
    lines.push(colors.green(`    ✅ Fixed`));
  }
  
  lines.push('');
  
  return lines.join('\n');
}

/**
 * Print JSON output
 */
function printJSON(results) {
  return JSON.stringify(results, null, 2);
}

/**
 * Print quiet summary
 */
function printQuiet(results) {
  const { summary } = results;
  
  if (summary.total === 0) {
    return '✅ No issues found';
  }
  
  const parts = [];
  if (summary.critical > 0) parts.push(`${icons.critical} ${summary.critical} critical`);
  if (summary.warning > 0) parts.push(`${icons.warning} ${summary.warning} warning`);
  if (summary.info > 0) parts.push(`${icons.info} ${summary.info} info`);
  
  const status = summary.critical > 0 ? '❌' : '⚠️';
  return `${status} ${parts.join(', ')}`;
}

module.exports = {
  printReport,
  printJSON,
  printQuiet,
  colors,
};
