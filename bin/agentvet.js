#!/usr/bin/env node
/**
 * AgentVet CLI
 * Security scanner for AI agent skills, configs, and MCP tools
 */

const { scan } = require('../src/index.js');
const { printReport, printJSON, printQuiet } = require('../src/reporter.js');

const VERSION = require('../package.json').version;

const HELP = `
AgentVet v${VERSION}
Security scanner for AI agent skills, configs, and MCP tools.

Usage:
  agentvet scan <path>    Scan a directory or file
  agentvet --help         Show this help message
  agentvet --version      Show version

Options:
  --format <type>   Output format: text (default), json
  --output <file>   Write output to file
  --quiet           Show summary only
  --fix             Auto-fix permission issues
  --severity <lvl>  Minimum severity to report: critical, warning, info (default: info)
  --no-yara         Disable YARA scanning
  --yara-rules <dir> Custom YARA rules directory

Examples:
  agentvet scan ./skills
  agentvet scan . --format json --output report.json
  agentvet scan ~/agent-config --quiet
  agentvet scan . --fix
  agentvet scan . --no-yara
  agentvet scan . --yara-rules ./my-rules

Exit codes:
  0 - No critical issues found
  1 - Critical issues found
`;

function parseArgs(args) {
  const options = {
    command: null,
    path: '.',
    format: 'text',
    output: null,
    quiet: false,
    fix: false,
    severity: 'info',
    yara: true,
    yaraRulesDir: null,
  };

  let i = 0;
  while (i < args.length) {
    const arg = args[i];
    
    switch (arg) {
      case 'scan':
        options.command = 'scan';
        if (args[i + 1] && !args[i + 1].startsWith('-')) {
          options.path = args[++i];
        }
        break;
      case '--help':
      case '-h':
        options.command = 'help';
        break;
      case '--version':
      case '-v':
        options.command = 'version';
        break;
      case '--format':
      case '-f':
        options.format = args[++i] || 'text';
        break;
      case '--output':
      case '-o':
        options.output = args[++i];
        break;
      case '--quiet':
      case '-q':
        options.quiet = true;
        break;
      case '--fix':
        options.fix = true;
        break;
      case '--severity':
      case '-s':
        options.severity = args[++i] || 'info';
        break;
      case '--no-yara':
        options.yara = false;
        break;
      case '--yara-rules':
        options.yaraRulesDir = args[++i];
        break;
      default:
        if (!options.command && !arg.startsWith('-')) {
          // Treat as path if no command yet
          options.command = 'scan';
          options.path = arg;
        }
    }
    i++;
  }

  return options;
}

async function main() {
  const args = process.argv.slice(2);
  const options = parseArgs(args);

  // Handle help and version
  if (options.command === 'help' || args.length === 0) {
    console.log(HELP);
    process.exit(0);
  }

  if (options.command === 'version') {
    console.log(`agentvet v${VERSION}`);
    process.exit(0);
  }

  // Run scan
  if (options.command === 'scan') {
    try {
      const results = await scan(options.path, {
        fix: options.fix,
        severityFilter: options.severity,
        yara: options.yara,
        yaraOptions: options.yaraRulesDir ? { rulesDir: options.yaraRulesDir } : undefined,
      });

      // Output results
      let output;
      if (options.format === 'json') {
        output = printJSON(results);
      } else if (options.quiet) {
        output = printQuiet(results);
      } else {
        output = printReport(results, options.path);
      }

      // Write to file or stdout
      if (options.output) {
        require('fs').writeFileSync(options.output, output);
        console.log(`Report written to ${options.output}`);
      } else {
        console.log(output);
      }

      // Exit code based on critical findings
      process.exit(results.summary.critical > 0 ? 1 : 0);
    } catch (error) {
      console.error(`Error: ${error.message}`);
      process.exit(2);
    }
  }

  // Unknown command
  console.error('Unknown command. Use --help for usage.');
  process.exit(1);
}

main();
