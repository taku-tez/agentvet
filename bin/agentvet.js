#!/usr/bin/env node
/**
 * AgentVet CLI
 * Security scanner for AI agent skills, configs, and MCP tools
 */

const fs = require('fs');
const path = require('path');
const { scan } = require('../src/index.js');
const { printReport, printJSON, printQuiet } = require('../src/reporter.js');

const VERSION = require('../package.json').version;

const HELP = `
AgentVet v${VERSION}
Security scanner for AI agent skills, configs, and MCP tools.

Usage:
  agentvet scan <paths...>   Scan directories or files (supports multiple paths and globs)
  agentvet --help            Show this help message
  agentvet --version         Show version

Options:
  --format <type>    Output format: text (default), json, sarif
  --output <file>    Write output to file
  --quiet            Show summary only
  --fix              Auto-fix permission issues
  --severity <lvl>   Minimum severity to report: critical, high, medium, low, info (default: info)
  --no-yara          Disable YARA scanning
  --yara-rules <dir> Custom YARA rules directory
  --no-deps          Disable dependency vulnerability scanning
  --rules <file>     Custom rules file (YAML format)
  --llm              Enable LLM-based intent analysis
  --llm-provider     LLM provider: openai (default), anthropic, openrouter
  --llm-model        LLM model to use
  --parallel         Scan multiple paths in parallel
  --config <file>    Load options from config file

Examples:
  # Single directory
  agentvet scan ./skills

  # Multiple directories
  agentvet scan ./skills ./mcp-configs ~/agent

  # Glob patterns
  agentvet scan "./projects/**/skills" "./configs/*.json"

  # With custom rules
  agentvet scan . --rules my-rules.yaml

  # JSON output
  agentvet scan . --format json --output report.json

  # LLM analysis
  agentvet scan . --llm --llm-provider anthropic

  # Quick check
  agentvet scan . --quiet --severity high

Exit codes:
  0 - No critical issues found
  1 - Critical issues found
  2 - Error during scan
`;

// Glob expansion (simple implementation)
function expandGlob(pattern) {
  const glob = require('path');
  const results = [];
  
  // If no wildcards, return as-is
  if (!pattern.includes('*') && !pattern.includes('?')) {
    return [pattern];
  }
  
  // Simple glob expansion using fs
  const parts = pattern.split('/');
  const baseParts = [];
  let globStart = -1;
  
  for (let i = 0; i < parts.length; i++) {
    if (parts[i].includes('*') || parts[i].includes('?')) {
      globStart = i;
      break;
    }
    baseParts.push(parts[i]);
  }
  
  if (globStart === -1) {
    return [pattern];
  }
  
  const baseDir = baseParts.length > 0 ? baseParts.join('/') : '.';
  const remainingPattern = parts.slice(globStart).join('/');
  
  try {
    // Recursive directory scan for glob matching
    const matches = findMatches(baseDir, remainingPattern);
    return matches.length > 0 ? matches : [pattern];
  } catch {
    return [pattern];
  }
}

function findMatches(dir, pattern, depth = 0) {
  const results = [];
  const maxDepth = 10;
  
  if (depth > maxDepth) return results;
  
  try {
    const entries = fs.readdirSync(dir, { withFileTypes: true });
    const parts = pattern.split('/');
    const currentPattern = parts[0];
    const remainingPattern = parts.slice(1).join('/');
    
    for (const entry of entries) {
      const entryPath = path.join(dir, entry.name);
      
      // Handle **
      if (currentPattern === '**') {
        // Match current directory
        if (remainingPattern) {
          results.push(...findMatches(dir, remainingPattern, depth));
        } else {
          results.push(dir);
        }
        
        // Recurse into subdirectories
        if (entry.isDirectory()) {
          results.push(...findMatches(entryPath, pattern, depth + 1));
          if (remainingPattern) {
            results.push(...findMatches(entryPath, remainingPattern, depth + 1));
          }
        }
      } else if (matchesPattern(entry.name, currentPattern)) {
        if (!remainingPattern) {
          results.push(entryPath);
        } else if (entry.isDirectory()) {
          results.push(...findMatches(entryPath, remainingPattern, depth + 1));
        }
      }
    }
  } catch {
    // Ignore errors
  }
  
  return results;
}

function matchesPattern(name, pattern) {
  const regex = pattern
    .replace(/\./g, '\\.')
    .replace(/\*\*/g, '.*')
    .replace(/\*/g, '[^/]*')
    .replace(/\?/g, '.');
  return new RegExp(`^${regex}$`).test(name);
}

function parseArgs(args) {
  const options = {
    command: null,
    paths: [],
    format: 'text',
    output: null,
    quiet: false,
    fix: false,
    severity: 'info',
    yara: true,
    yaraRulesDir: null,
    deps: true,
    rules: null,
    llm: false,
    llmProvider: null,
    llmModel: null,
    parallel: false,
    config: null,
  };

  let i = 0;
  while (i < args.length) {
    const arg = args[i];
    
    switch (arg) {
      case 'scan':
        options.command = 'scan';
        // Collect all subsequent non-flag arguments as paths
        while (args[i + 1] && !args[i + 1].startsWith('-')) {
          options.paths.push(args[++i]);
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
      case '--no-deps':
        options.deps = false;
        break;
      case '--rules':
      case '-r':
        options.rules = args[++i];
        break;
      case '--llm':
        options.llm = true;
        break;
      case '--llm-provider':
        options.llmProvider = args[++i];
        options.llm = true;
        break;
      case '--llm-model':
        options.llmModel = args[++i];
        options.llm = true;
        break;
      case '--parallel':
      case '-p':
        options.parallel = true;
        break;
      case '--config':
      case '-c':
        options.config = args[++i];
        break;
      default:
        if (!options.command && !arg.startsWith('-')) {
          // Treat as scan command with path
          options.command = 'scan';
          options.paths.push(arg);
        } else if (options.command === 'scan' && !arg.startsWith('-')) {
          options.paths.push(arg);
        }
    }
    i++;
  }

  // Default path
  if (options.command === 'scan' && options.paths.length === 0) {
    options.paths = ['.'];
  }

  return options;
}

// Load config file
function loadConfig(configPath) {
  try {
    const content = fs.readFileSync(configPath, 'utf-8');
    if (configPath.endsWith('.json')) {
      return JSON.parse(content);
    } else if (configPath.endsWith('.yaml') || configPath.endsWith('.yml')) {
      // Simple YAML parsing for config
      const yaml = require('./utils/yaml.js');
      return yaml.parse(content);
    }
    return JSON.parse(content);
  } catch (error) {
    console.error(`Warning: Could not load config file: ${error.message}`);
    return {};
  }
}

// Merge results from multiple scans
function mergeResults(results) {
  const merged = {
    findings: [],
    summary: {
      total: 0,
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
      fixed: 0,
    },
    scannedPaths: [],
    scanDuration: 0,
  };

  for (const result of results) {
    merged.findings.push(...result.findings);
    merged.summary.total += result.summary.total;
    merged.summary.critical += result.summary.critical;
    merged.summary.high += result.summary.high || 0;
    merged.summary.medium += result.summary.medium || 0;
    merged.summary.low += result.summary.low || 0;
    merged.summary.info += result.summary.info || 0;
    merged.summary.fixed += result.summary.fixed;
    merged.scannedPaths.push(...(result.scannedPaths || [result.path]));
    merged.scanDuration += result.scanDuration || 0;
  }

  // Deduplicate findings by file+rule
  const seen = new Set();
  merged.findings = merged.findings.filter(f => {
    const key = `${f.file}:${f.rule}:${f.line || 0}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  // Recalculate totals after dedup
  merged.summary.total = merged.findings.length;

  return merged;
}

async function main() {
  const args = process.argv.slice(2);
  let options = parseArgs(args);

  // Load config file if specified
  if (options.config) {
    const config = loadConfig(options.config);
    options = { ...options, ...config };
  }

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
      // Expand globs
      let expandedPaths = [];
      for (const p of options.paths) {
        expandedPaths.push(...expandGlob(p));
      }
      
      // Remove duplicates
      expandedPaths = [...new Set(expandedPaths)];
      
      // Validate paths exist
      const validPaths = expandedPaths.filter(p => {
        try {
          fs.accessSync(p);
          return true;
        } catch {
          console.error(`Warning: Path not found: ${p}`);
          return false;
        }
      });

      if (validPaths.length === 0) {
        console.error('Error: No valid paths to scan');
        process.exit(2);
      }

      const scanOptions = {
        fix: options.fix,
        severityFilter: options.severity,
        yara: options.yara,
        yaraOptions: options.yaraRulesDir ? { rulesDir: options.yaraRulesDir } : undefined,
        deps: options.deps,
        customRules: options.rules,
        llm: options.llm,
        llmOptions: (options.llmProvider || options.llmModel) ? {
          provider: options.llmProvider,
          model: options.llmModel,
        } : undefined,
      };

      let results;
      
      if (validPaths.length === 1) {
        // Single path scan
        results = await scan(validPaths[0], scanOptions);
        results.scannedPaths = validPaths;
      } else if (options.parallel) {
        // Parallel scan
        const scanResults = await Promise.all(
          validPaths.map(p => scan(p, scanOptions).catch(err => ({
            findings: [],
            summary: { total: 0, critical: 0, fixed: 0 },
            error: err.message,
            path: p,
          })))
        );
        results = mergeResults(scanResults);
      } else {
        // Sequential scan
        const scanResults = [];
        for (const p of validPaths) {
          try {
            const result = await scan(p, scanOptions);
            result.path = p;
            scanResults.push(result);
          } catch (err) {
            console.error(`Error scanning ${p}: ${err.message}`);
            scanResults.push({
              findings: [],
              summary: { total: 0, critical: 0, fixed: 0 },
              error: err.message,
              path: p,
            });
          }
        }
        results = mergeResults(scanResults);
      }

      // Output results
      let output;
      if (options.format === 'json') {
        output = printJSON(results);
      } else if (options.format === 'sarif') {
        output = printSARIF(results);
      } else if (options.quiet) {
        output = printQuiet(results);
      } else {
        const pathLabel = validPaths.length === 1 
          ? validPaths[0] 
          : `${validPaths.length} paths`;
        output = printReport(results, pathLabel);
      }

      // Write to file or stdout
      if (options.output) {
        fs.writeFileSync(options.output, output);
        console.log(`Report written to ${options.output}`);
      } else {
        console.log(output);
      }

      // Exit code based on critical findings
      process.exit(results.summary.critical > 0 ? 1 : 0);
    } catch (error) {
      console.error(`Error: ${error.message}`);
      if (process.env.DEBUG) {
        console.error(error.stack);
      }
      process.exit(2);
    }
  }

  // Unknown command
  console.error('Unknown command. Use --help for usage.');
  process.exit(1);
}

// SARIF output format (for GitHub Code Scanning)
function printSARIF(results) {
  const sarif = {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: {
        driver: {
          name: 'AgentVet',
          version: VERSION,
          informationUri: 'https://github.com/taku-tez/agentvet',
          rules: [],
        },
      },
      results: [],
    }],
  };

  const ruleMap = new Map();
  
  for (const finding of results.findings) {
    // Add rule if not seen
    if (!ruleMap.has(finding.rule)) {
      ruleMap.set(finding.rule, {
        id: finding.rule,
        name: finding.rule,
        shortDescription: { text: finding.message || finding.rule },
        defaultConfiguration: {
          level: finding.severity === 'critical' ? 'error' : 
                 finding.severity === 'warning' ? 'warning' : 'note',
        },
      });
    }

    // Add result
    sarif.runs[0].results.push({
      ruleId: finding.rule,
      level: finding.severity === 'critical' ? 'error' : 
             finding.severity === 'warning' ? 'warning' : 'note',
      message: { text: finding.message || finding.evidence || finding.rule },
      locations: [{
        physicalLocation: {
          artifactLocation: { uri: finding.file },
          region: finding.line ? {
            startLine: finding.line,
            startColumn: finding.column || 1,
          } : undefined,
        },
      }],
    });
  }

  sarif.runs[0].tool.driver.rules = Array.from(ruleMap.values());
  
  return JSON.stringify(sarif, null, 2);
}

main();
