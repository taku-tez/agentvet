#!/usr/bin/env node
/**
 * AgentVet CLI
 * Security scanner for AI agent skills, configs, and MCP tools
 */

const fs = require('fs');
const path = require('path');
const { scan } = require('../src/index.js');
const { printReport, printJSON, printQuiet, printHTML, printMarkdown } = require('../src/reporter.js');

const VERSION = require('../package.json').version;

const HELP = `
AgentVet v${VERSION}
Security scanner for AI agent skills, configs, and MCP tools.

Usage:
  agentvet scan <paths...>   Scan directories or files (supports multiple paths and globs)
  agentvet watch <paths...>  Watch for changes and scan automatically
  agentvet init              Generate sample config and rules files
  agentvet --help            Show this help message
  agentvet --version         Show version

Options:
  --format <type>    Output format: text (default), json, html, markdown, sarif
  --output <file>    Write output to file
  --quiet            Show summary only
  --fix              Auto-fix permission issues
  --severity <lvl>   Minimum severity: critical, high, medium, low, info (default: info)
  --no-yara          Disable YARA scanning
  --yara-rules <dir> Custom YARA rules directory
  --no-deps          Disable dependency vulnerability scanning
  --no-gitignore     Don't respect .gitignore patterns
  --reputation       Enable URL/IP reputation checking (requires API key)
  --vt-key <key>     VirusTotal API key (or set VIRUSTOTAL_API_KEY)
  --deps-deep        Deep dependency analysis (slower, more thorough)
  --rules <file>     Custom rules file (YAML format)
  --llm              Enable LLM-based intent analysis
  --llm-provider     LLM provider: openai (default), anthropic, openrouter
  --llm-model        LLM model to use
  --parallel         Scan multiple paths in parallel
  --config <file>    Load options from config file

Watch Mode Options:
  --debounce <ms>    Debounce delay for file changes (default: 500)
  --clear            Clear screen before each scan

Examples:
  # Basic scan
  agentvet scan ./skills

  # Multiple directories
  agentvet scan ./skills ./mcp-configs

  # HTML report
  agentvet scan . --format html --output report.html

  # Watch mode
  agentvet watch . --quiet

  # Deep dependency check
  agentvet scan . --deps-deep

  # Combined
  agentvet scan . --llm --format html --output report.html

Exit codes:
  0 - No critical issues found
  1 - Critical issues found
  2 - Error during scan
`;

// Glob expansion
function expandGlob(pattern) {
  const results = [];
  
  if (!pattern.includes('*') && !pattern.includes('?')) {
    return [pattern];
  }
  
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
      
      if (currentPattern === '**') {
        if (remainingPattern) {
          results.push(...findMatches(dir, remainingPattern, depth));
        } else {
          results.push(dir);
        }
        
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
    depsDeep: false,
    gitignore: true,
    reputation: false,
    vtKey: null,
    rules: null,
    llm: false,
    llmProvider: null,
    llmModel: null,
    parallel: false,
    config: null,
    // Watch options
    debounce: 500,
    clear: false,
  };

  let i = 0;
  while (i < args.length) {
    const arg = args[i];
    
    switch (arg) {
      case 'scan':
      case 'watch':
      case 'init':
        options.command = arg;
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
      case '--no-gitignore':
        options.gitignore = false;
        break;
      case '--reputation':
        options.reputation = true;
        break;
      case '--vt-key':
        options.vtKey = args[++i];
        options.reputation = true;
        break;
      case '--deps-deep':
        options.depsDeep = true;
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
      case '--debounce':
        options.debounce = parseInt(args[++i]) || 500;
        break;
      case '--clear':
        options.clear = true;
        break;
      default:
        if (!options.command && !arg.startsWith('-')) {
          options.command = 'scan';
          options.paths.push(arg);
        } else if ((options.command === 'scan' || options.command === 'watch') && !arg.startsWith('-')) {
          options.paths.push(arg);
        }
    }
    i++;
  }

  if ((options.command === 'scan' || options.command === 'watch') && options.paths.length === 0) {
    options.paths = ['.'];
  }

  return options;
}

function loadConfig(configPath) {
  try {
    const content = fs.readFileSync(configPath, 'utf-8');
    if (configPath.endsWith('.json')) {
      return JSON.parse(content);
    } else if (configPath.endsWith('.yaml') || configPath.endsWith('.yml')) {
      const yaml = require('../src/utils/yaml.js');
      return yaml.parse(content);
    }
    return JSON.parse(content);
  } catch (error) {
    console.error(`Warning: Could not load config file: ${error.message}`);
    return {};
  }
}

function mergeResults(results) {
  const merged = {
    findings: [],
    summary: {
      total: 0,
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      warning: 0,
      info: 0,
      fixed: 0,
    },
    scannedPaths: [],
    scannedFiles: 0,
    scanDuration: 0,
  };

  for (const result of results) {
    merged.findings.push(...result.findings);
    merged.summary.total += result.summary.total;
    merged.summary.critical += result.summary.critical;
    merged.summary.high += result.summary.high || 0;
    merged.summary.medium += result.summary.medium || 0;
    merged.summary.low += result.summary.low || 0;
    merged.summary.warning += result.summary.warning || 0;
    merged.summary.info += result.summary.info || 0;
    merged.summary.fixed += result.summary.fixed || 0;
    merged.scannedPaths.push(...(result.scannedPaths || [result.path]));
    merged.scannedFiles += result.scannedFiles || 0;
    merged.scanDuration += result.scanDuration || 0;
    
    // Copy other fields from first result
    if (!merged.yaraEnabled && result.yaraEnabled) {
      merged.yaraEnabled = result.yaraEnabled;
      merged.yaraMode = result.yaraMode;
    }
    if (!merged.depsEnabled && result.depsEnabled) {
      merged.depsEnabled = result.depsEnabled;
      merged.depsResults = result.depsResults;
    }
    if (!merged.llmEnabled && result.llmEnabled) {
      merged.llmEnabled = result.llmEnabled;
      merged.llmProvider = result.llmProvider;
    }
    if (!merged.customRulesEnabled && result.customRulesEnabled) {
      merged.customRulesEnabled = result.customRulesEnabled;
      merged.customRulesCount = result.customRulesCount;
    }
  }

  // Deduplicate findings
  const seen = new Set();
  merged.findings = merged.findings.filter(f => {
    const key = `${f.file}:${f.ruleId}:${f.line || 0}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  merged.summary.total = merged.findings.length;

  return merged;
}

function formatOutput(results, options, pathLabel) {
  switch (options.format) {
    case 'json':
      return printJSON(results);
    case 'html':
      return printHTML(results, pathLabel);
    case 'markdown':
    case 'md':
      return printMarkdown(results, pathLabel);
    case 'sarif':
      return printSARIF(results);
    default:
      if (options.quiet) {
        return printQuiet(results);
      }
      return printReport(results, pathLabel);
  }
}

// SARIF output format
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
    if (!ruleMap.has(finding.ruleId)) {
      ruleMap.set(finding.ruleId, {
        id: finding.ruleId,
        name: finding.ruleId,
        shortDescription: { text: finding.description || finding.ruleId },
        defaultConfiguration: {
          level: finding.severity === 'critical' ? 'error' : 
                 finding.severity === 'high' ? 'error' :
                 finding.severity === 'warning' ? 'warning' : 'note',
        },
      });
    }

    sarif.runs[0].results.push({
      ruleId: finding.ruleId,
      level: finding.severity === 'critical' ? 'error' : 
             finding.severity === 'high' ? 'error' :
             finding.severity === 'warning' ? 'warning' : 'note',
      message: { text: finding.description || finding.snippet || finding.ruleId },
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

// Watch mode implementation
async function watchMode(options, scanOptions) {
  const chokidar = await loadChokidar();
  if (!chokidar) {
    console.error('Watch mode requires chokidar. Install with: npm install -g chokidar');
    console.log('Falling back to polling mode...');
    return pollMode(options, scanOptions);
  }

  let expandedPaths = [];
  for (const p of options.paths) {
    expandedPaths.push(...expandGlob(p));
  }
  expandedPaths = [...new Set(expandedPaths)].filter(p => {
    try { fs.accessSync(p); return true; } catch { return false; }
  });

  console.log(`\n👁️  Watching ${expandedPaths.length} path(s) for changes...`);
  console.log('   Press Ctrl+C to stop\n');

  let debounceTimer = null;
  let isScanning = false;

  const runScan = async () => {
    if (isScanning) return;
    isScanning = true;

    if (options.clear) {
      console.clear();
    }

    console.log(`\n🔄 Scanning... (${new Date().toLocaleTimeString()})`);
    
    try {
      const results = await runMultiScan(expandedPaths, scanOptions, options.parallel);
      const output = formatOutput(results, options, expandedPaths.join(', '));
      console.log(output);
    } catch (error) {
      console.error(`Error: ${error.message}`);
    }

    isScanning = false;
  };

  const debouncedScan = () => {
    if (debounceTimer) clearTimeout(debounceTimer);
    debounceTimer = setTimeout(runScan, options.debounce);
  };

  // Initial scan
  await runScan();

  // Watch for changes
  const watcher = chokidar.watch(expandedPaths, {
    ignored: /(node_modules|\.git|__pycache__|dist|build)/,
    persistent: true,
    ignoreInitial: true,
  });

  watcher.on('change', (path) => {
    console.log(`📝 Changed: ${path}`);
    debouncedScan();
  });

  watcher.on('add', (path) => {
    console.log(`➕ Added: ${path}`);
    debouncedScan();
  });

  watcher.on('unlink', (path) => {
    console.log(`➖ Removed: ${path}`);
    debouncedScan();
  });

  // Handle exit
  process.on('SIGINT', () => {
    console.log('\n👋 Stopping watch mode...');
    watcher.close();
    process.exit(0);
  });
}

// Fallback polling mode
async function pollMode(options, scanOptions) {
  let expandedPaths = [];
  for (const p of options.paths) {
    expandedPaths.push(...expandGlob(p));
  }
  expandedPaths = [...new Set(expandedPaths)].filter(p => {
    try { fs.accessSync(p); return true; } catch { return false; }
  });

  console.log(`\n👁️  Polling ${expandedPaths.length} path(s) every 2 seconds...`);
  console.log('   Press Ctrl+C to stop\n');

  let lastHashes = new Map();

  const getFileHash = (filePath) => {
    try {
      const stat = fs.statSync(filePath);
      return `${stat.mtime.getTime()}-${stat.size}`;
    } catch {
      return null;
    }
  };

  const collectHashes = (dir, hashes = new Map()) => {
    try {
      const entries = fs.readdirSync(dir, { withFileTypes: true });
      for (const entry of entries) {
        if (['node_modules', '.git', '__pycache__'].includes(entry.name)) continue;
        const fullPath = path.join(dir, entry.name);
        if (entry.isDirectory()) {
          collectHashes(fullPath, hashes);
        } else {
          hashes.set(fullPath, getFileHash(fullPath));
        }
      }
    } catch {}
    return hashes;
  };

  const checkChanges = async () => {
    const currentHashes = new Map();
    for (const p of expandedPaths) {
      const stat = fs.statSync(p);
      if (stat.isDirectory()) {
        collectHashes(p, currentHashes);
      } else {
        currentHashes.set(p, getFileHash(p));
      }
    }

    let hasChanges = false;
    if (lastHashes.size === 0) {
      hasChanges = true;
    } else {
      for (const [file, hash] of currentHashes) {
        if (lastHashes.get(file) !== hash) {
          hasChanges = true;
          break;
        }
      }
    }

    if (hasChanges) {
      if (options.clear) console.clear();
      console.log(`\n🔄 Scanning... (${new Date().toLocaleTimeString()})`);
      
      try {
        const results = await runMultiScan(expandedPaths, scanOptions, options.parallel);
        const output = formatOutput(results, options, expandedPaths.join(', '));
        console.log(output);
      } catch (error) {
        console.error(`Error: ${error.message}`);
      }
    }

    lastHashes = currentHashes;
  };

  await checkChanges();
  setInterval(checkChanges, 2000);

  process.on('SIGINT', () => {
    console.log('\n👋 Stopping...');
    process.exit(0);
  });
}

async function loadChokidar() {
  try {
    return require('chokidar');
  } catch {
    return null;
  }
}

async function runMultiScan(paths, scanOptions, parallel) {
  if (paths.length === 1) {
    const result = await scan(paths[0], scanOptions);
    result.scannedPaths = paths;
    return result;
  }

  if (parallel) {
    const scanResults = await Promise.all(
      paths.map(p => scan(p, scanOptions).catch(err => ({
        findings: [],
        summary: { total: 0, critical: 0, fixed: 0 },
        scannedFiles: 0,
        error: err.message,
        path: p,
      })))
    );
    return mergeResults(scanResults);
  }

  const scanResults = [];
  for (const p of paths) {
    try {
      const result = await scan(p, scanOptions);
      result.path = p;
      scanResults.push(result);
    } catch (err) {
      console.error(`Error scanning ${p}: ${err.message}`);
      scanResults.push({
        findings: [],
        summary: { total: 0, critical: 0, fixed: 0 },
        scannedFiles: 0,
        error: err.message,
        path: p,
      });
    }
  }
  return mergeResults(scanResults);
}

// Init command - generate sample files
function initCommand() {
  const configContent = `# AgentVet Configuration
# Place this file in your project root as .agentvetrc.yaml

# Severity filter (default: info)
severity: info

# Enable/disable features
yara: true
deps: true
llm: false

# LLM settings (when enabled)
# llmProvider: openai
# llmModel: gpt-4o-mini

# Custom rules file
# rules: ./agentvet-rules.yaml

# Output settings
# format: text
# output: report.html
`;

  const rulesContent = `# AgentVet Custom Rules
# Add your organization-specific security rules here

rules:
  - id: example-api-key
    name: Example API Key
    description: Detects example API key pattern
    severity: critical
    type: regex
    pattern: "EXAMPLE_API_[A-Za-z0-9]{32}"
    message: Found hardcoded API key
    recommendation: Use environment variables
    tags: [credentials]
`;

  const ignoreContent = `# AgentVet Ignore File
# Patterns here will be skipped during scanning

# Dependencies
node_modules/
vendor/
.venv/

# Build outputs
dist/
build/
*.min.js

# Test fixtures (may contain intentional vulnerabilities)
test/fixtures/
__tests__/

# Generated files
*.generated.*
`;

  let created = [];

  if (!fs.existsSync('.agentvetrc.yaml')) {
    fs.writeFileSync('.agentvetrc.yaml', configContent);
    created.push('.agentvetrc.yaml');
  }

  if (!fs.existsSync('agentvet-rules.yaml')) {
    fs.writeFileSync('agentvet-rules.yaml', rulesContent);
    created.push('agentvet-rules.yaml');
  }

  if (!fs.existsSync('.agentvetignore')) {
    fs.writeFileSync('.agentvetignore', ignoreContent);
    created.push('.agentvetignore');
  }

  if (created.length > 0) {
    console.log('✅ Created configuration files:');
    created.forEach(f => console.log(`   - ${f}`));
  } else {
    console.log('ℹ️  Configuration files already exist.');
  }
}

async function main() {
  const args = process.argv.slice(2);
  let options = parseArgs(args);

  // Load config file
  if (options.config) {
    const config = loadConfig(options.config);
    options = { ...options, ...config };
  } else {
    // Try default config locations
    const defaultConfigs = ['.agentvetrc.yaml', '.agentvetrc.json', '.agentvet.yaml'];
    for (const cfg of defaultConfigs) {
      if (fs.existsSync(cfg)) {
        const config = loadConfig(cfg);
        options = { ...config, ...options };
        break;
      }
    }
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

  if (options.command === 'init') {
    initCommand();
    process.exit(0);
  }

  // Prepare scan options
  const scanOptions = {
    fix: options.fix,
    severityFilter: options.severity,
    yara: options.yara,
    yaraOptions: options.yaraRulesDir ? { rulesDir: options.yaraRulesDir } : undefined,
    deps: options.deps,
    depsOptions: options.depsDeep ? { deep: true } : undefined,
    customRules: options.rules,
    llm: options.llm,
    llmOptions: (options.llmProvider || options.llmModel) ? {
      provider: options.llmProvider,
      model: options.llmModel,
    } : undefined,
    respectGitignore: options.gitignore,
    reputation: options.reputation,
    reputationOptions: options.vtKey ? {
      virustotalKey: options.vtKey,
    } : undefined,
  };

  // Watch mode
  if (options.command === 'watch') {
    await watchMode(options, scanOptions);
    return;
  }

  // Scan mode
  if (options.command === 'scan') {
    try {
      let expandedPaths = [];
      for (const p of options.paths) {
        expandedPaths.push(...expandGlob(p));
      }
      expandedPaths = [...new Set(expandedPaths)];
      
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

      const results = await runMultiScan(validPaths, scanOptions, options.parallel);
      
      const pathLabel = validPaths.length === 1 ? validPaths[0] : `${validPaths.length} paths`;
      const output = formatOutput(results, options, pathLabel);

      if (options.output) {
        fs.writeFileSync(options.output, output);
        console.log(`Report written to ${options.output}`);
        
        // Also print summary to console
        if (!options.quiet) {
          console.log(printQuiet(results));
        }
      } else {
        console.log(output);
      }

      process.exit(results.summary.critical > 0 ? 1 : 0);
    } catch (error) {
      console.error(`Error: ${error.message}`);
      if (process.env.DEBUG) {
        console.error(error.stack);
      }
      process.exit(2);
    }
  }

  console.error('Unknown command. Use --help for usage.');
  process.exit(1);
}

main();
