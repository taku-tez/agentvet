/**
 * AgentVet Scanner
 * Core scanning logic
 */

const fs = require('fs');
const path = require('path');

// Simple gitignore-style pattern matcher
function matchesIgnorePattern(filePath, pattern) {
  // Normalize paths
  const normalizedPath = filePath.replace(/\\/g, '/');
  const normalizedPattern = pattern.replace(/\\/g, '/').trim();
  
  if (!normalizedPattern || normalizedPattern.startsWith('#')) {
    return false; // Empty or comment
  }
  
  // Handle negation (!)
  if (normalizedPattern.startsWith('!')) {
    return false; // Negation not supported yet
  }
  
  // Convert gitignore pattern to regex
  let regexPattern = normalizedPattern
    .replace(/\./g, '\\.') // Escape dots
    .replace(/\*\*/g, '{{GLOBSTAR}}') // Temp placeholder for **
    .replace(/\*/g, '[^/]*') // * matches anything except /
    .replace(/{{GLOBSTAR}}/g, '.*') // ** matches everything
    .replace(/\?/g, '[^/]'); // ? matches single char
  
  // If pattern starts with /, anchor to root
  if (regexPattern.startsWith('/')) {
    regexPattern = '^' + regexPattern.slice(1);
  } else {
    // Match anywhere in path
    regexPattern = '(^|/)' + regexPattern;
  }
  
  // If pattern ends with /, match directory
  if (regexPattern.endsWith('/')) {
    regexPattern = regexPattern + '.*';
  } else {
    regexPattern = regexPattern + '($|/)';
  }
  
  try {
    const regex = new RegExp(regexPattern);
    return regex.test(normalizedPath);
  } catch {
    return false;
  }
}

// Import rules
const credentials = require('./rules/credentials.js');
const commands = require('./rules/commands.js');
const urls = require('./rules/urls.js');
const permissions = require('./rules/permissions.js');
const mcp = require('./rules/mcp.js');
const agents = require('./rules/agents.js');
const cicd = require('./rules/cicd.js');

// YARA scanner (optional)
let YaraScanner;
try {
  ({ YaraScanner } = require('./yara/index.js'));
} catch {
  YaraScanner = null;
}

// Dependency scanner (optional)
let DependencyScanner;
try {
  ({ DependencyScanner } = require('./deps/index.js'));
} catch {
  DependencyScanner = null;
}

// LLM analyzer (optional)
let LLMAnalyzer;
try {
  ({ LLMAnalyzer } = require('./llm/index.js'));
} catch {
  LLMAnalyzer = null;
}

// Custom rules engine
let CustomRulesEngine;
try {
  ({ CustomRulesEngine } = require('./rules/custom.js'));
} catch {
  CustomRulesEngine = null;
}

// URL/IP Reputation checker
let ReputationChecker;
try {
  ({ ReputationChecker } = require('./reputation/index.js'));
} catch {
  ReputationChecker = null;
}

// Files to always scan
const _PRIORITY_FILES = [
  'SKILL.md',
  'skill.md',
  'AGENTS.md',
  'agents.md',
  'mcp.json',
  'mcp-config.json',
  '.mcp-config.json',
  '.mcp.json',
  'claude_desktop_config.json',
  'cline_mcp_settings.json',
  '.cursor-mcp.json',
  '.env',
  'config.json',
  'settings.json',
];

// Binary extensions to skip
const BINARY_EXTENSIONS = [
  '.jpg', '.jpeg', '.png', '.gif', '.webp', '.ico',
  '.pdf', '.doc', '.docx',
  '.zip', '.tar', '.gz', '.rar', '.7z',
  '.exe', '.bin', '.dll', '.so', '.dylib',
  '.mp3', '.mp4', '.wav', '.avi', '.mov',
  '.woff', '.woff2', '.ttf', '.eot',
];

// Directories to exclude
const EXCLUDE_DIRS = [
  'node_modules',
  '.git',
  '.cache',
  '.npm',
  '__pycache__',
  'venv',
  '.venv',
  'dist',
  'build',
  'coverage',
];

// Files to exclude
const EXCLUDE_FILES = [
  'package-lock.json',
  'yarn.lock',
  'pnpm-lock.yaml',
];

// File patterns to exclude (reduce false positives)
const EXCLUDE_PATTERNS = [
  // XML/XSD schema files (OOXML, etc.) - high false positive rate
  /\.xsd$/i,
  /\.xsl$/i,
  /\.dtd$/i,
  /schemas?\//i,
  // Minified/bundled files
  /\.min\.js$/i,
  /\.bundle\.js$/i,
  /vendor\.js$/i,
  // Test fixtures (may contain intentional "bad" patterns)
  /fixtures?\//i,
  /test-data\//i,
  // Documentation images and assets
  /docs?\/images?\//i,
  /assets?\/images?\//i,
  // Third party notices (legal text, not code)
  /THIRD_PARTY/i,
  /NOTICES?\.md$/i,
  /LICENSE/i,
  // Security scan result files (contain hashes, not secrets)
  /\.security-scan-passed$/i,
  /\.security-scan$/i,
  // Lock files and generated files
  /\.lock$/i,
  /\.sum$/i,
  // Reference documentation (contains code examples, not actual threats)
  /references?\//i,
  /examples?\//i,
  /samples?\//i,
  /tutorials?\//i,
  /templates?\//i,
  // Security documentation (contains intentional examples of secrets/patterns)
  /common_secrets/i,
  /secret_patterns/i,
  /credential_examples/i,
];

class Scanner {
  constructor(options = {}) {
    this.options = {
      fix: false,
      severityFilter: 'info',
      maxFileSize: 1024 * 1024, // 1MB
      checkPermissions: true,
      yara: true, // Enable YARA scanning by default
      deps: true, // Enable dependency scanning by default
      llm: false, // LLM analysis disabled by default (requires API key)
      ...options,
    };
    
    this.results = {
      findings: [],
      summary: {
        total: 0,
        critical: 0,
        warning: 0,
        info: 0,
      },
      scannedFiles: 0,
      fixedIssues: 0,
      yaraEnabled: false,
      depsEnabled: false,
      depsResults: null,
      llmEnabled: false,
      llmResults: null,
    };
    
    this.rules = [
      ...credentials.rules,
      ...commands.rules,
      ...urls.rules,
      ...mcp.rules,
      ...agents.rules,
      ...cicd.rules,
    ];
    
    // Ignore patterns (loaded from .agentvetignore)
    this.ignorePatterns = [];
    this.rootPath = null;
    
    // Initialize YARA scanner if available and enabled
    if (this.options.yara && YaraScanner) {
      try {
        this.yaraScanner = new YaraScanner(options.yaraOptions || {});
        this.results.yaraEnabled = true;
        this.results.yaraMode = this.yaraScanner.getStatus().mode;
      } catch (e) {
        // YARA initialization failed, continue without it
        this.yaraScanner = null;
      }
    }
    
    // Initialize dependency scanner if available and enabled
    if (this.options.deps && DependencyScanner) {
      try {
        this.depsScanner = new DependencyScanner(options.depsOptions || {});
        this.results.depsEnabled = true;
      } catch (e) {
        this.depsScanner = null;
      }
    }
    
    // Initialize LLM analyzer if available and enabled
    if (this.options.llm && LLMAnalyzer) {
      try {
        this.llmAnalyzer = new LLMAnalyzer(options.llmOptions || {});
        if (this.llmAnalyzer.isAvailable()) {
          this.results.llmEnabled = true;
          this.results.llmProvider = this.llmAnalyzer.getStatus().provider;
        } else {
          this.llmAnalyzer = null;
        }
      } catch (e) {
        this.llmAnalyzer = null;
      }
    }

    // Initialize custom rules engine if rules file specified
    if (this.options.customRules && CustomRulesEngine) {
      try {
        this.customRulesEngine = new CustomRulesEngine();
        const rulesLoaded = this.customRulesEngine.loadFromFile(this.options.customRules);
        this.results.customRulesEnabled = true;
        this.results.customRulesCount = rulesLoaded;
      } catch (e) {
        console.warn(`Custom rules warning: ${e.message}`);
        this.customRulesEngine = null;
      }
    }

    // Initialize reputation checker if enabled
    if (this.options.reputation && ReputationChecker) {
      try {
        this.reputationChecker = new ReputationChecker(options.reputationOptions || {});
        if (this.reputationChecker.isAvailable()) {
          this.results.reputationEnabled = true;
          this.results.reputationServices = this.reputationChecker.getAvailableServices();
        } else {
          this.reputationChecker = null;
        }
      } catch (e) {
        this.reputationChecker = null;
      }
    }
  }

  /**
   * Scan a path (file or directory)
   */
  async scan(targetPath) {
    const resolvedPath = path.resolve(targetPath.replace(/^~/, process.env.HOME || ''));
    
    if (!fs.existsSync(resolvedPath)) {
      throw new Error(`Path not found: ${resolvedPath}`);
    }
    
    const stat = fs.statSync(resolvedPath);
    
    // Set root path and load ignore patterns
    this.rootPath = stat.isDirectory() ? resolvedPath : path.dirname(resolvedPath);
    this.loadIgnorePatterns(this.rootPath);
    
    if (stat.isFile()) {
      this.scanFile(resolvedPath);
    } else if (stat.isDirectory()) {
      this.walkDirectory(resolvedPath);
    }
    
    // Check file permissions for sensitive files
    if (this.options.checkPermissions) {
      this.checkPermissions();
    }
    
    // Run YARA scan if enabled
    if (this.yaraScanner) {
      await this.runYaraScan(resolvedPath);
    }
    
    // Run dependency scan if enabled
    if (this.depsScanner) {
      await this.runDepsScan(resolvedPath);
    }
    
    // Run LLM analysis if enabled
    if (this.llmAnalyzer) {
      await this.runLLMAnalysis(resolvedPath);
    }

    // Run reputation check if enabled
    if (this.reputationChecker) {
      await this.runReputationCheck(resolvedPath);
    }
    
    // Auto-fix if requested
    if (this.options.fix) {
      this.autoFix();
    }
    
    return this.results;
  }

  /**
   * Load ignore patterns from .agentvetignore
   */
  loadIgnorePatterns(rootPath) {
    const patterns = [];
    const sources = [];

    // Load .agentvetignore (highest priority)
    const agentvetIgnore = path.join(rootPath, '.agentvetignore');
    if (fs.existsSync(agentvetIgnore)) {
      try {
        const content = fs.readFileSync(agentvetIgnore, 'utf8');
        const lines = content
          .split('\n')
          .map(line => line.trim())
          .filter(line => line && !line.startsWith('#'));
        patterns.push(...lines);
        sources.push('.agentvetignore');
      } catch {
        // Ignore read errors
      }
    }

    // Load .gitignore (if option enabled, default: true)
    if (this.options.respectGitignore !== false) {
      const gitignore = path.join(rootPath, '.gitignore');
      if (fs.existsSync(gitignore)) {
        try {
          const content = fs.readFileSync(gitignore, 'utf8');
          const lines = content
            .split('\n')
            .map(line => line.trim())
            .filter(line => line && !line.startsWith('#'));
          patterns.push(...lines);
          sources.push('.gitignore');
        } catch {
          // Ignore read errors
        }
      }

      // Also check for nested .gitignore files in subdirectories
      this.nestedGitignores = new Map();
    }

    this.ignorePatterns = [...new Set(patterns)]; // Deduplicate
    
    if (sources.length > 0) {
      this.results.ignoreSources = sources;
      this.results.ignorePatterns = this.ignorePatterns.length;
    }
  }

  /**
   * Load nested .gitignore for a directory
   */
  loadNestedGitignore(dirPath) {
    if (!this.options.respectGitignore !== false) return [];
    
    const gitignore = path.join(dirPath, '.gitignore');
    if (!fs.existsSync(gitignore)) return [];
    
    if (this.nestedGitignores?.has(dirPath)) {
      return this.nestedGitignores.get(dirPath);
    }

    try {
      const content = fs.readFileSync(gitignore, 'utf8');
      const patterns = content
        .split('\n')
        .map(line => line.trim())
        .filter(line => line && !line.startsWith('#'));
      
      this.nestedGitignores?.set(dirPath, patterns);
      return patterns;
    } catch {
      return [];
    }
  }

  /**
   * Check if a file should be ignored
   */
  isIgnored(filePath) {
    // Get relative path from root
    const relativePath = path.relative(this.rootPath, filePath);
    
    // Check root-level ignore patterns
    if (this.ignorePatterns.length > 0) {
      for (const pattern of this.ignorePatterns) {
        if (matchesIgnorePattern(relativePath, pattern)) {
          return true;
        }
      }
    }

    // Check nested .gitignore patterns
    if (this.options.respectGitignore !== false && this.nestedGitignores) {
      const dirPath = path.dirname(filePath);
      let currentDir = dirPath;
      
      // Walk up the directory tree checking for nested .gitignore
      while (currentDir.startsWith(this.rootPath) && currentDir !== this.rootPath) {
        const nestedPatterns = this.loadNestedGitignore(currentDir);
        const relativeToNested = path.relative(currentDir, filePath);
        
        for (const pattern of nestedPatterns) {
          if (matchesIgnorePattern(relativeToNested, pattern)) {
            return true;
          }
        }
        
        currentDir = path.dirname(currentDir);
      }
    }
    
    return false;
  }

  /**
   * Walk directory recursively
   */
  walkDirectory(dirPath) {
    let entries;
    try {
      entries = fs.readdirSync(dirPath);
    } catch (e) {
      return; // Skip inaccessible directories
    }
    
    for (const entry of entries) {
      const fullPath = path.join(dirPath, entry);
      
      // Skip excluded directories
      if (EXCLUDE_DIRS.includes(entry)) continue;
      
      // Skip excluded files
      if (EXCLUDE_FILES.includes(entry)) continue;
      
      // Skip ignored paths
      if (this.isIgnored(fullPath)) continue;
      
      try {
        const stat = fs.statSync(fullPath);
        
        if (stat.isDirectory()) {
          this.walkDirectory(fullPath);
        } else if (stat.isFile()) {
          this.scanFile(fullPath);
        }
      } catch (e) {
        // Skip files we can't access
      }
    }
  }

  /**
   * Scan a single file
   */
  scanFile(filePath) {
    const ext = path.extname(filePath).toLowerCase();
    const basename = path.basename(filePath);
    
    // Skip binary files
    if (BINARY_EXTENSIONS.includes(ext)) return;
    
    // Skip files matching exclude patterns (reduce false positives)
    for (const pattern of EXCLUDE_PATTERNS) {
      if (pattern.test(filePath)) return;
    }
    
    // Skip self
    if (basename === 'agentvet.js') return;
    
    // Check file size
    try {
      const stat = fs.statSync(filePath);
      if (stat.size > this.options.maxFileSize) return;
    } catch (e) {
      return;
    }
    
    // Read file content
    let content;
    try {
      content = fs.readFileSync(filePath, 'utf8');
    } catch (e) {
      return; // Skip unreadable files
    }
    
    this.results.scannedFiles++;
    
    // Parse ignore comments
    const ignoreMap = this.parseIgnoreComments(content);
    
    // Determine file type for rule filtering
    const isDocFile = ['.md', '.mdx', '.txt', '.rst'].includes(ext);
    
    // Apply each rule
    for (const rule of this.rules) {
      // Skip code-focused rules for documentation files
      if (isDocFile && this.isCodeOnlyRule(rule)) {
        continue;
      }
      this.applyRule(rule, filePath, content, ignoreMap);
    }

    // Apply custom rules if enabled
    if (this.customRulesEngine) {
      const customFindings = this.customRulesEngine.scan(filePath, content);
      for (const finding of customFindings) {
        // Check if this finding should be ignored
        if (this.shouldIgnore(ignoreMap, finding.line, finding.rule)) {
          this.results.ignoredFindings = (this.results.ignoredFindings || 0) + 1;
          continue;
        }
        
        this.results.findings.push({
          ruleId: finding.rule,
          severity: finding.severity,
          description: finding.message,
          file: finding.file,
          line: finding.line,
          snippet: finding.evidence,
          recommendation: finding.recommendation,
          tags: finding.tags,
          source: 'custom',
        });
        this.results.summary[finding.severity] = (this.results.summary[finding.severity] || 0) + 1;
        this.results.summary.total++;
      }
    }
  }

  /**
   * Check if rule should only apply to code files (not docs)
   */
  isCodeOnlyRule(rule) {
    // MCP rules and command execution rules are code-focused
    const codeOnlyPrefixes = ['mcp-', 'command-'];
    return codeOnlyPrefixes.some(prefix => rule.id.startsWith(prefix));
  }

  /**
   * Parse ignore comments from file content
   * Supports:
   *   // agentvet-ignore - ignore this line
   *   // agentvet-ignore-next-line - ignore next line
   *   // agentvet-ignore rule-id - ignore specific rule
   *   block comment style with agentvet-ignore
   *   # agentvet-ignore - for shell/python/yaml
   *   HTML comment with agentvet-ignore - for HTML/markdown
   */
  parseIgnoreComments(content) {
    const ignoreMap = {
      lines: new Set(),      // Lines to completely ignore
      lineRules: new Map(),  // Line -> Set of rule IDs to ignore
    };

    const lines = content.split('\n');
    
    // Patterns for ignore comments
    const ignorePatterns = [
      /(?:\/\/|#|\/\*)\s*agentvet-ignore(?:-next-line)?(?:\s+([\w-]+(?:\s*,\s*[\w-]+)*))?/gi,
      /<!--\s*agentvet-ignore(?:-next-line)?(?:\s+([\w-]+(?:\s*,\s*[\w-]+)*))?\s*-->/gi,
    ];

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const lineNum = i + 1;

      for (const pattern of ignorePatterns) {
        pattern.lastIndex = 0;
        const match = pattern.exec(line);
        
        if (match) {
          const isNextLine = line.includes('ignore-next-line');
          const targetLine = isNextLine ? lineNum + 1 : lineNum;
          const ruleIds = match[1] ? match[1].split(/\s*,\s*/).map(r => r.trim()) : null;

          if (ruleIds && ruleIds.length > 0) {
            // Ignore specific rules
            if (!ignoreMap.lineRules.has(targetLine)) {
              ignoreMap.lineRules.set(targetLine, new Set());
            }
            ruleIds.forEach(id => ignoreMap.lineRules.get(targetLine).add(id));
          } else {
            // Ignore all rules on this line
            ignoreMap.lines.add(targetLine);
          }
        }
      }
    }

    return ignoreMap;
  }

  /**
   * Check if a finding should be ignored
   */
  shouldIgnore(ignoreMap, lineNum, ruleId) {
    // Check if entire line is ignored
    if (ignoreMap.lines.has(lineNum)) {
      return true;
    }

    // Check if specific rule is ignored for this line
    if (ignoreMap.lineRules.has(lineNum)) {
      const ignoredRules = ignoreMap.lineRules.get(lineNum);
      if (ignoredRules.has(ruleId) || ignoredRules.has('*')) {
        return true;
      }
    }

    return false;
  }

  /**
   * Apply a single rule to file content
   */
  applyRule(rule, filePath, content, ignoreMap = null) {
    // Skip if severity doesn't match filter
    const severityOrder = { critical: 0, warning: 1, info: 2 };
    const filterLevel = severityOrder[this.options.severityFilter] ?? 2;
    const ruleLevel = severityOrder[rule.severity] ?? 2;
    if (ruleLevel > filterLevel) return;
    
    // Reset regex lastIndex
    rule.pattern.lastIndex = 0;
    
    const lines = content.split('\n');
    let match;
    
    while ((match = rule.pattern.exec(content)) !== null) {
      const lineNum = content.substring(0, match.index).split('\n').length;
      
      // Check if this finding should be ignored
      if (ignoreMap && this.shouldIgnore(ignoreMap, lineNum, rule.id)) {
        this.results.ignoredFindings = (this.results.ignoredFindings || 0) + 1;
        // Prevent infinite loop for zero-width matches
        if (match.index === rule.pattern.lastIndex) {
          rule.pattern.lastIndex++;
        }
        continue;
      }

      const lineContent = lines[lineNum - 1] || '';
      
      // Create finding
      const finding = {
        ruleId: rule.id,
        severity: rule.severity,
        description: rule.description,
        file: filePath,
        line: lineNum,
        column: match.index - content.lastIndexOf('\n', match.index - 1),
        snippet: this.sanitizeSnippet(match[0], rule),
        lineContent: lineContent.trim().substring(0, 100),
        recommendation: rule.recommendation,
      };
      
      this.results.findings.push(finding);
      this.results.summary[rule.severity]++;
      this.results.summary.total++;
      
      // Prevent infinite loop for zero-width matches
      if (match.index === rule.pattern.lastIndex) {
        rule.pattern.lastIndex++;
      }
    }
  }

  /**
   * Sanitize snippet (mask sensitive data)
   */
  sanitizeSnippet(snippet, rule) {
    // For credential rules, mask the actual value
    if (rule.id.startsWith('credential-')) {
      if (snippet.length > 20) {
        return snippet.substring(0, 10) + '***' + snippet.substring(snippet.length - 4);
      }
    }
    
    // Truncate long snippets
    if (snippet.length > 60) {
      return snippet.substring(0, 57) + '...';
    }
    
    return snippet;
  }

  /**
   * Check file permissions for sensitive files
   * Only checks files within the scan target directory (not system-wide)
   */
  checkPermissions() {
    // Only check permissions within the scanned directory
    // Do NOT check ~/.config or other system directories - those are out of scope
    if (!this.rootPath) return;
    
    for (const rule of permissions.rules) {
      this.walkForPermissions(this.rootPath, rule);
    }
  }

  /**
   * Walk directory checking permissions
   */
  walkForPermissions(dirPath, rule) {
    let entries;
    try {
      entries = fs.readdirSync(dirPath);
    } catch (e) {
      return;
    }
    
    for (const entry of entries) {
      const fullPath = path.join(dirPath, entry);
      
      try {
        const stat = fs.statSync(fullPath);
        
        if (stat.isDirectory()) {
          this.walkForPermissions(fullPath, rule);
        } else if (stat.isFile()) {
          // Check if file matches sensitive patterns
          const isSensitive = rule.patterns.some(p => 
            entry.includes(p) || entry.endsWith(p)
          );
          
          if (isSensitive) {
            const mode = (stat.mode & 0o777).toString(8);
            
            // Check if permissions are too open
            if (mode !== '600' && mode !== '400') {
              const finding = {
                ruleId: rule.id,
                severity: mode.charAt(2) !== '0' ? 'critical' : 'warning',
                description: rule.description,
                file: fullPath,
                line: 0,
                snippet: `Current: ${mode}, Recommended: 600`,
                recommendation: rule.recommendation,
                fixable: true,
                currentMode: mode,
              };
              
              this.results.findings.push(finding);
              this.results.summary[finding.severity]++;
              this.results.summary.total++;
            }
          }
        }
      } catch (e) {
        // Skip inaccessible files
      }
    }
  }

  /**
   * Auto-fix permission issues
   */
  autoFix() {
    for (const finding of this.results.findings) {
      if (finding.fixable && finding.ruleId === 'permission-sensitive-files') {
        try {
          fs.chmodSync(finding.file, 0o600);
          this.results.fixedIssues++;
          finding.fixed = true;
        } catch (e) {
          finding.fixError = e.message;
        }
      }
    }
  }

  /**
   * Run YARA scan on target path
   */
  async runYaraScan(targetPath) {
    if (!this.yaraScanner) return;
    
    try {
      const stat = fs.statSync(targetPath);
      let yaraFindings;
      
      if (stat.isFile()) {
        yaraFindings = await this.yaraScanner.scanFile(targetPath);
      } else {
        yaraFindings = await this.yaraScanner.scanDirectory(targetPath);
      }
      
      // Add YARA findings to results
      for (const finding of yaraFindings) {
        // Skip ignored files
        if (this.isIgnored(finding.file)) continue;
        
        // Skip files matching exclude patterns
        let excluded = false;
        for (const pattern of EXCLUDE_PATTERNS) {
          if (pattern.test(finding.file)) {
            excluded = true;
            break;
          }
        }
        if (excluded) continue;
        
        // Apply severity filter
        const severityOrder = { critical: 0, warning: 1, info: 2 };
        const filterLevel = severityOrder[this.options.severityFilter] ?? 2;
        const findingLevel = severityOrder[finding.severity] ?? 2;
        
        if (findingLevel > filterLevel) continue;
        
        this.results.findings.push({
          ruleId: finding.ruleId,
          severity: finding.severity,
          description: finding.description,
          file: finding.file,
          line: 0,
          snippet: finding.matches?.join(', ') || finding.matchedString || '',
          recommendation: `YARA rule ${finding.ruleName} matched. Review for potential ${finding.category} threat.`,
          category: finding.category,
          source: finding.source,
        });
        
        this.results.summary[finding.severity]++;
        this.results.summary.total++;
      }
    } catch (e) {
      // YARA scan failed, continue without it
    }
  }

  /**
   * Run dependency vulnerability scan
   */
  async runDepsScan(targetPath) {
    if (!this.depsScanner) return;
    
    try {
      const depsResults = await this.depsScanner.scan(targetPath);
      this.results.depsResults = depsResults;
      
      // Add dependency findings to main findings
      for (const finding of depsResults.findings) {
        // Map severity to our severity levels
        let severity;
        if (finding.severity === 'critical' || finding.severity === 'high') {
          severity = 'critical';
        } else if (finding.severity === 'moderate') {
          severity = 'warning';
        } else {
          severity = 'info';
        }
        
        // Apply severity filter
        const severityOrder = { critical: 0, warning: 1, info: 2 };
        const filterLevel = severityOrder[this.options.severityFilter] ?? 2;
        const findingLevel = severityOrder[severity] ?? 2;
        
        if (findingLevel > filterLevel) continue;
        
        this.results.findings.push({
          ruleId: `deps-${finding.source}-${finding.severity}`,
          severity,
          description: `[${finding.source.toUpperCase()}] ${finding.title}`,
          file: `package: ${finding.package}${finding.version ? '@' + finding.version : ''}`,
          line: 0,
          snippet: finding.range || finding.fixVersions || '',
          recommendation: finding.fixAvailable || 
            (finding.fixVersions ? `Update to: ${finding.fixVersions}` : 'No fix available'),
          category: 'dependency',
          source: finding.source,
          url: finding.url || '',
        });
        
        this.results.summary[severity]++;
        this.results.summary.total++;
      }
    } catch (e) {
      // Dependency scan failed, continue without it
    }
  }

  /**
   * Run LLM-based intent analysis
   */
  async runLLMAnalysis(targetPath) {
    if (!this.llmAnalyzer) return;
    
    try {
      const llmResults = await this.llmAnalyzer.analyze(targetPath);
      this.results.llmResults = llmResults;
      
      // Add LLM findings to main findings
      for (const finding of llmResults.findings || []) {
        // Map severity
        let severity;
        if (finding.severity === 'critical' || finding.severity === 'high') {
          severity = 'critical';
        } else if (finding.severity === 'medium') {
          severity = 'warning';
        } else {
          severity = 'info';
        }
        
        // Apply severity filter
        const severityOrder = { critical: 0, warning: 1, info: 2 };
        const filterLevel = severityOrder[this.options.severityFilter] ?? 2;
        const findingLevel = severityOrder[severity] ?? 2;
        
        if (findingLevel > filterLevel) continue;
        
        // Skip ignored files
        if (finding.file && this.isIgnored(finding.file)) continue;
        
        this.results.findings.push({
          ruleId: `llm-${finding.type || 'analysis'}`,
          severity,
          description: `[LLM] ${finding.description || finding.type}`,
          file: finding.file || 'unknown',
          line: 0,
          snippet: finding.evidence || '',
          recommendation: finding.recommendation || 'Review this instruction for potential security issues.',
          category: 'llm-analysis',
          source: 'llm',
        });
        
        this.results.summary[severity]++;
        this.results.summary.total++;
      }
    } catch (e) {
      // LLM analysis failed, continue without it
      this.results.llmError = e.message;
    }
  }

  /**
   * Run URL/IP reputation check
   */
  async runReputationCheck(targetPath) {
    try {
      // Collect all file contents for URL/IP extraction
      const files = this.collectFiles(targetPath);
      let allContent = '';
      
      for (const file of files.slice(0, 50)) { // Limit to 50 files
        try {
          const content = fs.readFileSync(file, 'utf8');
          allContent += content + '\n';
        } catch {
          // Skip unreadable files
        }
      }

      // Run reputation check
      const repResults = await this.reputationChecker.scanContent(allContent, {
        maxChecks: this.options.reputationOptions?.maxChecks || 10,
      });

      // Store results
      this.results.reputationResults = {
        checked: repResults.checked,
        skipped: repResults.skipped,
        findingsCount: repResults.findings.length,
      };

      // Add findings
      for (const finding of repResults.findings) {
        // Apply severity filter
        const severityOrder = { critical: 0, warning: 1, info: 2 };
        const filterLevel = severityOrder[this.options.severityFilter] ?? 2;
        const findingLevel = severityOrder[finding.severity] ?? 2;
        
        if (findingLevel > filterLevel) continue;

        this.results.findings.push({
          ruleId: `reputation-${finding.type}`,
          severity: finding.severity,
          description: finding.message,
          file: targetPath,
          line: 0,
          snippet: finding.target,
          recommendation: `This ${finding.type} has been flagged by ${finding.sources.join(', ')}. Review and remove if not necessary.`,
          category: 'reputation',
          source: 'reputation',
          score: finding.score,
        });

        this.results.summary[finding.severity]++;
        this.results.summary.total++;
      }
    } catch (e) {
      this.results.reputationError = e.message;
    }
  }

  /**
   * Collect files from a path
   */
  collectFiles(targetPath) {
    const files = [];
    const stat = fs.statSync(targetPath);
    
    if (stat.isFile()) {
      return [targetPath];
    }

    const walk = (dir) => {
      try {
        const entries = fs.readdirSync(dir);
        for (const entry of entries) {
          if (EXCLUDE_DIRS.includes(entry)) continue;
          if (EXCLUDE_FILES.includes(entry)) continue;
          
          const fullPath = path.join(dir, entry);
          if (this.isIgnored(fullPath)) continue;
          
          try {
            const entryStat = fs.statSync(fullPath);
            if (entryStat.isDirectory()) {
              walk(fullPath);
            } else if (entryStat.isFile()) {
              const ext = path.extname(fullPath).toLowerCase();
              if (!BINARY_EXTENSIONS.includes(ext)) {
                files.push(fullPath);
              }
            }
          } catch {
            // Skip inaccessible
          }
        }
      } catch {
        // Skip inaccessible directories
      }
    };

    walk(targetPath);
    return files;
  }
}

module.exports = { Scanner };
