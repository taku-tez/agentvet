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

// YARA scanner (optional)
let YaraScanner;
try {
  ({ YaraScanner } = require('./yara/index.js'));
} catch {
  YaraScanner = null;
}

// Files to always scan
const PRIORITY_FILES = [
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

class Scanner {
  constructor(options = {}) {
    this.options = {
      fix: false,
      severityFilter: 'info',
      maxFileSize: 1024 * 1024, // 1MB
      checkPermissions: true,
      yara: true, // Enable YARA scanning by default
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
    };
    
    this.rules = [
      ...credentials.rules,
      ...commands.rules,
      ...urls.rules,
      ...mcp.rules,
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
    const ignoreFile = path.join(rootPath, '.agentvetignore');
    
    if (fs.existsSync(ignoreFile)) {
      try {
        const content = fs.readFileSync(ignoreFile, 'utf8');
        this.ignorePatterns = content
          .split('\n')
          .map(line => line.trim())
          .filter(line => line && !line.startsWith('#'));
        this.results.ignoreFile = ignoreFile;
        this.results.ignorePatterns = this.ignorePatterns.length;
      } catch {
        // Ignore read errors
      }
    }
  }

  /**
   * Check if a file should be ignored
   */
  isIgnored(filePath) {
    if (this.ignorePatterns.length === 0) return false;
    
    // Get relative path from root
    const relativePath = path.relative(this.rootPath, filePath);
    
    for (const pattern of this.ignorePatterns) {
      if (matchesIgnorePattern(relativePath, pattern)) {
        return true;
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
    
    // Determine file type for rule filtering
    const isDocFile = ['.md', '.mdx', '.txt', '.rst'].includes(ext);
    
    // Apply each rule
    for (const rule of this.rules) {
      // Skip code-focused rules for documentation files
      if (isDocFile && this.isCodeOnlyRule(rule)) {
        continue;
      }
      this.applyRule(rule, filePath, content);
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
   * Apply a single rule to file content
   */
  applyRule(rule, filePath, content) {
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
   */
  checkPermissions() {
    const sensitivePatterns = [
      '.env',
      'api_key',
      'credentials.json',
      'secrets.json',
      '.pem',
      '.key',
    ];
    
    const homeDir = process.env.HOME || '';
    const configDirs = [
      path.join(homeDir, '.config'),
      path.join(homeDir, '.clawdbot'),
    ];
    
    for (const rule of permissions.rules) {
      // Check common sensitive file locations
      for (const configDir of configDirs) {
        if (!fs.existsSync(configDir)) continue;
        
        this.walkForPermissions(configDir, rule);
      }
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
}

module.exports = { Scanner };
