/**
 * AgentVet Scanner
 * Core scanning logic
 */

import * as fs from 'fs';
import * as path from 'path';
import type { Rule, Finding, ScanOptions, ScanResult, Severity } from './types.js';

// Simple gitignore-style pattern matcher
function matchesIgnorePattern(filePath: string, pattern: string): boolean {
  const normalizedPath = filePath.replace(/\\/g, '/');
  const normalizedPattern = pattern.replace(/\\/g, '/').trim();
  
  if (!normalizedPattern || normalizedPattern.startsWith('#')) {
    return false;
  }
  
  if (normalizedPattern.startsWith('!')) {
    return false;
  }
  
  let regexPattern = normalizedPattern
    .replace(/\./g, '\\.')
    .replace(/\*\*/g, '{{GLOBSTAR}}')
    .replace(/\*/g, '[^/]*')
    .replace(/{{GLOBSTAR}}/g, '.*')
    .replace(/\?/g, '[^/]');
  
  if (regexPattern.startsWith('/')) {
    regexPattern = '^' + regexPattern.slice(1);
  } else {
    regexPattern = '(^|/)' + regexPattern;
  }
  
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
const pickle = require('./rules/pickle.js');
const mcpDiscovery = require('./rules/mcp-discovery.js');

// Optional modules
let YaraScanner: any = null;
try {
  ({ YaraScanner } = require('./yara/index.js'));
} catch {
  // YARA not available
}

let DependencyScanner: any = null;
try {
  ({ DependencyScanner } = require('./deps/index.js'));
} catch {
  // Dependency scanner not available
}

let LLMAnalyzer: any = null;
try {
  ({ LLMAnalyzer } = require('./llm/index.js'));
} catch {
  // LLM analyzer not available
}

let CustomRulesEngine: any = null;
try {
  ({ CustomRulesEngine } = require('./rules/custom.js'));
} catch {
  // Custom rules not available
}

let ReputationChecker: any = null;
try {
  ({ ReputationChecker } = require('./reputation/index.js'));
} catch {
  // Reputation checker not available
}

// Priority files
const _PRIORITY_FILES = [
  'SKILL.md', 'skill.md', 'AGENTS.md', 'agents.md',
  'mcp.json', 'mcp-config.json', '.mcp-config.json', '.mcp.json',
  'claude_desktop_config.json', 'cline_mcp_settings.json', '.cursor-mcp.json',
  '.env', 'config.json', 'settings.json',
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
  'node_modules', '.git', '.cache', '.npm', '__pycache__',
  'venv', '.venv', 'dist', 'build', 'coverage',
];

// Files to exclude
const EXCLUDE_FILES = [
  'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml',
];

// Exclude patterns (reduce false positives)
const EXCLUDE_PATTERNS = [
  /\.xsd$/i, /\.xsl$/i, /\.dtd$/i, /schemas?\//i,
  /\.min\.js$/i, /\.bundle\.js$/i, /vendor\.js$/i,
  /fixtures?\//i, /test-data\//i,
  /docs?\/images?\//i, /assets?\/images?\//i,
  /THIRD_PARTY/i, /NOTICES?\.md$/i, /LICENSE/i,
  /\.security-scan-passed$/i, /\.security-scan$/i,
  /\.lock$/i, /\.sum$/i,
  /references?\//i, /examples?\//i, /samples?\//i, /tutorials?\//i, /templates?\//i,
  /common_secrets/i, /secret_patterns/i, /credential_examples/i,
];

interface ScannerOptions {
  fix?: boolean;
  severityFilter?: Severity | string;
  maxFileSize?: number;
  checkPermissions?: boolean;
  yara?: boolean;
  deps?: boolean;
  llm?: boolean;
  customRules?: string;
  reputation?: boolean;
  yaraOptions?: any;
  depsOptions?: any;
  llmOptions?: any;
  reputationOptions?: any;
  respectGitignore?: boolean;
}

interface InternalResults {
  findings: any[];
  summary: {
    total: number;
    critical: number;
    warning: number;
    info: number;
    [key: string]: number;
  };
  scannedFiles: number;
  fixedIssues: number;
  yaraEnabled: boolean;
  depsEnabled: boolean;
  depsResults: any;
  llmEnabled: boolean;
  llmResults: any;
  yaraMode?: string;
  llmProvider?: string;
  customRulesEnabled?: boolean;
  customRulesCount?: number;
  reputationEnabled?: boolean;
  reputationServices?: string[];
  ignoreSources?: string[];
  ignorePatterns?: number;
  ignoredFindings?: number;
  reputationResults?: any;
  reputationError?: string;
  llmError?: string;
}

interface IgnoreMap {
  lines: Set<number>;
  lineRules: Map<number, Set<string>>;
}

export class Scanner {
  private options: ScannerOptions;
  private results: InternalResults;
  private rules: any[];
  private ignorePatterns: string[];
  private rootPath: string | null;
  private nestedGitignores?: Map<string, string[]>;
  private yaraScanner: any;
  private depsScanner: any;
  private llmAnalyzer: any;
  private customRulesEngine: any;
  private reputationChecker: any;

  constructor(options: ScannerOptions = {}) {
    this.options = {
      fix: false,
      severityFilter: 'info',
      maxFileSize: 1024 * 1024,
      checkPermissions: true,
      yara: true,
      deps: true,
      llm: false,
      ...options,
    };
    
    this.results = {
      findings: [],
      summary: { total: 0, critical: 0, warning: 0, info: 0 },
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
      ...pickle.rules,
      ...mcpDiscovery.rules,
    ];
    
    this.ignorePatterns = [];
    this.rootPath = null;
    
    // Initialize optional scanners
    this.initializeOptionalScanners();
  }

  private initializeOptionalScanners(): void {
    if (this.options.yara && YaraScanner) {
      try {
        this.yaraScanner = new YaraScanner(this.options.yaraOptions || {});
        this.results.yaraEnabled = true;
        this.results.yaraMode = this.yaraScanner.getStatus().mode;
      } catch {
        this.yaraScanner = null;
      }
    }
    
    if (this.options.deps && DependencyScanner) {
      try {
        this.depsScanner = new DependencyScanner(this.options.depsOptions || {});
        this.results.depsEnabled = true;
      } catch {
        this.depsScanner = null;
      }
    }
    
    if (this.options.llm && LLMAnalyzer) {
      try {
        this.llmAnalyzer = new LLMAnalyzer(this.options.llmOptions || {});
        if (this.llmAnalyzer.isAvailable()) {
          this.results.llmEnabled = true;
          this.results.llmProvider = this.llmAnalyzer.getStatus().provider;
        } else {
          this.llmAnalyzer = null;
        }
      } catch {
        this.llmAnalyzer = null;
      }
    }

    if (this.options.customRules && CustomRulesEngine) {
      try {
        this.customRulesEngine = new CustomRulesEngine();
        const rulesLoaded = this.customRulesEngine.loadFromFile(this.options.customRules);
        this.results.customRulesEnabled = true;
        this.results.customRulesCount = rulesLoaded;
      } catch (e: any) {
        console.warn(`Custom rules warning: ${e.message}`);
        this.customRulesEngine = null;
      }
    }

    if (this.options.reputation && ReputationChecker) {
      try {
        this.reputationChecker = new ReputationChecker(this.options.reputationOptions || {});
        if (this.reputationChecker.isAvailable()) {
          this.results.reputationEnabled = true;
          this.results.reputationServices = this.reputationChecker.getAvailableServices();
        } else {
          this.reputationChecker = null;
        }
      } catch {
        this.reputationChecker = null;
      }
    }
  }

  async scan(targetPath: string): Promise<InternalResults> {
    const resolvedPath = path.resolve(targetPath.replace(/^~/, process.env.HOME || ''));
    
    if (!fs.existsSync(resolvedPath)) {
      throw new Error(`Path not found: ${resolvedPath}`);
    }
    
    const stat = fs.statSync(resolvedPath);
    
    this.rootPath = stat.isDirectory() ? resolvedPath : path.dirname(resolvedPath);
    this.loadIgnorePatterns(this.rootPath);
    
    if (stat.isFile()) {
      this.scanFile(resolvedPath);
    } else if (stat.isDirectory()) {
      this.walkDirectory(resolvedPath);
    }
    
    if (this.options.checkPermissions) {
      this.checkPermissions();
    }
    
    if (this.yaraScanner) {
      await this.runYaraScan(resolvedPath);
    }
    
    if (this.depsScanner) {
      await this.runDepsScan(resolvedPath);
    }
    
    if (this.llmAnalyzer) {
      await this.runLLMAnalysis(resolvedPath);
    }

    if (this.reputationChecker) {
      await this.runReputationCheck(resolvedPath);
    }
    
    if (this.options.fix) {
      this.autoFix();
    }
    
    return this.results;
  }

  private loadIgnorePatterns(rootPath: string): void {
    const patterns: string[] = [];
    const sources: string[] = [];

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
      this.nestedGitignores = new Map();
    }

    this.ignorePatterns = [...new Set(patterns)];
    
    if (sources.length > 0) {
      this.results.ignoreSources = sources;
      this.results.ignorePatterns = this.ignorePatterns.length;
    }
  }

  private loadNestedGitignore(dirPath: string): string[] {
    if (this.options.respectGitignore === false) return [];
    
    const gitignore = path.join(dirPath, '.gitignore');
    if (!fs.existsSync(gitignore)) return [];
    
    if (this.nestedGitignores?.has(dirPath)) {
      return this.nestedGitignores.get(dirPath)!;
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

  private isIgnored(filePath: string): boolean {
    const relativePath = path.relative(this.rootPath!, filePath);
    
    if (this.ignorePatterns.length > 0) {
      for (const pattern of this.ignorePatterns) {
        if (matchesIgnorePattern(relativePath, pattern)) {
          return true;
        }
      }
    }

    if (this.options.respectGitignore !== false && this.nestedGitignores) {
      const dirPath = path.dirname(filePath);
      let currentDir = dirPath;
      
      while (currentDir.startsWith(this.rootPath!) && currentDir !== this.rootPath) {
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

  private walkDirectory(dirPath: string): void {
    let entries: string[];
    try {
      entries = fs.readdirSync(dirPath);
    } catch {
      return;
    }
    
    for (const entry of entries) {
      const fullPath = path.join(dirPath, entry);
      
      if (EXCLUDE_DIRS.includes(entry)) continue;
      if (EXCLUDE_FILES.includes(entry)) continue;
      if (this.isIgnored(fullPath)) continue;
      
      try {
        const stat = fs.statSync(fullPath);
        
        if (stat.isDirectory()) {
          this.walkDirectory(fullPath);
        } else if (stat.isFile()) {
          this.scanFile(fullPath);
        }
      } catch {
        // Skip inaccessible files
      }
    }
  }

  private scanFile(filePath: string): void {
    const ext = path.extname(filePath).toLowerCase();
    const basename = path.basename(filePath);
    
    if (BINARY_EXTENSIONS.includes(ext)) return;
    
    for (const pattern of EXCLUDE_PATTERNS) {
      if (pattern.test(filePath)) return;
    }
    
    if (basename === 'agentvet.js') return;
    
    try {
      const stat = fs.statSync(filePath);
      if (stat.size > this.options.maxFileSize!) return;
    } catch {
      return;
    }
    
    let content: string;
    try {
      content = fs.readFileSync(filePath, 'utf8');
    } catch {
      return;
    }
    
    this.results.scannedFiles++;
    
    const ignoreMap = this.parseIgnoreComments(content);
    const isDocFile = ['.md', '.mdx', '.txt', '.rst'].includes(ext);
    
    for (const rule of this.rules) {
      if (isDocFile && this.isCodeOnlyRule(rule)) {
        continue;
      }
      this.applyRule(rule, filePath, content, ignoreMap);
    }

    if (this.customRulesEngine) {
      const customFindings = this.customRulesEngine.scan(filePath, content);
      for (const finding of customFindings) {
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

  private isCodeOnlyRule(rule: any): boolean {
    const codeOnlyPrefixes = ['mcp-', 'command-'];
    return codeOnlyPrefixes.some(prefix => rule.id.startsWith(prefix));
  }

  private parseIgnoreComments(content: string): IgnoreMap {
    const ignoreMap: IgnoreMap = {
      lines: new Set(),
      lineRules: new Map(),
    };

    const lines = content.split('\n');
    
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
            if (!ignoreMap.lineRules.has(targetLine)) {
              ignoreMap.lineRules.set(targetLine, new Set());
            }
            ruleIds.forEach(id => ignoreMap.lineRules.get(targetLine)!.add(id));
          } else {
            ignoreMap.lines.add(targetLine);
          }
        }
      }
    }

    return ignoreMap;
  }

  private shouldIgnore(ignoreMap: IgnoreMap, lineNum: number, ruleId: string): boolean {
    if (ignoreMap.lines.has(lineNum)) {
      return true;
    }

    if (ignoreMap.lineRules.has(lineNum)) {
      const ignoredRules = ignoreMap.lineRules.get(lineNum)!;
      if (ignoredRules.has(ruleId) || ignoredRules.has('*')) {
        return true;
      }
    }

    return false;
  }

  private applyRule(rule: any, filePath: string, content: string, ignoreMap: IgnoreMap | null = null): void {
    const severityOrder: Record<string, number> = { critical: 0, warning: 1, info: 2 };
    const filterLevel = severityOrder[this.options.severityFilter as string] ?? 2;
    const ruleLevel = severityOrder[rule.severity] ?? 2;
    if (ruleLevel > filterLevel) return;
    
    rule.pattern.lastIndex = 0;
    
    const lines = content.split('\n');
    let match;
    
    while ((match = rule.pattern.exec(content)) !== null) {
      const lineNum = content.substring(0, match.index).split('\n').length;
      
      if (ignoreMap && this.shouldIgnore(ignoreMap, lineNum, rule.id)) {
        this.results.ignoredFindings = (this.results.ignoredFindings || 0) + 1;
        if (match.index === rule.pattern.lastIndex) {
          rule.pattern.lastIndex++;
        }
        continue;
      }

      const lineContent = lines[lineNum - 1] || '';
      
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
      
      if (match.index === rule.pattern.lastIndex) {
        rule.pattern.lastIndex++;
      }
    }
  }

  private sanitizeSnippet(snippet: string, rule: any): string {
    if (rule.id.startsWith('credential-')) {
      if (snippet.length > 20) {
        return snippet.substring(0, 10) + '***' + snippet.substring(snippet.length - 4);
      }
    }
    
    if (snippet.length > 60) {
      return snippet.substring(0, 57) + '...';
    }
    
    return snippet;
  }

  private checkPermissions(): void {
    if (!this.rootPath) return;
    
    for (const rule of permissions.rules) {
      this.walkForPermissions(this.rootPath, rule);
    }
  }

  private walkForPermissions(dirPath: string, rule: any): void {
    let entries: string[];
    try {
      entries = fs.readdirSync(dirPath);
    } catch {
      return;
    }
    
    for (const entry of entries) {
      const fullPath = path.join(dirPath, entry);
      
      try {
        const stat = fs.statSync(fullPath);
        
        if (stat.isDirectory()) {
          this.walkForPermissions(fullPath, rule);
        } else if (stat.isFile()) {
          const isSensitive = rule.patterns.some((p: string) => 
            entry.includes(p) || entry.endsWith(p)
          );
          
          if (isSensitive) {
            const mode = (stat.mode & 0o777).toString(8);
            
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
      } catch {
        // Skip inaccessible
      }
    }
  }

  private autoFix(): void {
    for (const finding of this.results.findings) {
      if ((finding as any).fixable && finding.ruleId === 'permission-sensitive-files') {
        try {
          fs.chmodSync(finding.file, 0o600);
          this.results.fixedIssues++;
          (finding as any).fixed = true;
        } catch (e: any) {
          (finding as any).fixError = e.message;
        }
      }
    }
  }

  private async runYaraScan(targetPath: string): Promise<void> {
    if (!this.yaraScanner) return;
    
    try {
      const stat = fs.statSync(targetPath);
      let yaraFindings;
      
      if (stat.isFile()) {
        yaraFindings = await this.yaraScanner.scanFile(targetPath);
      } else {
        yaraFindings = await this.yaraScanner.scanDirectory(targetPath);
      }
      
      for (const finding of yaraFindings) {
        if (this.isIgnored(finding.file)) continue;
        
        let excluded = false;
        for (const pattern of EXCLUDE_PATTERNS) {
          if (pattern.test(finding.file)) {
            excluded = true;
            break;
          }
        }
        if (excluded) continue;
        
        const severityOrder: Record<string, number> = { critical: 0, warning: 1, info: 2 };
        const filterLevel = severityOrder[this.options.severityFilter as string] ?? 2;
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
    } catch {
      // YARA scan failed
    }
  }

  private async runDepsScan(targetPath: string): Promise<void> {
    if (!this.depsScanner) return;
    
    try {
      const depsResults = await this.depsScanner.scan(targetPath);
      this.results.depsResults = depsResults;
      
      for (const finding of depsResults.findings) {
        let severity: string;
        if (finding.severity === 'critical' || finding.severity === 'high') {
          severity = 'critical';
        } else if (finding.severity === 'moderate') {
          severity = 'warning';
        } else {
          severity = 'info';
        }
        
        const severityOrder: Record<string, number> = { critical: 0, warning: 1, info: 2 };
        const filterLevel = severityOrder[this.options.severityFilter as string] ?? 2;
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
    } catch {
      // Dependency scan failed
    }
  }

  private async runLLMAnalysis(targetPath: string): Promise<void> {
    if (!this.llmAnalyzer) return;
    
    try {
      const llmResults = await this.llmAnalyzer.analyze(targetPath);
      this.results.llmResults = llmResults;
      
      for (const finding of llmResults.findings || []) {
        let severity: string;
        if (finding.severity === 'critical' || finding.severity === 'high') {
          severity = 'critical';
        } else if (finding.severity === 'medium') {
          severity = 'warning';
        } else {
          severity = 'info';
        }
        
        const severityOrder: Record<string, number> = { critical: 0, warning: 1, info: 2 };
        const filterLevel = severityOrder[this.options.severityFilter as string] ?? 2;
        const findingLevel = severityOrder[severity] ?? 2;
        
        if (findingLevel > filterLevel) continue;
        
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
    } catch (e: any) {
      this.results.llmError = e.message;
    }
  }

  private async runReputationCheck(targetPath: string): Promise<void> {
    try {
      const files = this.collectFiles(targetPath);
      let allContent = '';
      
      for (const file of files.slice(0, 50)) {
        try {
          const content = fs.readFileSync(file, 'utf8');
          allContent += content + '\n';
        } catch {
          // Skip unreadable
        }
      }

      const repResults = await this.reputationChecker.scanContent(allContent, {
        maxChecks: this.options.reputationOptions?.maxChecks || 10,
      });

      this.results.reputationResults = {
        checked: repResults.checked,
        skipped: repResults.skipped,
        findingsCount: repResults.findings.length,
      };

      for (const finding of repResults.findings) {
        const severityOrder: Record<string, number> = { critical: 0, warning: 1, info: 2 };
        const filterLevel = severityOrder[this.options.severityFilter as string] ?? 2;
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
    } catch (e: any) {
      this.results.reputationError = e.message;
    }
  }

  private collectFiles(targetPath: string): string[] {
    const files: string[] = [];
    const stat = fs.statSync(targetPath);
    
    if (stat.isFile()) {
      return [targetPath];
    }

    const walk = (dir: string) => {
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

// CommonJS export
module.exports = { Scanner };
