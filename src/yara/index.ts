// @ts-nocheck

/**
 * YARA Integration for AgentVet
 * Uses yara CLI if available, falls back to JS-based pattern matching
 */

const { spawn, execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

// Default rules directory
const RULES_DIR = path.join(__dirname, '../../yara');

class YaraScanner {
  options: any;
  rules: any;
  nativeAvailable: boolean = false;
  constructor(options = {}) {
    this.rulesDir = options.rulesDir || RULES_DIR;
    this.yaraAvailable = this.checkYaraInstalled();
    this.compiledRules = null;
    
    // Load and parse rules for fallback mode
    if (!this.yaraAvailable) {
      this.parsedRules = this.parseRulesForFallback();
    }
  }

  /**
   * Check if yara CLI is installed
   */
  checkYaraInstalled() {
    try {
      execSync('which yara', { stdio: 'pipe' });
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Get all rule files
   */
  getRuleFiles() {
    if (!fs.existsSync(this.rulesDir)) {
      return [];
    }
    
    return fs.readdirSync(this.rulesDir)
      .filter(f => f.endsWith('.yar') || f.endsWith('.yara'))
      .map(f => path.join(this.rulesDir, f));
  }

  /**
   * Parse YARA rules into JS patterns for fallback mode
   */
  parseRulesForFallback() {
    const rules = [];
    const ruleFiles = this.getRuleFiles();
    
    for (const file of ruleFiles) {
      try {
        const content = fs.readFileSync(file, 'utf8');
        const parsed = this.parseYaraFile(content);
        rules.push(...parsed);
      } catch (e) {
        console.error(`Failed to parse ${file}: ${e.message}`);
      }
    }
    
    return rules;
  }

  /**
   * Parse a YARA file into rule objects
   */
  parseYaraFile(content) {
    const rules = [];
    
    // Simple regex-based parser for YARA rules
    const ruleRegex = /rule\s+(\w+)\s*\{([^}]+meta:[^}]+strings:[^}]+condition:[^}]+)\}/gs;
    let match;
    
    while ((match = ruleRegex.exec(content)) !== null) {
      const ruleName = match[1];
      const ruleBody = match[2];
      
      // Extract meta
      const meta = {};
      const metaMatch = ruleBody.match(/meta:\s*([\s\S]*?)(?=strings:|condition:|$)/);
      if (metaMatch) {
        const metaLines = metaMatch[1].match(/(\w+)\s*=\s*"([^"]+)"/g) || [];
        for (const line of metaLines) {
          const [, key, value] = line.match(/(\w+)\s*=\s*"([^"]+)"/) || [];
          if (key && value) meta[key] = value;
        }
      }
      
      // Extract condition
      const conditionMatch = ruleBody.match(/condition:\s*([\s\S]*?)$/);
      const condition = conditionMatch ? conditionMatch[1].trim() : 'any of them';
      
      // Parse condition to extract pattern groups for AND conditions
      const patternGroups = this.parseCondition(condition);
      
      // Extract string patterns with their variable names
      const patterns = [];
      const patternsByPrefix = {};
      const stringsMatch = ruleBody.match(/strings:\s*([\s\S]*?)(?=condition:|$)/);
      if (stringsMatch) {
        // Match patterns with their variable names
        const stringPatterns = stringsMatch[1].matchAll(/(\$\w+)\s*=\s*(?:"([^"]+)"(?:\s+nocase)?|\/([^\/]+)\/[i]?)/g);
        for (const sp of stringPatterns) {
          const varName = sp[1]; // e.g., $env1, $send2
          const strValue = sp[2];
          const regexValue = sp[3];
          const isNocase = sp[0].includes('nocase') || sp[0].endsWith('/i');
          
          // Extract prefix (e.g., $env from $env1)
          const prefixMatch = varName.match(/^(\$[a-z]+)/i);
          const prefix = prefixMatch ? prefixMatch[1] : varName;
          
          const pattern = {
            varName,
            prefix,
            type: strValue ? 'string' : 'regex',
            value: strValue || (regexValue ? new RegExp(regexValue, isNocase ? 'gi' : 'g') : null),
            nocase: isNocase,
          };
          
          if (pattern.value) {
            patterns.push(pattern);
            if (!patternsByPrefix[prefix]) patternsByPrefix[prefix] = [];
            patternsByPrefix[prefix].push(pattern);
          }
        }
      }
      
      if (patterns.length > 0) {
        rules.push({
          name: ruleName,
          meta,
          patterns,
          patternsByPrefix,
          patternGroups,
          condition,
          severity: meta.severity || 'warning',
          category: meta.category || 'unknown',
          description: meta.description || ruleName,
        });
      }
    }
    
    return rules;
  }

  /**
   * Parse YARA condition to extract pattern groups
   * Returns array of groups that must ALL match (AND conditions)
   * Each group is { prefixes: [...], mode: 'any' | 'all' | 'count' }
   */
  parseCondition(condition) {
    // Handle "any of them" - simple case
    if (/^\s*any\s+of\s+them\s*$/.test(condition)) {
      return [{ prefixes: ['*'], mode: 'any', minCount: 1 }];
    }
    
    // Handle "N of them" 
    const nOfThem = condition.match(/^(\d+)\s+of\s+them$/);
    if (nOfThem) {
      return [{ prefixes: ['*'], mode: 'count', minCount: parseInt(nOfThem[1]) }];
    }
    
    // Handle complex conditions - find all "any of ($prefix*)" groups
    const groups = [];
    const anyOfRegex = /any\s+of\s+\(\s*\$(\w+)\s*\*?\s*\)/gi;
    let match;
    
    while ((match = anyOfRegex.exec(condition)) !== null) {
      groups.push({ 
        prefixes: ['$' + match[1]], 
        mode: 'any', 
        minCount: 1 
      });
    }
    
    // Handle "N of ($prefix*)" patterns
    const nOfRegex = /(\d+)\s+of\s+\(\s*\$(\w+)\s*\*?\s*\)/gi;
    while ((match = nOfRegex.exec(condition)) !== null) {
      groups.push({ 
        prefixes: ['$' + match[2]], 
        mode: 'count', 
        minCount: parseInt(match[1]) 
      });
    }
    
    // If condition has "and", all groups must match (already the case)
    // If no groups found, default to "any of them"
    if (groups.length === 0) {
      return [{ prefixes: ['*'], mode: 'any', minCount: 1 }];
    }
    
    return groups;
  }

  /**
   * Scan a file with YARA
   */
  async scanFile(filePath) {
    if (this.yaraAvailable) {
      return this.scanWithYaraCLI(filePath);
    }
    return this.scanWithFallback(filePath);
  }

  /**
   * Scan using yara CLI
   */
  async scanWithYaraCLI(filePath) {
    return new Promise((resolve) => {
      const findings = [];
      const ruleFiles = this.getRuleFiles();
      
      if (ruleFiles.length === 0) {
        resolve(findings);
        return;
      }
      
      // Build yara command with all rule files
      const args = ['-s', ...ruleFiles, filePath];
      
      const yara = spawn('yara', args);
      let stdout = '';
      let _stderr = '';
      
      yara.stdout.on('data', (data) => {
        stdout += data.toString();
      });
      
      yara.stderr.on('data', (data) => {
        _stderr += data.toString();
      });
      
      yara.on('close', (_code) => {
        if (stdout.trim()) {
          // Parse yara output
          const lines = stdout.trim().split('\n');
          for (const line of lines) {
            // Format: "RuleName filePath" or "RuleName:$string filePath"
            const match = line.match(/^(\w+)(?::(\$\w+))?\s+(.+)$/);
            if (match) {
              const ruleName = match[1];
              const matchedString = match[2] || '';
              
              // Find rule metadata
              const rule = this.findRuleByName(ruleName);
              
              findings.push({
                ruleId: `yara-${ruleName}`,
                ruleName,
                severity: rule?.meta?.severity || 'warning',
                category: rule?.meta?.category || 'yara',
                description: rule?.meta?.description || ruleName,
                file: filePath,
                matchedString,
                source: 'yara-cli',
              });
            }
          }
        }
        resolve(findings);
      });
      
      yara.on('error', () => {
        resolve(findings);
      });
    });
  }

  /**
   * Find rule by name in parsed rules
   */
  findRuleByName(name) {
    if (!this.parsedRules) {
      // Parse rules if not already done
      this.parsedRules = this.parseRulesForFallback();
    }
    return this.parsedRules.find(r => r.name === name);
  }

  /**
   * Scan using JS fallback
   */
  scanWithFallback(filePath) {
    const findings = [];
    
    let content;
    try {
      content = fs.readFileSync(filePath, 'utf8');
    } catch {
      return findings;
    }
    
    for (const rule of this.parsedRules) {
      // Track matches by prefix
      const matchesByPrefix = {};
      const allMatches = [];
      
      for (const pattern of rule.patterns) {
        let found = false;
        
        if (pattern.type === 'string') {
          const searchContent = pattern.nocase ? content.toLowerCase() : content;
          const searchPattern = pattern.nocase ? pattern.value.toLowerCase() : pattern.value;
          
          if (searchContent.includes(searchPattern)) {
            found = true;
            allMatches.push(pattern.value);
          }
        } else if (pattern.type === 'regex') {
          pattern.value.lastIndex = 0;
          if (pattern.value.test(content)) {
            found = true;
            allMatches.push(pattern.value.source);
          }
        }
        
        if (found) {
          const prefix = pattern.prefix || pattern.varName || '*';
          if (!matchesByPrefix[prefix]) matchesByPrefix[prefix] = 0;
          matchesByPrefix[prefix]++;
        }
      }
      
      // Evaluate condition groups (all groups must match for AND conditions)
      const conditionMet = this.evaluateCondition(rule, matchesByPrefix, allMatches.length);
      
      if (conditionMet) {
        findings.push({
          ruleId: `yara-${rule.name}`,
          ruleName: rule.name,
          severity: rule.severity,
          category: rule.category,
          description: rule.description,
          file: filePath,
          matchCount: allMatches.length,
          matches: allMatches.slice(0, 3), // Limit shown matches
          source: 'yara-fallback',
        });
      }
    }
    
    return findings;
  }

  /**
   * Evaluate if condition is met based on matches
   */
  evaluateCondition(rule, matchesByPrefix, totalMatches) {
    const groups = rule.patternGroups || [{ prefixes: ['*'], mode: 'any', minCount: 1 }];
    
    // All groups must be satisfied (AND logic)
    for (const group of groups) {
      let groupSatisfied = false;
      
      if (group.prefixes.includes('*')) {
        // "any of them" or "N of them" - check total matches
        groupSatisfied = totalMatches >= group.minCount;
      } else {
        // Check specific prefix groups
        let prefixMatches = 0;
        for (const prefix of group.prefixes) {
          prefixMatches += matchesByPrefix[prefix] || 0;
        }
        groupSatisfied = prefixMatches >= group.minCount;
      }
      
      if (!groupSatisfied) {
        return false; // One group failed, whole condition fails
      }
    }
    
    return true; // All groups satisfied
  }

  /**
   * Scan a directory
   */
  async scanDirectory(dirPath) {
    const findings = [];
    const files = this.walkDirectory(dirPath);
    
    for (const file of files) {
      const fileFindings = await this.scanFile(file);
      findings.push(...fileFindings);
    }
    
    return findings;
  }

  /**
   * Walk directory and return file paths
   */
  walkDirectory(dirPath, files = []) {
    const EXCLUDE_DIRS = ['node_modules', '.git', '__pycache__', 'dist', 'build'];
    const BINARY_EXTS = ['.jpg', '.png', '.gif', '.pdf', '.zip', '.exe', '.bin'];
    
    let entries;
    try {
      entries = fs.readdirSync(dirPath);
    } catch {
      return files;
    }
    
    for (const entry of entries) {
      const fullPath = path.join(dirPath, entry);
      
      if (EXCLUDE_DIRS.includes(entry)) continue;
      
      try {
        const stat = fs.statSync(fullPath);
        
        if (stat.isDirectory()) {
          this.walkDirectory(fullPath, files);
        } else if (stat.isFile()) {
          const ext = path.extname(entry).toLowerCase();
          if (!BINARY_EXTS.includes(ext) && stat.size < 1024 * 1024) {
            files.push(fullPath);
          }
        }
      } catch {
        // Skip inaccessible
      }
    }
    
    return files;
  }

  /**
   * Get scanner status
   */
  getStatus() {
    return {
      yaraAvailable: this.yaraAvailable,
      mode: this.yaraAvailable ? 'yara-cli' : 'js-fallback',
      rulesDir: this.rulesDir,
      ruleFiles: this.getRuleFiles(),
      ruleCount: this.parsedRules?.length || 0,
    };
  }
}

module.exports = { YaraScanner };
