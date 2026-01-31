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
      
      // Extract string patterns
      const patterns = [];
      const stringsMatch = ruleBody.match(/strings:\s*([\s\S]*?)(?=condition:|$)/);
      if (stringsMatch) {
        // Match simple string patterns: $name = "value" or $name = /regex/
        const stringPatterns = stringsMatch[1].matchAll(/\$\w+\s*=\s*(?:"([^"]+)"(?:\s+nocase)?|\/([^\/]+)\/[i]?)/g);
        for (const sp of stringPatterns) {
          const strValue = sp[1];
          const regexValue = sp[2];
          const isNocase = sp[0].includes('nocase') || sp[0].endsWith('/i');
          
          if (strValue) {
            patterns.push({
              type: 'string',
              value: strValue,
              nocase: isNocase,
            });
          } else if (regexValue) {
            try {
              patterns.push({
                type: 'regex',
                value: new RegExp(regexValue, isNocase ? 'gi' : 'g'),
              });
            } catch {
              // Skip invalid regex
            }
          }
        }
      }
      
      if (patterns.length > 0) {
        rules.push({
          name: ruleName,
          meta,
          patterns,
          severity: meta.severity || 'warning',
          category: meta.category || 'unknown',
          description: meta.description || ruleName,
        });
      }
    }
    
    return rules;
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
      let stderr = '';
      
      yara.stdout.on('data', (data) => {
        stdout += data.toString();
      });
      
      yara.stderr.on('data', (data) => {
        stderr += data.toString();
      });
      
      yara.on('close', (code) => {
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
      let matchCount = 0;
      const matches = [];
      
      for (const pattern of rule.patterns) {
        let found = false;
        
        if (pattern.type === 'string') {
          const searchContent = pattern.nocase ? content.toLowerCase() : content;
          const searchPattern = pattern.nocase ? pattern.value.toLowerCase() : pattern.value;
          
          if (searchContent.includes(searchPattern)) {
            found = true;
            matches.push(pattern.value);
          }
        } else if (pattern.type === 'regex') {
          pattern.value.lastIndex = 0;
          if (pattern.value.test(content)) {
            found = true;
            matches.push(pattern.value.source);
          }
        }
        
        if (found) matchCount++;
      }
      
      // Most rules use "any of them" condition, so 1+ match triggers
      if (matchCount > 0) {
        findings.push({
          ruleId: `yara-${rule.name}`,
          ruleName: rule.name,
          severity: rule.severity,
          category: rule.category,
          description: rule.description,
          file: filePath,
          matchCount,
          matches: matches.slice(0, 3), // Limit shown matches
          source: 'yara-fallback',
        });
      }
    }
    
    return findings;
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
