/**
 * Custom Rules Loader
 * Load user-defined rules from YAML files
 */

import * as fs from 'fs';
import * as path from 'path';
const yaml = require('../utils/yaml.js');

interface CustomRule {
  id: string;
  name: string;
  description: string;
  severity: string;
  type: string;
  patterns: string[];
  compiledPatterns?: RegExp[];
  filePatterns: string[];
  message: string;
  recommendation: string;
  tags: string[];
  enabled: boolean;
}

interface CustomFinding {
  rule: string;
  severity: string;
  file: string;
  line: number;
  message: string;
  evidence: string;
  recommendation: string;
  tags: string[];
  source: string;
}

interface RuleSummary {
  id: string;
  name: string;
  severity: string;
  enabled: boolean;
}

export class CustomRulesEngine {
  private rules: CustomRule[] = [];

  constructor() {
    this.rules = [];
  }

  loadFromFile(filePath: string): number {
    try {
      const content = fs.readFileSync(filePath, 'utf-8');
      const parsed = yaml.parse(content);
      
      if (parsed.rules && Array.isArray(parsed.rules)) {
        for (const rule of parsed.rules) {
          this.addRule(this.normalizeRule(rule));
        }
      }
      
      return this.rules.length;
    } catch (error: any) {
      throw new Error(`Failed to load custom rules from ${filePath}: ${error.message}`);
    }
  }

  private normalizeRule(rule: any): CustomRule {
    const normalized: CustomRule = {
      id: rule.id || `custom-${Date.now()}`,
      name: rule.name || rule.id,
      description: rule.description || '',
      severity: this.normalizeSeverity(rule.severity),
      type: rule.type || 'regex',
      patterns: [],
      filePatterns: rule.filePatterns || rule.files || ['*'],
      message: rule.message || `Custom rule violation: ${rule.name || rule.id}`,
      recommendation: rule.recommendation || '',
      tags: rule.tags || [],
      enabled: rule.enabled !== false,
    };

    if (rule.pattern) {
      normalized.patterns = [rule.pattern];
    } else if (rule.patterns) {
      normalized.patterns = Array.isArray(rule.patterns) ? rule.patterns : [rule.patterns];
    }

    if (normalized.type === 'regex') {
      normalized.compiledPatterns = normalized.patterns.map(p => {
        try {
          return new RegExp(p, 'gi');
        } catch {
          console.warn(`Invalid regex pattern in rule ${normalized.id}: ${p}`);
          return null;
        }
      }).filter((p): p is RegExp => p !== null);
    }

    return normalized;
  }

  private normalizeSeverity(severity: any): string {
    const map: Record<string, string> = {
      'critical': 'critical',
      'high': 'critical',
      'warning': 'warning',
      'medium': 'warning',
      'low': 'info',
      'info': 'info',
    };
    return map[String(severity).toLowerCase()] || 'warning';
  }

  addRule(rule: CustomRule): void {
    this.rules.push(rule);
  }

  private matchesFilePattern(filename: string, patterns: string[]): boolean {
    const basename = path.basename(filename);
    
    for (const pattern of patterns) {
      if (pattern === '*') return true;
      
      const regex = new RegExp(
        '^' + pattern
          .replace(/\./g, '\\.')
          .replace(/\*\*/g, '.*')
          .replace(/\*/g, '[^/]*')
          .replace(/\?/g, '.') + '$'
      );
      
      if (regex.test(basename) || regex.test(filename)) {
        return true;
      }
    }
    
    return false;
  }

  scan(filePath: string, content: string): CustomFinding[] {
    const findings: CustomFinding[] = [];
    const lines = content.split('\n');

    for (const rule of this.rules) {
      if (!rule.enabled) continue;
      
      if (!this.matchesFilePattern(filePath, rule.filePatterns)) {
        continue;
      }

      switch (rule.type) {
        case 'regex':
          findings.push(...this.scanRegex(filePath, content, lines, rule));
          break;
        case 'string':
          findings.push(...this.scanString(filePath, content, lines, rule));
          break;
        default:
          findings.push(...this.scanRegex(filePath, content, lines, rule));
      }
    }

    return findings;
  }

  private scanRegex(filePath: string, content: string, _lines: string[], rule: CustomRule): CustomFinding[] {
    const findings: CustomFinding[] = [];

    for (const regex of rule.compiledPatterns || []) {
      regex.lastIndex = 0;
      
      let match;
      while ((match = regex.exec(content)) !== null) {
        const beforeMatch = content.substring(0, match.index);
        const lineNumber = beforeMatch.split('\n').length;
        
        findings.push({
          rule: rule.id,
          severity: rule.severity,
          file: filePath,
          line: lineNumber,
          message: rule.message,
          evidence: match[0].substring(0, 100),
          recommendation: rule.recommendation,
          tags: rule.tags,
          source: 'custom',
        });
        
        if (match[0].length === 0) {
          regex.lastIndex++;
        }
      }
    }

    return findings;
  }

  private scanString(filePath: string, content: string, _lines: string[], rule: CustomRule): CustomFinding[] {
    const findings: CustomFinding[] = [];
    const contentLower = content.toLowerCase();

    for (const pattern of rule.patterns) {
      const patternLower = pattern.toLowerCase();
      let index = 0;
      
      while ((index = contentLower.indexOf(patternLower, index)) !== -1) {
        const beforeMatch = content.substring(0, index);
        const lineNumber = beforeMatch.split('\n').length;
        
        findings.push({
          rule: rule.id,
          severity: rule.severity,
          file: filePath,
          line: lineNumber,
          message: rule.message,
          evidence: content.substring(index, index + pattern.length + 20),
          recommendation: rule.recommendation,
          tags: rule.tags,
          source: 'custom',
        });
        
        index += pattern.length;
      }
    }

    return findings;
  }

  getRulesCount(): number {
    return this.rules.length;
  }

  getRulesSummary(): RuleSummary[] {
    return this.rules.map(r => ({
      id: r.id,
      name: r.name,
      severity: r.severity,
      enabled: r.enabled,
    }));
  }
}

const TEMPLATE = `# AgentVet Custom Rules
# Documentation: https://github.com/taku-tez/agentvet#custom-rules

rules:
  # Example: Detect custom API key pattern
  - id: my-api-key
    name: My Custom API Key
    description: Detects our internal API key format
    severity: critical
    type: regex
    pattern: "MYAPP_KEY_[A-Za-z0-9]{24}"
    filePatterns: ["*.js", "*.json", "*.env", "*.yaml"]
    message: "Found exposed internal API key"
    recommendation: "Move to secure secrets manager"
    tags: [credentials, internal]

  # Example: Forbidden domains
  - id: forbidden-domains
    name: Forbidden Domains
    description: Connections to known bad domains
    severity: warning
    type: string
    patterns:
      - "attacker-server.com"
      - "data-exfil.net"
    message: "Connection to suspicious domain detected"
    tags: [network, exfiltration]

  # Example: Dangerous patterns
  - id: shell-injection
    name: Shell Injection Risk
    severity: critical
    type: regex
    pattern: "(exec|spawn|execSync)\\\\s*\\\\([^)]*\\\\$\\\\{"
    filePatterns: ["*.js", "*.ts"]
    message: "Potential shell injection via template string"
    recommendation: "Sanitize user input before shell execution"
`;

export function generateTemplate(): string {
  return TEMPLATE;
}

// CommonJS compatibility
module.exports = { CustomRulesEngine, generateTemplate };
