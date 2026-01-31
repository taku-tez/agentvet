/**
 * Custom Rules Loader
 * Load user-defined rules from YAML files
 */

const fs = require('fs');
const path = require('path');
const yaml = require('../utils/yaml.js');

/**
 * Custom rule format:
 * 
 * rules:
 *   - id: custom-api-key
 *     name: Custom API Key Pattern
 *     description: Detects custom API key patterns
 *     severity: critical
 *     pattern: "MY_SECRET_KEY_[A-Za-z0-9]{32}"
 *     type: regex
 *     filePatterns: ["*.js", "*.json", "*.env"]
 *     message: "Found exposed custom API key"
 *     recommendation: "Store in environment variable"
 *     tags: [credentials, secrets]
 * 
 *   - id: forbidden-domain
 *     name: Forbidden Domain
 *     description: Detects connections to forbidden domains
 *     severity: warning
 *     type: string
 *     patterns:
 *       - "evil.com"
 *       - "malware.net"
 *     message: "Connection to forbidden domain detected"
 * 
 *   - id: dangerous-function
 *     name: Dangerous Function Call
 *     description: Detects dangerous function usage
 *     severity: warning
 *     type: ast
 *     language: javascript
 *     selector: "CallExpression[callee.name='eval']"
 *     message: "Dangerous eval() usage"
 */

class CustomRulesEngine {
  constructor() {
    this.rules = [];
  }

  /**
   * Load rules from YAML file
   */
  loadFromFile(filePath) {
    try {
      const content = fs.readFileSync(filePath, 'utf-8');
      const parsed = yaml.parse(content);
      
      if (parsed.rules && Array.isArray(parsed.rules)) {
        for (const rule of parsed.rules) {
          this.addRule(this.normalizeRule(rule));
        }
      }
      
      return this.rules.length;
    } catch (error) {
      throw new Error(`Failed to load custom rules from ${filePath}: ${error.message}`);
    }
  }

  /**
   * Normalize rule definition
   */
  normalizeRule(rule) {
    const normalized = {
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

    // Handle pattern/patterns
    if (rule.pattern) {
      normalized.patterns = [rule.pattern];
    } else if (rule.patterns) {
      normalized.patterns = Array.isArray(rule.patterns) ? rule.patterns : [rule.patterns];
    }

    // Compile regex patterns
    if (normalized.type === 'regex') {
      normalized.compiledPatterns = normalized.patterns.map(p => {
        try {
          return new RegExp(p, 'gi');
        } catch {
          console.warn(`Invalid regex pattern in rule ${normalized.id}: ${p}`);
          return null;
        }
      }).filter(Boolean);
    }

    return normalized;
  }

  /**
   * Normalize severity level
   */
  normalizeSeverity(severity) {
    const map = {
      'critical': 'critical',
      'high': 'critical',
      'warning': 'warning',
      'medium': 'warning',
      'low': 'info',
      'info': 'info',
    };
    return map[String(severity).toLowerCase()] || 'warning';
  }

  /**
   * Add a rule
   */
  addRule(rule) {
    this.rules.push(rule);
  }

  /**
   * Check if file matches rule's file patterns
   */
  matchesFilePattern(filename, patterns) {
    const basename = path.basename(filename);
    
    for (const pattern of patterns) {
      if (pattern === '*') return true;
      
      // Convert glob to regex
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

  /**
   * Scan content with custom rules
   */
  scan(filePath, content) {
    const findings = [];
    const lines = content.split('\n');

    for (const rule of this.rules) {
      if (!rule.enabled) continue;
      
      // Check file pattern match
      if (!this.matchesFilePattern(filePath, rule.filePatterns)) {
        continue;
      }

      // Apply rule based on type
      switch (rule.type) {
        case 'regex':
          findings.push(...this.scanRegex(filePath, content, lines, rule));
          break;
        case 'string':
          findings.push(...this.scanString(filePath, content, lines, rule));
          break;
        // AST-based rules would go here
        default:
          findings.push(...this.scanRegex(filePath, content, lines, rule));
      }
    }

    return findings;
  }

  /**
   * Scan with regex patterns
   */
  scanRegex(filePath, content, lines, rule) {
    const findings = [];

    for (const regex of rule.compiledPatterns || []) {
      // Reset regex state
      regex.lastIndex = 0;
      
      let match;
      while ((match = regex.exec(content)) !== null) {
        // Find line number
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
        
        // Prevent infinite loop on zero-width matches
        if (match[0].length === 0) {
          regex.lastIndex++;
        }
      }
    }

    return findings;
  }

  /**
   * Scan for exact string matches
   */
  scanString(filePath, content, lines, rule) {
    const findings = [];
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

  /**
   * Get loaded rules count
   */
  getRulesCount() {
    return this.rules.length;
  }

  /**
   * Get rules summary
   */
  getRulesSummary() {
    return this.rules.map(r => ({
      id: r.id,
      name: r.name,
      severity: r.severity,
      enabled: r.enabled,
    }));
  }
}

// Example rule file template
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

function generateTemplate() {
  return TEMPLATE;
}

module.exports = { CustomRulesEngine, generateTemplate };
