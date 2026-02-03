# Writing Custom Rules for AgentVet

This guide explains how to create custom detection rules for AgentVet.

## Rule Structure

Each rule is a JavaScript object with the following properties:

```javascript
{
  id: 'my-custom-rule',           // Unique identifier
  severity: 'critical',            // 'critical', 'warning', or 'info'
  description: 'What this detects', // Human-readable description
  pattern: /regex-pattern/gi,      // RegExp to match
  recommendation: 'How to fix',    // Remediation guidance
}
```

## Creating a Custom Rule File

### 1. Create the rule file

Create a file (e.g., `my-rules.js`) with your custom rules:

```javascript
// my-rules.js
const rules = [
  {
    id: 'custom-internal-api-key',
    severity: 'critical',
    description: 'Internal API key pattern detected',
    pattern: /INTERNAL_API_[A-Z0-9]{32}/g,
    recommendation: 'Use environment variables for internal API keys',
  },
  {
    id: 'custom-debug-endpoint',
    severity: 'warning',
    description: 'Debug endpoint exposed',
    pattern: /\/debug\/|\/\.debug|debug=true/gi,
    recommendation: 'Remove debug endpoints in production',
  },
  {
    id: 'custom-internal-domain',
    severity: 'info',
    description: 'Internal domain reference',
    pattern: /\.internal\.company\.com/gi,
    recommendation: 'Verify internal domains are not exposed',
  },
];

module.exports = { rules };
```

### 2. Use with AgentVet

```bash
# CLI
agentvet scan ./project --rules ./my-rules.js

# Or place in .agentvet/rules/ directory
mkdir -p .agentvet/rules
cp my-rules.js .agentvet/rules/
agentvet scan ./project  # Auto-loads custom rules
```

## Rule Writing Best Practices

### 1. Use Specific Patterns

❌ Too broad (many false positives):
```javascript
pattern: /password/gi
```

✅ Specific (fewer false positives):
```javascript
pattern: /password\s*[:=]\s*["'][^"']{8,}["']/gi
```

### 2. Handle Edge Cases

Consider variations in formatting:

```javascript
// Handles: api_key, apiKey, API_KEY, api-key
pattern: /(?:api[_-]?key|apiKey|API[_-]?KEY)\s*[:=]\s*["'][^"']+["']/gi
```

### 3. Avoid Catastrophic Backtracking

❌ Dangerous pattern (can hang on certain inputs):
```javascript
pattern: /.*password.*/gi
```

✅ Bounded pattern:
```javascript
pattern: /\bpassword\b[^;\n]{0,100}/gi
```

### 4. Test Your Rules

```javascript
// test-rules.js
const { rules } = require('./my-rules.js');

const testCases = [
  { content: 'INTERNAL_API_ABCD1234567890ABCD1234567890AB', shouldMatch: true },
  { content: 'normal text', shouldMatch: false },
];

for (const rule of rules) {
  console.log(`Testing: ${rule.id}`);
  for (const tc of testCases) {
    rule.pattern.lastIndex = 0;
    const matched = rule.pattern.test(tc.content);
    console.log(`  "${tc.content.substring(0, 30)}..." → ${matched} (expected: ${tc.shouldMatch})`);
  }
}
```

## Advanced: YARA Rules

For more complex pattern matching, create custom YARA rules:

### 1. Create YARA rule file

```yara
// my-rules.yar
rule CustomMalwarePattern {
    meta:
        description = "Custom malware indicator"
        severity = "critical"
        author = "Your Name"
    
    strings:
        $suspicious_import = "require('child_process')" ascii
        $hidden_eval = /eval\s*\(\s*atob\s*\(/ ascii
        $webhook = /webhook\.site|requestbin\.com/ ascii
    
    condition:
        $suspicious_import and ($hidden_eval or $webhook)
}
```

### 2. Use with AgentVet

```bash
agentvet scan ./project --yara-rules ./my-rules.yar
```

## Rule Categories

Organize rules by category using ID prefixes:

| Prefix | Category |
|--------|----------|
| `credential-` | Credential/secret detection |
| `command-` | Dangerous commands |
| `url-` | Suspicious URLs |
| `mcp-` | MCP configuration issues |
| `agent-` | Agent instruction attacks |
| `cicd-` | CI/CD security |
| `custom-` | Your custom rules |

## Example: Organization-Specific Rules

```javascript
// company-rules.js
const rules = [
  // Detect company-specific secrets
  {
    id: 'custom-company-api-key',
    severity: 'critical',
    description: 'Company API key detected',
    pattern: /ACME_API_[A-Za-z0-9]{40}/g,
    recommendation: 'Use ACME_API_KEY environment variable',
  },
  
  // Detect internal service URLs
  {
    id: 'custom-internal-service',
    severity: 'warning',
    description: 'Internal service URL hardcoded',
    pattern: /https?:\/\/[a-z0-9-]+\.acme-internal\.com/gi,
    recommendation: 'Use service discovery or environment variables',
  },
  
  // Detect legacy patterns
  {
    id: 'custom-deprecated-function',
    severity: 'info',
    description: 'Deprecated internal function used',
    pattern: /acme\.legacy\./gi,
    recommendation: 'Migrate to acme.v2.* functions',
  },
];

module.exports = { rules };
```

## Sharing Rules

### As npm package

```json
{
  "name": "@myorg/agentvet-rules",
  "main": "index.js",
  "peerDependencies": {
    "agentvet": ">=0.7.0"
  }
}
```

### As GitHub repository

```
my-agentvet-rules/
├── README.md
├── index.js
├── rules/
│   ├── credentials.js
│   ├── internal.js
│   └── compliance.js
└── yara/
    └── custom.yar
```

## Debugging Rules

Enable verbose output to see which rules match:

```bash
agentvet scan ./project --format json | jq '.findings[] | {ruleId, file, line}'
```

Or programmatically:

```javascript
const { scan } = require('agentvet');

const results = await scan('./project');
for (const f of results.findings) {
  console.log(`${f.ruleId}: ${f.file}:${f.line}`);
  console.log(`  ${f.snippet}`);
}
```
