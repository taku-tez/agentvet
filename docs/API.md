# AgentVet API Documentation

## Programmatic Usage

AgentVet can be used as a library in your Node.js projects.

### Installation

```bash
npm install agentvet
```

### Basic Usage

```javascript
const { scan } = require('agentvet');

// Scan a directory
const results = await scan('./my-project', {
  severityFilter: 'warning',  // 'critical', 'warning', or 'info'
  yara: true,                 // Enable YARA scanning
  deps: true,                 // Enable dependency scanning
  llm: false,                 // Enable LLM analysis (requires API key)
});

console.log(results.findings);
console.log(results.summary);
```

### API Reference

#### `scan(targetPath, options)`

Scans a directory or file for security issues.

**Parameters:**

| Name | Type | Default | Description |
|------|------|---------|-------------|
| `targetPath` | string | (required) | Path to scan |
| `options.severityFilter` | string | `'info'` | Minimum severity: `'critical'`, `'warning'`, `'info'` |
| `options.yara` | boolean | `true` | Enable YARA malware detection |
| `options.deps` | boolean | `true` | Enable dependency scanning |
| `options.llm` | boolean | `false` | Enable LLM intent analysis |
| `options.llmProvider` | string | auto | LLM provider: `'openai'`, `'anthropic'`, `'openrouter'` |
| `options.llmModel` | string | auto | LLM model name |
| `options.checkPermissions` | boolean | `true` | Check file permissions |
| `options.maxFileSize` | number | `1048576` | Max file size in bytes (1MB) |

**Returns:** `Promise<ScanResults>`

```typescript
interface ScanResults {
  findings: Finding[];
  summary: {
    total: number;
    critical: number;
    warning: number;
    info: number;
  };
  scannedFiles: number;
  yaraEnabled: boolean;
  yaraMode?: 'yara-cli' | 'js-fallback';
  depsEnabled: boolean;
  depsResults?: DepsResults;
  llmEnabled: boolean;
  llmResults?: LLMResults;
  ignorePatterns?: number;
}

interface Finding {
  ruleId: string;
  severity: 'critical' | 'warning' | 'info';
  description: string;
  file: string;
  line: number;
  column?: number;
  snippet: string;
  lineContent?: string;
  recommendation: string;
  source?: 'static' | 'yara' | 'deps' | 'llm';
}
```

### Examples

#### Scan with JSON output

```javascript
const { scan } = require('agentvet');

async function auditProject(path) {
  const results = await scan(path, {
    severityFilter: 'warning',
    yara: true,
    deps: true,
  });
  
  if (results.summary.critical > 0) {
    console.error(`Found ${results.summary.critical} critical issues!`);
    process.exit(1);
  }
  
  return results;
}
```

#### Integrate with CI/CD

```javascript
const { scan } = require('agentvet');

async function ciScan() {
  const results = await scan('.', {
    severityFilter: 'critical', // Only fail on critical
    yara: true,
    deps: true,
  });
  
  // Output findings for CI logs
  for (const finding of results.findings) {
    console.log(`::error file=${finding.file},line=${finding.line}::${finding.description}`);
  }
  
  return results.summary.critical === 0 ? 0 : 1;
}
```

#### Custom filtering

```javascript
const { scan } = require('agentvet');

async function scanWithFilter(path) {
  const results = await scan(path);
  
  // Filter to specific rule categories
  const credentialFindings = results.findings.filter(f => 
    f.ruleId.startsWith('credential-')
  );
  
  const mcpFindings = results.findings.filter(f => 
    f.ruleId.startsWith('mcp-')
  );
  
  return { credentialFindings, mcpFindings };
}
```

### CLI Reference

```bash
agentvet scan <target> [options]

Options:
  --format <type>     Output format: text, json (default: text)
  --output <file>     Write output to file
  --severity <level>  Minimum severity: critical, warning, info (default: info)
  --quiet             Summary only
  --no-yara           Disable YARA scanning
  --no-deps           Disable dependency scanning
  --llm               Enable LLM analysis
  --llm-provider      LLM provider: openai, anthropic, openrouter
  --llm-model         LLM model name
  --yara-rules <dir>  Custom YARA rules directory
  --help              Show help
```

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No critical/warning issues (or only info-level) |
| 1 | Critical or warning issues found |
| 2 | Scan error (invalid path, etc.) |
