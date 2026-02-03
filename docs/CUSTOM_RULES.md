# Custom Rules Guide

AgentVet supports custom rules to detect organization-specific patterns, internal secrets, or unique threats.

## Quick Start

1. Create a YAML file (e.g., `my-rules.yaml`):

```yaml
rules:
  - id: my-internal-key
    name: Internal API Key
    description: Detects our internal API key format
    severity: critical
    type: regex
    pattern: "MYAPP_[A-Z]+_[A-Za-z0-9]{32}"
    recommendation: "Use environment variables instead"
```

2. Run AgentVet with custom rules:

```bash
agentvet scan . --rules my-rules.yaml
```

## Rule Schema

```yaml
rules:
  - id: string          # Required: Unique rule identifier
    name: string        # Optional: Human-readable name
    description: string # Optional: What this rule detects
    severity: string    # Required: critical | high | warning | medium | low | info
    type: string        # Optional: regex (default) | string
    pattern: string     # Required for single pattern
    patterns: []        # Required for multiple patterns (type: string)
    filePatterns: []    # Optional: Glob patterns for files to scan
    message: string     # Optional: Custom finding message
    recommendation: string  # Optional: How to fix
    tags: []            # Optional: Categorization tags
    enabled: boolean    # Optional: true (default) | false
```

## Rule Types

### Regex Rules (default)

Match content using regular expressions:

```yaml
rules:
  - id: internal-endpoint
    severity: warning
    type: regex
    pattern: "https://internal\\.mycorp\\.com/api/[a-z]+"
    message: "Internal endpoint should not be hardcoded"
```

**Tips:**
- Escape special regex characters: `\.` `\[` `\(` etc.
- Use `(?i)` for case-insensitive matching
- Patterns are applied with global flag (`/g`)

### String Rules

Match exact strings (case-insensitive):

```yaml
rules:
  - id: forbidden-domains
    severity: warning
    type: string
    patterns:
      - "competitor.com"
      - "legacy-api.internal"
      - "staging.mycorp.com"
    message: "Connection to forbidden domain"
```

## File Patterns

Limit rules to specific file types:

```yaml
rules:
  - id: js-eval-usage
    severity: high
    pattern: "eval\\s*\\("
    filePatterns:
      - "*.js"
      - "*.ts"
      - "*.mjs"
    message: "Dangerous eval() usage"
```

**Supported patterns:**
- `*.js` - All JavaScript files
- `*.{js,ts}` - JS and TS files
- `src/**/*.py` - Python files in src/
- `*` - All files (default)

## Severity Levels

| Level | Use Case | Exit Code |
|-------|----------|-----------|
| `critical` | Immediate security risk | 1 |
| `high` | Serious vulnerability | 1 |
| `warning` / `medium` | Potential issue | 0 |
| `low` / `info` | Informational | 0 |

## Examples

### Detect Internal Secrets

```yaml
rules:
  - id: corp-api-key
    name: Corporate API Key
    description: Detects MyCorp API keys
    severity: critical
    pattern: "MYCORP_KEY_[A-Za-z0-9]{40}"
    recommendation: "Use MYCORP_API_KEY environment variable"
    tags: [credentials, internal]

  - id: corp-jwt-secret
    name: JWT Signing Secret
    severity: critical
    pattern: "JWT_SECRET[\"':\\s=]+[A-Za-z0-9+/]{32,}"
    filePatterns: ["*.env", "*.json", "*.yaml", "*.js"]
```

### Block Forbidden Patterns

```yaml
rules:
  - id: no-console-log
    name: Console.log in Production
    severity: warning
    pattern: "console\\.log\\s*\\("
    filePatterns: ["*.js", "*.ts"]
    message: "Remove console.log before production"
    recommendation: "Use a proper logging library"

  - id: no-todo-comments
    severity: info
    pattern: "(?i)(TODO|FIXME|HACK|XXX):"
    message: "Unresolved TODO comment"
```

### Detect Data Exfiltration

```yaml
rules:
  - id: exfil-to-discord
    name: Discord Webhook Exfiltration
    severity: critical
    pattern: "https://discord\\.com/api/webhooks/\\d+/[A-Za-z0-9_-]+"
    message: "Discord webhook URL detected - potential data exfiltration"
    tags: [exfiltration, webhook]

  - id: exfil-to-slack
    severity: critical
    pattern: "https://hooks\\.slack\\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+"
    message: "Slack webhook URL detected"
```

### Organization-Specific Rules

```yaml
rules:
  - id: deprecated-api-v1
    name: Deprecated API v1
    severity: warning
    type: string
    patterns:
      - "/api/v1/"
      - "api-v1.mycorp.com"
    message: "API v1 is deprecated, migrate to v2"
    recommendation: "See migration guide: https://docs.mycorp.com/api-v2"

  - id: internal-only-function
    severity: high
    pattern: "__internal_[a-z_]+\\s*\\("
    message: "Internal function used outside allowed scope"
```

## Advanced Patterns

### Multi-line Matching

```yaml
rules:
  - id: unsafe-cors
    severity: high
    pattern: "Access-Control-Allow-Origin[\"':\\s]+[*]"
    message: "Wildcard CORS is unsafe"
```

### Negative Lookahead (avoid false positives)

```yaml
rules:
  - id: real-api-key
    severity: critical
    # Match API keys but not example/test values
    pattern: "api[_-]?key[\"':\\s=]+(?!example|test|xxx)[A-Za-z0-9]{20,}"
```

### Context-Aware Detection

```yaml
rules:
  - id: password-in-url
    severity: critical
    pattern: "https?://[^:]+:([^@]+)@"
    message: "Password embedded in URL"
    recommendation: "Use environment variables for credentials"
```

## Combining with Built-in Rules

Custom rules run alongside AgentVet's built-in rules. To focus only on custom rules:

```bash
# Run only custom rules (disable built-in)
agentvet scan . --rules my-rules.yaml --no-builtin

# Run both (default)
agentvet scan . --rules my-rules.yaml
```

## Rule File Locations

AgentVet searches for rules in:

1. `--rules` CLI argument (highest priority)
2. `.agentvet-rules.yaml` in scan directory
3. `.agentvet/rules.yaml` in scan directory
4. `~/.config/agentvet/rules.yaml` (global)

## Debugging Rules

Test your rules with verbose output:

```bash
agentvet scan . --rules my-rules.yaml --verbose
```

Check which rules matched:

```bash
agentvet scan . --rules my-rules.yaml --format json | jq '.findings[] | {rule: .ruleId, file: .file}'
```

## Best Practices

1. **Use specific patterns** - Avoid overly broad regex that causes false positives
2. **Set appropriate severity** - Reserve `critical` for actual security risks
3. **Add recommendations** - Help developers fix issues
4. **Use file patterns** - Limit rules to relevant file types
5. **Test thoroughly** - Run against known good/bad samples
6. **Document rules** - Use `name` and `description` for clarity
7. **Version control** - Keep rules in your repo for team consistency

## Example: Complete Rules File

```yaml
# .agentvet-rules.yaml
# Custom security rules for MyProject

rules:
  # Credentials
  - id: myproject-api-key
    name: MyProject API Key
    severity: critical
    pattern: "MP_[A-Z]+_[A-Za-z0-9]{32}"
    recommendation: "Use MP_API_KEY environment variable"
    tags: [credentials]

  # Network
  - id: internal-endpoint
    severity: warning
    type: string
    patterns:
      - "internal.myproject.com"
      - "staging.myproject.com"
      - "10.0.0."
    message: "Internal/staging endpoint in code"
    filePatterns: ["*.js", "*.ts", "*.json"]

  # Code Quality
  - id: debug-code
    severity: info
    pattern: "(?i)(debugger|console\\.debug)"
    filePatterns: ["*.js", "*.ts"]
    message: "Debug code should be removed"

  # Compliance
  - id: pii-email-collection
    name: PII Email Collection
    severity: warning
    pattern: "collect.*email|gather.*user.*email"
    message: "Potential PII collection - ensure GDPR compliance"
    tags: [compliance, pii]
```

## Need Help?

- [GitHub Issues](https://github.com/taku-tez/agentvet/issues)
- [Built-in Rules Reference](./RULES.md)
- [API Documentation](./API.md)
