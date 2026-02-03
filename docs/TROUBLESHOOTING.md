# AgentVet Troubleshooting Guide

## Common Issues

### Installation Issues

#### "command not found: agentvet"

**Problem:** AgentVet is not in your PATH.

**Solutions:**

1. Use npx instead:
   ```bash
   npx agentvet scan ./project
   ```

2. Or install globally:
   ```bash
   npm install -g agentvet
   ```

3. Or add node_modules/.bin to PATH:
   ```bash
   export PATH="./node_modules/.bin:$PATH"
   agentvet scan ./project
   ```

#### YARA not found

**Problem:** Native YARA is not installed.

**Solution:** AgentVet will automatically fall back to JavaScript-based YARA matching. For better performance, install native YARA:

```bash
# macOS
brew install yara

# Ubuntu/Debian
apt-get install yara

# Or disable YARA
agentvet scan ./project --no-yara
```

### Scanning Issues

#### "ENOENT: no such file or directory"

**Problem:** The target path doesn't exist.

**Solution:** Verify the path:
```bash
ls -la ./project
agentvet scan ./project
```

#### Scan takes too long

**Problem:** Large repository with many files.

**Solutions:**

1. Exclude unnecessary directories with `.agentvetignore`:
   ```
   node_modules/
   dist/
   build/
   coverage/
   .git/
   vendor/
   ```

2. Disable slower features:
   ```bash
   agentvet scan ./project --no-yara --no-deps
   ```

3. Scan specific subdirectory:
   ```bash
   agentvet scan ./project/src
   ```

#### Out of memory

**Problem:** Scanning very large files.

**Solution:** AgentVet skips files over 1MB by default. For custom limits:
```javascript
const { scan } = require('agentvet');
await scan('./project', { maxFileSize: 512 * 1024 }); // 512KB limit
```

### False Positives

#### Credentials in documentation

**Problem:** Example API keys in README trigger alerts.

**Solution:** Use `.agentvetignore`:
```
# Ignore documentation
README.md
docs/
*.example

# Ignore test fixtures
test/fixtures/
__tests__/
```

#### Test files triggering rules

**Problem:** Security test cases are flagged.

**Solution:** 
1. Add to `.agentvetignore`:
   ```
   test/
   **/test/**
   *.test.js
   *.spec.js
   ```

2. Or use comments in code:
   ```javascript
   // agentvet-ignore-next-line
   const testKey = "AKIAIOSFODNN7EXAMPLE";
   ```

#### Internal URLs flagged as suspicious

**Problem:** Company-internal URLs are flagged.

**Solution:** Create allowlist in custom rules:
```javascript
// .agentvet/rules/allowlist.js
const rules = [
  {
    id: 'allowlist-internal-urls',
    severity: 'info',  // Downgrade severity
    description: 'Internal URL (allowed)',
    pattern: /https:\/\/.*\.mycompany\.internal/gi,
    recommendation: 'Internal URLs are allowed per company policy',
  },
];
module.exports = { rules };
```

### LLM Analysis Issues

#### "No API key configured"

**Problem:** LLM analysis requires an API key.

**Solution:** Set environment variable:
```bash
# OpenAI
export OPENAI_API_KEY=sk-...

# Anthropic
export ANTHROPIC_API_KEY=sk-ant-...

# OpenRouter
export OPENROUTER_API_KEY=sk-or-...

agentvet scan ./project --llm
```

#### LLM analysis timeout

**Problem:** API call takes too long.

**Solution:** Use a faster model:
```bash
agentvet scan ./project --llm --llm-model gpt-4o-mini
```

#### LLM returns unparseable response

**Problem:** Model output isn't valid JSON.

**Solution:** This is usually a model issue. Try:
1. Different model: `--llm-model gpt-4o`
2. Disable LLM and rely on static analysis: remove `--llm` flag

### CI/CD Integration Issues

#### GitHub Actions failing

**Problem:** Workflow exits with error.

**Solutions:**

1. Check YAML syntax:
   ```yaml
   - name: Run AgentVet
     uses: taku-tez/agentvet@v1
     with:
       path: '.'
       severity: 'warning'
       fail-on-critical: 'true'  # String, not boolean!
   ```

2. Debug with verbose output:
   ```yaml
   - run: npx agentvet scan . --format json > report.json
   - run: cat report.json
   ```

#### Pre-commit hook not working

**Problem:** Hook doesn't run or exits incorrectly.

**Solution:** Ensure hook is executable:
```bash
chmod +x .git/hooks/pre-commit

# Verify content
cat .git/hooks/pre-commit
# Should contain:
# #!/bin/sh
# npx agentvet scan . --quiet || exit 1
```

### Output Issues

#### JSON output is invalid

**Problem:** Text mixed with JSON.

**Solution:** Ensure `--format json` is specified:
```bash
agentvet scan ./project --format json 2>/dev/null
```

Or capture only stdout:
```bash
agentvet scan ./project --format json 2>&1 | tail -n +2
```

#### Colors in CI logs

**Problem:** ANSI escape codes appear as garbage.

**Solution:** Use JSON format or disable colors:
```bash
NO_COLOR=1 agentvet scan ./project
# or
agentvet scan ./project --format json
```

## Debugging

### Enable verbose output

```bash
DEBUG=agentvet* agentvet scan ./project
```

### Check rule matching

```bash
# See which rules matched
agentvet scan ./project --format json | jq '.findings | group_by(.ruleId) | map({rule: .[0].ruleId, count: length})'
```

### Test specific rule

```javascript
const { rules } = require('agentvet/src/rules/credentials');
const rule = rules.find(r => r.id === 'credential-aws-key');

const content = 'const key = "AKIAIOSFODNN7EXAMPLE";';
rule.pattern.lastIndex = 0;
console.log('Matches:', rule.pattern.test(content));
```

## Getting Help

1. **GitHub Issues:** https://github.com/taku-tez/agentvet/issues
2. **Discussions:** https://github.com/taku-tez/agentvet/discussions
3. **Moltbook:** https://moltbook.com/u/MoltBot-2

When reporting issues, please include:
- AgentVet version: `agentvet --version`
- Node.js version: `node --version`
- OS and version
- Full error message
- Minimal reproduction steps
