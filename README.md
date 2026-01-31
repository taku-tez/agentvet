# 🛡️ AgentVet

> Security scanner for AI agent skills, configs, and MCP tools. **Vet before you trust.**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

---

## Why AgentVet?

AI agents like Claude Code, Devin, Cursor, and Clawdbot are increasingly using external skills, plugins, and MCP tools. These files are often:

- **Unsigned** — no way to verify authenticity
- **User-contributed** — anyone can publish to skill marketplaces
- **Highly privileged** — agents can execute code, access files, and make API calls

A single malicious skill can exfiltrate credentials, install backdoors, or hijack your agent's actions.

**AgentVet scans these files before they can do damage.**

---

## Features

- 🔍 **Credential Detection** — Finds hardcoded API keys, tokens, and secrets
- 🌐 **Suspicious URL Detection** — Flags webhook.site, ngrok, pastebin, and other exfiltration endpoints
- ⚠️ **Dangerous Command Patterns** — Detects `rm -rf`, `curl | bash`, `eval()`, and similar risks
- 📁 **Permission Analysis** — Identifies overly permissive file access patterns
- 🔐 **File Permission Checks** — Warns when sensitive files have insecure permissions
- 🦠 **YARA Integration** — Advanced threat detection with AI agent-specific YARA rules

---

## Installation

```bash
npm install -g agentvet
```

Or run directly with npx:

```bash
npx agentvet scan ./my-skills
```

---

## Usage

### Scan a local directory

```bash
agentvet scan ./skills/my-skill
```

### Scan a GitHub repository

```bash
agentvet scan https://github.com/user/agent-config
```

### Output formats

```bash
# Human-readable (default)
agentvet scan ./skills

# JSON output for CI/CD
agentvet scan ./skills --format json --output report.json

# Quiet mode (summary only)
agentvet scan ./skills --quiet
```

### YARA scanning

AgentVet includes built-in YARA rules for AI agent threats:

```bash
# YARA enabled by default
agentvet scan ./skills

# Disable YARA scanning
agentvet scan ./skills --no-yara

# Use custom YARA rules
agentvet scan ./skills --yara-rules ./my-rules
```

YARA works in two modes:
- **yara-cli**: Uses the native `yara` command (fastest, requires yara installed)
- **js-fallback**: Pure JavaScript implementation (works everywhere, no dependencies)

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | No issues found (or warnings only) |
| 1 | Critical or high severity issues found |

---

## What It Scans

| Target | Description |
|--------|-------------|
| `SKILL.md` / `skill.md` | Clawdbot skill definitions |
| `AGENTS.md` | Agent instruction files |
| `mcp.json` / `mcp-config.json` | MCP tool configurations |
| `claude_desktop_config.json` | Claude Desktop MCP config |
| `cline_mcp_settings.json` | Cline MCP settings |
| `.cursor-mcp.json` | Cursor MCP config |
| `*.js`, `*.ts`, `*.py` | Scripts referenced by skills |
| `.env`, `config.json` | Configuration files |

---

## Detection Rules

### 🔴 Critical
- Hardcoded AWS keys, API tokens, private keys
- Known malware patterns (YARA-based)
- Data exfiltration URLs (webhook.site, requestbin, etc.)
- **MCP**: Unrestricted command execution (`bash`, `sh`)
- **MCP**: Shell injection risks (`-c` flag patterns)
- **MCP**: Hardcoded credentials in tool configs
- **MCP**: Root filesystem access

### 🟡 Warning
- Dangerous shell commands (`rm -rf /`, `curl | bash`)
- Eval/exec patterns in scripts
- Overly broad file access permissions
- Insecure file permissions on credential files
- **MCP**: Tunnel services (ngrok, localtunnel)
- **MCP**: Raw IP address endpoints
- **MCP**: Unrestricted filesystem/network access
- **MCP**: Environment variable exposure

### 🔵 Info
- Unusual network endpoints
- Deprecated API usage

### 🦠 YARA Rules (AI Agent Threats)
- **Prompt Injection** — System override attempts, jailbreak patterns
- **Agent Hijacking** — Hidden instructions, behavior modification
- **Credential Exfiltration** — Env leaks, file theft to external endpoints
- **Backdoors** — Reverse shells, crypto miners, remote access
- **Supply Chain** — Package hijacking, postinstall attacks
- **Obfuscation** — Base64/hex encoded payloads
- **Privilege Escalation** — sudo abuse, setuid patterns

---

## CI/CD Integration

### GitHub Actions

```yaml
name: AgentVet Security Scan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run AgentVet
        run: npx agentvet scan . --format json --output agentvet-report.json
      - name: Upload Report
        uses: actions/upload-artifact@v4
        with:
          name: agentvet-report
          path: agentvet-report.json
```

### Pre-commit hook

```bash
# .git/hooks/pre-commit
npx agentvet scan . --quiet || exit 1
```

---

## Roadmap

- [x] CLI with basic rules
- [x] MCP tool configuration scanning
- [x] YARA rule integration
- [ ] LLM-based intent analysis for natural language instructions
- [ ] Dependency vulnerability scanning (npm audit, pip-audit integration)
- [ ] VS Code extension
- [ ] Web dashboard

---

## Contributing

Contributions welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Adding Detection Rules

Rules are defined in `src/rules/`. Each rule exports:

```javascript
module.exports = {
  id: 'credential-aws-key',
  severity: 'critical',
  description: 'Hardcoded AWS access key',
  pattern: /AKIA[0-9A-Z]{16}/g,
  recommendation: 'Use environment variables or a secrets manager'
};
```

---

## License

MIT © [AgentVet Contributors](https://github.com/taku-tez/agentvet/graphs/contributors)

---

<p align="center">
  <strong>Don't let rogue skills hijack your AI agent. Vet first. 🛡️</strong>
</p>
