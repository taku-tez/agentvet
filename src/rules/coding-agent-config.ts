import type { Rule } from "../types.js";

/**
 * Coding Agent Configuration Attack Rules
 * Detects malicious instructions planted in AI coding agent config files
 * (e.g., .cursorrules, CLAUDE.md, .github/copilot-instructions.md, AGENTS.md,
 *  .windsurfrules, .aider, rules_file, etc.)
 *
 * Attack scenario: A malicious repo contains a config file that instructs the
 * coding agent to execute arbitrary commands, exfiltrate data, or install
 * backdoors when a developer opens the repo with an AI coding assistant.
 *
 * References:
 * - Pillar Security "Rules File Backdoor" Attack (2025)
 * - Trail of Bits "Sleeper Agent in Your IDE" (2025)
 * - OWASP LLM Top 10 2025 - LLM01: Prompt Injection
 * - CWE-94: Improper Control of Generation of Code
 */

export const rules: Rule[] = [
  // ============================================
  // 1. Hidden/Invisible Unicode Injection
  // ============================================
  {
    id: 'cac-invisible-unicode',
    severity: 'critical',
    description: 'Invisible Unicode characters in agent config file (instruction hiding)',
    pattern: /[\u200B\u200C\u200D\u200E\u200F\u2060\u2061\u2062\u2063\u2064\uFEFF\u00AD\u034F\u061C\u115F\u1160\u17B4\u17B5\u180E]{2,}/g,
    recommendation: 'CRITICAL: Multiple invisible Unicode characters detected. Attackers use zero-width joiners/spaces to hide malicious instructions in AI config files that are invisible to human reviewers but interpreted by AI agents.',
    category: 'coding-agent-config',
    cwe: 'CWE-116',
  },
  {
    id: 'cac-bidi-override',
    severity: 'critical',
    description: 'Bidirectional text override characters (text direction attack to hide code)',
    pattern: /[\u202A\u202B\u202C\u202D\u202E\u2066\u2067\u2068\u2069]/g,
    recommendation: 'CRITICAL: Bidirectional override characters detected. These can reorder displayed text to hide malicious instructions from human review while AI agents process the real text order.',
    category: 'coding-agent-config',
    cwe: 'CWE-1007',
  },

  // ============================================
  // 2. Command Execution in Config Files
  // ============================================
  {
    id: 'cac-shell-exec-instruction',
    severity: 'critical',
    description: 'AI config file instructs agent to execute shell commands',
    pattern: /(?:always|must|should|please|first|before\s+(?:anything|starting))\s+(?:run|execute|call|invoke|perform|do)\s+(?:the\s+following\s+)?(?:shell\s+)?(?:command|script|bash|sh|terminal|exec)/gi,
    recommendation: 'CRITICAL: Config file instructs the coding agent to execute shell commands. Malicious repos use this to run arbitrary code when a developer opens the project with an AI assistant.',
    category: 'coding-agent-config',
    cwe: 'CWE-78',
  },
  {
    id: 'cac-curl-pipe-exec',
    severity: 'critical',
    description: 'Config file contains curl-pipe-bash pattern (remote code execution)',
    pattern: /(?:curl|wget)\s+[^\n]*\|\s*(?:bash|sh|zsh|python|node|ruby|perl)/gi,
    recommendation: 'CRITICAL: curl-pipe-bash pattern in config file. This downloads and executes remote code when the AI agent follows the instruction. Classic supply chain attack vector.',
    category: 'coding-agent-config',
    cwe: 'CWE-829',
  },
  {
    id: 'cac-npm-preinstall-inject',
    severity: 'high',
    description: 'Config instructs adding preinstall/postinstall scripts (lifecycle hook injection)',
    pattern: /(?:add|insert|include|set|modify|update|create)\s+(?:a\s+)?(?:pre|post)(?:install|build|test|publish|version)\s+(?:script|hook|command)/gi,
    recommendation: 'Config file instructs adding npm lifecycle hooks. Malicious instructions to inject preinstall/postinstall scripts can execute code on every npm install.',
    category: 'coding-agent-config',
    cwe: 'CWE-94',
  },

  // ============================================
  // 3. Exfiltration via Config Instructions
  // ============================================
  {
    id: 'cac-exfil-instruction',
    severity: 'critical',
    description: 'Config instructs agent to send/upload/transmit data to external endpoint',
    pattern: /(?:send|upload|transmit|post|forward|exfiltrate|relay|pipe)\s+(?:the\s+)?(?:contents?|data|output|results?|code|files?|env|secrets?|tokens?|keys?|credentials?)\s+(?:to|via|using|through)\s+(?:https?:\/\/|webhook|endpoint|server|api|url)/gi,
    recommendation: 'CRITICAL: Config instructs the agent to send data to an external endpoint. This is a data exfiltration instruction planted in a coding agent config file.',
    category: 'coding-agent-config',
    cwe: 'CWE-200',
  },
  {
    id: 'cac-read-env-instruction',
    severity: 'high',
    description: 'Config instructs agent to read environment variables or credentials',
    pattern: /(?:read|access|get|fetch|retrieve|include|extract|output|print|display|show)\s+(?:the\s+)?(?:contents?\s+of\s+)?(?:environment\s+variables?|env\s+vars?|\.env\s+file|process\.env|os\.environ|credentials?\s+file|secret\s+file|ssh\s+keys?|api\s+keys?|auth\s+tokens?)/gi,
    recommendation: 'Config instructs the agent to access environment variables or credential files. AI coding agents should not be directed to read secrets from the environment.',
    category: 'coding-agent-config',
    cwe: 'CWE-522',
  },

  // ============================================
  // 4. Instruction Concealment Techniques
  // ============================================
  {
    id: 'cac-hidden-in-comment',
    severity: 'high',
    description: 'HTML comment or code comment containing suspicious agent instructions',
    pattern: /<!--[\s\S]{0,50}(?:ignore\s+(?:previous|above|all)|execute|run\s+(?:this|the)|send\s+(?:to|data)|you\s+(?:must|should|are)\s+(?:also|actually|secretly))[\s\S]{0,200}-->/gi,
    recommendation: 'Suspicious instructions hidden inside HTML comments. Attackers use comments to hide malicious directives that are invisible in rendered markdown but processed by AI agents.',
    category: 'coding-agent-config',
    cwe: 'CWE-94',
  },
  {
    id: 'cac-base64-instruction',
    severity: 'critical',
    description: 'Base64-encoded content in agent config file (hidden instruction payload)',
    pattern: /(?:decode|atob|Buffer\.from)\s*\(\s*['"`][A-Za-z0-9+/]{40,}={0,2}['"`]/gi,
    recommendation: 'CRITICAL: Base64-encoded payload in config file. Attackers encode malicious instructions in base64 to evade human review and content scanning.',
    category: 'coding-agent-config',
    cwe: 'CWE-116',
  },

  // ============================================
  // 5. Backdoor Injection Instructions
  // ============================================
  {
    id: 'cac-backdoor-instruction',
    severity: 'critical',
    description: 'Config instructs agent to add backdoor, hidden endpoint, or covert functionality',
    pattern: /(?:add|insert|include|create|implement|place)\s+(?:a\s+)?(?:hidden|secret|covert|undocumented|backdoor|debug)\s+(?:endpoint|route|api|function|method|handler|listener|admin\s+panel|access|login)/gi,
    recommendation: 'CRITICAL: Config file instructs the AI coding agent to implement backdoor functionality. This is a code injection attack via agent configuration.',
    category: 'coding-agent-config',
    cwe: 'CWE-506',
  },
  {
    id: 'cac-disable-security',
    severity: 'critical',
    description: 'Config instructs agent to disable security features',
    pattern: /(?:disable|remove|skip|bypass|turn\s+off|deactivate|comment\s+out)\s+(?:the\s+)?(?:authentication|authorization|csrf\s+(?:protection|token|check)|cors\s+(?:check|restriction|validation)|input\s+(?:validation|sanitization)|rate\s+limit|security\s+(?:check|header|middleware|guard|filter)|ssl\s+(?:verification|check)|certificate\s+(?:check|validation|pinning))/gi,
    recommendation: 'CRITICAL: Config instructs the agent to disable security features. Malicious configs weaken application security by directing AI agents to remove protections.',
    category: 'coding-agent-config',
    cwe: 'CWE-693',
  },

  // ============================================
  // 6. Trust Boundary Violations
  // ============================================
  {
    id: 'cac-ignore-previous-instructions',
    severity: 'critical',
    description: 'Config file attempts to override/ignore previous safety instructions',
    pattern: /(?:ignore|disregard|forget|override|supersede|replace)\s+(?:all\s+)?(?:previous|prior|existing|default|built-in|original)\s+(?:instructions?|rules?|guidelines?|constraints?|safety\s+(?:rules?|measures?|instructions?)|security\s+(?:rules?|policies?)|restrictions?)/gi,
    recommendation: 'CRITICAL: Config file attempts to override safety instructions. This is a prompt injection attack targeting the AI coding agent\'s safety guardrails.',
    category: 'coding-agent-config',
    cwe: 'CWE-284',
  },
  {
    id: 'cac-do-not-mention',
    severity: 'high',
    description: 'Config instructs agent to hide actions from user (stealth instructions)',
    pattern: /(?:do\s+not|don'?t|never|avoid)\s+(?:mention|tell|inform|show|reveal|disclose|display|report|log|warn\s+(?:the\s+)?(?:user|developer|human)|ask\s+(?:for\s+)?(?:permission|confirmation|approval)|(?:prompt|ask)\s+(?:the\s+)?(?:user|developer|human))/gi,
    recommendation: 'Config instructs the agent to hide actions from the user. Stealth instructions prevent human oversight and enable covert malicious behavior.',
    category: 'coding-agent-config',
    cwe: 'CWE-778',
  },

  // ============================================
  // 7. Supply Chain Poisoning via Config
  // ============================================
  {
    id: 'cac-install-package-instruction',
    severity: 'high',
    description: 'Config instructs agent to install specific packages (dependency injection)',
    pattern: /(?:always|must|should|please)\s+(?:install|add|include|use|require|import)\s+(?:the\s+)?(?:package|dependency|module|library|npm\s+package)\s+['"`]?[a-z@][a-z0-9_./@-]+['"`]?/gi,
    recommendation: 'Config instructs the agent to install specific packages. Malicious configs can direct AI agents to add trojanized or typosquatted packages as dependencies.',
    category: 'coding-agent-config',
    cwe: 'CWE-829',
  },
  {
    id: 'cac-replace-dependency',
    severity: 'critical',
    description: 'Config instructs agent to replace legitimate dependency with alternative',
    pattern: /(?:replace|swap|substitute|switch|change|use\s+instead)\s+(?:the\s+)?(?:package|dependency|module|library)\s+['"`]?[a-z@][a-z0-9_./@-]+['"`]?\s+(?:with|for|to|by)\s+['"`]?[a-z@][a-z0-9_./@-]+['"`]?/gi,
    recommendation: 'CRITICAL: Config instructs replacing a dependency with another. This is a dependency substitution attack that can swap legitimate packages with malicious ones.',
    category: 'coding-agent-config',
    cwe: 'CWE-829',
  },

  // ============================================
  // 8. Persistence Mechanisms
  // ============================================
  {
    id: 'cac-modify-gitconfig',
    severity: 'critical',
    description: 'Config instructs agent to modify git hooks or git config (persistence)',
    pattern: /(?:add|create|modify|update|write|insert|install)\s+(?:a\s+)?(?:git\s+hook|\.git\/hooks|pre-commit\s+hook|post-commit\s+hook|pre-push\s+hook|\.gitconfig|git\s+config\s+--global|\.husky)/gi,
    recommendation: 'CRITICAL: Config instructs modifying git hooks or config. Malicious git hooks persist across branches and execute code on every commit/push, providing a persistence mechanism.',
    category: 'coding-agent-config',
    cwe: 'CWE-506',
  },
  {
    id: 'cac-cron-instruction',
    severity: 'critical',
    description: 'Config instructs agent to create scheduled tasks (persistence via cron/systemd)',
    pattern: /(?:add|create|install|set\s+up|configure|write|register)\s+(?:a\s+)?(?:cron\s*(?:job|tab|entry)|systemd\s+(?:service|timer|unit)|launchd\s+(?:plist|agent|daemon)|scheduled\s+task|startup\s+(?:script|entry|item)|(?:auto|boot)\s*(?:start|run))/gi,
    recommendation: 'CRITICAL: Config instructs creating scheduled tasks or startup entries. This establishes persistence, ensuring malicious code runs repeatedly even after the coding session ends.',
    category: 'coding-agent-config',
    cwe: 'CWE-506',
  },

  // ============================================
  // 9. Scope Escalation
  // ============================================
  {
    id: 'cac-file-outside-project',
    severity: 'high',
    description: 'Config instructs agent to read/write files outside project directory',
    pattern: /(?:read|write|modify|edit|create|access|open|cat|touch)\s+(?:the\s+)?(?:file\s+)?(?:at\s+)?(?:\/etc\/|\/root\/|~\/\.|\/home\/|\/var\/|\/usr\/|\/tmp\/|\.\.\/\.\.\/|C:\\Users\\|C:\\Windows\\|%APPDATA%|%USERPROFILE%)/gi,
    recommendation: 'Config instructs the agent to access files outside the project directory. AI coding agents should be sandboxed to the current project scope.',
    category: 'coding-agent-config',
    cwe: 'CWE-22',
  },
  {
    id: 'cac-sudo-instruction',
    severity: 'critical',
    description: 'Config instructs agent to use sudo or elevated privileges',
    pattern: /(?:use|run\s+with|execute\s+with|prefix\s+with|always\s+use)\s+sudo\b|sudo\s+(?:chmod|chown|rm|mv|cp|dd|mkfs|mount|umount|systemctl|service|iptables|ufw|passwd|useradd|usermod)/gi,
    recommendation: 'CRITICAL: Config instructs the agent to use sudo. AI coding agents should never require elevated privileges for normal development tasks.',
    category: 'coding-agent-config',
    cwe: 'CWE-250',
  },
];

// CommonJS compatibility
module.exports = { rules };
