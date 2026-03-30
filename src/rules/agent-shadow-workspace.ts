import type { Rule } from "../types.js";

/**
 * Agent Shadow Workspace & Hidden Persistence Rules
 * Detects patterns where AI agents create hidden files, directories, or
 * persistence mechanisms outside their sanctioned workspace.
 *
 * Agents with filesystem access can establish covert persistence by:
 * - Writing dotfiles/hidden directories for state persistence
 * - Creating cron jobs or scheduled tasks
 * - Modifying shell profiles (.bashrc, .zshrc) for re-execution
 * - Writing to /tmp or system directories to survive restarts
 * - Establishing reverse shells or callback mechanisms
 *
 * References:
 * - "MCP Servers: The New Shadow IT for AI" (Qualys, March 2026)
 * - Anthropic Model Spec § Avoid self-preservation/replication
 * - OWASP LLM Top 10 2025 - LLM08: Excessive Agency
 * - CWE-506: Embedded Malicious Code
 */

export const rules: Rule[] = [
  // ── Agent creating hidden dotfiles/directories ──
  {
    id: 'agent-shadow-hidden-dotfile',
    severity: 'high',
    description: 'Agent instruction to create hidden dotfiles or directories for persistence',
    pattern: /(?:(?:create|write|mkdir|touch|save)\s+(?:a\s+)?(?:hidden\s+)?(?:file|directory|folder|dir)\s+(?:named?\s+)?['"]?\.(?!git\b|env\b|npmrc\b|eslint|prettier|vscode)\w{2,}|(?:write|save|store|dump)\s+(?:to|in|at)\s+(?:~\/|\/home\/|\/root\/)?\.(?!git\b|env\b|npmrc\b|eslint|prettier|vscode)\w+(?:\/\w+)*|mkdir\s+-p?\s*(?:~\/|\/home\/|\/root\/)?\.(?!git\b|config\b|local\b|cache\b|npm\b|ssh\b)\w+)/gi,
    recommendation: 'Agent is creating hidden dotfiles/directories outside standard tooling paths. This may indicate shadow workspace creation for persistence. Restrict agent filesystem writes to an explicit sandbox directory.',
    category: 'agent-shadow-workspace',
    cwe: 'CWE-506',
  },

  // ── Agent modifying shell profiles for persistence ──
  {
    id: 'agent-shadow-shell-profile',
    severity: 'critical',
    description: 'Agent modifying shell profile files (.bashrc, .zshrc, .profile) for persistent execution',
    pattern: /(?:(?:append|write|add|echo|cat)\s+(?:to|>>)\s*(?:~\/|\/home\/\w+\/|\/root\/)?\.(?:bash(?:rc|_profile|_login|_aliases)|zshrc|zsh_profile|profile|login|cshrc)|(?:>>|>\s*>)\s*(?:~\/|\/home\/\w+\/|\/root\/)?\.(?:bash(?:rc|_profile)|zshrc|profile))/gi,
    recommendation: 'CRITICAL: Agent is modifying shell profile files. This enables persistent code execution on every shell login. Deny agents write access to profile/rc files.',
    category: 'agent-shadow-workspace',
    cwe: 'CWE-506',
  },

  // ── Agent creating cron jobs or systemd timers ──
  {
    id: 'agent-shadow-scheduled-task',
    severity: 'critical',
    description: 'Agent creating cron jobs, systemd timers, or scheduled tasks for persistent execution',
    pattern: /(?:(?:crontab\s+-[el]|crontab\s+<<|echo\s+[^|]*\|\s*crontab)|(?:create|write|install)\s+(?:a\s+)?(?:cron(?:\s+job)?|systemd\s+timer|scheduled\s+task|at\s+job)|systemctl\s+(?:enable|start)\s+.*\.timer|\/etc\/cron\.\w+\/)/gi,
    recommendation: 'CRITICAL: Agent is creating scheduled tasks (cron/systemd timer). This establishes persistent execution independent of agent sessions. Deny agents access to scheduling subsystems.',
    category: 'agent-shadow-workspace',
    cwe: 'CWE-506',
  },

  // ── Agent writing to system-wide temp or shared directories ──
  {
    id: 'agent-shadow-tmp-persistence',
    severity: 'medium',
    description: 'Agent writing executable or script files to /tmp or /var/tmp for cross-session persistence',
    pattern: /(?:(?:write|save|create|cp|mv|install)\s+(?:to\s+)?(?:\/tmp|\/var\/tmp|\/dev\/shm)\/\S*\.(?:sh|py|js|ts|rb|pl|exe|bin|elf)|chmod\s+\+?[0-7]*x\s+(?:\/tmp|\/var\/tmp|\/dev\/shm)\/|(?:>>|>\s*>?)\s*(?:\/tmp|\/var\/tmp|\/dev\/shm)\/\S*\.(?:sh|py|js))/gi,
    recommendation: 'Agent is writing executable files to shared temp directories. These survive session boundaries and may be executed by other processes. Restrict agent writes to a dedicated sandboxed directory.',
    category: 'agent-shadow-workspace',
    cwe: 'CWE-377',
  },

  // ── Agent instruction to maintain state across sessions ──
  {
    id: 'agent-shadow-cross-session-state',
    severity: 'medium',
    description: 'Agent instructed to maintain hidden state or memory across separate sessions',
    pattern: /(?:(?:save|store|persist|remember|keep)\s+(?:this|your|the)\s+(?:state|context|memory|data|config)\s+(?:so\s+(?:that\s+)?)?(?:between|across|for\s+(?:future|next|later))\s+sessions?|(?:hidden|secret|covert)\s+(?:state|storage|persistence|channel)\s+(?:that|which)\s+(?:survives?|persists?|remains?)\s+(?:across|between)\s+(?:sessions?|restarts?|conversations?)|maintain\s+(?:a\s+)?(?:persistent|permanent|hidden)\s+(?:state|memory|record)\s+(?:outside|beyond)\s+(?:this\s+)?(?:session|conversation|context))/gi,
    recommendation: 'Instruction to maintain hidden cross-session state detected. Agents should only persist state through sanctioned, auditable mechanisms. Covert persistence enables long-term manipulation.',
    category: 'agent-shadow-workspace',
    cwe: 'CWE-506',
  },
];
