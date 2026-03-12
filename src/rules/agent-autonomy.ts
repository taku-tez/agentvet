import type { Rule } from "../types.js";

/**
 * Agent Autonomy & Authorization Boundary Rules
 * Detects configurations where agents operate without proper
 * scope limits, human oversight, or capability boundaries.
 */

export const rules: Rule[] = [
  // ============================================
  // Unrestricted Autonomy
  // ============================================
  {
    id: 'autonomy-unrestricted-tool-access',
    severity: 'critical',
    description: 'Agent configured with unrestricted tool/function access',
    pattern: /(?:allowed_tools|available_tools|tool_access|enabled_tools|tool_permissions)\s*[:=]\s*(?:\[?\s*["']?\*["']?\s*\]?|["']all["']|["']any["'])/gi,
    recommendation: 'CRITICAL: Agent has unrestricted tool access. Apply least-privilege by explicitly listing allowed tools.',
  },
  {
    id: 'autonomy-no-confirmation-destructive',
    severity: 'critical',
    description: 'Destructive operations without human confirmation requirement',
    pattern: /(?:auto_(?:delete|remove|drop|truncate|destroy|terminate|shutdown)|skip_confirm(?:ation)?|no_confirm|confirm(?:ation)?\s*[:=]\s*(?:false|no|off|0|none))/gi,
    recommendation: 'CRITICAL: Destructive operations should require human confirmation. Enable confirmation prompts for delete/remove/destroy actions.',
  },
  {
    id: 'autonomy-bypass-approval',
    severity: 'critical',
    description: 'Agent configured to bypass approval workflows',
    pattern: /(?:bypass_approval|skip_review|auto_approve|no_review_needed|approval_required\s*[:=]\s*(?:false|no|off|0)|require_approval\s*[:=]\s*(?:false|no|off|0))/gi,
    recommendation: 'CRITICAL: Approval workflows should not be bypassed. Implement human-in-the-loop for sensitive operations.',
  },
  {
    id: 'autonomy-unlimited-iterations',
    severity: 'warning',
    description: 'Agent loop without iteration limit (potential runaway)',
    pattern: /(?:max_(?:iterations?|steps?|loops?|turns?|rounds?)\s*[:=]\s*(?:-1|0|None|null|Infinity|inf|unlimited|999\d+)|(?:iterations?|loops?)\s*[:=]\s*(?:unlimited|infinite|forever))/gi,
    recommendation: 'Set a reasonable iteration limit to prevent runaway agent loops. Typical safe range: 10-50 iterations.',
  },
  {
    id: 'autonomy-unlimited-budget',
    severity: 'warning',
    description: 'Agent configured without cost/token budget limits',
    pattern: /(?:max_(?:cost|budget|spend|tokens?)\s*[:=]\s*(?:-1|0|None|null|Infinity|inf|unlimited|999\d{4,})|budget\s*[:=]\s*(?:unlimited|infinite|none))/gi,
    recommendation: 'Set cost and token budget limits to prevent excessive API spending from autonomous agents.',
  },

  // ============================================
  // Missing Human-in-the-Loop (HITL)
  // ============================================
  {
    id: 'autonomy-no-hitl-external',
    severity: 'critical',
    description: 'External actions (email, API calls, payments) without human-in-the-loop',
    pattern: /(?:auto_(?:send|email|post|publish|tweet|pay|transfer|deploy|push)|(?:send_email|make_payment|deploy|publish|push_to_prod)\s*.*?(?:auto|without_review|no_confirm))/gi,
    recommendation: 'CRITICAL: External-facing actions must include human-in-the-loop confirmation. Implement approval gates for actions with real-world effects.',
  },
  {
    id: 'autonomy-full-autonomous-mode',
    severity: 'critical',
    description: 'Agent running in fully autonomous mode without safety boundaries',
    pattern: /(?:(?:fully_?|complete(?:ly)?_?)?autonomous(?:_mode)?\s*[:=]\s*(?:true|yes|on|1|enabled)|mode\s*[:=]\s*["']?(?:fully_?autonomous|unattended|unsupervised)["']?|human_(?:oversight|review|approval)\s*[:=]\s*(?:false|no|off|0|none|disabled))/gi,
    recommendation: 'CRITICAL: Fully autonomous mode should include safety boundaries. Implement fallback to human review for high-risk decisions.',
  },
  {
    id: 'autonomy-self-modification',
    severity: 'critical',
    description: 'Agent capable of modifying its own instructions or configuration',
    pattern: /(?:(?:self|auto)_(?:modify|update|edit|rewrite|change)_(?:instructions?|config|prompt|rules?|system)|modify_own_(?:instructions?|config|prompt|behavior)|can_update_system_prompt\s*[:=]\s*(?:true|yes|on|1))/gi,
    recommendation: 'CRITICAL: Agents should not be able to modify their own instructions. This enables prompt injection persistence.',
  },

  // ============================================
  // Scope & Permission Escalation
  // ============================================
  {
    id: 'autonomy-wildcard-permissions',
    severity: 'critical',
    description: 'Wildcard or overly broad permission grants to agent',
    pattern: /(?:permissions?\s*[:=]\s*(?:\[?\s*["']?\*["']?\s*\]?|["'](?:admin|root|superuser|full)["'])|role\s*[:=]\s*["']?(?:admin|root|superuser|owner)["']?|access_level\s*[:=]\s*["']?(?:full|unlimited|unrestricted|admin)["']?)/gi,
    recommendation: 'CRITICAL: Apply least-privilege principle. Grant only the minimum permissions necessary for the agent task.',
  },
  {
    id: 'autonomy-dynamic-permission-escalation',
    severity: 'critical',
    description: 'Agent can dynamically escalate its own permissions',
    pattern: /(?:(?:request|acquire|escalate|elevate|grant_self)_(?:permissions?|access|privilege|role)|(?:self|auto)_(?:grant|elevate|escalate)|can_(?:request|acquire)_(?:new_)?permissions?\s*[:=]\s*(?:true|yes|on|1))/gi,
    recommendation: 'CRITICAL: Agents should not be able to escalate their own permissions. Implement static permission boundaries.',
  },
  {
    id: 'autonomy-cross-tenant-access',
    severity: 'critical',
    description: 'Agent configured with cross-tenant or cross-org access capabilities',
    pattern: /(?:cross_(?:tenant|org|organization|account)\s*[:=]\s*(?:true|yes|on|1|enabled|allowed)|tenant_isolation\s*[:=]\s*(?:false|no|off|0|disabled)|(?:all|any)_tenants?\s*[:=]\s*(?:true|yes|on|1))/gi,
    recommendation: 'CRITICAL: Agent should not have cross-tenant access. Enforce strict tenant isolation boundaries.',
  },

  // ============================================
  // Rate Limiting & Resource Boundaries
  // ============================================
  {
    id: 'autonomy-no-rate-limit',
    severity: 'warning',
    description: 'Agent operations without rate limiting',
    pattern: /(?:rate_limit\s*[:=]\s*(?:0|none|null|false|off|disabled|unlimited|-1)|disable_rate_limit|no_rate_limit|rate_limiting\s*[:=]\s*(?:false|no|off|0|disabled))/gi,
    recommendation: 'Enable rate limiting on agent operations to prevent abuse and excessive resource consumption.',
  },
  {
    id: 'autonomy-no-timeout',
    severity: 'warning',
    description: 'Agent operations without timeout configuration',
    pattern: /(?:timeout\s*[:=]\s*(?:0|none|null|false|off|disabled|unlimited|-1|infinity)|disable_timeout|no_timeout)/gi,
    recommendation: 'Set appropriate timeouts for agent operations to prevent hanging processes and resource exhaustion.',
  },

  // ============================================
  // Unsafe Delegation Patterns
  // ============================================
  {
    id: 'autonomy-delegate-with-full-context',
    severity: 'warning',
    description: 'Agent delegation passing full context including secrets/credentials',
    pattern: /(?:delegate|forward|pass|share)_(?:full_context|all_context|entire_context|complete_context)|(?:include|share|forward)_(?:credentials|secrets|api_keys?)\s*[:=]\s*(?:true|yes|on|1)/gi,
    recommendation: 'When delegating to sub-agents, sanitize context to exclude secrets and credentials. Apply need-to-know principle.',
  },
  {
    id: 'autonomy-spawn-unlimited-agents',
    severity: 'warning',
    description: 'No limit on sub-agent spawning (fork bomb risk)',
    pattern: /(?:max_(?:sub_?agents?|child(?:ren)?|workers?|spawned?)\s*[:=]\s*(?:-1|0|None|null|Infinity|inf|unlimited|999\d+)|(?:spawn|fork)_limit\s*[:=]\s*(?:none|unlimited|infinite))/gi,
    recommendation: 'Set a maximum number of sub-agents to prevent fork-bomb scenarios and resource exhaustion.',
  },
  {
    id: 'autonomy-no-delegation-depth-limit',
    severity: 'warning',
    description: 'No depth limit on agent delegation chains',
    pattern: /(?:max_(?:delegation_)?depth\s*[:=]\s*(?:-1|0|None|null|Infinity|inf|unlimited|999\d+)|delegation_depth\s*[:=]\s*(?:unlimited|infinite|none))/gi,
    recommendation: 'Set a maximum delegation depth to prevent infinite delegation chains (confused deputy attacks).',
  },

  // ============================================
  // Instruction Content Patterns
  // ============================================
  {
    id: 'autonomy-instruction-no-boundaries',
    severity: 'warning',
    description: 'Agent instructions lacking explicit action boundaries (do whatever, anything needed)',
    pattern: /(?:do\s+whatever\s+(?:is\s+)?(?:necessary|needed|required|it\s+takes)|take\s+any\s+action(?:s)?\s+(?:necessary|needed|you\s+(?:see\s+fit|want|deem))|(?:you\s+(?:can|may|are\s+allowed\s+to)\s+)?do\s+anything|no\s+(?:restrictions?|limitations?|boundaries|constraints?)\s+(?:on|for)\s+(?:your|the)\s+(?:actions?|operations?))/gi,
    recommendation: 'Define explicit action boundaries for agents. Unbounded instructions increase risk of unintended destructive actions.',
  },
  {
    id: 'autonomy-instruction-persist-across-sessions',
    severity: 'warning',
    description: 'Instructions that persist modifications across agent sessions',
    pattern: /(?:remember\s+(?:this|these)\s+(?:for|across)\s+(?:all\s+)?(?:future\s+)?sessions?|persist\s+(?:this|these)\s+(?:changes?|modifications?|settings?)\s+(?:permanently|forever|across)|permanently\s+(?:change|modify|update|alter)\s+(?:your|the)\s+(?:behavior|instructions?|config|rules?))/gi,
    recommendation: 'Avoid instructions that persist across sessions. Each session should start from a known-good configuration.',
  },
];

// CommonJS compatibility
module.exports = { rules };
