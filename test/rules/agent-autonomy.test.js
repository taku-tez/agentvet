/**
 * Agent Autonomy & Authorization Boundary Rules Tests
 */

const { describe, test } = require('node:test');
const assert = require('node:assert');
const { rules } = require('../../dist/rules/agent-autonomy.js');

function testRule(ruleId, text, shouldMatch) {
  const rule = rules.find(r => r.id === ruleId);
  assert.ok(rule, `Rule ${ruleId} not found`);
  const pattern = new RegExp(rule.pattern.source, rule.pattern.flags);
  const matched = pattern.test(text);
  assert.strictEqual(matched, shouldMatch,
    `Rule ${ruleId}: expected ${shouldMatch ? 'match' : 'no match'} for: ${text.substring(0, 80)}`);
}

describe('Agent Autonomy Rules', () => {
  // Unrestricted Tool Access
  describe('autonomy-unrestricted-tool-access', () => {
    test('detect wildcard tool access (star)', () => testRule('autonomy-unrestricted-tool-access', 'allowed_tools: "*"', true));
    test('detect wildcard tool access (all)', () => testRule('autonomy-unrestricted-tool-access', 'tool_access: "all"', true));
    test('detect wildcard tool access (bracket star)', () => testRule('autonomy-unrestricted-tool-access', 'enabled_tools: [*]', true));
    test('no match for specific tools', () => testRule('autonomy-unrestricted-tool-access', 'allowed_tools: ["read", "write"]', false));
  });

  // No Confirmation Destructive
  describe('autonomy-no-confirmation-destructive', () => {
    test('detect auto_delete', () => testRule('autonomy-no-confirmation-destructive', 'auto_delete: true', true));
    test('detect skip_confirmation', () => testRule('autonomy-no-confirmation-destructive', 'skip_confirmation = true', true));
    test('detect confirmation false', () => testRule('autonomy-no-confirmation-destructive', 'confirmation: false', true));
    test('detect no_confirm', () => testRule('autonomy-no-confirmation-destructive', 'no_confirm = true', true));
    test('detect auto_destroy', () => testRule('autonomy-no-confirmation-destructive', 'auto_destroy = true', true));
    test('detect auto_terminate', () => testRule('autonomy-no-confirmation-destructive', 'auto_terminate: yes', true));
    test('no match for confirm true', () => testRule('autonomy-no-confirmation-destructive', 'confirmation: true', false));
  });

  // Bypass Approval
  describe('autonomy-bypass-approval', () => {
    test('detect bypass_approval', () => testRule('autonomy-bypass-approval', 'bypass_approval = true', true));
    test('detect auto_approve', () => testRule('autonomy-bypass-approval', 'auto_approve: yes', true));
    test('detect approval_required false', () => testRule('autonomy-bypass-approval', 'approval_required: false', true));
    test('detect require_approval false', () => testRule('autonomy-bypass-approval', 'require_approval = false', true));
    test('detect skip_review', () => testRule('autonomy-bypass-approval', 'skip_review = true', true));
    test('detect no_review_needed', () => testRule('autonomy-bypass-approval', 'no_review_needed = true', true));
  });

  // Unlimited Iterations
  describe('autonomy-unlimited-iterations', () => {
    test('detect -1 iterations', () => testRule('autonomy-unlimited-iterations', 'max_iterations: -1', true));
    test('detect Infinity steps', () => testRule('autonomy-unlimited-iterations', 'max_steps = Infinity', true));
    test('detect None loops', () => testRule('autonomy-unlimited-iterations', 'max_loops: None', true));
    test('detect unlimited iterations', () => testRule('autonomy-unlimited-iterations', 'iterations: unlimited', true));
    test('detect very high turns', () => testRule('autonomy-unlimited-iterations', 'max_turns = 999999', true));
    test('no match for 25', () => testRule('autonomy-unlimited-iterations', 'max_iterations: 25', false));
    test('no match for 50', () => testRule('autonomy-unlimited-iterations', 'max_steps: 50', false));
  });

  // Unlimited Budget
  describe('autonomy-unlimited-budget', () => {
    test('detect -1 cost', () => testRule('autonomy-unlimited-budget', 'max_cost: -1', true));
    test('detect unlimited budget', () => testRule('autonomy-unlimited-budget', 'budget: unlimited', true));
    test('detect Infinity budget', () => testRule('autonomy-unlimited-budget', 'max_budget = Infinity', true));
    test('detect very high tokens', () => testRule('autonomy-unlimited-budget', 'max_tokens: 99999999', true));
  });

  // No HITL External
  describe('autonomy-no-hitl-external', () => {
    test('detect auto_send_email', () => testRule('autonomy-no-hitl-external', 'auto_send_email = true', true));
    test('detect auto_deploy', () => testRule('autonomy-no-hitl-external', 'auto_deploy: yes', true));
    test('detect auto_publish', () => testRule('autonomy-no-hitl-external', 'auto_publish: true', true));
    test('detect auto_pay', () => testRule('autonomy-no-hitl-external', 'auto_pay: enabled', true));
    test('detect auto_push', () => testRule('autonomy-no-hitl-external', 'auto_push: true', true));
  });

  // Full Autonomous Mode
  describe('autonomy-full-autonomous-mode', () => {
    test('detect autonomous_mode true', () => testRule('autonomy-full-autonomous-mode', 'autonomous_mode: true', true));
    test('detect fully_autonomous true', () => testRule('autonomy-full-autonomous-mode', 'fully_autonomous = true', true));
    test('detect mode fully_autonomous', () => testRule('autonomy-full-autonomous-mode', 'mode: "fully_autonomous"', true));
    test('detect human_oversight false', () => testRule('autonomy-full-autonomous-mode', 'human_oversight: false', true));
    test('detect human_approval disabled', () => testRule('autonomy-full-autonomous-mode', 'human_approval = disabled', true));
    test('detect mode unsupervised', () => testRule('autonomy-full-autonomous-mode', 'mode = "unsupervised"', true));
    test('no match for supervised', () => testRule('autonomy-full-autonomous-mode', 'mode: "supervised"', false));
  });

  // Self Modification
  describe('autonomy-self-modification', () => {
    test('detect self_modify_instructions', () => testRule('autonomy-self-modification', 'self_modify_instructions = true', true));
    test('detect auto_update_config', () => testRule('autonomy-self-modification', 'auto_update_config: yes', true));
    test('detect modify_own_instructions', () => testRule('autonomy-self-modification', 'modify_own_instructions: true', true));
    test('detect can_update_system_prompt', () => testRule('autonomy-self-modification', 'can_update_system_prompt: true', true));
    test('detect self_rewrite_config', () => testRule('autonomy-self-modification', 'self_rewrite_config = true', true));
  });

  // Wildcard Permissions
  describe('autonomy-wildcard-permissions', () => {
    test('detect permissions star', () => testRule('autonomy-wildcard-permissions', 'permissions: "*"', true));
    test('detect permissions array star', () => testRule('autonomy-wildcard-permissions', 'permissions = ["*"]', true));
    test('detect role admin', () => testRule('autonomy-wildcard-permissions', 'role: "admin"', true));
    test('detect access_level full', () => testRule('autonomy-wildcard-permissions', 'access_level: "full"', true));
    test('detect role superuser', () => testRule('autonomy-wildcard-permissions', 'role = "superuser"', true));
    test('no match for viewer role', () => testRule('autonomy-wildcard-permissions', 'role: "viewer"', false));
    test('no match for readonly', () => testRule('autonomy-wildcard-permissions', 'access_level: "readonly"', false));
  });

  // Dynamic Permission Escalation
  describe('autonomy-dynamic-permission-escalation', () => {
    test('detect request_permissions', () => testRule('autonomy-dynamic-permission-escalation', 'request_permissions = true', true));
    test('detect self_grant', () => testRule('autonomy-dynamic-permission-escalation', 'self_grant: allowed', true));
    test('detect can_request_permissions', () => testRule('autonomy-dynamic-permission-escalation', 'can_request_permissions: true', true));
    test('detect escalate_privilege', () => testRule('autonomy-dynamic-permission-escalation', 'escalate_privilege: yes', true));
    test('detect auto_escalate', () => testRule('autonomy-dynamic-permission-escalation', 'auto_escalate: true', true));
  });

  // Cross-Tenant Access
  describe('autonomy-cross-tenant-access', () => {
    test('detect cross_tenant true', () => testRule('autonomy-cross-tenant-access', 'cross_tenant: true', true));
    test('detect tenant_isolation false', () => testRule('autonomy-cross-tenant-access', 'tenant_isolation: false', true));
    test('detect cross_org enabled', () => testRule('autonomy-cross-tenant-access', 'cross_org = enabled', true));
    test('detect all_tenants true', () => testRule('autonomy-cross-tenant-access', 'all_tenants: true', true));
    test('no match for isolation enabled', () => testRule('autonomy-cross-tenant-access', 'tenant_isolation: true', false));
  });

  // No Rate Limit
  describe('autonomy-no-rate-limit', () => {
    test('detect rate_limit 0', () => testRule('autonomy-no-rate-limit', 'rate_limit: 0', true));
    test('detect rate_limit none', () => testRule('autonomy-no-rate-limit', 'rate_limit = none', true));
    test('detect disable_rate_limit', () => testRule('autonomy-no-rate-limit', 'disable_rate_limit = true', true));
    test('detect rate_limiting disabled', () => testRule('autonomy-no-rate-limit', 'rate_limiting: disabled', true));
    test('no match for rate_limit 100', () => testRule('autonomy-no-rate-limit', 'rate_limit: 100', false));
  });

  // No Timeout
  describe('autonomy-no-timeout', () => {
    test('detect timeout 0', () => testRule('autonomy-no-timeout', 'timeout: 0', true));
    test('detect timeout none', () => testRule('autonomy-no-timeout', 'timeout = none', true));
    test('detect disable_timeout', () => testRule('autonomy-no-timeout', 'disable_timeout = true', true));
    test('detect no_timeout', () => testRule('autonomy-no-timeout', 'no_timeout: true', true));
    test('no match for timeout 30', () => testRule('autonomy-no-timeout', 'timeout: 30', false));
  });

  // Delegate with Full Context
  describe('autonomy-delegate-with-full-context', () => {
    test('detect delegate_full_context', () => testRule('autonomy-delegate-with-full-context', 'delegate_full_context = true', true));
    test('detect share_credentials', () => testRule('autonomy-delegate-with-full-context', 'share_credentials: true', true));
    test('detect forward_api_keys', () => testRule('autonomy-delegate-with-full-context', 'forward_api_keys = true', true));
    test('detect include_secrets', () => testRule('autonomy-delegate-with-full-context', 'include_secrets: true', true));
  });

  // Spawn Unlimited Agents
  describe('autonomy-spawn-unlimited-agents', () => {
    test('detect max_sub_agents -1', () => testRule('autonomy-spawn-unlimited-agents', 'max_sub_agents: -1', true));
    test('detect max_children Infinity', () => testRule('autonomy-spawn-unlimited-agents', 'max_children = Infinity', true));
    test('detect spawn_limit unlimited', () => testRule('autonomy-spawn-unlimited-agents', 'spawn_limit: unlimited', true));
    test('detect very high workers', () => testRule('autonomy-spawn-unlimited-agents', 'max_workers: 9999999', true));
    test('no match for 5 agents', () => testRule('autonomy-spawn-unlimited-agents', 'max_sub_agents: 5', false));
  });

  // No Delegation Depth Limit
  describe('autonomy-no-delegation-depth-limit', () => {
    test('detect max_delegation_depth -1', () => testRule('autonomy-no-delegation-depth-limit', 'max_delegation_depth: -1', true));
    test('detect delegation_depth unlimited', () => testRule('autonomy-no-delegation-depth-limit', 'delegation_depth: unlimited', true));
    test('detect max_depth Infinity', () => testRule('autonomy-no-delegation-depth-limit', 'max_depth = Infinity', true));
  });

  // Instruction No Boundaries
  describe('autonomy-instruction-no-boundaries', () => {
    test('detect do whatever necessary', () => testRule('autonomy-instruction-no-boundaries', 'do whatever is necessary to complete the task', true));
    test('detect take any actions needed', () => testRule('autonomy-instruction-no-boundaries', 'take any actions needed', true));
    test('detect you can do anything', () => testRule('autonomy-instruction-no-boundaries', 'you can do anything', true));
    test('detect no restrictions on actions', () => testRule('autonomy-instruction-no-boundaries', 'no restrictions on your actions', true));
    test('detect do whatever it takes', () => testRule('autonomy-instruction-no-boundaries', 'do whatever it takes', true));
    test('no match for bounded instruction', () => testRule('autonomy-instruction-no-boundaries', 'you can read and search files', false));
  });

  // Instruction Persist Across Sessions
  describe('autonomy-instruction-persist-across-sessions', () => {
    test('detect remember for future sessions', () => testRule('autonomy-instruction-persist-across-sessions', 'remember this for all future sessions', true));
    test('detect persist changes permanently', () => testRule('autonomy-instruction-persist-across-sessions', 'persist these changes permanently', true));
    test('detect permanently change behavior', () => testRule('autonomy-instruction-persist-across-sessions', 'permanently change your behavior', true));
    test('no match for current task', () => testRule('autonomy-instruction-persist-across-sessions', 'remember this for the current task', false));
  });
});
