/**
 * AgentVet Rules Index
 * Exports all rule modules
 */

import * as credentials from './credentials.js';
import * as commands from './commands.js';
import * as urls from './urls.js';
import * as permissions from './permissions.js';
import * as mcp from './mcp.js';
import * as mcpSchema from './mcp-schema.js';
import * as agents from './agents.js';
import * as cicd from './cicd.js';
import * as mcpShadowing from './mcp-shadowing.js';
import * as pii from './pii.js';
import * as guardrails from './guardrails.js';
import * as jailbreak from './jailbreak.js';
import * as hallucination from './hallucination.js';
import * as exfiltration from './exfiltration.js';
import * as indirectInjection from './indirect-injection.js';

export {
  credentials,
  commands,
  urls,
  permissions,
  mcp,
  mcpSchema,
  mcpShadowing,
  agents,
  cicd,
  pii,
  guardrails,
  jailbreak,
  hallucination,
  exfiltration,
  indirectInjection,
};

// Combined rules array
export const all = [
  ...credentials.rules,
  ...commands.rules,
  ...urls.rules,
  ...permissions.rules,
  ...mcp.rules,
  ...mcpSchema.rules,
  ...mcpShadowing.rules,
  ...agents.rules,
  ...cicd.rules,
  ...pii.rules,
  ...guardrails.rules,
  ...jailbreak.rules,
  ...hallucination.rules,
  ...exfiltration.rules,
  ...indirectInjection.rules,
];

// CommonJS compatibility
module.exports = {
  credentials,
  commands,
  urls,
  permissions,
  mcp,
  mcpSchema,
  mcpShadowing,
  agents,
  cicd,
  pii,
  guardrails,
  jailbreak,
  hallucination,
  exfiltration,
  indirectInjection,
  all,
};
