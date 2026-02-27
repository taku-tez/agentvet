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
import * as skillManifest from './skill-manifest.js';
import * as jwt from './jwt.js';
import * as container from './container.js';
import * as ssrf from './ssrf.js';
import * as deserialization from './deserialization.js';
import * as obfuscation from './obfuscation.js';
import * as computerUse from './computer-use.js';
import * as ragPoisoning from './rag-poisoning.js';
import * as supplyChain from './supply-chain.js';

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
  skillManifest,
  jwt,
  container,
  ssrf,
  deserialization,
  obfuscation,
  computerUse,
  ragPoisoning,
  supplyChain,
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
  ...skillManifest.rules,
  ...jwt.rules,
  ...container.rules,
  ...ssrf.rules,
  ...deserialization.rules,
  ...obfuscation.rules,
  ...computerUse.rules,
  ...ragPoisoning.rules,
  ...supplyChain.rules,
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
  skillManifest,
  jwt,
  container,
  ssrf,
  deserialization,
  obfuscation,
  computerUse,
  ragPoisoning,
  supplyChain,
  all,
};
