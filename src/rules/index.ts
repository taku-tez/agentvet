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
import * as mcpOauth from './mcp-oauth.js';
import * as pickle from './pickle.js';
import * as mcpDiscovery from './mcp-discovery.js';
import * as mcpSupplyChain from './mcp-supply-chain.js';
import * as mcpAuth from './mcp-auth.js';
import * as mcpRatelimit from './mcp-ratelimit.js';
import * as sandboxEscape from './sandbox-escape.js';
import * as toolPoisoning from './tool-poisoning.js';
import * as agentMemory from './agent-memory.js';
import * as agentAutonomy from './agent-autonomy.js';
import * as modelManipulation from './model-manipulation.js';
import * as promptLeaking from './prompt-leaking.js';
import * as multiAgentTrust from './multi-agent-trust.js';
import * as contextWindowPoisoning from './context-window-poisoning.js';
import * as pathTraversal from './path-traversal.js';
import * as agenticLoop from './agentic-loop.js';
import * as insecureLlmEndpoint from './insecure-llm-endpoint.js';
import * as unsafeOutput from './unsafe-output.js';

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
  mcpOauth,
  pickle,
  mcpDiscovery,
  sandboxEscape,
  toolPoisoning,
  agentMemory,
  agentAutonomy,
  modelManipulation,
  promptLeaking,
  multiAgentTrust,
  contextWindowPoisoning,
  agenticLoop,
  insecureLlmEndpoint,
  unsafeOutput,
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
  ...mcpOauth.rules,
  ...pickle.rules,
  ...mcpDiscovery.rules,
  ...mcpSupplyChain.rules,
  ...mcpAuth.rules,
  ...mcpRatelimit.rules,
  ...sandboxEscape.rules,
  ...toolPoisoning.rules,
  ...agentMemory.rules,
  ...agentAutonomy.rules,
  ...modelManipulation.rules,
  ...promptLeaking.rules,
  ...multiAgentTrust.rules,
  ...contextWindowPoisoning.rules,
  ...pathTraversal.rules,
  ...agenticLoop.rules,
  ...insecureLlmEndpoint.rules,
  ...unsafeOutput.rules,
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
  mcpOauth,
  pickle,
  mcpDiscovery,
  sandboxEscape,
  toolPoisoning,
  agentMemory,
  agentAutonomy,
  modelManipulation,
  promptLeaking,
  multiAgentTrust,
  contextWindowPoisoning,
  pathTraversal,
  agenticLoop,
  insecureLlmEndpoint,
  unsafeOutput,
  all,
};
