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

export {
  credentials,
  commands,
  urls,
  permissions,
  mcp,
  mcpSchema,
  agents,
  cicd,
};

// Combined rules array
export const all = [
  ...credentials.rules,
  ...commands.rules,
  ...urls.rules,
  ...permissions.rules,
  ...mcp.rules,
  ...mcpSchema.rules,
  ...agents.rules,
  ...cicd.rules,
];

// CommonJS compatibility
module.exports = {
  credentials,
  commands,
  urls,
  permissions,
  mcp,
  mcpSchema,
  agents,
  cicd,
  all,
};
