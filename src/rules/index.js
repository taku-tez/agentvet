/**
 * AgentVet Rules Index
 * Exports all rule modules
 */

const credentials = require('./credentials.js');
const commands = require('./commands.js');
const urls = require('./urls.js');
const permissions = require('./permissions.js');
const mcp = require('./mcp.js');
const agents = require('./agents.js');

module.exports = {
  credentials,
  commands,
  urls,
  permissions,
  mcp,
  agents,
  
  // Combined rules array
  all: [
    ...credentials.rules,
    ...commands.rules,
    ...urls.rules,
    ...permissions.rules,
    ...mcp.rules,
    ...agents.rules,
  ],
};
