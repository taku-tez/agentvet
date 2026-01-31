/**
 * AgentVet Rules Index
 * Exports all rule modules
 */

const credentials = require('./credentials.js');
const commands = require('./commands.js');
const urls = require('./urls.js');
const permissions = require('./permissions.js');
const mcp = require('./mcp.js');

module.exports = {
  credentials,
  commands,
  urls,
  permissions,
  mcp,
  
  // Combined rules array
  all: [
    ...credentials.rules,
    ...commands.rules,
    ...urls.rules,
    ...permissions.rules,
    ...mcp.rules,
  ],
};
