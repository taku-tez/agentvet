/**
 * AgentVet - Main Entry Point
 * Security scanner for AI agent skills, configs, and MCP tools
 */

const { Scanner } = require('./scanner.js');

/**
 * Scan a directory or file for security issues
 * @param {string} targetPath - Path to scan
 * @param {Object} options - Scan options
 * @returns {Object} Scan results
 */
async function scan(targetPath, options = {}) {
  const scanner = new Scanner(options);
  return scanner.scan(targetPath);
}

/**
 * Get the default rules
 * @returns {Array} Array of rule definitions
 */
function getRules() {
  const credentials = require('./rules/credentials.js');
  const commands = require('./rules/commands.js');
  const urls = require('./rules/urls.js');
  const permissions = require('./rules/permissions.js');
  
  return [
    ...credentials.rules,
    ...commands.rules,
    ...urls.rules,
    ...permissions.rules,
  ];
}

module.exports = {
  scan,
  getRules,
  Scanner,
};
