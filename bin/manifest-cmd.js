#!/usr/bin/env node
/**
 * AgentVet Manifest Commands
 * Permission Manifest と Trust Chain の管理コマンド
 */

const _fs = require('fs');
const path = require('path');

// ESM modules need dynamic import
async function loadManifestModule() {
  const { 
    loadManifest, 
    saveManifest,
    validateManifest, 
    comparePermissions, 
    generateManifest,
    verifyTrustChain,
    calculateContentHash,
    createAuditEntry,
    formatTrustChain,
    exampleManifest
  } = await import('../src/manifest/index.js');
  
  return {
    loadManifest,
    saveManifest,
    validateManifest,
    comparePermissions,
    generateManifest,
    verifyTrustChain,
    calculateContentHash,
    createAuditEntry,
    formatTrustChain,
    exampleManifest
  };
}

const HELP = `
AgentVet Manifest Commands
Manage Permission Manifests and Trust Chains for AI agent skills.

Usage:
  agentvet manifest init [path]         Generate manifest from detected usage
  agentvet manifest validate [path]     Validate manifest schema
  agentvet manifest verify [path]       Verify manifest against actual skill content
  agentvet manifest trust [path]        Show trust chain information
  agentvet manifest audit [path]        Create audit entry for manifest
  agentvet manifest example             Show example manifest

Options:
  --format <type>    Output format: text (default), json, yaml
  --output <file>    Write manifest to file
  --auditor <id>     Auditor identifier (e.g., "user:yourname", "org:company")
  --notes <text>     Audit notes

Examples:
  # Generate manifest for a skill
  agentvet manifest init ./skills/my-skill

  # Validate existing manifest
  agentvet manifest validate ./skills/my-skill

  # Verify skill matches its manifest
  agentvet manifest verify ./skills/my-skill

  # Show trust chain
  agentvet manifest trust ./skills/my-skill

  # Create audit entry
  agentvet manifest audit ./skills/my-skill --auditor "org:mycompany" --notes "Reviewed all permissions"
`;

async function main(args) {
  if (args.length === 0 || args[0] === '--help' || args[0] === '-h') {
    console.log(HELP);
    return;
  }

  const subcommand = args[0];
  const skillPath = args[1] || '.';
  
  // Parse options
  const options = {
    format: 'text',
    output: null,
    auditor: null,
    notes: null,
  };
  
  for (let i = 2; i < args.length; i++) {
    switch (args[i]) {
      case '--format':
      case '-f':
        options.format = args[++i] || 'text';
        break;
      case '--output':
      case '-o':
        options.output = args[++i];
        break;
      case '--auditor':
        options.auditor = args[++i];
        break;
      case '--notes':
        options.notes = args[++i];
        break;
    }
  }

  const mod = await loadManifestModule();

  switch (subcommand) {
    case 'init':
      await initManifest(skillPath, options, mod);
      break;
    case 'validate':
      await validateManifestCmd(skillPath, options, mod);
      break;
    case 'verify':
      await verifyManifestCmd(skillPath, options, mod);
      break;
    case 'trust':
      await trustChainCmd(skillPath, options, mod);
      break;
    case 'audit':
      await createAuditCmd(skillPath, options, mod);
      break;
    case 'example':
      showExample(options, mod);
      break;
    default:
      console.error(`Unknown manifest command: ${subcommand}`);
      console.log('Use "agentvet manifest --help" for usage.');
      process.exit(1);
  }
}

async function initManifest(skillPath, options, mod) {
  console.log(`🔍 Scanning ${skillPath} to detect permission usage...`);
  
  // Run a scan to detect actual usage
  const { scan } = require('../src/index.js');
  const results = await scan(skillPath, { 
    yara: false, 
    deps: false,
    severityFilter: 'info'
  });
  
  // Extract detected permissions from findings
  const detected = {
    commands: [],
    urls: [],
    fileAccess: [],
    secrets: [],
    tools: [],
    elevated: false,
  };
  
  for (const finding of results.findings) {
    if (finding.ruleId.includes('command') || finding.ruleId.includes('exec')) {
      // Extract command from snippet
      const cmdMatch = finding.snippet?.match(/(?:exec|spawn|system)\s*\(\s*['"]([^'"]+)/);
      if (cmdMatch) {
        detected.commands.push(cmdMatch[1].split(' ')[0]);
      }
    }
    if (finding.ruleId.includes('url') || finding.ruleId.includes('http')) {
      const urlMatch = finding.snippet?.match(/https?:\/\/[^\s'"]+/);
      if (urlMatch) {
        detected.urls.push(urlMatch[0]);
      }
    }
    if (finding.ruleId.includes('credential') || finding.ruleId.includes('secret')) {
      const envMatch = finding.snippet?.match(/process\.env\.(\w+)|getenv\(['"](\w+)/);
      if (envMatch) {
        detected.secrets.push(envMatch[1] || envMatch[2]);
      }
    }
    if (finding.ruleId.includes('sudo') || finding.ruleId.includes('elevated')) {
      detected.elevated = true;
    }
  }
  
  // Generate manifest
  const manifest = mod.generateManifest(detected, {
    name: path.basename(skillPath),
    description: `Auto-generated manifest for ${path.basename(skillPath)}`,
    author: options.auditor || 'unknown',
  });
  
  // Output
  if (options.output || options.format === 'text') {
    const outputPath = options.output || mod.saveManifest(skillPath, manifest, 
      options.format === 'yaml' ? 'yaml' : 'json');
    console.log(`✅ Manifest generated: ${outputPath}`);
    console.log('\nDetected permissions:');
    console.log(JSON.stringify(manifest.permissions, null, 2));
    console.log('\n⚠️  Review and adjust the manifest before committing!');
  } else if (options.format === 'json') {
    console.log(JSON.stringify(manifest, null, 2));
  } else if (options.format === 'yaml') {
    const yaml = require('yaml');
    console.log(yaml.stringify(manifest));
  }
}

async function validateManifestCmd(skillPath, options, mod) {
  const { manifest, path: manifestPath } = mod.loadManifest(skillPath);
  
  if (!manifest) {
    console.error('❌ No manifest found in', skillPath);
    console.log('   Run "agentvet manifest init" to generate one.');
    process.exit(1);
  }
  
  console.log(`📋 Validating manifest: ${manifestPath}`);
  
  const result = mod.validateManifest(manifest);
  
  if (result.valid) {
    console.log('✅ Manifest schema is valid');
    
    // Also show summary
    console.log('\nDeclared permissions:');
    const perms = manifest.permissions || {};
    if (perms.exec?.length) console.log(`  exec: ${perms.exec.join(', ')}`);
    if (perms.network?.length) console.log(`  network: ${perms.network.join(', ')}`);
    if (perms.files?.length) console.log(`  files: ${perms.files.join(', ')}`);
    if (perms.secrets?.length) console.log(`  secrets: ${perms.secrets.join(', ')}`);
    if (perms.elevated) console.log('  elevated: true');
  } else {
    console.error('❌ Manifest validation failed:');
    for (const error of result.errors) {
      console.error(`   - ${error.instancePath}: ${error.message}`);
    }
    process.exit(1);
  }
}

async function verifyManifestCmd(skillPath, options, mod) {
  const { manifest, path: manifestPath } = mod.loadManifest(skillPath);
  
  if (!manifest) {
    console.error('❌ No manifest found in', skillPath);
    process.exit(1);
  }
  
  console.log(`🔍 Verifying ${manifestPath} against actual content...`);
  
  // Scan to detect actual usage
  const { scan } = require('../src/index.js');
  const results = await scan(skillPath, { 
    yara: false, 
    deps: false,
    severityFilter: 'info'
  });
  
  // Extract detected permissions (same as init)
  const detected = {
    commands: [],
    urls: [],
    fileAccess: [],
    secrets: [],
    elevated: false,
  };
  
  for (const finding of results.findings) {
    if (finding.ruleId.includes('command')) {
      const cmdMatch = finding.snippet?.match(/(?:exec|spawn)\s*\(\s*['"]([^'"]+)/);
      if (cmdMatch) detected.commands.push(cmdMatch[1].split(' ')[0]);
    }
    if (finding.ruleId.includes('url')) {
      const urlMatch = finding.snippet?.match(/https?:\/\/[^\s'"]+/);
      if (urlMatch) detected.urls.push(urlMatch[0]);
    }
    if (finding.ruleId.includes('credential')) {
      const envMatch = finding.snippet?.match(/process\.env\.(\w+)/);
      if (envMatch) detected.secrets.push(envMatch[1]);
    }
  }
  
  // Compare
  const comparison = mod.comparePermissions(manifest, detected);
  
  if (comparison.undeclared.length === 0) {
    console.log('✅ All detected permissions are declared in manifest');
  } else {
    console.log('❌ Undeclared permissions found:');
    for (const issue of comparison.undeclared) {
      const icon = issue.severity === 'critical' ? '🔴' : 
                   issue.severity === 'high' ? '🟠' : '🟡';
      console.log(`   ${icon} ${issue.message}`);
    }
  }
  
  if (comparison.unused.length > 0) {
    console.log('\n⚠️  Unused declarations (consider removing):');
    for (const item of comparison.unused) {
      console.log(`   - ${item.type}: ${item.value}`);
    }
  }
  
  if (comparison.matches.length > 0) {
    console.log(`\n✅ ${comparison.matches.length} permission(s) correctly declared`);
  }
  
  process.exit(comparison.undeclared.length > 0 ? 1 : 0);
}

async function trustChainCmd(skillPath, options, mod) {
  const { manifest, path: manifestPath } = mod.loadManifest(skillPath);
  
  if (!manifest) {
    console.error('❌ No manifest found in', skillPath);
    process.exit(1);
  }
  
  console.log(`🔗 Trust chain for: ${manifestPath}\n`);
  
  // Calculate current content hash
  const currentHash = await mod.calculateContentHash(skillPath);
  
  const trustResult = mod.verifyTrustChain(manifest, { currentHash });
  
  if (options.format === 'json') {
    console.log(JSON.stringify(trustResult, null, 2));
  } else {
    console.log(mod.formatTrustChain(trustResult));
    console.log(`\nCurrent content hash: ${currentHash.slice(0, 20)}...`);
  }
}

async function createAuditCmd(skillPath, options, mod) {
  if (!options.auditor) {
    console.error('❌ Auditor required. Use --auditor "user:yourname" or "org:company"');
    process.exit(1);
  }
  
  const { manifest, path: manifestPath } = mod.loadManifest(skillPath);
  
  if (!manifest) {
    console.error('❌ No manifest found. Run "agentvet manifest init" first.');
    process.exit(1);
  }
  
  console.log(`📝 Creating audit entry for: ${manifestPath}`);
  
  // Calculate content hash
  const contentHash = await mod.calculateContentHash(skillPath);
  
  // Create audit entry
  const auditEntry = mod.createAuditEntry({
    auditor: options.auditor,
    contentHash,
    notes: options.notes || 'Audit completed',
  });
  
  // Add to manifest
  if (!manifest.trust) manifest.trust = {};
  if (!manifest.trust.audits) manifest.trust.audits = [];
  manifest.trust.audits.push(auditEntry);
  
  // Save
  const outputPath = mod.saveManifest(skillPath, manifest);
  
  console.log('✅ Audit entry added:');
  console.log(JSON.stringify(auditEntry, null, 2));
  console.log(`\nManifest updated: ${outputPath}`);
}

function showExample(options, mod) {
  if (options.format === 'yaml') {
    const yaml = require('yaml');
    console.log(yaml.stringify(mod.exampleManifest));
  } else {
    console.log(JSON.stringify(mod.exampleManifest, null, 2));
  }
}

// Run if called directly
if (require.main === module) {
  main(process.argv.slice(2)).catch(err => {
    console.error('Error:', err.message);
    process.exit(2);
  });
}

module.exports = { main };
