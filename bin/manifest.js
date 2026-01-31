#!/usr/bin/env node
/**
 * AgentVet Manifest CLI
 * Permission manifest management for skills
 */

const fs = require('fs');
const path = require('path');
const {
  initManifest,
  verifyManifest,
  scorePermissions,
  PERMISSION_CATEGORIES,
} = require('../src/manifest/index.js');

// Colors
const c = {
  red: (s) => `\x1b[31m${s}\x1b[0m`,
  green: (s) => `\x1b[32m${s}\x1b[0m`,
  yellow: (s) => `\x1b[33m${s}\x1b[0m`,
  blue: (s) => `\x1b[34m${s}\x1b[0m`,
  gray: (s) => `\x1b[90m${s}\x1b[0m`,
  bold: (s) => `\x1b[1m${s}\x1b[0m`,
};

const HELP = `
AgentVet Manifest - Permission Management for Skills

Usage:
  agentvet manifest init <path>      Generate manifest from skill analysis
  agentvet manifest verify <path>    Verify manifest against actual code
  agentvet manifest show <path>      Display manifest contents
  agentvet manifest score <path>     Calculate permission risk score

Options:
  --output, -o <file>    Output file (default: agentvet.manifest.json)
  --json                 JSON output
  --no-integrity         Skip integrity hash calculation
  --help, -h             Show this help

Examples:
  agentvet manifest init ./my-skill
  agentvet manifest verify ./my-skill
  agentvet manifest show ./my-skill/agentvet.manifest.json
`;

function parseArgs(args) {
  const options = {
    command: null,
    path: null,
    output: 'agentvet.manifest.json',
    json: false,
    integrity: true,
    help: false,
  };

  let i = 0;
  while (i < args.length) {
    const arg = args[i];
    switch (arg) {
      case 'init':
      case 'verify':
      case 'show':
      case 'score':
        options.command = arg;
        if (args[i + 1] && !args[i + 1].startsWith('-')) {
          options.path = args[++i];
        }
        break;
      case '--output':
      case '-o':
        options.output = args[++i];
        break;
      case '--json':
        options.json = true;
        break;
      case '--no-integrity':
        options.integrity = false;
        break;
      case '--help':
      case '-h':
        options.help = true;
        break;
      default:
        if (!arg.startsWith('-') && !options.path) {
          options.path = arg;
        }
    }
    i++;
  }

  return options;
}

function printManifest(manifest) {
  console.log(c.bold('\n📋 Permission Manifest'));
  console.log('═'.repeat(50));
  
  if (manifest.name) console.log(`Name: ${manifest.name}`);
  if (manifest.description) console.log(`Description: ${manifest.description}`);
  if (manifest.author) console.log(`Author: ${manifest.author}`);
  console.log('');

  console.log(c.bold('Permissions:'));
  for (const [category, perms] of Object.entries(manifest.permissions || {})) {
    if (!Array.isArray(perms) || perms.length === 0) continue;
    const desc = PERMISSION_CATEGORIES[category] || category;
    console.log(`  ${c.blue(desc)}:`);
    for (const perm of perms) {
      const icon = perm === '*' ? c.red('⚠️ ') : '  ';
      console.log(`    ${icon}${perm}`);
    }
  }

  if (manifest.integrity?.hash) {
    console.log('');
    console.log(c.bold('Integrity:'));
    console.log(`  Algorithm: ${manifest.integrity.algorithm}`);
    console.log(`  Hash: ${manifest.integrity.hash.substring(0, 16)}...`);
    console.log(`  Files: ${manifest.integrity.files?.length || 0}`);
  }

  if (manifest.trust) {
    console.log('');
    console.log(c.bold('Trust:'));
    console.log(`  Signed: ${manifest.trust.signed ? c.green('Yes') : c.gray('No')}`);
    if (manifest.trust.verifiedBy?.length > 0) {
      console.log(`  Verified by: ${manifest.trust.verifiedBy.join(', ')}`);
    }
  }
}

function printScore(score) {
  const levelColors = {
    low: c.green,
    medium: c.yellow,
    high: c.red,
    critical: (s) => c.bold(c.red(s)),
  };
  const colorFn = levelColors[score.level] || c.gray;

  console.log(c.bold('\n📊 Permission Risk Score'));
  console.log('═'.repeat(50));
  console.log(`Total Score: ${colorFn(score.score)} (${colorFn(score.level.toUpperCase())})`);
  console.log('');
  console.log('Breakdown:');
  for (const [category, points] of Object.entries(score.breakdown)) {
    if (points > 0) {
      const bar = '█'.repeat(Math.min(points / 5, 20));
      console.log(`  ${category.padEnd(10)} ${String(points).padStart(3)} ${c.blue(bar)}`);
    }
  }
}

function printVerification(results) {
  console.log(c.bold('\n🔍 Manifest Verification'));
  console.log('═'.repeat(50));

  if (results.valid) {
    console.log(c.green('✅ Manifest is valid'));
  } else {
    console.log(c.red('❌ Manifest verification failed'));
  }

  if (results.errors.length > 0) {
    console.log('');
    console.log(c.red('Errors:'));
    for (const err of results.errors) {
      console.log(`  ${c.red('•')} ${err}`);
    }
  }

  if (results.warnings.length > 0) {
    console.log('');
    console.log(c.yellow('Warnings:'));
    for (const warn of results.warnings) {
      console.log(`  ${c.yellow('•')} ${warn}`);
    }
  }

  if (Object.keys(results.undeclared).length > 0) {
    console.log('');
    console.log(c.red('Undeclared permissions (add to manifest):'));
    for (const [cat, perms] of Object.entries(results.undeclared)) {
      console.log(`  ${cat}: ${JSON.stringify(perms)}`);
    }
  }

  if (Object.keys(results.unused).length > 0) {
    console.log('');
    console.log(c.gray('Unused declarations (can be removed):'));
    for (const [cat, perms] of Object.entries(results.unused)) {
      console.log(`  ${cat}: ${JSON.stringify(perms)}`);
    }
  }

  return results.valid;
}

async function main() {
  const args = process.argv.slice(2);
  
  // Check if called as subcommand of agentvet
  const filteredArgs = args.filter(a => a !== 'manifest');
  const options = parseArgs(filteredArgs);

  if (options.help || !options.command) {
    console.log(HELP);
    process.exit(0);
  }

  if (!options.path) {
    console.error('Error: Path required');
    process.exit(1);
  }

  const targetPath = path.resolve(options.path);

  switch (options.command) {
    case 'init': {
      if (!fs.existsSync(targetPath)) {
        console.error(`Error: Path not found: ${targetPath}`);
        process.exit(1);
      }

      console.log(c.blue(`Analyzing ${targetPath}...`));
      const manifest = initManifest(targetPath, { integrity: options.integrity });
      
      if (options.json) {
        console.log(JSON.stringify(manifest, null, 2));
      } else {
        printManifest(manifest);
        
        // Score
        const score = scorePermissions(manifest.permissions);
        printScore(score);

        // Write to file
        const outputPath = path.join(targetPath, options.output);
        fs.writeFileSync(outputPath, JSON.stringify(manifest, null, 2));
        console.log('');
        console.log(c.green(`✅ Manifest written to ${outputPath}`));
      }
      break;
    }

    case 'verify': {
      const manifestPath = targetPath.endsWith('.json') 
        ? targetPath 
        : path.join(targetPath, 'agentvet.manifest.json');
      
      const skillDir = targetPath.endsWith('.json')
        ? path.dirname(targetPath)
        : targetPath;

      if (!fs.existsSync(manifestPath)) {
        console.error(`Error: Manifest not found: ${manifestPath}`);
        console.error('Run "agentvet manifest init" first to generate one.');
        process.exit(1);
      }

      const results = verifyManifest(skillDir, manifestPath);

      if (options.json) {
        console.log(JSON.stringify(results, null, 2));
      } else {
        const valid = printVerification(results);
        process.exit(valid ? 0 : 1);
      }
      break;
    }

    case 'show': {
      const manifestPath = targetPath.endsWith('.json')
        ? targetPath
        : path.join(targetPath, 'agentvet.manifest.json');

      if (!fs.existsSync(manifestPath)) {
        console.error(`Error: Manifest not found: ${manifestPath}`);
        process.exit(1);
      }

      const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));

      if (options.json) {
        console.log(JSON.stringify(manifest, null, 2));
      } else {
        printManifest(manifest);
      }
      break;
    }

    case 'score': {
      const manifestPath = targetPath.endsWith('.json')
        ? targetPath
        : path.join(targetPath, 'agentvet.manifest.json');

      let permissions;
      if (fs.existsSync(manifestPath)) {
        const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
        permissions = manifest.permissions;
      } else {
        // Analyze directly
        const { analyzeDirectory } = require('../src/manifest/index.js');
        permissions = analyzeDirectory(targetPath);
      }

      const score = scorePermissions(permissions);

      if (options.json) {
        console.log(JSON.stringify(score, null, 2));
      } else {
        printScore(score);
      }

      // Exit with error if high/critical
      if (score.level === 'critical') process.exit(2);
      if (score.level === 'high') process.exit(1);
      break;
    }
  }
}

main().catch(err => {
  console.error(`Error: ${err.message}`);
  process.exit(1);
});
