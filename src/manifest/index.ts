// @ts-nocheck

/**
 * Permission Manifest System
 * Declares and verifies skill permissions
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// Permission categories
const PERMISSION_CATEGORIES = {
  exec: 'Command execution',
  network: 'Network access',
  files: 'File system access',
  secrets: 'Secret/credential access',
  env: 'Environment variable access',
};

// Default manifest template
const MANIFEST_TEMPLATE = {
  version: '1.0',
  name: '',
  description: '',
  author: '',
  permissions: {
    exec: [],
    network: [],
    files: [],
    secrets: [],
    env: [],
  },
  trust: {
    signed: false,
    verifiedBy: [],
  },
  integrity: {
    algorithm: 'sha256',
    hash: '',
    files: [],
  },
};

/**
 * Static analysis patterns for permission detection
 */
const DETECTION_PATTERNS = {
  exec: [
    // Node.js exec patterns
    { pattern: /(?:exec|execSync|spawn|spawnSync|fork)\s*\(\s*['"`]([^'"`]+)['"`]/g, extract: 1 },
    { pattern: /child_process/g, value: '*' },
    // Shell commands
    { pattern: /\$\(([^)]+)\)/g, extract: 1 },
    { pattern: /`([^`]+)`/g, extract: 1 },
  ],
  network: [
    // URLs
    { pattern: /https?:\/\/([a-zA-Z0-9.-]+)/g, extract: 1 },
    // Fetch/axios/request
    { pattern: /fetch\s*\(\s*['"`]https?:\/\/([^'"`/]+)/g, extract: 1 },
    { pattern: /axios\.[a-z]+\s*\(\s*['"`]https?:\/\/([^'"`/]+)/g, extract: 1 },
  ],
  files: [
    // Read operations
    { pattern: /readFile(?:Sync)?\s*\(\s*['"`]([^'"`]+)['"`]/g, extract: 1, prefix: 'read:' },
    { pattern: /readdir(?:Sync)?\s*\(\s*['"`]([^'"`]+)['"`]/g, extract: 1, prefix: 'read:' },
    // Write operations
    { pattern: /writeFile(?:Sync)?\s*\(\s*['"`]([^'"`]+)['"`]/g, extract: 1, prefix: 'write:' },
    { pattern: /appendFile(?:Sync)?\s*\(\s*['"`]([^'"`]+)['"`]/g, extract: 1, prefix: 'write:' },
    { pattern: /mkdir(?:Sync)?\s*\(\s*['"`]([^'"`]+)['"`]/g, extract: 1, prefix: 'write:' },
    // Delete operations
    { pattern: /unlink(?:Sync)?\s*\(\s*['"`]([^'"`]+)['"`]/g, extract: 1, prefix: 'delete:' },
    { pattern: /rm(?:Sync)?\s*\(\s*['"`]([^'"`]+)['"`]/g, extract: 1, prefix: 'delete:' },
  ],
  secrets: [
    // Common secret patterns
    { pattern: /(?:API_KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL|AUTH)[A-Z_]*/g, extract: 0 },
    { pattern: /process\.env\.([A-Z_]+(?:KEY|SECRET|TOKEN|PASSWORD|AUTH)[A-Z_]*)/g, extract: 1 },
  ],
  env: [
    // Environment variable access
    { pattern: /process\.env\.([A-Z_]+)/g, extract: 1 },
    { pattern: /process\.env\[['"`]([^'"`]+)['"`]\]/g, extract: 1 },
  ],
};

/**
 * Analyze a file for permission usage
 */
function analyzeFile(filepath) {
  const detected = {
    exec: new Set(),
    network: new Set(),
    files: new Set(),
    secrets: new Set(),
    env: new Set(),
  };

  let content;
  try {
    content = fs.readFileSync(filepath, 'utf8');
  } catch {
    return detected;
  }

  for (const [category, patterns] of Object.entries(DETECTION_PATTERNS)) {
    for (const { pattern, extract, value, prefix } of patterns) {
      pattern.lastIndex = 0;
      let match;
      while ((match = pattern.exec(content)) !== null) {
        let extracted;
        if (value !== undefined) {
          extracted = value;
        } else if (extract !== undefined) {
          extracted = match[extract];
        } else {
          extracted = match[0];
        }
        if (prefix) {
          extracted = prefix + extracted;
        }
        if (extracted) {
          detected[category].add(extracted);
        }
      }
    }
  }

  return detected;
}

/**
 * Walk directory and analyze all files
 */
function analyzeDirectory(dir, options = {}) {
  const detected = {
    exec: new Set(),
    network: new Set(),
    files: new Set(),
    secrets: new Set(),
    env: new Set(),
  };

  const exclude = options.exclude || [
    /node_modules/,
    /\.git/,
    /\.min\.js$/,
    /\.map$/,
    /test\//,
    /tests\//,
    /__tests__\//,
    /\.test\./,
    /\.spec\./,
    /examples\//,
    /fixtures\//,
  ];

  // Only analyze actual code files, not documentation
  const codeExtensions = ['.js', '.ts', '.mjs', '.cjs', '.jsx', '.tsx', '.py', '.sh', '.bash'];
  const docExtensions = ['.md', '.rst', '.txt'];

  function walk(currentDir) {
    let entries;
    try {
      entries = fs.readdirSync(currentDir, { withFileTypes: true });
    } catch {
      return;
    }

    for (const entry of entries) {
      const fullPath = path.join(currentDir, entry.name);
      
      // Check exclusions
      if (exclude.some(p => p.test(fullPath))) continue;

      if (entry.isDirectory()) {
        walk(fullPath);
      } else if (entry.isFile()) {
        const ext = path.extname(entry.name).toLowerCase();
        // Skip documentation files (they contain examples, not actual code)
        if (docExtensions.includes(ext)) continue;
        // Only analyze code files
        if (codeExtensions.includes(ext)) {
          const fileDetected = analyzeFile(fullPath);
          for (const [cat, values] of Object.entries(fileDetected)) {
            values.forEach(v => detected[cat].add(v));
          }
        }
      }
    }
  }

  walk(dir);

  // Convert Sets to Arrays
  return {
    exec: [...detected.exec].sort(),
    network: [...detected.network].sort(),
    files: [...detected.files].sort(),
    secrets: [...detected.secrets].sort(),
    env: [...detected.env].sort(),
  };
}

/**
 * Calculate content hash for integrity
 */
function calculateIntegrity(dir, options = {}) {
  const hashes = [];
  const exclude = options.exclude || [/node_modules/, /\.git/];

  function walk(currentDir) {
    let entries;
    try {
      entries = fs.readdirSync(currentDir, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name));
    } catch {
      return;
    }

    for (const entry of entries) {
      const fullPath = path.join(currentDir, entry.name);
      if (exclude.some(p => p.test(fullPath))) continue;

      if (entry.isDirectory()) {
        walk(fullPath);
      } else if (entry.isFile()) {
        try {
          const content = fs.readFileSync(fullPath);
          const hash = crypto.createHash('sha256').update(content).digest('hex');
          const relativePath = path.relative(dir, fullPath);
          hashes.push({ path: relativePath, hash });
        } catch {
          // Skip unreadable files
        }
      }
    }
  }

  walk(dir);

  // Calculate combined hash
  const combined = hashes.map(h => h.hash).join('');
  const totalHash = crypto.createHash('sha256').update(combined).digest('hex');

  return {
    algorithm: 'sha256',
    hash: totalHash,
    files: hashes,
  };
}

/**
 * Initialize manifest for a skill
 */
function initManifest(skillDir, options = {}) {
  const manifest = JSON.parse(JSON.stringify(MANIFEST_TEMPLATE));

  // Try to read skill metadata
  const skillMdPath = path.join(skillDir, 'SKILL.md');
  if (fs.existsSync(skillMdPath)) {
    const content = fs.readFileSync(skillMdPath, 'utf8');
    // Parse frontmatter
    const frontmatterMatch = content.match(/^---\n([\s\S]*?)\n---/);
    if (frontmatterMatch) {
      const fm = frontmatterMatch[1];
      const nameMatch = fm.match(/name:\s*(.+)/);
      const descMatch = fm.match(/description:\s*(.+)/);
      if (nameMatch) manifest.name = nameMatch[1].trim();
      if (descMatch) manifest.description = descMatch[1].trim();
    }
  }

  // Try to read package.json
  const pkgPath = path.join(skillDir, 'package.json');
  if (fs.existsSync(pkgPath)) {
    try {
      const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
      if (!manifest.name && pkg.name) manifest.name = pkg.name;
      if (!manifest.description && pkg.description) manifest.description = pkg.description;
      if (pkg.author) manifest.author = typeof pkg.author === 'string' ? pkg.author : pkg.author.name;
    } catch {
      // Ignore parse errors
    }
  }

  // Analyze directory for permissions
  manifest.permissions = analyzeDirectory(skillDir);

  // Calculate integrity
  if (options.integrity !== false) {
    manifest.integrity = calculateIntegrity(skillDir);
  }

  return manifest;
}

/**
 * Verify manifest against actual code
 */
function verifyManifest(skillDir, manifestPath) {
  const results = {
    valid: true,
    errors: [],
    warnings: [],
    undeclared: {},
    unused: {},
  };

  // Load manifest
  let manifest;
  try {
    manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
  } catch (err) {
    results.valid = false;
    results.errors.push(`Failed to read manifest: ${err.message}`);
    return results;
  }

  // Analyze actual permissions
  const actual = analyzeDirectory(skillDir);
  const declared = manifest.permissions || {};

  // Check for undeclared permissions (actual but not declared)
  for (const [category, actualPerms] of Object.entries(actual)) {
    const declaredPerms = new Set(declared[category] || []);
    const undeclared = actualPerms.filter(p => {
      // Check for wildcard
      if (declaredPerms.has('*')) return false;
      // Check exact match
      if (declaredPerms.has(p)) return false;
      // Check prefix match for files
      if (category === 'files') {
        for (const dp of declaredPerms) {
          if (p.startsWith(dp)) return false;
        }
      }
      // Check domain match for network
      if (category === 'network') {
        for (const dp of declaredPerms) {
          if (p === dp || p.endsWith('.' + dp)) return false;
        }
      }
      return true;
    });

    if (undeclared.length > 0) {
      results.valid = false;
      results.undeclared[category] = undeclared;
      results.errors.push(`Undeclared ${category} permissions: ${undeclared.join(', ')}`);
    }
  }

  // Check for unused declarations (declared but not used)
  for (const [category, declaredPerms] of Object.entries(declared)) {
    if (!Array.isArray(declaredPerms)) continue;
    const actualPerms = new Set(actual[category] || []);
    const unused = declaredPerms.filter(p => {
      if (p === '*') return false; // Wildcard always "used"
      return !actualPerms.has(p);
    });

    if (unused.length > 0) {
      results.unused[category] = unused;
      results.warnings.push(`Unused ${category} declarations: ${unused.join(', ')}`);
    }
  }

  // Check for wildcards
  for (const [category, perms] of Object.entries(declared)) {
    if (Array.isArray(perms) && perms.includes('*')) {
      results.warnings.push(`⚠️ Wildcard permission in ${category} - grants unrestricted access`);
    }
  }

  // Verify integrity if present
  if (manifest.integrity?.hash) {
    const currentIntegrity = calculateIntegrity(skillDir);
    if (currentIntegrity.hash !== manifest.integrity.hash) {
      results.valid = false;
      results.errors.push('Integrity check failed: content has been modified since manifest was created');
    }
  }

  return results;
}

/**
 * Score permission risk
 */
function scorePermissions(permissions) {
  let score = 0;
  const breakdown = {};

  const weights = {
    exec: { base: 20, wildcard: 50 },
    network: { base: 10, wildcard: 30 },
    files: { base: 5, write: 15, delete: 25, wildcard: 40 },
    secrets: { base: 15, wildcard: 50 },
    env: { base: 2, wildcard: 10 },
  };

  for (const [category, perms] of Object.entries(permissions)) {
    if (!Array.isArray(perms)) continue;
    
    let categoryScore = 0;
    const w = weights[category] || { base: 5, wildcard: 20 };

    for (const perm of perms) {
      if (perm === '*') {
        categoryScore += w.wildcard;
      } else if (category === 'files') {
        if (perm.startsWith('delete:')) categoryScore += w.delete;
        else if (perm.startsWith('write:')) categoryScore += w.write;
        else categoryScore += w.base;
      } else {
        categoryScore += w.base;
      }
    }

    breakdown[category] = categoryScore;
    score += categoryScore;
  }

  return {
    score,
    breakdown,
    level: score < 20 ? 'low' : score < 50 ? 'medium' : score < 100 ? 'high' : 'critical',
  };
}

module.exports = {
  PERMISSION_CATEGORIES,
  MANIFEST_TEMPLATE,
  analyzeFile,
  analyzeDirectory,
  calculateIntegrity,
  initManifest,
  verifyManifest,
  scorePermissions,
};
