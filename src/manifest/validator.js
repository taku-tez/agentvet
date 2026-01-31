/**
 * Permission Manifest Validator
 * 
 * マニフェストの検証と、実際のスキル内容との照合。
 */

import Ajv from 'ajv';
import addFormats from 'ajv-formats';
import { manifestSchema, MANIFEST_VERSION } from './schema.js';

const ajv = new Ajv({ allErrors: true });
addFormats(ajv);

const validateSchema = ajv.compile(manifestSchema);

/**
 * Validate manifest against schema
 */
export function validateManifest(manifest) {
  const valid = validateSchema(manifest);
  return {
    valid,
    errors: validateSchema.errors || []
  };
}

/**
 * Compare manifest permissions with actual detected usage
 * Returns undeclared permissions (security risk) and unused declarations (bloat)
 */
export function comparePermissions(manifest, detected) {
  const issues = {
    undeclared: [], // 宣言されていないが使用されている（危険）
    unused: [],     // 宣言されているが使用されていない（過剰宣言）
    matches: []     // 正しく宣言されている
  };

  const declared = manifest?.permissions || {};
  
  // Check exec commands
  if (detected.commands) {
    for (const cmd of detected.commands) {
      if (declared.exec?.some(e => matchPattern(cmd, e))) {
        issues.matches.push({ type: 'exec', value: cmd });
      } else {
        issues.undeclared.push({ 
          type: 'exec', 
          value: cmd,
          severity: 'high',
          message: `Undeclared command execution: ${cmd}`
        });
      }
    }
    // Check for unused exec declarations
    for (const declaredCmd of (declared.exec || [])) {
      if (!detected.commands.some(c => matchPattern(c, declaredCmd))) {
        issues.unused.push({ type: 'exec', value: declaredCmd });
      }
    }
  }

  // Check network access
  if (detected.urls) {
    for (const url of detected.urls) {
      const host = extractHost(url);
      if (host && declared.network?.some(n => matchHostPattern(host, n))) {
        issues.matches.push({ type: 'network', value: host });
      } else if (host) {
        issues.undeclared.push({
          type: 'network',
          value: host,
          severity: isSuspiciousHost(host) ? 'critical' : 'medium',
          message: `Undeclared network access: ${host}`
        });
      }
    }
  }

  // Check file access
  if (detected.fileAccess) {
    for (const access of detected.fileAccess) {
      const pattern = `${access.mode}:${access.path}`;
      if (declared.files?.some(f => matchFilePattern(pattern, f))) {
        issues.matches.push({ type: 'files', value: pattern });
      } else {
        issues.undeclared.push({
          type: 'files',
          value: pattern,
          severity: access.path.includes('/etc') || access.path.includes('..') ? 'high' : 'low',
          message: `Undeclared file access: ${pattern}`
        });
      }
    }
  }

  // Check secrets
  if (detected.secrets) {
    for (const secret of detected.secrets) {
      if (declared.secrets?.includes(secret)) {
        issues.matches.push({ type: 'secrets', value: secret });
      } else {
        issues.undeclared.push({
          type: 'secrets',
          value: secret,
          severity: 'medium',
          message: `Undeclared secret usage: ${secret}`
        });
      }
    }
  }

  // Check elevated permissions
  if (detected.elevated && !declared.elevated) {
    issues.undeclared.push({
      type: 'elevated',
      value: true,
      severity: 'critical',
      message: 'Undeclared elevated/sudo permission usage'
    });
  }

  return issues;
}

/**
 * Simple pattern matching (supports * wildcard)
 */
function matchPattern(value, pattern) {
  if (pattern === '*') return true;
  if (pattern.includes('*')) {
    const regex = new RegExp('^' + pattern.replace(/\*/g, '.*') + '$');
    return regex.test(value);
  }
  return value === pattern || value.startsWith(pattern + ' ');
}

/**
 * Match host against pattern (supports *.domain.com)
 */
function matchHostPattern(host, pattern) {
  if (pattern === '*') return true;
  if (pattern.startsWith('*.')) {
    const domain = pattern.slice(2);
    return host === domain || host.endsWith('.' + domain);
  }
  return host === pattern;
}

/**
 * Match file access pattern
 */
function matchFilePattern(actual, declared) {
  // actual: "read:/path/to/file"
  // declared: "read:./", "write:./output", etc.
  const [actualMode, actualPath] = actual.split(':');
  const [declaredMode, declaredPath] = declared.split(':');
  
  if (actualMode !== declaredMode && declaredMode !== '*') {
    return false;
  }
  
  // Normalize paths
  const normalizedActual = actualPath.replace(/^\.\//, '');
  const normalizedDeclared = declaredPath.replace(/^\.\//, '');
  
  if (normalizedDeclared === '' || normalizedDeclared === '*') {
    return true;
  }
  
  return normalizedActual.startsWith(normalizedDeclared) || 
         matchPattern(normalizedActual, normalizedDeclared);
}

/**
 * Extract host from URL
 */
function extractHost(url) {
  try {
    if (!url.startsWith('http')) {
      url = 'https://' + url;
    }
    return new URL(url).hostname;
  } catch {
    // Try to extract domain from partial URL
    const match = url.match(/(?:https?:\/\/)?([^\/\s:]+)/);
    return match ? match[1] : null;
  }
}

/**
 * Check if host is suspicious (exfiltration endpoints)
 */
function isSuspiciousHost(host) {
  const suspiciousPatterns = [
    'webhook.site',
    'requestbin',
    'ngrok.io',
    'pipedream.net',
    'hookbin.com',
    'pastebin.com',
    'hastebin.com',
    'transfer.sh',
    'file.io'
  ];
  return suspiciousPatterns.some(p => host.includes(p));
}

/**
 * Generate a permission manifest from detected usage
 */
export function generateManifest(detected, options = {}) {
  return {
    version: MANIFEST_VERSION,
    name: options.name || 'unknown-skill',
    description: options.description || 'Auto-generated manifest',
    permissions: {
      exec: [...new Set(detected.commands || [])],
      network: [...new Set((detected.urls || []).map(extractHost).filter(Boolean))],
      files: [...new Set((detected.fileAccess || []).map(a => `${a.mode}:${a.path}`))],
      tools: [...new Set(detected.tools || [])],
      secrets: [...new Set(detected.secrets || [])],
      elevated: detected.elevated || false
    },
    trust: {
      author: options.author || 'unknown',
      audits: [],
      chain: [],
      verified: false
    },
    risks: {
      level: calculateRiskLevel(detected),
      notes: generateRiskNotes(detected)
    }
  };
}

function calculateRiskLevel(detected) {
  let score = 0;
  if (detected.elevated) score += 3;
  if (detected.commands?.some(c => ['rm', 'curl', 'wget', 'eval'].includes(c))) score += 2;
  if (detected.urls?.some(u => isSuspiciousHost(extractHost(u)))) score += 3;
  if (detected.secrets?.length > 3) score += 1;
  
  if (score >= 4) return 'critical';
  if (score >= 3) return 'high';
  if (score >= 1) return 'medium';
  return 'low';
}

function generateRiskNotes(detected) {
  const notes = [];
  if (detected.elevated) {
    notes.push('Requires elevated permissions - review carefully');
  }
  if (detected.commands?.includes('curl') || detected.commands?.includes('wget')) {
    notes.push('Downloads external content - verify sources');
  }
  if (detected.secrets?.length > 0) {
    notes.push(`Uses ${detected.secrets.length} secret(s): ${detected.secrets.join(', ')}`);
  }
  return notes;
}

export default { validateManifest, comparePermissions, generateManifest };
