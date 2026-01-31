/**
 * Trust Chain Verification
 * 
 * スキルの信頼チェーンを追跡・検証する。
 * 誰が作成し、誰が監査し、どのレジストリで検証されたかを追跡。
 */

import crypto from 'crypto';
import fs from 'fs';
import path from 'path';

/**
 * Trust levels for auditors/sources
 */
export const TRUST_LEVELS = {
  SELF: 0,           // 自己宣言のみ
  COMMUNITY: 1,      // コミュニティメンバーによる監査
  ORGANIZATION: 2,   // 組織による監査
  REGISTRY: 3,       // 公式レジストリによる検証
  OFFICIAL: 4        // 公式スキル
};

/**
 * Known trusted auditors/registries
 */
export const KNOWN_AUDITORS = {
  'clawdhub:official': { level: TRUST_LEVELS.OFFICIAL, name: 'ClawdHub Official' },
  'clawdhub:verified': { level: TRUST_LEVELS.REGISTRY, name: 'ClawdHub Verified' },
  'org:openclaw': { level: TRUST_LEVELS.ORGANIZATION, name: 'OpenClaw Team' },
  'org:3shake': { level: TRUST_LEVELS.ORGANIZATION, name: '3shake Inc.' },
  // ユーザーは動的に追加可能
};

/**
 * Calculate content hash for a skill directory
 */
export async function calculateContentHash(skillPath) {
  const hash = crypto.createHash('sha256');
  const files = await getSkillFiles(skillPath);
  
  // Sort files for deterministic hash
  files.sort();
  
  for (const file of files) {
    const content = fs.readFileSync(file);
    hash.update(file.replace(skillPath, '') + ':');
    hash.update(content);
  }
  
  return 'sha256:' + hash.digest('hex');
}

/**
 * Get all relevant files in a skill directory
 */
async function getSkillFiles(dir, files = []) {
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  
  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    
    // Skip hidden files, node_modules, etc.
    if (entry.name.startsWith('.') || 
        entry.name === 'node_modules' ||
        entry.name === 'package-lock.json') {
      continue;
    }
    
    if (entry.isDirectory()) {
      await getSkillFiles(fullPath, files);
    } else if (entry.isFile()) {
      files.push(fullPath);
    }
  }
  
  return files;
}

/**
 * Verify trust chain for a manifest
 */
export function verifyTrustChain(manifest, options = {}) {
  const result = {
    trustLevel: TRUST_LEVELS.SELF,
    trustScore: 0,
    verified: false,
    audits: [],
    warnings: [],
    chain: []
  };

  const trust = manifest?.trust;
  if (!trust) {
    result.warnings.push('No trust information in manifest');
    return result;
  }

  // Check author
  if (trust.author) {
    const authorInfo = resolveAuditor(trust.author);
    result.chain.push({
      entity: trust.author,
      role: 'author',
      level: authorInfo.level,
      name: authorInfo.name
    });
    result.trustScore += authorInfo.level;
  }

  // Check audits
  if (trust.audits && trust.audits.length > 0) {
    for (const audit of trust.audits) {
      const auditorInfo = resolveAuditor(audit.auditor);
      
      const auditResult = {
        auditor: audit.auditor,
        date: audit.date,
        scope: audit.scope || 'full',
        level: auditorInfo.level,
        name: auditorInfo.name,
        hashVerified: false
      };

      // Verify content hash if provided
      if (audit.contentHash && options.currentHash) {
        auditResult.hashVerified = audit.contentHash === options.currentHash;
        if (!auditResult.hashVerified) {
          result.warnings.push(
            `Content has changed since audit by ${audit.auditor} on ${audit.date}`
          );
        }
      }

      // Check audit freshness (warn if older than 6 months)
      if (audit.date) {
        const auditDate = new Date(audit.date);
        const monthsOld = (Date.now() - auditDate.getTime()) / (1000 * 60 * 60 * 24 * 30);
        if (monthsOld > 6) {
          result.warnings.push(
            `Audit by ${audit.auditor} is ${Math.floor(monthsOld)} months old`
          );
        }
      }

      result.audits.push(auditResult);
      result.chain.push({
        entity: audit.auditor,
        role: 'auditor',
        level: auditorInfo.level,
        name: auditorInfo.name,
        date: audit.date
      });

      // Use highest audit level
      if (auditorInfo.level > result.trustLevel) {
        result.trustLevel = auditorInfo.level;
      }
      result.trustScore += auditorInfo.level;
    }
  }

  // Check trust chain entries
  if (trust.chain && trust.chain.length > 0) {
    for (const entry of trust.chain) {
      const entryInfo = resolveAuditor(entry);
      result.chain.push({
        entity: entry,
        role: 'chain',
        level: entryInfo.level,
        name: entryInfo.name
      });
      
      if (entryInfo.level > result.trustLevel) {
        result.trustLevel = entryInfo.level;
      }
    }
  }

  // Check verified flag
  if (trust.verified) {
    result.verified = true;
    if (result.trustLevel < TRUST_LEVELS.REGISTRY) {
      result.warnings.push('Marked as verified but no registry audit found');
    }
  }

  return result;
}

/**
 * Resolve auditor/entity to trust level
 */
function resolveAuditor(auditor) {
  // Check known auditors
  if (KNOWN_AUDITORS[auditor]) {
    return KNOWN_AUDITORS[auditor];
  }

  // Parse auditor format
  const [type, name] = auditor.split(':');
  
  switch (type) {
    case 'clawdhub':
      return { level: TRUST_LEVELS.COMMUNITY, name: `ClawdHub user: ${name}` };
    case 'github':
      return { level: TRUST_LEVELS.COMMUNITY, name: `GitHub user: ${name}` };
    case 'org':
      return { level: TRUST_LEVELS.ORGANIZATION, name: `Organization: ${name}` };
    case 'user':
      return { level: TRUST_LEVELS.COMMUNITY, name: `User: ${name}` };
    default:
      return { level: TRUST_LEVELS.SELF, name: auditor };
  }
}

/**
 * Create an audit entry for signing
 */
export function createAuditEntry(options) {
  const { auditor, contentHash, scope = 'full', notes = '' } = options;
  
  return {
    auditor,
    date: new Date().toISOString().split('T')[0],
    contentHash,
    scope,
    notes
  };
}

/**
 * Format trust chain for display
 */
export function formatTrustChain(trustResult) {
  const lines = [];
  const levelNames = ['Self', 'Community', 'Organization', 'Registry', 'Official'];
  
  lines.push(`Trust Level: ${levelNames[trustResult.trustLevel]} (score: ${trustResult.trustScore})`);
  lines.push(`Verified: ${trustResult.verified ? '✅ Yes' : '❌ No'}`);
  
  if (trustResult.chain.length > 0) {
    lines.push('\nTrust Chain:');
    for (const entry of trustResult.chain) {
      const icon = entry.role === 'author' ? '👤' : 
                   entry.role === 'auditor' ? '🔍' : '🔗';
      const date = entry.date ? ` (${entry.date})` : '';
      lines.push(`  ${icon} ${entry.name}${date}`);
    }
  }
  
  if (trustResult.warnings.length > 0) {
    lines.push('\n⚠️ Warnings:');
    for (const warning of trustResult.warnings) {
      lines.push(`  - ${warning}`);
    }
  }
  
  return lines.join('\n');
}

export default { 
  verifyTrustChain, 
  calculateContentHash, 
  createAuditEntry,
  formatTrustChain,
  TRUST_LEVELS,
  KNOWN_AUDITORS
};
