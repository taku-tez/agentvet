/**
 * Trust Chain Verification
 * 
 * スキルの信頼チェーンを追跡・検証する。
 * 誰が作成し、誰が監査し、どのレジストリで検証されたかを追跡。
 */

import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import type { PermissionManifest, ManifestAudit } from './schema.js';

/**
 * Trust levels for auditors/sources
 */
export const TRUST_LEVELS = {
  SELF: 0,
  COMMUNITY: 1,
  ORGANIZATION: 2,
  REGISTRY: 3,
  OFFICIAL: 4
} as const;

export type TrustLevel = typeof TRUST_LEVELS[keyof typeof TRUST_LEVELS];

export interface AuditorInfo {
  level: TrustLevel;
  name: string;
}

/**
 * Known trusted auditors/registries
 */
export const KNOWN_AUDITORS: Record<string, AuditorInfo> = {
  'clawdhub:official': { level: TRUST_LEVELS.OFFICIAL, name: 'ClawdHub Official' },
  'clawdhub:verified': { level: TRUST_LEVELS.REGISTRY, name: 'ClawdHub Verified' },
  'org:openclaw': { level: TRUST_LEVELS.ORGANIZATION, name: 'OpenClaw Team' },
  'org:acme-corp': { level: TRUST_LEVELS.ORGANIZATION, name: 'Acme Corp.' },
};

export interface ChainEntry {
  entity: string;
  role: 'author' | 'auditor' | 'chain';
  level: TrustLevel;
  name: string;
  date?: string;
}

export interface AuditResult {
  auditor: string;
  date: string;
  scope: string;
  level: TrustLevel;
  name: string;
  hashVerified: boolean;
}

export interface TrustVerificationResult {
  trustLevel: TrustLevel;
  trustScore: number;
  verified: boolean;
  audits: AuditResult[];
  warnings: string[];
  chain: ChainEntry[];
}

export interface VerifyOptions {
  currentHash?: string;
}

export interface CreateAuditOptions {
  auditor: string;
  contentHash: string;
  scope?: 'full' | 'partial' | 'permissions-only';
  notes?: string;
}

/**
 * Calculate content hash for a skill directory
 */
export async function calculateContentHash(skillPath: string): Promise<string> {
  const hash = crypto.createHash('sha256');
  const files = await getSkillFiles(skillPath);
  
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
async function getSkillFiles(dir: string, files: string[] = []): Promise<string[]> {
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  
  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    
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
export function verifyTrustChain(manifest: PermissionManifest | null, options: VerifyOptions = {}): TrustVerificationResult {
  const result: TrustVerificationResult = {
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
      
      const auditResult: AuditResult = {
        auditor: audit.auditor,
        date: audit.date,
        scope: audit.scope || 'full',
        level: auditorInfo.level,
        name: auditorInfo.name,
        hashVerified: false
      };

      if (audit.contentHash && options.currentHash) {
        auditResult.hashVerified = audit.contentHash === options.currentHash;
        if (!auditResult.hashVerified) {
          result.warnings.push(
            `Content has changed since audit by ${audit.auditor} on ${audit.date}`
          );
        }
      }

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
function resolveAuditor(auditor: string): AuditorInfo {
  if (KNOWN_AUDITORS[auditor]) {
    return KNOWN_AUDITORS[auditor];
  }

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
export function createAuditEntry(options: CreateAuditOptions): ManifestAudit {
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
export function formatTrustChain(trustResult: TrustVerificationResult): string {
  const lines: string[] = [];
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
