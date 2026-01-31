/**
 * Permission Manifest Module
 * 
 * スキルの権限宣言（Permission Manifest）と信頼チェーン（Trust Chain）を管理。
 */

export { manifestSchema, exampleManifest, MANIFEST_VERSION } from './schema.js';
export { validateManifest, comparePermissions, generateManifest } from './validator.js';
export { 
  verifyTrustChain, 
  calculateContentHash, 
  createAuditEntry,
  formatTrustChain,
  TRUST_LEVELS,
  KNOWN_AUDITORS
} from './trust.js';

/**
 * Load manifest from skill directory
 */
import fs from 'fs';
import path from 'path';
import yaml from 'yaml';

export function loadManifest(skillPath) {
  // Try multiple manifest file locations
  const manifestFiles = [
    'agentvet.manifest.json',
    'agentvet.manifest.yaml',
    'agentvet.manifest.yml',
    'manifest.json',
    '.agentvet/manifest.json'
  ];

  for (const file of manifestFiles) {
    const fullPath = path.join(skillPath, file);
    if (fs.existsSync(fullPath)) {
      const content = fs.readFileSync(fullPath, 'utf-8');
      if (file.endsWith('.yaml') || file.endsWith('.yml')) {
        return { manifest: yaml.parse(content), path: fullPath };
      }
      return { manifest: JSON.parse(content), path: fullPath };
    }
  }

  return { manifest: null, path: null };
}

/**
 * Save manifest to skill directory
 */
export function saveManifest(skillPath, manifest, format = 'json') {
  const filename = format === 'yaml' 
    ? 'agentvet.manifest.yaml' 
    : 'agentvet.manifest.json';
  const fullPath = path.join(skillPath, filename);
  
  const content = format === 'yaml'
    ? yaml.stringify(manifest, { indent: 2 })
    : JSON.stringify(manifest, null, 2);
  
  fs.writeFileSync(fullPath, content);
  return fullPath;
}

export default {
  loadManifest,
  saveManifest
};
