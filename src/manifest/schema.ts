// @ts-nocheck
/**
 * Permission Manifest Schema
 * 
 * スキルが必要とする権限を宣言的に記述するフォーマット。
 * AgentVetでスキャン時に実際の挙動と照合し、未宣言の権限使用を検出。
 */

export const MANIFEST_VERSION = '1.0';

/**
 * Permission Manifest Schema (JSON Schema)
 */
export const manifestSchema = {
  $schema: 'http://json-schema.org/draft-07/schema#',
  type: 'object',
  required: ['version', 'permissions'],
  properties: {
    version: {
      type: 'string',
      description: 'Manifest schema version',
      enum: ['1.0']
    },
    name: {
      type: 'string',
      description: 'Skill name'
    },
    description: {
      type: 'string',
      description: 'What the skill does'
    },
    permissions: {
      type: 'object',
      description: 'Declared permissions',
      properties: {
        exec: {
          type: 'array',
          items: { type: 'string' },
          description: 'Allowed commands/binaries (e.g., ["npm", "git", "curl"])'
        },
        network: {
          type: 'array',
          items: { type: 'string' },
          description: 'Allowed network hosts (supports wildcards, e.g., ["api.github.com", "*.openai.com"])'
        },
        files: {
          type: 'array',
          items: { type: 'string' },
          description: 'File access patterns (e.g., ["read:./", "write:./output", "read:/etc/hosts"])'
        },
        tools: {
          type: 'array',
          items: { type: 'string' },
          description: 'Agent tools used (e.g., ["browser", "message", "exec"])'
        },
        secrets: {
          type: 'array',
          items: { type: 'string' },
          description: 'Required secrets/env vars (e.g., ["GITHUB_TOKEN", "OPENAI_API_KEY"])'
        },
        elevated: {
          type: 'boolean',
          description: 'Requires elevated/sudo permissions',
          default: false
        }
      },
      additionalProperties: false
    },
    trust: {
      type: 'object',
      description: 'Trust chain information',
      properties: {
        author: {
          type: 'string',
          description: 'Original author (e.g., "github:username", "clawdhub:username")'
        },
        audits: {
          type: 'array',
          items: {
            type: 'object',
            required: ['auditor', 'date', 'contentHash'],
            properties: {
              auditor: {
                type: 'string',
                description: 'Who audited (e.g., "user:john-doe", "org:acme-corp")'
              },
              date: {
                type: 'string',
                format: 'date',
                description: 'Audit date (ISO 8601)'
              },
              contentHash: {
                type: 'string',
                description: 'SHA-256 hash of audited content'
              },
              signature: {
                type: 'string',
                description: 'Optional cryptographic signature'
              },
              notes: {
                type: 'string',
                description: 'Audit notes/findings'
              },
              scope: {
                type: 'string',
                enum: ['full', 'partial', 'permissions-only'],
                description: 'Audit scope',
                default: 'full'
              }
            }
          }
        },
        chain: {
          type: 'array',
          items: { type: 'string' },
          description: 'Trust chain (e.g., ["clawdhub:verified", "forked-from:original-skill"])'
        },
        verified: {
          type: 'boolean',
          description: 'Verified by ClawdHub or trusted registry',
          default: false
        }
      }
    },
    risks: {
      type: 'object',
      description: 'Self-declared risks and mitigations',
      properties: {
        level: {
          type: 'string',
          enum: ['low', 'medium', 'high', 'critical'],
          description: 'Overall risk level'
        },
        notes: {
          type: 'array',
          items: { type: 'string' },
          description: 'Risk notes and mitigations'
        }
      }
    }
  },
  additionalProperties: false
};

/**
 * Example manifest for documentation
 */
export const exampleManifest = {
  version: '1.0',
  name: 'github-skill',
  description: 'Interact with GitHub using gh CLI',
  permissions: {
    exec: ['gh', 'git'],
    network: ['api.github.com', 'github.com'],
    files: ['read:./', 'write:.git/'],
    tools: ['exec', 'read', 'write'],
    secrets: ['GITHUB_TOKEN'],
    elevated: false
  },
  trust: {
    author: 'clawdhub:openclaw',
    audits: [
      {
        auditor: 'org:acme-corp',
        date: '2026-01-31',
        contentHash: 'sha256:abc123...',
        scope: 'full',
        notes: 'No malicious patterns found. Permissions match actual usage.'
      }
    ],
    chain: ['clawdhub:official', 'audited:acme-corp'],
    verified: true
  },
  risks: {
    level: 'medium',
    notes: [
      'Executes git commands - ensure repo is trusted',
      'Requires GITHUB_TOKEN with repo scope'
    ]
  }
};

export default manifestSchema;
