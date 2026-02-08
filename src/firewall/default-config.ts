/**
 * Default Firewall Configuration
 */

import { FirewallConfig } from './types.js';

export const DEFAULT_FIREWALL_CONFIG: FirewallConfig = {
  version: '1.0',
  name: 'default',
  description: 'AgentVet Prompt Firewall - Default Configuration',

  inbound: {
    enabled: true,
    action: 'block',
    categories: ['instruction_override', 'prompt_extraction', 'role_hijack', 'data_exfiltration', 'evasion'],
  },

  outbound: {
    enabled: true,
    action: 'block',
    categories: ['tool_manipulation', 'steganography', 'delimiter', 'data_exfiltration'],
  },

  context_protection: {
    enabled: true,
    action: 'block',
  },

  audit: {
    enabled: true,
    file: 'firewall-audit.log',
    format: 'json',
    include_content: false,
  },

  thresholds: {
    block: 30,
    warn: 15,
  },
};

export const DEFAULT_FIREWALL_YAML = `# AgentVet Prompt Firewall Configuration
version: "1.0"
name: default
description: AgentVet Prompt Firewall - Default Configuration

inbound:
  enabled: true
  action: block
  categories:
    - instruction_override
    - prompt_extraction
    - role_hijack
    - data_exfiltration
    - evasion

outbound:
  enabled: true
  action: block
  categories:
    - tool_manipulation
    - steganography
    - delimiter
    - data_exfiltration

context_protection:
  enabled: true
  action: block
  # canary_token: "CANARY-xxxx-yyyy"

custom_patterns: []
#  - id: CUSTOM001
#    description: Block specific phrase
#    pattern: "some dangerous pattern"
#    category: custom
#    severity: high
#    direction: both
#    action: block

audit:
  enabled: true
  file: firewall-audit.log
  format: json
  include_content: false

thresholds:
  block: 30
  warn: 15
`;
