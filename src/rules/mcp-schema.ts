import type { Rule } from "../types.js";

/**
 * MCP Tool Input Schema Security Rules
 * Detects vulnerabilities in MCP tool inputSchema definitions
 * Based on OWASP API Security Top 10 2023 principles applied to MCP
 *
 * Key insight: MCP tools with unsafe input schemas can be exploited
 * through prompt injection → schema manipulation → backend attack chains
 */

// Input Schema Injection Patterns
// Detect tool schemas that accept dangerous input types without validation
const schemaInjectionRules: Rule[] = [
  {
    id: 'mcp-schema-path-traversal',
    severity: 'critical',
    description: 'MCP tool accepts file paths without validation (path traversal risk)',
    pattern: /"(?:inputSchema|parameters)"[\s\S]{0,300}?"(?:file_?path|path|filename|directory|folder|dir)"[\s\S]{0,100}?"type"\s*:\s*"string"(?![\s\S]{0,200}(?:pattern|enum|const))/gi,
    recommendation: 'Add path validation: use "pattern" to restrict to safe directories (e.g., "^/home/user/workspace/"), or use "enum" for allowed paths.',
    cwe: 'CWE-22',
  },
  {
    id: 'mcp-schema-shell-injection',
    severity: 'critical',
    description: 'MCP tool accepts command/shell arguments without restrictions',
    pattern: /"(?:inputSchema|parameters)"[\s\S]{0,300}?"(?:command|cmd|shell|exec|args|arguments|script)"[\s\S]{0,100}?"type"\s*:\s*"string"(?![\s\S]{0,200}(?:pattern|enum|const|maxLength))/gi,
    recommendation: 'Never accept arbitrary commands. Use "enum" for allowed commands or implement server-side command whitelist.',
    cwe: 'CWE-78',
  },
  {
    id: 'mcp-schema-ssrf-url',
    severity: 'high',
    description: 'MCP tool accepts URLs without validation (SSRF risk)',
    pattern: /"(?:inputSchema|parameters)"[\s\S]{0,300}?"(?:url|uri|endpoint|href|link|target_url|webhook)"[\s\S]{0,100}?"type"\s*:\s*"string"(?![\s\S]{0,200}(?:pattern|enum|const|format.*uri))/gi,
    recommendation: 'Add URL validation: use "format": "uri" and "pattern" to restrict to allowed domains. Implement server-side SSRF protection.',
    cwe: 'CWE-918',
  },
  {
    id: 'mcp-schema-sql-injection',
    severity: 'critical',
    description: 'MCP tool accepts raw SQL or query strings',
    pattern: /"(?:inputSchema|parameters)"[\s\S]{0,300}?"(?:query|sql|statement|filter|where|condition)"[\s\S]{0,100}?"type"\s*:\s*"string"(?![\s\S]{0,200}(?:pattern|enum|const))/gi,
    recommendation: 'Never accept raw SQL. Use parameterized queries on server-side. If filtering is needed, use "enum" for allowed field names.',
    cwe: 'CWE-89',
  },
  {
    id: 'mcp-schema-code-injection',
    severity: 'critical',
    description: 'MCP tool accepts code/expression strings for evaluation',
    pattern: /"(?:inputSchema|parameters)"[\s\S]{0,300}?"(?:code|expression|eval|script|formula|javascript|python)"[\s\S]{0,100}?"type"\s*:\s*"string"/gi,
    recommendation: 'Avoid accepting code for evaluation. If necessary, use a sandboxed interpreter with strict limits.',
    cwe: 'CWE-94',
  },
];

// Schema Validation Weakness Patterns
const schemaValidationRules: Rule[] = [
  // NOTE: Detecting missing "required" via regex is unreliable due to JSON nesting.
  // This rule is moved to static analysis phase (TODO: implement AST-based check)
  {
    id: 'mcp-schema-missing-additionalProperties',
    severity: 'warning',
    description: 'MCP tool allows additional unvalidated properties',
    pattern: /"inputSchema"\s*:\s*\{[^}]*"properties"\s*:\s*\{[^}]+\}(?![^}]*"additionalProperties"\s*:\s*false)/gi,
    recommendation: 'Set "additionalProperties": false to prevent injection of unexpected parameters.',
  },
  {
    id: 'mcp-schema-unbounded-string',
    severity: 'warning',
    description: 'String input without maxLength constraint',
    pattern: /"type"\s*:\s*"string"(?![^}]{0,150}(?:"maxLength"|"enum"|"const"|"pattern"))/gi,
    recommendation: 'Add "maxLength" to string inputs to prevent memory exhaustion and injection attacks.',
  },
  {
    id: 'mcp-schema-unbounded-array',
    severity: 'warning',
    description: 'Array input without maxItems constraint',
    pattern: /"type"\s*:\s*"array"(?![^}]{0,150}"maxItems")/gi,
    recommendation: 'Add "maxItems" to array inputs to prevent memory exhaustion attacks.',
  },
  {
    id: 'mcp-schema-unbounded-number',
    severity: 'low',
    description: 'Number input without min/max constraints',
    pattern: /"type"\s*:\s*"(?:number|integer)"(?![^}]{0,100}(?:"minimum"|"maximum"))/gi,
    recommendation: 'Consider adding "minimum" and "maximum" to numeric inputs for defense in depth.',
  },
];

// Dangerous Default Values
const schemaDefaultRules: Rule[] = [
  {
    id: 'mcp-schema-dangerous-default-path',
    severity: 'high',
    description: 'MCP tool has dangerous default path value',
    pattern: /"default"\s*:\s*"(?:\/etc\/|\/var\/|\/root\/|\/home\/|~\/|\.\.\/|\$HOME|%USERPROFILE%)/gi,
    recommendation: 'Avoid defaulting to system directories. Use workspace-relative paths.',
  },
  {
    id: 'mcp-schema-dangerous-default-url',
    severity: 'high',
    description: 'MCP tool has default URL pointing to internal/metadata endpoint',
    pattern: /"default"\s*:\s*"https?:\/\/(?:169\.254\.|localhost|127\.0\.0\.1|0\.0\.0\.0|metadata|internal|\.local)/gi,
    recommendation: 'Default URLs should not point to internal services or cloud metadata endpoints.',
  },
  {
    id: 'mcp-schema-default-wildcard',
    severity: 'warning',
    description: 'MCP tool has overly permissive default value',
    pattern: /"default"\s*:\s*"(?:\*|\.\*|all|any|true|enabled|admin|root)"/gi,
    recommendation: 'Defaults should be restrictive. Apply principle of least privilege.',
  },
];

// Schema Type Confusion
const schemaTypeRules: Rule[] = [
  {
    id: 'mcp-schema-any-type',
    severity: 'warning',
    description: 'MCP tool input accepts any type (no type constraint)',
    pattern: /"(?:inputSchema|parameters)"[\s\S]{0,200}?"[a-zA-Z_]+"\s*:\s*\{\s*(?!"type")[^}]*\}/gi,
    recommendation: 'Always specify "type" for each property to prevent type confusion attacks.',
  },
  {
    id: 'mcp-schema-object-without-properties',
    severity: 'warning',
    description: 'Object type without defined properties',
    pattern: /"type"\s*:\s*"object"(?![^}]{0,100}"properties")/gi,
    recommendation: 'Define "properties" for object types to validate structure.',
  },
];

// Sensitive Data in Schema
const schemaSensitiveRules: Rule[] = [
  {
    id: 'mcp-schema-password-input',
    severity: 'warning',
    description: 'MCP tool accepts password as input',
    pattern: /"(?:inputSchema|parameters)"[\s\S]{0,300}?"(?:password|passwd|pwd|secret|api_?key|token|credential)"\s*:/gi,
    recommendation: 'Avoid accepting secrets as tool inputs. Use environment variables or secure credential stores instead.',
  },
  {
    id: 'mcp-schema-pii-collection',
    severity: 'warning',
    description: 'MCP tool may collect personally identifiable information',
    pattern: /"(?:inputSchema|parameters)"[\s\S]{0,300}?"(?:ssn|social_?security|credit_?card|card_?number|cvv|passport|license_?number|national_?id)"\s*:/gi,
    recommendation: 'PII collection through MCP tools requires careful handling. Ensure compliance with data protection regulations.',
  },
];

// Export all rules
export const rules: Rule[] = [
  ...schemaInjectionRules,
  ...schemaValidationRules,
  ...schemaDefaultRules,
  ...schemaTypeRules,
  ...schemaSensitiveRules,
];

// CommonJS compatibility
module.exports = { rules };
