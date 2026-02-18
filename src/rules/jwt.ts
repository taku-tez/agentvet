/**
 * JWT Security Rules
 *
 * Detects insecure JWT implementation patterns:
 * - Algorithm confusion attacks (alg:none, HS256 vs RS256 confusion)
 * - Disabled signature verification
 * - Hardcoded signing secrets
 * - Missing expiration validation
 * - Insecure key management
 *
 * CWE-347: Improper Verification of Cryptographic Signature
 * CWE-345: Insufficient Verification of Data Authenticity
 */

import { Rule } from '../types.js';

export const rules: Rule[] = [
  // ============================================
  // Algorithm Confusion / None Algorithm
  // ============================================
  {
    id: 'jwt-alg-none',
    name: 'JWT Algorithm None',
    description: 'JWT configured with "none" algorithm, allowing unsigned tokens',
    severity: 'critical',
    pattern: /(?:algorithm|alg)[\s]*[:=]\s*['"`]none['"`]/gi,
    category: 'jwt',
    tags: ['jwt', 'auth', 'crypto'],
    cwe: 'CWE-347',
    recommendation: 'Never allow the "none" algorithm. Use RS256 or ES256 for asymmetric, or HS256 with a strong secret for symmetric signing.',
  },
  {
    id: 'jwt-algorithms-none-array',
    name: 'JWT Algorithms Array Includes None',
    description: 'JWT verification accepts "none" in algorithms list',
    severity: 'critical',
    pattern: /algorithms\s*:\s*\[(?:[^\]]*['"`]none['"`][^\]]*)\]/gi,
    category: 'jwt',
    tags: ['jwt', 'auth', 'crypto'],
    cwe: 'CWE-347',
    recommendation: 'Remove "none" from the accepted algorithms list. Explicitly whitelist only the expected algorithm.',
  },

  // ============================================
  // Disabled Verification
  // ============================================
  {
    id: 'jwt-verify-disabled',
    name: 'JWT Verification Disabled',
    description: 'JWT signature verification is explicitly disabled',
    severity: 'critical',
    pattern: /(?:verify|verification|validate_signature|verify_signature)\s*[:=]\s*(?:false|False|FALSE|0|nil|None)/g,
    category: 'jwt',
    tags: ['jwt', 'auth', 'crypto'],
    cwe: 'CWE-345',
    recommendation: 'Always verify JWT signatures. Never disable verification even in development.',
    falsePositiveCheck: (match, content) => {
      // Only flag if JWT-related context nearby
      const idx = content.indexOf(match[0]);
      const context = content.slice(Math.max(0, idx - 200), idx + 200);
      return !(/jwt|token|auth|sign/i.test(context));
    },
  },
  {
    id: 'jwt-decode-unverified',
    name: 'JWT Unverified Decode',
    description: 'Using jwt.decode() which does not verify signatures - may process untrusted data',
    severity: 'medium',
    pattern: /jwt\.decode\s*\(\s*(?:token|req\.|request\.|params|body|input|data|payload)/g,
    category: 'jwt',
    tags: ['jwt', 'auth'],
    cwe: 'CWE-345',
    recommendation: 'Use jwt.verify() for untrusted tokens. jwt.decode() should only be used for inspecting trusted tokens.',
  },

  // ============================================
  // Weak Secrets
  // ============================================
  {
    id: 'jwt-hardcoded-secret',
    name: 'JWT Hardcoded Secret',
    description: 'JWT signing with a hardcoded secret string',
    severity: 'high',
    pattern: /jwt\.sign\s*\([^,]+,\s*['"`][^'"`]{1,64}['"`]/g,
    category: 'jwt',
    tags: ['jwt', 'auth', 'secrets'],
    cwe: 'CWE-798',
    recommendation: 'Load JWT signing secrets from environment variables or a secrets manager. Never hardcode them.',
  },
  {
    id: 'jwt-weak-secret-keyword',
    name: 'JWT Weak Secret Keyword',
    description: 'JWT secret uses a common weak value (secret, password, key, etc.)',
    severity: 'high',
    pattern: /(?:jwt_secret|JWT_SECRET|token_secret|signing_key)\s*[:=]\s*['"`](?:secret|password|key|changeme|test|default|1234|admin)['"`]/gi,
    category: 'jwt',
    tags: ['jwt', 'auth', 'secrets'],
    cwe: 'CWE-521',
    recommendation: 'Use a cryptographically random secret of at least 256 bits for HMAC-based JWT signing.',
  },

  // ============================================
  // Missing Expiration
  // ============================================
  {
    id: 'jwt-no-expiration',
    name: 'JWT No Expiration',
    description: 'JWT signed without expiration (expiresIn/exp), tokens never expire',
    severity: 'medium',
    pattern: /jwt\.sign\s*\(\s*\{(?:(?!exp[ir'"`:])[\s\S]){0,200}\}\s*,\s*[^,]+\s*\)/g,
    category: 'jwt',
    tags: ['jwt', 'auth'],
    cwe: 'CWE-613',
    recommendation: 'Always set an expiration (expiresIn or exp claim) on JWT tokens to limit their validity window.',
    falsePositiveCheck: (match, content) => {
      // Check if expiresIn is passed as third options argument
      const idx = content.indexOf(match[0]);
      const after = content.slice(idx, idx + match[0].length + 100);
      return /expiresIn|exp/.test(after);
    },
  },

  // ============================================
  // Algorithm Confusion Attack (RS256 → HS256)
  // ============================================
  {
    id: 'jwt-alg-confusion-risk',
    name: 'JWT Algorithm Confusion Risk',
    description: 'JWT verification uses public key with multiple algorithms - potential algorithm confusion attack',
    severity: 'high',
    pattern: /jwt\.verify\s*\([^,]+,\s*(?:publicKey|pub_key|public_key|rsaPublic|cert)[^,]*,\s*\{[^}]*algorithms\s*:\s*\[[^\]]*(?:HS256|HS384|HS512)/gi,
    category: 'jwt',
    tags: ['jwt', 'auth', 'crypto'],
    cwe: 'CWE-347',
    recommendation: 'When verifying with a public key, only allow asymmetric algorithms (RS256, ES256). Never mix HMAC algorithms with public key verification.',
  },

  // ============================================
  // Insecure JWT Libraries / Patterns
  // ============================================
  {
    id: 'jwt-kid-injection',
    name: 'JWT KID Injection Risk',
    description: 'JWT key ID (kid) used in file path or SQL query - potential injection vector',
    severity: 'high',
    pattern: /(?:header|decoded)(?:\.|(?:\[['"`]))kid(?:['"`]\])?\s*[\s\S]{0,30}(?:readFile|readFileSync|path\.join|path\.resolve|SELECT|query|exec|open\()/g,
    category: 'jwt',
    tags: ['jwt', 'injection'],
    cwe: 'CWE-20',
    recommendation: 'Validate and sanitize the JWT kid header before using it in file operations or database queries.',
  },
  {
    id: 'jwt-jku-jws-url',
    name: 'JWT JKU/X5U URL Injection',
    description: 'JWT header JKU or X5U URL used without validation - allows attacker-controlled key servers',
    severity: 'high',
    pattern: /(?:header|decoded)(?:\.|(?:\[['"`]))(?:jku|x5u)(?:['"`]\])?\s*[\s\S]{0,30}(?:fetch|request|axios|got|http\.get|urllib)/g,
    category: 'jwt',
    tags: ['jwt', 'ssrf', 'injection'],
    cwe: 'CWE-918',
    recommendation: 'Validate JKU/X5U URLs against an allowlist of trusted key servers. Never fetch keys from arbitrary URLs.',
  },

  // ============================================
  // PyJWT / python-jose specifics
  // ============================================
  {
    id: 'jwt-python-no-algorithms',
    name: 'PyJWT Decode Without Algorithm Specification',
    description: 'PyJWT decode() called without specifying algorithms parameter',
    severity: 'high',
    pattern: /jwt\.decode\s*\([^)]*\)\s*(?!.*algorithms)/g,
    category: 'jwt',
    tags: ['jwt', 'auth', 'python'],
    cwe: 'CWE-347',
    recommendation: 'Always specify the algorithms parameter in jwt.decode() to prevent algorithm confusion attacks.',
    falsePositiveCheck: (match, content) => {
      // Check if algorithms is on the same or next line
      const idx = content.indexOf(match[0]);
      const context = content.slice(idx, idx + match[0].length + 100);
      return /algorithms\s*=/.test(context);
    },
  },

  // ============================================
  // Token Exposure
  // ============================================
  {
    id: 'jwt-token-in-url',
    name: 'JWT Token in URL Parameter',
    description: 'JWT token passed as URL query parameter, exposing it in logs and browser history',
    severity: 'medium',
    pattern: /(?:url|href|redirect|location|window\.location|fetch|axios\.get|request)\s*(?:=|\()\s*['"`][^'"`]*[?&](?:token|jwt|access_token|auth_token)=/gi,
    category: 'jwt',
    tags: ['jwt', 'auth', 'exposure'],
    cwe: 'CWE-598',
    recommendation: 'Pass JWT tokens in the Authorization header instead of URL parameters to prevent exposure in logs and history.',
  },
  {
    id: 'jwt-token-in-log',
    name: 'JWT Token Logged',
    description: 'JWT token value potentially written to logs',
    severity: 'medium',
    pattern: /(?:console\.log|logger\.(?:info|debug|warn|error|log)|logging\.(?:info|debug|warn|error)|log\.(?:info|debug|warn|error)|print)\s*\([^)]*(?:token|jwt|authorization|bearer)/gi,
    category: 'jwt',
    tags: ['jwt', 'auth', 'exposure'],
    cwe: 'CWE-532',
    recommendation: 'Never log JWT tokens or authorization headers. Mask or redact sensitive values before logging.',
    falsePositiveCheck: (match, content) => {
      // Allow if it's clearly about a token name/type, not value
      return /token_type|token_name|tokenizer|jwt_config|jwt_issuer/.test(match[0]);
    },
  },
];

module.exports = { rules };
