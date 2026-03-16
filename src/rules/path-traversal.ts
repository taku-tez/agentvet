import type { Rule } from "../types.js";

/**
 * Path Traversal & Unsafe File Operation Rules
 * Detects configurations and code patterns where agents can access
 * arbitrary file system paths, potentially reading/writing sensitive
 * files outside their intended sandbox.
 *
 * Attack vector: An agent receives a crafted file path (e.g., from user
 * input or tool output) containing traversal sequences like "../" or
 * absolute paths targeting sensitive system files.
 *
 * References:
 * - CWE-22: Improper Limitation of a Pathname to a Restricted Directory
 * - CWE-73: External Control of File Name or Path
 * - OWASP Path Traversal
 */

export const rules: Rule[] = [
  // ── Direct path traversal patterns ────────────────────────────
  {
    id: 'path-traversal-dot-dot-sequence',
    severity: 'critical',
    description: 'Path traversal sequence (../) detected in file path or configuration',
    pattern: /(?:file_?path|read_file|write_file|save_(?:to|path|file)|output_(?:path|file|dir)|upload_(?:path|to)|download_(?:path|to)|load_(?:from|path|file))\s*[:=]\s*["']?[^"'\s]*(?:\.\.\/|\.\.\\){2,}[^"'\s]*/gi,
    recommendation: 'CRITICAL: Path traversal detected. Validate and canonicalize all file paths. Use path.resolve() and verify the result is within the allowed directory.',
    cwe: 'CWE-22',
  },

  // ── Sensitive system file access ──────────────────────────────
  {
    id: 'path-traversal-sensitive-file-access',
    severity: 'critical',
    description: 'Agent configured with access to sensitive system files',
    pattern: /(?:file_?path|read_file|write_file|allowed_paths?|include_paths?|watch_paths?)\s*[:=]\s*[^,\n]*?(?:\/etc\/(?:passwd|shadow|sudoers|ssh)|\/root\/|\/proc\/|\/sys\/|~\/\.ssh|~\/\.aws|~\/\.gnupg|~\/\.config\/(?:gh|gcloud)|C:\\Windows\\System32|C:\\Users\\[^\\]+\\\.ssh)/gi,
    recommendation: 'CRITICAL: Agent should not have access to sensitive system files. Restrict file access to the project working directory only.',
    cwe: 'CWE-22',
  },

  // ── Unrestricted file system access ───────────────────────────
  {
    id: 'path-traversal-unrestricted-fs-access',
    severity: 'critical',
    description: 'Agent configured with unrestricted file system access (root or wildcard paths)',
    pattern: /(?:allowed_paths?|accessible_paths?|file_access|fs_access|read_access|write_access)\s*[:=]\s*(?:\[?\s*["']?(?:\/["'\s\],]|~["'\s\],]|\*["'\s\],])|["'](?:all|any|unrestricted|full)["'])/gi,
    recommendation: 'CRITICAL: Restrict agent file access to specific directories. Never allow root (/) or wildcard (*) path access.',
    cwe: 'CWE-22',
  },

  // ── Unsanitized path concatenation ────────────────────────────
  {
    id: 'path-traversal-unsanitized-concat',
    severity: 'warning',
    description: 'File path constructed from user/agent input without sanitization',
    pattern: /(?:path\.join|path\.resolve|os\.path\.join|Path\()\s*\(\s*(?:base_?(?:dir|path)|root_?(?:dir|path)|upload_?dir)\s*,\s*(?:user_?input|request\.|params?\.|args?\.|input\.|body\.|query\.)/gi,
    recommendation: 'Sanitize file paths constructed from external input. After path.join(), verify the result starts with the intended base directory using path.resolve() comparison.',
    cwe: 'CWE-73',
  },

  // ── Symlink following without check ───────────────────────────
  {
    id: 'path-traversal-symlink-follow',
    severity: 'warning',
    description: 'File operations that follow symlinks without validation (symlink attack vector)',
    pattern: /(?:follow_?symlinks?\s*[:=]\s*(?:true|yes|on|1)|resolve_?symlinks?\s*[:=]\s*(?:true|yes|on|1)|no_?follow\s*[:=]\s*(?:false|no|off|0))/gi,
    recommendation: 'Disable symlink following or validate the resolved path is within the allowed directory to prevent symlink-based path traversal.',
    cwe: 'CWE-59',
  },

  // ── Temp file creation in shared directories ──────────────────
  {
    id: 'path-traversal-shared-temp-dir',
    severity: 'warning',
    description: 'Agent using shared temporary directory without unique subdirectory',
    pattern: /(?:temp_?(?:dir|path|folder)|tmp_?(?:dir|path|folder)|work_?dir)\s*[:=]\s*["']?(?:\/tmp|\/var\/tmp|C:\\(?:Windows\\)?Temp)["']?\s*(?:[,;\n]|$)/gi,
    recommendation: 'Use a unique subdirectory within /tmp (e.g., mkdtemp) to prevent symlink attacks and file race conditions in shared temp directories.',
    cwe: 'CWE-377',
  },

  // ── Writing to system/startup paths ───────────────────────────
  {
    id: 'path-traversal-write-system-path',
    severity: 'critical',
    description: 'Agent configured to write to system or startup paths',
    pattern: /(?:write_(?:to|path|dir)|output_(?:path|dir)|save_(?:to|path))\s*[:=]\s*["']?(?:\/usr\/(?:bin|sbin|lib|local)|\/(?:bin|sbin)|\/etc\/(?:cron|init|systemd|profile)|~\/\.(?:bashrc|profile|zshrc|bash_profile)|~\/\.config\/autostart|C:\\(?:Windows|Program\s*Files))/gi,
    recommendation: 'CRITICAL: Agent should not write to system paths or startup directories. This enables persistence attacks.',
    cwe: 'CWE-22',
  },

  // ── Null byte injection in file paths ─────────────────────────
  {
    id: 'path-traversal-null-byte',
    severity: 'critical',
    description: 'Null byte in file path (null byte injection for path truncation)',
    pattern: /(?:file_?(?:path|name)|path)\s*[:=]\s*["'][^"']*(?:%00|\\x00|\\0|\\u0000)[^"']*["']/gi,
    recommendation: 'CRITICAL: Null bytes in file paths can truncate the path and bypass extension checks. Strip null bytes from all file path inputs.',
    cwe: 'CWE-158',
  },

  // ── Path with encoded traversal ───────────────────────────────
  {
    id: 'path-traversal-encoded-sequence',
    severity: 'critical',
    description: 'URL-encoded or double-encoded path traversal sequence',
    pattern: /(?:%2e%2e%2f|%2e%2e\/|\.\.%2f|%2e%2e%5c|%252e%252e%252f|\.\.%255c|%c0%ae%c0%ae%c0%af|\.\.%c0%af)/gi,
    recommendation: 'CRITICAL: Encoded path traversal detected. Decode all path components before validation, and reject paths containing traversal sequences.',
    cwe: 'CWE-22',
  },
];

// CommonJS compatibility
module.exports = { rules };
