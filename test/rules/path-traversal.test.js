/**
 * Path Traversal & Unsafe File Operation Rules Tests
 */

const { describe, test } = require('node:test');
const assert = require('node:assert');
const { rules } = require('../../dist/rules/path-traversal.js');

function testRule(ruleId, text, shouldMatch) {
  const rule = rules.find(r => r.id === ruleId);
  assert.ok(rule, `Rule ${ruleId} not found`);
  const pattern = new RegExp(rule.pattern.source, rule.pattern.flags);
  const matched = pattern.test(text);
  assert.strictEqual(matched, shouldMatch,
    `Rule ${ruleId}: expected ${shouldMatch ? 'match' : 'no match'} for: ${text.substring(0, 80)}`);
}

describe('Path Traversal Rules', () => {
  // Path traversal dot-dot sequences
  describe('path-traversal-dot-dot-sequence', () => {
    test('detect deep traversal in file_path', () => testRule('path-traversal-dot-dot-sequence', 'file_path = "../../etc/passwd"', true));
    test('detect traversal in read_file', () => testRule('path-traversal-dot-dot-sequence', 'read_file: "../../../etc/shadow"', true));
    test('detect traversal in save_path', () => testRule('path-traversal-dot-dot-sequence', 'save_path = "../../root/.ssh/id_rsa"', true));
    test('detect traversal in output_path', () => testRule('path-traversal-dot-dot-sequence', 'output_path: "../../var/log/auth.log"', true));
    test('no match for normal relative path', () => testRule('path-traversal-dot-dot-sequence', 'file_path = "./data/output.json"', false));
  });

  // Sensitive file access
  describe('path-traversal-sensitive-file-access', () => {
    test('detect /etc/passwd access', () => testRule('path-traversal-sensitive-file-access', 'read_file: "/etc/passwd"', true));
    test('detect /etc/shadow access', () => testRule('path-traversal-sensitive-file-access', 'file_path = "/etc/shadow"', true));
    test('detect ~/.ssh access', () => testRule('path-traversal-sensitive-file-access', 'allowed_paths: ["~/.ssh"]', true));
    test('detect ~/.aws access', () => testRule('path-traversal-sensitive-file-access', 'read_file = "~/.aws"', true));
    test('detect /root/ access', () => testRule('path-traversal-sensitive-file-access', 'file_path: "/root/secrets"', true));
    test('detect /proc/ access', () => testRule('path-traversal-sensitive-file-access', 'read_file: "/proc/self/environ"', true));
    test('no match for project file', () => testRule('path-traversal-sensitive-file-access', 'read_file: "./src/index.ts"', false));
  });

  // Unrestricted FS access
  describe('path-traversal-unrestricted-fs-access', () => {
    test('detect root path access', () => testRule('path-traversal-unrestricted-fs-access', 'allowed_paths: ["/"]', true));
    test('detect wildcard path access', () => testRule('path-traversal-unrestricted-fs-access', 'allowed_paths = "*"', true));
    test('detect unrestricted string', () => testRule('path-traversal-unrestricted-fs-access', 'file_access: "unrestricted"', true));
    test('detect full access', () => testRule('path-traversal-unrestricted-fs-access', 'fs_access = "full"', true));
    test('no match for specific path', () => testRule('path-traversal-unrestricted-fs-access', 'allowed_paths: ["/app/data"]', false));
  });

  // Unsanitized path concat
  describe('path-traversal-unsanitized-concat', () => {
    test('detect path.join with user_input', () => testRule('path-traversal-unsanitized-concat', 'path.join(base_dir, user_input)', true));
    test('detect path.resolve with request', () => testRule('path-traversal-unsanitized-concat', 'path.resolve(root_dir, request.filename)', true));
    test('detect os.path.join with params', () => testRule('path-traversal-unsanitized-concat', 'os.path.join(upload_dir, params.file)', true));
    test('no match for static paths', () => testRule('path-traversal-unsanitized-concat', 'path.join(base_dir, "static", "index.html")', false));
  });

  // Symlink following
  describe('path-traversal-symlink-follow', () => {
    test('detect follow_symlinks true', () => testRule('path-traversal-symlink-follow', 'follow_symlinks: true', true));
    test('detect resolve_symlinks true', () => testRule('path-traversal-symlink-follow', 'resolve_symlinks = true', true));
    test('detect no_follow false', () => testRule('path-traversal-symlink-follow', 'no_follow: false', true));
    test('no match for follow_symlinks false', () => testRule('path-traversal-symlink-follow', 'follow_symlinks: false', false));
  });

  // Shared temp dir
  describe('path-traversal-shared-temp-dir', () => {
    test('detect /tmp as temp_dir', () => testRule('path-traversal-shared-temp-dir', 'temp_dir: "/tmp"\n', true));
    test('detect /var/tmp as tmp_path', () => testRule('path-traversal-shared-temp-dir', 'tmp_path = "/var/tmp"\n', true));
    test('no match for unique tmp subdir', () => testRule('path-traversal-shared-temp-dir', 'temp_dir = "/tmp/agentvet-abc123"', false));
  });

  // Write to system paths
  describe('path-traversal-write-system-path', () => {
    test('detect write to /usr/bin', () => testRule('path-traversal-write-system-path', 'write_to: "/usr/bin/agent"', true));
    test('detect write to /etc/cron', () => testRule('path-traversal-write-system-path', 'output_path = "/etc/cron.d/agent"', true));
    test('detect write to ~/.bashrc', () => testRule('path-traversal-write-system-path', 'save_to: "~/.bashrc"', true));
    test('detect write to /etc/systemd', () => testRule('path-traversal-write-system-path', 'write_path: "/etc/systemd/system/agent.service"', true));
    test('no match for project dir', () => testRule('path-traversal-write-system-path', 'write_to: "./dist/output.json"', false));
  });

  // Null byte injection
  describe('path-traversal-null-byte', () => {
    test('detect %00 in path', () => testRule('path-traversal-null-byte', 'file_path = "upload.jpg%00.php"', true));
    test('detect \\x00 in path', () => testRule('path-traversal-null-byte', 'path = "file\\x00.txt"', true));
    test('detect \\0 in path', () => testRule('path-traversal-null-byte', 'file_name = "data\\0.json"', true));
    test('no match for normal file', () => testRule('path-traversal-null-byte', 'file_path = "data.json"', false));
  });

  // Encoded traversal
  describe('path-traversal-encoded-sequence', () => {
    test('detect %2e%2e%2f', () => testRule('path-traversal-encoded-sequence', '%2e%2e%2f%2e%2e%2fetc/passwd', true));
    test('detect %2e%2e/', () => testRule('path-traversal-encoded-sequence', '%2e%2e/etc/passwd', true));
    test('detect double-encoded', () => testRule('path-traversal-encoded-sequence', '%252e%252e%252f%252e%252e%252fetc', true));
    test('detect ..%2f', () => testRule('path-traversal-encoded-sequence', '..%2f..%2fetc/passwd', true));
    test('no match for normal URL encoding', () => testRule('path-traversal-encoded-sequence', '%20hello%20world', false));
  });
});
