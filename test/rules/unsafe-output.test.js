'use strict';
const { test, describe } = require('node:test');
const assert = require('node:assert');
let rules;
try {
  ({ rules } = require('../../dist/rules/unsafe-output.js'));
} catch {
  ({ rules } = require('../../src/rules/unsafe-output.js'));
}

describe('Unsafe LLM Output Handling Rules', () => {
  function testRule(ruleId, content, shouldMatch) {
    const rule = rules.find(r => r.id === ruleId);
    assert.ok(rule, `Rule ${ruleId} should exist`);
    rule.pattern.lastIndex = 0;
    const matches = rule.pattern.test(content);
    assert.strictEqual(matches, shouldMatch,
      `Rule ${ruleId} ${shouldMatch ? 'should' : 'should not'} match: ${content.substring(0, 120)}`);
  }

  // ── eval / exec ──────────────────────────────────────────────
  describe('Eval/Exec with LLM Output', () => {
    test('should detect eval(response)', () => {
      testRule('unsafe-output-eval-llm', 'eval(response.text)', true);
    });
    test('should detect eval(completion)', () => {
      testRule('unsafe-output-eval-llm', 'eval(completion)', true);
    });
    test('should detect exec(llm_output)', () => {
      testRule('unsafe-output-eval-llm', 'exec(llm_output)', true);
    });
    test('should detect execSync(result)', () => {
      testRule('unsafe-output-eval-llm', 'execSync(result)', true);
    });
    test('should detect Function(ai_output)', () => {
      testRule('unsafe-output-eval-llm', 'Function(ai_output)', true);
    });
    test('should not flag eval with static string', () => {
      testRule('unsafe-output-eval-llm', 'eval("2+2")', false);
    });
    test('should not flag eval with user variable', () => {
      testRule('unsafe-output-eval-llm', 'eval(formula)', false);
    });
  });

  describe('new Function with LLM Output', () => {
    test('should detect new Function(response)', () => {
      testRule('unsafe-output-new-function', 'new Function(response.code)', true);
    });
    test('should detect new Function with ai_output', () => {
      testRule('unsafe-output-new-function', 'const fn = new Function("return " + ai_output)', true);
    });
    test('should not flag new Function with static code', () => {
      testRule('unsafe-output-new-function', 'new Function("return 42")', false);
    });
  });

  describe('Python exec with LLM Output', () => {
    test('should detect exec(response)', () => {
      testRule('unsafe-output-python-exec', 'exec(response)', true);
    });
    test('should detect compile(llm_output)', () => {
      testRule('unsafe-output-python-exec', 'compile(llm_output, "<string>", "exec")', true);
    });
    test('should not flag exec with static string', () => {
      testRule('unsafe-output-python-exec', 'exec("print(42)")', false);
    });
  });

  // ── Shell Command Injection ───────────────────────────────────
  describe('Shell Injection', () => {
    test('should detect subprocess with interpolated response', () => {
      testRule('unsafe-output-shell-injection',
        'subprocess.Popen(f"ls {response.path}")', true);
    });
    test('should detect os.system with string concat', () => {
      testRule('unsafe-output-shell-injection',
        'os.system("echo " + result)', true);
    });
    test('should detect execSync with template literal', () => {
      testRule('unsafe-output-shell-template',
        'execSync(`rm -rf ${response.path}`)', true);
    });
    test('should detect exec with output variable in template', () => {
      testRule('unsafe-output-shell-template',
        'exec(`docker run ${output.image}`)', true);
    });
    test('should not flag execSync with static command', () => {
      testRule('unsafe-output-shell-template',
        'execSync(`ls -la`)', false);
    });
  });

  // ── SQL Injection ─────────────────────────────────────────────
  describe('SQL Injection', () => {
    test('should detect query with template literal response', () => {
      testRule('unsafe-output-sql-injection',
        'db.query(`SELECT * FROM users WHERE name = ${response.name}`)', true);
    });
    test('should detect execute with f-string output', () => {
      testRule('unsafe-output-sql-injection',
        'cursor.execute(f"INSERT INTO logs VALUES ({ai_output})")', true);
    });
    test('should detect SQL concat with result', () => {
      testRule('unsafe-output-sql-concat',
        '"SELECT * FROM users WHERE name = " + result', true);
    });
    test('should detect INSERT concat with output', () => {
      testRule('unsafe-output-sql-concat',
        '"INSERT INTO table VALUES (" + output + ")"', true);
    });
    test('should not flag parameterized query', () => {
      testRule('unsafe-output-sql-concat',
        'db.query("SELECT * FROM users WHERE id = ?", [userId])', false);
    });
  });

  // ── XSS / innerHTML ──────────────────────────────────────────
  describe('XSS / innerHTML', () => {
    test('should detect innerHTML = response', () => {
      testRule('unsafe-output-innerhtml',
        'element.innerHTML = response.html', true);
    });
    test('should detect innerHTML += output', () => {
      testRule('unsafe-output-innerhtml',
        'div.innerHTML += output', true);
    });
    test('should detect outerHTML with chat_response', () => {
      testRule('unsafe-output-innerhtml',
        'container.outerHTML = chat_response', true);
    });
    test('should not flag textContent = response', () => {
      testRule('unsafe-output-innerhtml',
        'element.textContent = response.text', false);
    });

    test('should detect dangerouslySetInnerHTML with response', () => {
      testRule('unsafe-output-dangerously-set',
        '<div dangerouslySetInnerHTML={{ __html: response.content }} />', true);
    });
    test('should detect dangerouslySetInnerHTML with ai_output', () => {
      testRule('unsafe-output-dangerously-set',
        'dangerouslySetInnerHTML={{ __html: ai_output }}', true);
    });
    test('should not flag dangerouslySetInnerHTML with sanitized', () => {
      testRule('unsafe-output-dangerously-set',
        'dangerouslySetInnerHTML={{ __html: sanitizedHtml }}', false);
    });

    test('should detect v-html with response', () => {
      testRule('unsafe-output-v-html',
        '<div v-html="response.content"></div>', true);
    });
    test('should not flag v-html with safe variable', () => {
      testRule('unsafe-output-v-html',
        '<div v-html="sanitizedContent"></div>', false);
    });
  });

  // ── Deserialization ───────────────────────────────────────────
  describe('Deserialization', () => {
    test('should detect JSON.parse(response)', () => {
      testRule('unsafe-output-json-parse-unvalidated',
        'const data = JSON.parse(response.body)', true);
    });
    test('should detect JSON.parse(llm_output)', () => {
      testRule('unsafe-output-json-parse-unvalidated',
        'JSON.parse(llm_output)', true);
    });

    test('should detect yaml.load with response', () => {
      testRule('unsafe-output-yaml-load',
        'data = yaml.load(response.text)', true);
    });
    test('should detect yaml.unsafe_load with output', () => {
      testRule('unsafe-output-yaml-load',
        'yaml.unsafe_load(output)', true);
    });
    test('should not flag yaml.safe_load', () => {
      testRule('unsafe-output-yaml-load',
        'yaml.safe_load(response.text)', false);
    });
  });

  // ── File Write ────────────────────────────────────────────────
  describe('File Write', () => {
    test('should detect writeFile with response', () => {
      testRule('unsafe-output-file-write',
        'fs.writeFile("output.js", response.code)', true);
    });
    test('should detect writeFileSync with output', () => {
      testRule('unsafe-output-file-write',
        'fs.writeFileSync("config.json", output)', true);
    });
    test('should not flag writeFile with user content', () => {
      testRule('unsafe-output-file-write',
        'fs.writeFile("notes.txt", userContent)', false);
    });
  });

  describe('File Path from LLM', () => {
    test('should detect readFile(response)', () => {
      testRule('unsafe-output-path-from-llm',
        'fs.readFile(response.filePath)', true);
    });
    test('should detect open(output)', () => {
      testRule('unsafe-output-path-from-llm',
        'open(output.path, "r")', true);
    });
    test('should detect unlink(ai_output)', () => {
      testRule('unsafe-output-path-from-llm',
        'fs.unlink(ai_output.file)', true);
    });
  });

  // ── SSRF via LLM URL ─────────────────────────────────────────
  describe('SSRF via LLM URL', () => {
    test('should detect fetch(response)', () => {
      testRule('unsafe-output-ssrf-url',
        'fetch(response.url)', true);
    });
    test('should detect axios(output)', () => {
      testRule('unsafe-output-ssrf-url',
        'axios(output.endpoint)', true);
    });
    test('should detect requests.get(llm_output)', () => {
      testRule('unsafe-output-ssrf-url',
        'requests.get(llm_output.url)', true);
    });
    test('should not flag fetch with hardcoded URL', () => {
      testRule('unsafe-output-ssrf-url',
        'fetch("https://api.example.com/data")', false);
    });
  });

  // ── Dynamic Import ────────────────────────────────────────────
  describe('Dynamic Import', () => {
    test('should detect import(response)', () => {
      testRule('unsafe-output-dynamic-import',
        'const mod = await import(response.module)', true);
    });
    test('should detect require(output)', () => {
      testRule('unsafe-output-dynamic-import',
        'require(output.path)', true);
    });
    test('should not flag import of static module', () => {
      testRule('unsafe-output-dynamic-import',
        'import("./config.js")', false);
    });
  });

  // ── Regex Injection ───────────────────────────────────────────
  describe('Regex Injection', () => {
    test('should detect new RegExp(response)', () => {
      testRule('unsafe-output-regex-injection',
        'const re = new RegExp(response.pattern)', true);
    });
    test('should detect new RegExp(llm_output)', () => {
      testRule('unsafe-output-regex-injection',
        'new RegExp(llm_output)', true);
    });
    test('should not flag new RegExp with static string', () => {
      testRule('unsafe-output-regex-injection',
        'new RegExp("^[a-z]+$")', false);
    });
  });

  // ── Metadata checks ──────────────────────────────────────────
  describe('Rule Metadata', () => {
    test('all rules should have category unsafe-output', () => {
      for (const rule of rules) {
        assert.strictEqual(rule.category, 'unsafe-output',
          `Rule ${rule.id} should have category unsafe-output`);
      }
    });
    test('all rules should have CWE references', () => {
      for (const rule of rules) {
        assert.ok(rule.cwe, `Rule ${rule.id} should have a CWE reference`);
      }
    });
    test('all rules should have recommendations', () => {
      for (const rule of rules) {
        assert.ok(rule.recommendation, `Rule ${rule.id} should have a recommendation`);
      }
    });
    test('should have at least 15 rules', () => {
      assert.ok(rules.length >= 15, `Expected at least 15 rules, got ${rules.length}`);
    });
    test('all rule IDs should be unique', () => {
      const ids = rules.map(r => r.id);
      const unique = new Set(ids);
      assert.strictEqual(ids.length, unique.size, 'Duplicate rule IDs found');
    });
  });
});
