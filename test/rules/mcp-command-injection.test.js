const { describe, it } = require('node:test');
const assert = require('node:assert');
const { rules } = require('../../dist/rules/mcp-command-injection.js');

describe('MCP Command Injection Rules', () => {
  describe('mcp-cmdinj-exec-tool-input', () => {
    const rule = rules.find(r => r.id === 'mcp-cmdinj-exec-tool-input');

    it('should detect MCP tool handler using exec with tool input', () => {
      const code = `
        tools["run_command"] = {
          handler: async (args) => {
            const result = execSync(args.command);
            return result.toString();
          }
        };
      `;
      assert.ok(rule.pattern.test(code));
    });

    it('should detect subprocess in tool handler', () => {
      rule.pattern.lastIndex = 0;
      const code = `
        handle_call("execute", async (args) => {
          const proc = child_process.exec(args.cmd);
          return proc.stdout;
        });
      `;
      assert.ok(rule.pattern.test(code));
    });

    it('should detect Python os.system in tool handler', () => {
      rule.pattern.lastIndex = 0;
      const code = `
        @tool_handler("shell")
        def run_shell(args):
            result = os.system(args["command"])
            return str(result)
      `;
      assert.ok(rule.pattern.test(code));
    });
  });

  describe('mcp-cmdinj-template-shell', () => {
    const rule = rules.find(r => r.id === 'mcp-cmdinj-template-shell');

    it('should detect template literal in exec', () => {
      const code = 'execSync(`ls -la ${args.path}`)';
      assert.ok(rule.pattern.test(code));
    });

    it('should detect string concatenation in system call', () => {
      rule.pattern.lastIndex = 0;
      const code = 'os.system("grep " + args.query + " /var/log/app.log")';
      assert.ok(rule.pattern.test(code));
    });

    it('should detect Python f-string in subprocess', () => {
      rule.pattern.lastIndex = 0;
      const code = 'subprocess.run(f"cat {params.file}")';
      assert.ok(rule.pattern.test(code));
    });
  });

  describe('mcp-cmdinj-eval-tool-input', () => {
    const rule = rules.find(r => r.id === 'mcp-cmdinj-eval-tool-input');

    it('should detect eval with tool args', () => {
      const code = `
        const toolHandler = {
          execute: (args) => {
            return eval(args.expression);
          }
        };
      `;
      assert.ok(rule.pattern.test(code));
    });

    it('should detect new Function with tool input', () => {
      rule.pattern.lastIndex = 0;
      const code = `
        mcpServer.registerTool("calc", (args) => {
          const fn = new Function("return " + args.code);
          return fn();
        });
      `;
      assert.ok(rule.pattern.test(code));
    });
  });

  describe('mcp-cmdinj-unsanitized-path', () => {
    const rule = rules.find(r => r.id === 'mcp-cmdinj-unsanitized-path');

    it('should detect readFile with unsanitized args.path', () => {
      const code = 'fs.readFileSync(args.path)';
      assert.ok(rule.pattern.test(code));
    });

    it('should detect writeFile with request.filepath', () => {
      rule.pattern.lastIndex = 0;
      const code = 'fs.writeFile(request.filepath, data, cb)';
      assert.ok(rule.pattern.test(code));
    });
  });

  describe('mcp-cmdinj-sql-injection', () => {
    const rule = rules.find(r => r.id === 'mcp-cmdinj-sql-injection');

    it('should detect SQL template literal with args', () => {
      const code = 'db.query(`SELECT * FROM users WHERE name = ${args.name}`)';
      assert.ok(rule.pattern.test(code));
    });

    it('should detect SQL string concatenation with params', () => {
      rule.pattern.lastIndex = 0;
      const code = 'db.execute("DELETE FROM records WHERE id = " + params.id)';
      assert.ok(rule.pattern.test(code));
    });
  });
});
