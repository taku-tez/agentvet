import { describe, it } from 'node:test';
import assert from 'node:assert';
import { rules } from '../../dist/rules/mcp-discovery.js';

/**
 * MCP Server Discovery Rules Tests
 * Validates detection of MCP servers and AI agents in codebases.
 */

describe('MCP Discovery Rules', () => {
  const testPattern = (ruleId, content, shouldMatch) => {
    const rule = rules.find(r => r.id === ruleId);
    assert.ok(rule, `Rule ${ruleId} should exist`);
    rule.pattern.lastIndex = 0;
    const result = rule.pattern.test(content);
    assert.strictEqual(
      result,
      shouldMatch,
      `Rule ${ruleId} should ${shouldMatch ? 'match' : 'not match'}: ${content.substring(0, 120)}...`
    );
  };

  // ============================================
  // Package Detection
  // ============================================
  describe('MCP Server Package JSON', () => {
    it('should detect MCP server in package.json name', () => {
      testPattern('mcp-server-package-json', '"name": "mcp-server-github"', true);
    });

    it('should detect scoped MCP package', () => {
      testPattern('mcp-server-package-json', '"name" : "@org/mcp-tools"', true);
    });

    it('should not flag unrelated packages', () => {
      testPattern('mcp-server-package-json', '"name": "express"', false);
    });
  });

  describe('MCP Server PyProject', () => {
    it('should detect MCP in pyproject.toml', () => {
      testPattern('mcp-server-pyproject', 'name = "mcp-server-sqlite"', true);
    });

    it('should not flag unrelated Python packages', () => {
      testPattern('mcp-server-pyproject', 'name = "fastapi"', false);
    });
  });

  // ============================================
  // Python Server Detection
  // ============================================
  describe('MCP Server Python Import', () => {
    it('should detect mcp.server import', () => {
      testPattern('mcp-server-python-import', 'from mcp.server import Server', true);
    });

    it('should not flag unrelated imports', () => {
      testPattern('mcp-server-python-import', 'from flask import Flask', false);
    });
  });

  describe('MCP Server Class', () => {
    it('should detect Server() instantiation', () => {
      testPattern('mcp-server-class', 'const server = new Server({ name: "my-server" })', true);
    });

    it('should detect MCPServer() instantiation', () => {
      testPattern('mcp-server-class', 'const s = new MCPServer(config)', true);
    });

    it('should detect McpServer()', () => {
      testPattern('mcp-server-class', 'const s = new McpServer()', true);
    });
  });

  // ============================================
  // AI Agent Detection
  // ============================================
  describe('AI Agent Package Detected', () => {
    it('should detect bot in package name', () => {
      testPattern('ai-agent-package-detected', '"name": "my-discord-bot"', true);
    });

    it('should detect agent in package name', () => {
      testPattern('ai-agent-package-detected', '"name": "coding-agent"', true);
    });

    it('should detect client in package name', () => {
      testPattern('ai-agent-package-detected', '"name": "mcp-client-lib"', true);
    });

    it('should not flag unrelated packages', () => {
      testPattern('ai-agent-package-detected', '"name": "lodash"', false);
    });
  });

  // ============================================
  // Tool Definitions
  // ============================================
  describe('MCP Tool Definition', () => {
    it('should detect @tool decorator', () => {
      testPattern('mcp-tool-definition', '@tool()', true);
    });

    it('should detect @mcp.tool decorator', () => {
      testPattern('mcp-tool-definition', '@mcp.tool()', true);
    });

    it('should detect tools array in JSON', () => {
      testPattern('mcp-tool-definition', '"tools": [{ "name": "read_file" }]', true);
    });

    it('should not flag unrelated arrays', () => {
      testPattern('mcp-tool-definition', '"items": [1, 2, 3]', false);
    });
  });

  // ============================================
  // Server Transport Types
  // ============================================
  describe('MCP Stdio Server', () => {
    it('should detect StdioServerTransport', () => {
      testPattern('mcp-stdio-server', 'new StdioServerTransport()', true);
    });

    it('should detect stdio_server', () => {
      testPattern('mcp-stdio-server', 'async with stdio_server() as (read, write):', true);
    });

    it('should detect serve_stdio', () => {
      testPattern('mcp-stdio-server', 'await serve_stdio(app)', true);
    });
  });

  describe('MCP HTTP Server', () => {
    it('should detect SSEServerTransport', () => {
      testPattern('mcp-http-server', 'new SSEServerTransport("/messages")', true);
    });

    it('should detect HTTPServerTransport', () => {
      testPattern('mcp-http-server', 'new HTTPServerTransport()', true);
    });

    it('should detect serve_sse', () => {
      testPattern('mcp-http-server', 'await serve_sse(app)', true);
    });

    it('should detect serve_http', () => {
      testPattern('mcp-http-server', 'serve_http(app, port=8080)', true);
    });
  });

  // ============================================
  // Security Issues
  // ============================================
  describe('MCP Unauthenticated Server', () => {
    it('should detect SSEServerTransport without auth', () => {
      testPattern('mcp-unauthenticated-server',
        'transport = SSEServerTransport("/messages")\nserver.run(transport)', true);
    });

    it('should detect serve_sse without auth', () => {
      testPattern('mcp-unauthenticated-server',
        'serve_sse(app)', true);
    });
  });

  describe('MCP Public Binding', () => {
    it('should detect host=0.0.0.0', () => {
      testPattern('mcp-public-binding', 'host="0.0.0.0"', true);
    });

    it('should detect host: "0.0.0.0"', () => {
      testPattern('mcp-public-binding', 'host: "0.0.0.0"', true);
    });

    it('should detect bind=::  (IPv6 all)', () => {
      testPattern('mcp-public-binding', 'bind="::"', true);
    });

    it('should not flag localhost binding', () => {
      testPattern('mcp-public-binding', 'host="127.0.0.1"', false);
    });
  });

  describe('MCP No Rate Limit', () => {
    it('should detect serve_sse without rate limit', () => {
      testPattern('mcp-no-rate-limit',
        'serve_sse(app)\nserver.start()', true);
    });

    it('should detect HTTPServerTransport without throttle', () => {
      testPattern('mcp-no-rate-limit',
        'const t = new HTTPServerTransport()\nserver.connect(t)', true);
    });
  });

  describe('MCP Tool Typosquat Risk', () => {
    it('should detect read_flie typo', () => {
      testPattern('mcp-tool-typosquat-risk', '"name": "read_flie"', true);
    });

    it('should detect filesytem typo', () => {
      testPattern('mcp-tool-typosquat-risk', '"tool": "filesytem"', true);
    });

    it('should detect web_serach typo', () => {
      testPattern('mcp-tool-typosquat-risk', '"name": "web_serach"', true);
    });

    it('should not flag correct tool names', () => {
      testPattern('mcp-tool-typosquat-risk', '"name": "read_file"', false);
    });
  });

  // ============================================
  // Framework Detection
  // ============================================
  describe('LangChain Agent', () => {
    it('should detect create_react_agent', () => {
      testPattern('langchain-agent', 'agent = create_react_agent(llm, tools)', true);
    });

    it('should detect AgentExecutor', () => {
      testPattern('langchain-agent', 'executor = AgentExecutor(agent=agent, tools=tools)', true);
    });

    it('should detect initialize_agent', () => {
      testPattern('langchain-agent', 'agent = initialize_agent(tools, llm)', true);
    });

    it('should not flag unrelated agent references', () => {
      testPattern('langchain-agent', 'user_agent = "Mozilla/5.0"', false);
    });
  });

  describe('AutoGen Agent', () => {
    it('should detect AssistantAgent', () => {
      testPattern('autogen-agent', 'assistant = AssistantAgent("coder")', true);
    });

    it('should detect UserProxyAgent', () => {
      testPattern('autogen-agent', 'user = UserProxyAgent("user")', true);
    });

    it('should detect GroupChat', () => {
      testPattern('autogen-agent', 'chat = GroupChat(agents=[a, b])', true);
    });

    it('should detect autogen module usage', () => {
      testPattern('autogen-agent', 'config = autogen.config_list()', true);
    });
  });

  describe('CrewAI Agent', () => {
    it('should detect crewai module', () => {
      testPattern('crewai-agent', 'from crewai.tools import tool', true);
    });

    it('should detect Agent with role', () => {
      testPattern('crewai-agent', 'researcher = Agent(role="Research Analyst")', true);
    });

    it('should detect Crew()', () => {
      testPattern('crewai-agent', 'crew = Crew(agents=[a], tasks=[t])', true);
    });
  });

  describe('OpenAI Assistant', () => {
    it('should detect assistants.create', () => {
      testPattern('openai-assistant', 'client.beta.assistants.create({ model: "gpt-4" })', true);
    });

    it('should detect assistant_id reference', () => {
      testPattern('openai-assistant', 'thread = client.beta.threads.create(assistant_id="asst_abc")', true);
    });
  });

  describe('Anthropic Tool Use', () => {
    it('should detect tool_choice', () => {
      testPattern('anthropic-tool-use', 'tool_choice={"type": "auto"}', true);
    });

    it('should detect tools with input_schema', () => {
      testPattern('anthropic-tool-use', 'tools = [{"name": "calc", "input_schema": {}}]', true);
    });
  });

  describe('Claude Desktop MCP Config', () => {
    it('should detect claude_desktop_config', () => {
      testPattern('claude-desktop-mcp-config', 'edit ~/Library/Application Support/Claude/claude_desktop_config.json', true);
    });

    it('should detect mcpServers key', () => {
      testPattern('claude-desktop-mcp-config', '"mcpServers": { "filesystem": {} }', true);
    });

    it('should not flag unrelated config', () => {
      testPattern('claude-desktop-mcp-config', '"servers": { "api": {} }', false);
    });
  });

  // ============================================
  // Handler Detection
  // ============================================
  describe('MCP Resource Handler', () => {
    it('should detect @resource decorator', () => {
      testPattern('mcp-resource-handler', '@mcp.resource("config://app")', true);
    });

    it('should detect list_resources', () => {
      testPattern('mcp-resource-handler', 'async def list_resources():', true);
    });

    it('should detect read_resource', () => {
      testPattern('mcp-resource-handler', 'await server.read_resource(uri)', true);
    });
  });

  describe('MCP Prompt Handler', () => {
    it('should detect @prompt decorator', () => {
      testPattern('mcp-prompt-handler', '@mcp.prompt()', true);
    });

    it('should detect list_prompts', () => {
      testPattern('mcp-prompt-handler', 'async def list_prompts():', true);
    });

    it('should detect get_prompt', () => {
      testPattern('mcp-prompt-handler', 'result = await server.get_prompt("summarize")', true);
    });
  });

  describe('MCP Sampling Handler', () => {
    it('should detect create_message', () => {
      testPattern('mcp-sampling-handler', 'result = await client.create_message(messages=[])', true);
    });

    it('should detect sampling.createMessage', () => {
      testPattern('mcp-sampling-handler', 'await sampling.createMessage({ messages })', true);
    });
  });

  // ============================================
  // SDK Detection
  // ============================================
  describe('Vercel AI SDK', () => {
    it('should detect import from "ai"', () => {
      testPattern('vercel-ai-sdk', 'import { generateText } from "ai"', true);
    });

    it('should detect from \'ai\'', () => {
      testPattern('vercel-ai-sdk', "import { streamText } from 'ai'", true);
    });

    it('should detect @ai-sdk/ package', () => {
      testPattern('vercel-ai-sdk', 'import { openai } from "@ai-sdk/openai"', true);
    });

    it('should detect experimental_createMCPClient', () => {
      testPattern('vercel-ai-sdk', 'const client = experimental_createMCPClient(config)', true);
    });

    it('should not flag unrelated AI mentions', () => {
      testPattern('vercel-ai-sdk', 'const ai = "artificial intelligence"', false);
    });
  });

  describe('Semantic Kernel Agent', () => {
    it('should detect semantic_kernel import', () => {
      testPattern('semantic-kernel-agent', 'import semantic_kernel as sk', true);
    });

    it('should detect KernelFunction', () => {
      testPattern('semantic-kernel-agent', '@KernelFunction(name="search")', true);
    });

    it('should detect ChatCompletionAgent', () => {
      testPattern('semantic-kernel-agent', 'agent = ChatCompletionAgent(kernel=kernel)', true);
    });
  });
});
