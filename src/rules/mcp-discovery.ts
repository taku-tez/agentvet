import type { Rule } from "../types.js";

/**
 * MCP Server Discovery Rules
 * Detects MCP servers and AI agents in the codebase for inventory purposes
 * Based on Wiz AI-SPM MCP detection methodology
 */

export const rules: Rule[] = [
  // Package.json MCP server detection
  {
    id: 'mcp-server-package-json',
    severity: 'info',
    description: 'MCP server detected in package.json',
    pattern: /"name"\s*:\s*"[^"]*mcp[^"]*"/gi,
    recommendation: 'MCP server identified. Ensure proper security controls are in place including input validation and access controls.',
  },

  // PyProject.toml MCP server detection
  {
    id: 'mcp-server-pyproject',
    severity: 'info',
    description: 'MCP server detected in pyproject.toml',
    pattern: /name\s*=\s*"[^"]*mcp[^"]*"/gi,
    recommendation: 'MCP server identified. Ensure proper security controls are in place.',
  },

  // Python MCP server import
  {
    id: 'mcp-server-python-import',
    severity: 'info',
    description: 'MCP server import detected in Python code',
    pattern: /from\s+mcp\.server\s+import\s+/gi,
    recommendation: 'MCP server implementation found. Review security controls and tool permissions.',
  },

  // MCP server class pattern
  {
    id: 'mcp-server-class',
    severity: 'info',
    description: 'MCP Server class instantiation detected',
    pattern: /(?:Server|MCPServer|McpServer)\s*\(/gi,
    recommendation: 'MCP server instantiation found. Verify tool definitions and access controls.',
  },

  // AI Agent detection (bot/client in name)
  {
    id: 'ai-agent-package-detected',
    severity: 'info',
    description: 'AI agent/bot package detected',
    pattern: /"name"\s*:\s*"[^"]*(?:bot|client|agent)[^"]*"/gi,
    recommendation: 'AI agent/bot identified. Ensure proper guardrails and monitoring are in place.',
  },

  // MCP tool definition
  {
    id: 'mcp-tool-definition',
    severity: 'info',
    description: 'MCP tool definition found',
    pattern: /@(?:mcp\.)?tool\s*\(|"tools"\s*:\s*\[/gi,
    recommendation: 'MCP tool definition found. Review tool capabilities and permissions.',
  },

  // MCP stdio transport (server mode)
  {
    id: 'mcp-stdio-server',
    severity: 'info',
    description: 'MCP stdio server transport detected',
    pattern: /stdio_server|StdioServerTransport|serve_stdio/gi,
    recommendation: 'MCP server using stdio transport identified.',
  },

  // MCP HTTP/SSE transport
  {
    id: 'mcp-http-server',
    severity: 'info',
    description: 'MCP HTTP/SSE server transport detected',
    pattern: /SSEServerTransport|HTTPServerTransport|serve_sse|serve_http/gi,
    recommendation: 'MCP server using HTTP/SSE transport. Ensure proper authentication and HTTPS.',
  },

  // LangChain agent
  {
    id: 'langchain-agent',
    severity: 'info',
    description: 'LangChain agent detected',
    pattern: /(?:create_react_agent|AgentExecutor|initialize_agent|create_.*_agent)/gi,
    recommendation: 'LangChain agent found. Review tool bindings and safety settings.',
  },

  // AutoGPT/AutoGen patterns
  {
    id: 'autogen-agent',
    severity: 'info',
    description: 'AutoGen/AutoGPT agent detected',
    pattern: /(?:AssistantAgent|UserProxyAgent|GroupChat|autogen\.)/gi,
    recommendation: 'AutoGen agent found. Review agent permissions and execution settings.',
  },

  // CrewAI agent
  {
    id: 'crewai-agent',
    severity: 'info',
    description: 'CrewAI agent detected',
    pattern: /(?:crewai\.|Agent\s*\(\s*role|Crew\s*\()/gi,
    recommendation: 'CrewAI agent found. Review crew composition and tool access.',
  },

  // OpenAI Assistants API
  {
    id: 'openai-assistant',
    severity: 'info',
    description: 'OpenAI Assistant detected',
    pattern: /client\.beta\.assistants|assistants\.create|assistant_id/gi,
    recommendation: 'OpenAI Assistant found. Review function calling permissions.',
  },

  // Anthropic Tool Use
  {
    id: 'anthropic-tool-use',
    severity: 'info',
    description: 'Anthropic tool use detected',
    pattern: /tool_choice|tools\s*=\s*\[.*input_schema/gi,
    recommendation: 'Anthropic tool use found. Review tool definitions and permissions.',
  },

  // Claude Desktop MCP config
  {
    id: 'claude-desktop-mcp-config',
    severity: 'info',
    description: 'Claude Desktop MCP configuration detected',
    pattern: /mcpServers|claude_desktop_config/gi,
    recommendation: 'Claude Desktop MCP configuration found. Review connected servers.',
  },

  // MCP resource handler
  {
    id: 'mcp-resource-handler',
    severity: 'info',
    description: 'MCP resource handler detected',
    pattern: /@(?:mcp\.)?resource|list_resources|read_resource/gi,
    recommendation: 'MCP resource handler found. Review exposed resources.',
  },

  // MCP prompt handler
  {
    id: 'mcp-prompt-handler',
    severity: 'info',
    description: 'MCP prompt handler detected',
    pattern: /@(?:mcp\.)?prompt|list_prompts|get_prompt/gi,
    recommendation: 'MCP prompt handler found. Review prompt templates.',
  },

  // MCP sampling handler (advanced)
  {
    id: 'mcp-sampling-handler',
    severity: 'warning',
    description: 'MCP sampling/LLM access handler detected',
    pattern: /create_message|sampling\.createMessage/gi,
    recommendation: 'MCP sampling handler allows server to request LLM completions. Review carefully.',
  },

  // AI SDK (Vercel)
  {
    id: 'vercel-ai-sdk',
    severity: 'info',
    description: 'Vercel AI SDK agent detected',
    pattern: /from\s+['"]ai['"]|@ai-sdk\/|generateText|streamText|experimental_createMCPClient/gi,
    recommendation: 'Vercel AI SDK found. Review streaming and tool configurations.',
  },

  // Semantic Kernel agent
  {
    id: 'semantic-kernel-agent',
    severity: 'info',
    description: 'Microsoft Semantic Kernel agent detected',
    pattern: /semantic_kernel|KernelFunction|ChatCompletionAgent/gi,
    recommendation: 'Semantic Kernel agent found. Review plugin and function permissions.',
  },
];

// Export summary function for MCP server inventory
export function summarizeMCPFindings(findings: any[]): {
  mcpServers: string[];
  aiAgents: string[];
  frameworks: string[];
} {
  const mcpServers: string[] = [];
  const aiAgents: string[] = [];
  const frameworks: string[] = [];

  for (const finding of findings) {
    if (finding.ruleId?.includes('mcp-server')) {
      mcpServers.push(finding.file || 'unknown');
    }
    if (finding.ruleId?.includes('agent') || finding.ruleId?.includes('bot')) {
      aiAgents.push(finding.file || 'unknown');
    }
    if (finding.ruleId?.match(/langchain|autogen|crewai|openai-assistant|anthropic|semantic-kernel|vercel-ai/)) {
      const framework = finding.ruleId.replace(/-/g, ' ');
      if (!frameworks.includes(framework)) {
        frameworks.push(framework);
      }
    }
  }

  return {
    mcpServers: [...new Set(mcpServers)],
    aiAgents: [...new Set(aiAgents)],
    frameworks: [...new Set(frameworks)],
  };
}

// CommonJS compatibility
module.exports = { rules, summarizeMCPFindings };
