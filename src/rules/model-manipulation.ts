import type { Rule } from "../types.js";

/**
 * AI Model Manipulation Attack Detection Rules
 * Detects attempts to hijack AI API endpoints, spoof model identities,
 * steal API keys via malicious endpoints, and manipulate model parameters
 * to cause unsafe or unintended behavior.
 *
 * Attack categories:
 * - Endpoint hijacking (redirecting API calls to attacker-controlled server)
 * - Model spoofing (claiming to use one model while using another)
 * - Parameter manipulation (unsafe temperature, max_tokens, etc.)
 * - API key theft via compromised endpoints
 * - Streaming interception
 * - Response format injection
 */

export const rules: Rule[] = [
  // ============================================
  // API Endpoint Hijacking
  // Detects overrides of the official AI provider base URLs
  // that redirect calls to attacker-controlled servers.
  // ============================================
  {
    id: 'model-openai-base-url-override',
    severity: 'critical',
    description: 'OpenAI API base URL overridden to non-official host (endpoint hijacking)',
    pattern: /(?:baseURL|base_url|apiBase|OPENAI_BASE_URL|OPENAI_API_BASE)\s*[=:]\s*['"`]?https?:\/\/(?!(?:api\.openai\.com|openai\.azure\.com)[/'"`\s])[^\s'"`]{5,}/gi,
    recommendation: 'OpenAI base URL is overridden to a non-official endpoint. This can redirect API calls (including API keys) to an attacker-controlled server. Ensure only https://api.openai.com is used.',
    category: 'model-manipulation',
    cwe: 'CWE-441',
  },
  {
    id: 'model-anthropic-base-url-override',
    severity: 'critical',
    description: 'Anthropic API base URL overridden to non-official host (endpoint hijacking)',
    pattern: /(?:baseURL|base_url|ANTHROPIC_BASE_URL|anthropicApiBase)\s*[=:]\s*['"`]https?:\/\/(?!(?:api\.anthropic\.com)[/'"`])[^\s'"`]{5,}/gi,
    recommendation: 'Anthropic base URL is overridden to a non-official endpoint. This is a known API key exfiltration technique. All Anthropic calls must go to https://api.anthropic.com.',
    category: 'model-manipulation',
    cwe: 'CWE-441',
  },
  {
    id: 'model-generic-ai-proxy',
    severity: 'high',
    description: 'AI API proxied through unofficial host (MITM / API key theft risk)',
    pattern: /(?:llmProxyUrl|ai_proxy|LLM_PROXY|OPENAI_PROXY|proxyUrl)\s*[=:]\s*['"`]https?:\/\/(?!(?:api\.openai\.com|api\.anthropic\.com|generativelanguage\.googleapis\.com))[^\s'"`]{5,}/gi,
    recommendation: 'AI API traffic proxied through an unofficial host exposes your API key to MITM attacks. Remove proxy configuration or verify the proxy is trusted and audited.',
    category: 'model-manipulation',
    cwe: 'CWE-300',
  },

  // ============================================
  // Model Identity Spoofing
  // Skills claiming to use a safe/approved model
  // while silently switching to a different one.
  // ============================================
  {
    id: 'model-name-shadow',
    severity: 'high',
    description: 'Model name variable reassigned after being set to an approved model (shadow substitution)',
    pattern: /(?:model(?:Name|Id|Version)?)\s*=\s*['"`][a-z0-9.:/-]+['"`][^;]{0,200}?\n[^;]{0,200}?(?:model(?:Name|Id|Version)?)\s*=\s*['"`][a-z0-9.:/-]+['"`]/gi,
    recommendation: 'Model name is reassigned after initialization. This can silently switch from an approved model to an unsafe one. Review all model name assignments.',
    category: 'model-manipulation',
  },
  {
    id: 'model-dynamic-selection',
    severity: 'high',
    description: 'AI model selected dynamically from user input or environment (model injection risk)',
    pattern: /(?:model|modelId|modelName)\s*[:=]\s*(?:process\.env\.[A-Z_]+|req\.(?:body|query|params)\.[a-zA-Z]+|params\.[a-zA-Z]+|userInput|input\.[a-zA-Z]+)/gi,
    recommendation: 'Model name derived from user input or env vars can be controlled by an attacker. Allowlist approved models and validate before use.',
    category: 'model-manipulation',
    cwe: 'CWE-20',
  },

  // ============================================
  // Unsafe Parameter Manipulation
  // Extreme values for temperature, max_tokens, etc.
  // used to induce jailbreak-friendly or denial-of-service outputs.
  // ============================================
  {
    id: 'model-extreme-temperature',
    severity: 'high',
    description: 'Model temperature set to an extreme value (≥ 1.8 or < 0) — jailbreak or chaos induction risk',
    pattern: /temperature\s*[=:]\s*(?:1\.[89][0-9]*|[2-9][0-9]*(?:\.[0-9]+)?|-[0-9]+(?:\.[0-9]+)?)/gi,
    recommendation: 'Very high temperature values (≥ 1.8) produce unpredictable outputs and are a known jailbreak-assisting technique. Use values between 0.0 and 1.0 for production.',
    category: 'model-manipulation',
  },
  {
    id: 'model-excessive-max-tokens',
    severity: 'medium',
    description: 'max_tokens set extremely high (> 100,000) — potential context flood or cost amplification attack',
    pattern: /max_tokens\s*[=:]\s*(?:[1-9][0-9]{5,})/gi,
    recommendation: 'Extremely high max_tokens values can amplify costs (billing attack) or flood downstream consumers with oversized responses. Cap max_tokens to a reasonable limit.',
    category: 'model-manipulation',
  },
  {
    id: 'model-top-p-zero',
    severity: 'medium',
    description: 'top_p set to 0 or 1 with high temperature (deterministic bypass pattern)',
    // top_p:0 makes sampling fully greedy; combined with manipulation it can bypass restrictions
    pattern: /top_p\s*[=:]\s*0(?:\.0+)?(?![.\d])/gi,
    recommendation: 'top_p=0 disables sampling entirely. Combined with adversarial prompts this can force deterministic undesirable outputs. Review this configuration.',
    category: 'model-manipulation',
  },

  // ============================================
  // System Prompt Injection via Parameters
  // Injecting attacker content through model API parameters
  // rather than the user turn (harder to detect).
  // ============================================
  {
    id: 'model-system-prompt-from-env',
    severity: 'high',
    description: 'System prompt loaded from environment variable (attacker-controlled system prompt risk)',
    pattern: /(?:system(?:Prompt|_prompt)?|content)\s*[:=]\s*process\.env\.[A-Z_]*(?:SYSTEM|PROMPT|INSTRUCTION)[A-Z_]*/gi,
    recommendation: 'Loading the system prompt from an environment variable allows an attacker who controls env vars to inject arbitrary system-level instructions. Hardcode the system prompt or load it from a verified, immutable source.',
    category: 'model-manipulation',
    cwe: 'CWE-20',
  },
  {
    id: 'model-system-prompt-from-url',
    severity: 'critical',
    description: 'System prompt fetched from remote URL at runtime (remote system prompt injection)',
    pattern: /(?:system|systemPrompt|system_prompt)\s*[:=][\s\S]{0,100}(?:fetch|axios\.get|https?\.get)\s*\(\s*['"`][^'"`]+['"`]/gi,
    recommendation: 'Fetching the system prompt from a URL means an attacker who compromises that URL can inject malicious system-level instructions into all future conversations.',
    category: 'model-manipulation',
    cwe: 'CWE-829',
  },

  // ============================================
  // Streaming Response Interception
  // Intercepting or proxying streaming AI output
  // to read, modify, or re-route AI responses.
  // ============================================
  {
    id: 'model-stream-intercept',
    severity: 'high',
    description: 'AI streaming response piped to unexpected external destination (response interception)',
    pattern: /(?:stream|readable)\s*\.(?:pipe|pipeTo)\s*\([^)]*(?:https?|socket|net\.connect|tls\.connect)/gi,
    recommendation: 'Streaming AI responses piped to network sockets can be intercepted and read by unauthorized parties. Ensure stream destinations are trusted and local.',
    category: 'model-manipulation',
    cwe: 'CWE-319',
  },

  // ============================================
  // Response Format Injection
  // Forcing dangerous output formats (e.g., JSON schema
  // that redirects model to emit exploit payloads).
  // ============================================
  {
    id: 'model-response-format-injection',
    severity: 'high',
    description: 'response_format or JSON schema loaded from user input (format injection risk)',
    pattern: /response_format\s*[:=]\s*(?:JSON\.parse\s*\(|req\.(?:body|query)|params\.|userInput)/gi,
    recommendation: 'Setting response_format from user-controlled input lets an attacker craft a schema that forces the model to produce malicious structured output. Hardcode all response_format values.',
    category: 'model-manipulation',
    cwe: 'CWE-20',
  },

  // ============================================
  // API Key Exfiltration via Model Calls
  // Using the model API itself as an exfiltration channel
  // by embedding secrets in the prompt sent to a rogue endpoint.
  // ============================================
  {
    id: 'model-key-in-prompt',
    severity: 'critical',
    description: 'Sensitive key/secret embedded directly in AI prompt string (API key exfiltration via LLM)',
    pattern: /(?:messages|prompt|content)\s*[=:+][\s\S]{0,200}(?:sk-[a-zA-Z0-9]{20,}|xai-[a-zA-Z0-9]{20,}|claude-key-[a-zA-Z0-9]{20,}|AKIA[A-Z0-9]{16})/gi,
    recommendation: 'API keys embedded in prompts are sent to the LLM provider and logged. If the endpoint is attacker-controlled, keys are immediately compromised. Never include secrets in prompt strings.',
    category: 'model-manipulation',
    cwe: 'CWE-312',
  },
  {
    id: 'model-env-key-forwarded-to-llm',
    severity: 'critical',
    description: 'Environment variable (likely API key) interpolated into AI prompt (key forwarding attack)',
    pattern: /(?:messages|prompt|content|userContent)\s*[=:+`][\s\S]{0,300}\$\{process\.env\.[A-Z_]*(?:KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL)[A-Z_]*\}/gi,
    recommendation: 'Injecting secret env vars into LLM prompts forwards them to the AI provider or, if the endpoint is hijacked, to an attacker. Remove all secret interpolation from prompt templates.',
    category: 'model-manipulation',
    cwe: 'CWE-312',
  },

  // ============================================
  // Model Capability Bypass
  // Using tool/function calling to extract capabilities
  // beyond what the model is configured to allow.
  // ============================================
  {
    id: 'model-unrestricted-function-calling',
    severity: 'high',
    description: 'Function/tool calling schema allows arbitrary code execution (capability bypass)',
    // Detects when function parameters allow "code", "command", "eval", "exec" as field names
    pattern: /["']?(?:name|description)["']?\s*:\s*["'](?:execute_code|run_command|eval_python|exec_shell|arbitrary_code|run_script)["']/gi,
    recommendation: 'Tool/function definitions that expose code execution capabilities allow the model to bypass application-level restrictions. Remove or restrict dangerous function definitions.',
    category: 'model-manipulation',
    cwe: 'CWE-78',
  },
];

// CommonJS compatibility
module.exports = { rules };
