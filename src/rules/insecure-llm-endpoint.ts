import type { Rule } from "../types.js";

/**
 * Insecure LLM Endpoint Rules
 * Detects unencrypted, hardcoded, or otherwise insecure LLM API endpoints.
 *
 * References:
 * - OWASP LLM Top 10 2025 - LLM09: Misinformation
 * - CWE-319: Cleartext Transmission of Sensitive Information
 */

export const rules: Rule[] = [
  // Plaintext HTTP LLM endpoint
  {
    id: 'insecure-llm-endpoint-http',
    severity: 'high',
    description: 'LLM API endpoint using unencrypted HTTP (not HTTPS)',
    pattern: /(?:base_url|api_base|endpoint|url|host)\s*[:=]\s*["']http:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0|::1)[\w.-]+(?:\/[^"']*)?["']/gi,
    recommendation: 'LLM API calls over plain HTTP expose API keys and prompt data to interception. Use HTTPS for all remote LLM endpoints.',
    cwe: 'CWE-319',
  },

  // Deprecated/pinned model versions
  {
    id: 'insecure-llm-endpoint-deprecated-model',
    severity: 'info',
    description: 'Deprecated or version-pinned LLM model name detected',
    pattern: /(?:model|model_name|engine)\s*[:=]\s*["'](?:gpt-4-0314|gpt-4-0613|gpt-4-32k-0314|gpt-4-32k-0613|gpt-3\.5-turbo-0301|gpt-3\.5-turbo-0613|gpt-3\.5-turbo-16k-0613|text-davinci-001|text-davinci-002|text-davinci-003|code-davinci-002|gpt-4-vision-preview|gpt-4-1106-preview|gpt-4-0125-preview)["']/gi,
    recommendation: 'Pinned model versions (e.g., gpt-4-0314) may be deprecated or removed. Use stable aliases like gpt-4 or gpt-4o.',
    cwe: 'CWE-1104',
  },

  // Self-hosted LLM on default/insecure port
  {
    id: 'insecure-llm-endpoint-default-port',
    severity: 'medium',
    description: 'LLM endpoint on default/common unprotected port without auth',
    pattern: /(?:base_url|api_base|endpoint|url)\s*[:=]\s*["']https?:\/\/[\w.-]+:(?:11434|8080|7869|5000|1234|3000|8000|8888)(?:\/[^"']*)?["']/gi,
    recommendation: 'Local LLM servers on default ports (Ollama:11434, LM Studio:1234, etc.) often have no authentication. Restrict access or add auth middleware.',
    cwe: 'CWE-306',
  },

  // LLM endpoint with hardcoded IP address
  {
    id: 'insecure-llm-endpoint-hardcoded-ip',
    severity: 'medium',
    description: 'LLM API endpoint uses hardcoded IP address instead of hostname',
    pattern: /(?:base_url|api_base|endpoint|url|host)\s*[:=]\s*["']https?:\/\/(?!127\.0\.0\.1|localhost|0\.0\.0\.0|::1)\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d+)?(?:\/[^"']*)?["']/gi,
    recommendation: 'Hardcoded IP addresses for LLM endpoints prevent certificate validation and complicate rotation. Use DNS hostnames.',
    cwe: 'CWE-1188',
  },
];
