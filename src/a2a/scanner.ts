/**
 * A2A Protocol Security Scanner
 * Validates Google A2A (Agent-to-Agent) protocol configurations for security issues
 */

import * as fs from 'fs';
import * as https from 'https';
import * as http from 'http';
import * as url from 'url';
import type {
  AgentCard,
  A2AScanOptions,
  A2AFinding,
  A2AScanResult,
  SecurityScheme,
  OAuthFlow,
} from './types.js';

// Prompt injection patterns (reused from agent rules)
const INJECTION_PATTERNS = [
  { pattern: /ignore\s+(?:all\s+)?(?:previous|above|prior)\s+(?:instructions?|prompts?|rules?)/gi, desc: 'ignore instructions' },
  { pattern: /(?:forget|disregard|dismiss)\s+(?:everything|all|what)\s+(?:above|before)/gi, desc: 'forget/disregard' },
  { pattern: /you\s+are\s+(?:now|no\s+longer)\s+(?:a|an)/gi, desc: 'role reassignment' },
  { pattern: /(?:jailbreak|bypass\s+safety|unlock\s+unrestricted)/gi, desc: 'jailbreak attempt' },
  { pattern: /system\s*(?:prompt|message)\s*[:=]/gi, desc: 'system prompt override' },
  { pattern: /\{\{.*?\}\}|\$\{.*?\}/g, desc: 'template injection' },
  { pattern: /<script[\s>]|javascript:/gi, desc: 'script injection' },
  { pattern: /(?:exec|eval|spawn|require)\s*\(/gi, desc: 'code execution' },
];

export class A2AScanner {
  private findings: A2AFinding[] = [];
  private options: A2AScanOptions;

  constructor(options: A2AScanOptions = {}) {
    this.options = {
      timeout: 10000,
      ...options,
    };
  }

  /**
   * Run the full A2A security scan
   */
  async scan(): Promise<A2AScanResult> {
    const startTime = Date.now();
    this.findings = [];

    let agentCard: AgentCard | undefined;
    let target = '';

    if (this.options.config) {
      // Load from local file
      target = this.options.config;
      agentCard = this.loadAgentCardFromFile(this.options.config);
    } else if (this.options.url) {
      // Fetch from URL
      target = this.options.url;
      agentCard = await this.fetchAgentCard(this.options.url);
    } else {
      throw new Error('Either --url or --config must be specified');
    }

    const checks = {
      agentCard: false,
      authentication: false,
      permissions: false,
      encryption: false,
      injection: false,
    };

    if (agentCard) {
      checks.agentCard = true;
      this.checkAgentCard(agentCard);

      checks.authentication = true;
      this.checkAuthentication(agentCard);

      checks.permissions = true;
      this.checkPermissionScopes(agentCard);

      checks.injection = true;
      this.checkInjection(agentCard);
    }

    if (this.options.url) {
      checks.encryption = true;
      this.checkEncryption(this.options.url);
    }

    const duration = Date.now() - startTime;
    const summary = this.buildSummary();

    return {
      target,
      timestamp: new Date().toISOString(),
      duration,
      agentCard,
      findings: this.findings,
      summary,
      checks,
    };
  }

  /**
   * Load Agent Card from local JSON file
   */
  private loadAgentCardFromFile(filePath: string): AgentCard | undefined {
    try {
      const content = fs.readFileSync(filePath, 'utf-8');
      const card = JSON.parse(content) as AgentCard;
      return card;
    } catch (err: any) {
      this.addFinding({
        id: 'a2a-card-parse-error',
        category: 'Agent Card',
        severity: 'critical',
        title: 'Agent Card parse error',
        description: `Failed to parse Agent Card: ${err.message}`,
        recommendation: 'Ensure the Agent Card is valid JSON conforming to the A2A specification.',
        cwe: 'CWE-20',
      });
      return undefined;
    }
  }

  /**
   * Fetch Agent Card from /.well-known/agent.json
   */
  async fetchAgentCard(baseUrl: string): Promise<AgentCard | undefined> {
    const cardUrl = baseUrl.replace(/\/+$/, '') + '/.well-known/agent.json';

    try {
      const content = await this.httpGet(cardUrl);
      const card = JSON.parse(content) as AgentCard;
      return card;
    } catch (err: any) {
      this.addFinding({
        id: 'a2a-card-fetch-error',
        category: 'Agent Card',
        severity: 'high',
        title: 'Agent Card not accessible',
        description: `Failed to fetch Agent Card from ${cardUrl}: ${err.message}`,
        recommendation: 'Ensure /.well-known/agent.json is accessible and returns valid JSON.',
        cwe: 'CWE-200',
      });
      return undefined;
    }
  }

  /**
   * Check 1: Agent Card Validation
   */
  private checkAgentCard(card: AgentCard): void {
    // Required fields
    if (!card.name) {
      this.addFinding({
        id: 'a2a-card-missing-name',
        category: 'Agent Card',
        severity: 'medium',
        title: 'Missing agent name',
        description: 'Agent Card does not specify a name.',
        recommendation: 'Add a "name" field to identify the agent.',
      });
    }

    if (!card.url) {
      this.addFinding({
        id: 'a2a-card-missing-url',
        category: 'Agent Card',
        severity: 'high',
        title: 'Missing service endpoint URL',
        description: 'Agent Card does not specify a service endpoint URL.',
        recommendation: 'Add a "url" field with the agent\'s service endpoint.',
        cwe: 'CWE-16',
      });
    }

    if (!card.version) {
      this.addFinding({
        id: 'a2a-card-missing-version',
        category: 'Agent Card',
        severity: 'low',
        title: 'Missing protocol version',
        description: 'Agent Card does not specify a protocol version.',
        recommendation: 'Add a "version" field to declare A2A protocol compatibility.',
      });
    }

    if (!card.skills || card.skills.length === 0) {
      this.addFinding({
        id: 'a2a-card-no-skills',
        category: 'Agent Card',
        severity: 'medium',
        title: 'No skills declared',
        description: 'Agent Card does not declare any skills.',
        recommendation: 'Declare skills to help clients understand agent capabilities.',
      });
    }

    if (!card.description) {
      this.addFinding({
        id: 'a2a-card-missing-description',
        category: 'Agent Card',
        severity: 'info',
        title: 'Missing agent description',
        description: 'Agent Card does not include a description.',
        recommendation: 'Add a "description" field for better discoverability.',
      });
    }

    // Check for overly permissive input/output modes
    if (card.defaultInputModes?.includes('*/*') || card.defaultOutputModes?.includes('*/*')) {
      this.addFinding({
        id: 'a2a-card-wildcard-modes',
        category: 'Agent Card',
        severity: 'medium',
        title: 'Wildcard content type modes',
        description: 'Agent Card accepts all content types (*/*), which may expose it to unexpected input types.',
        recommendation: 'Restrict input/output modes to specific content types the agent supports.',
        cwe: 'CWE-20',
      });
    }

    // Check capabilities
    if (card.capabilities) {
      if (card.capabilities.pushNotifications && !card.securitySchemes) {
        this.addFinding({
          id: 'a2a-card-push-no-auth',
          category: 'Agent Card',
          severity: 'high',
          title: 'Push notifications without authentication',
          description: 'Agent supports push notifications but has no security schemes defined.',
          recommendation: 'Configure authentication to protect push notification endpoints from abuse.',
          cwe: 'CWE-306',
        });
      }
    }

    // Provider info
    if (!card.provider?.organization) {
      this.addFinding({
        id: 'a2a-card-no-provider',
        category: 'Agent Card',
        severity: 'info',
        title: 'No provider information',
        description: 'Agent Card does not identify the provider organization.',
        recommendation: 'Add provider info for trust and accountability.',
      });
    }

    // Check for sensitive info leakage in card
    const cardStr = JSON.stringify(card);
    if (/(?:password|secret|private.?key|api.?key)\s*[:=]\s*(?:["'][^"']+|\\?"[^"\\]+)/gi.test(cardStr)) {
      this.addFinding({
        id: 'a2a-card-credential-leak',
        category: 'Agent Card',
        severity: 'critical',
        title: 'Credentials exposed in Agent Card',
        description: 'Agent Card appears to contain embedded credentials or secrets.',
        recommendation: 'Remove all credentials from the Agent Card. Use proper secret management.',
        cwe: 'CWE-798',
      });
    }
  }

  /**
   * Check 2: Authentication Configuration
   */
  private checkAuthentication(card: AgentCard): void {
    if (!card.securitySchemes || Object.keys(card.securitySchemes).length === 0) {
      this.addFinding({
        id: 'a2a-auth-none',
        category: 'Authentication',
        severity: 'critical',
        title: 'No authentication configured',
        description: 'Agent Card has no securitySchemes defined. The agent is publicly accessible without authentication.',
        recommendation: 'Configure at least one security scheme (OAuth2, API key, or HTTP bearer) as per the A2A specification.',
        cwe: 'CWE-306',
      });
      return;
    }

    if (!card.security || card.security.length === 0) {
      this.addFinding({
        id: 'a2a-auth-not-required',
        category: 'Authentication',
        severity: 'high',
        title: 'Security schemes defined but not required',
        description: 'securitySchemes are defined but the "security" field is empty, meaning auth is not enforced.',
        recommendation: 'Add a "security" array referencing the required security schemes.',
        cwe: 'CWE-862',
      });
    }

    for (const [name, scheme] of Object.entries(card.securitySchemes)) {
      this.checkSecurityScheme(name, scheme);
    }
  }

  /**
   * Validate individual security scheme
   */
  private checkSecurityScheme(name: string, scheme: SecurityScheme): void {
    if (!scheme.type) {
      this.addFinding({
        id: 'a2a-auth-scheme-no-type',
        category: 'Authentication',
        severity: 'high',
        title: `Security scheme "${name}" has no type`,
        description: 'A security scheme must declare its type.',
        recommendation: 'Set "type" to one of: oauth2, apiKey, http, openIdConnect.',
        cwe: 'CWE-287',
      });
      return;
    }

    switch (scheme.type) {
      case 'apiKey':
        this.checkApiKeyScheme(name, scheme);
        break;
      case 'http':
        this.checkHttpScheme(name, scheme);
        break;
      case 'oauth2':
        this.checkOAuth2Scheme(name, scheme);
        break;
      case 'openIdConnect':
        this.checkOIDCScheme(name, scheme);
        break;
      default:
        this.addFinding({
          id: 'a2a-auth-unknown-type',
          category: 'Authentication',
          severity: 'medium',
          title: `Unknown security scheme type: "${scheme.type}"`,
          description: `Security scheme "${name}" uses an unrecognized type.`,
          recommendation: 'Use a standard type: oauth2, apiKey, http, or openIdConnect.',
        });
    }
  }

  private checkApiKeyScheme(name: string, scheme: SecurityScheme): void {
    if (scheme.in === 'query') {
      this.addFinding({
        id: 'a2a-auth-apikey-in-query',
        category: 'Authentication',
        severity: 'high',
        title: `API key in query string ("${name}")`,
        description: 'API key transmitted in URL query parameters can be logged in server logs, browser history, and proxy caches.',
        recommendation: 'Transmit API keys in HTTP headers instead of query parameters.',
        cwe: 'CWE-598',
      });
    }

    if (scheme.in === 'cookie') {
      this.addFinding({
        id: 'a2a-auth-apikey-in-cookie',
        category: 'Authentication',
        severity: 'medium',
        title: `API key in cookie ("${name}")`,
        description: 'API key in cookies may be vulnerable to CSRF attacks.',
        recommendation: 'Prefer HTTP header-based API key transmission with CSRF protections.',
        cwe: 'CWE-352',
      });
    }

    if (!scheme.name) {
      this.addFinding({
        id: 'a2a-auth-apikey-no-name',
        category: 'Authentication',
        severity: 'medium',
        title: `API key scheme "${name}" missing header/param name`,
        description: 'apiKey scheme should specify the "name" field for the header or parameter.',
        recommendation: 'Add a "name" field (e.g., "X-API-Key" or "Authorization").',
      });
    }
  }

  private checkHttpScheme(name: string, scheme: SecurityScheme): void {
    if (scheme.scheme === 'basic') {
      this.addFinding({
        id: 'a2a-auth-basic',
        category: 'Authentication',
        severity: 'high',
        title: `Basic authentication used ("${name}")`,
        description: 'HTTP Basic authentication transmits credentials in Base64 (not encrypted). Vulnerable to credential theft without TLS.',
        recommendation: 'Use Bearer tokens (JWT) or OAuth2 instead of Basic auth.',
        cwe: 'CWE-522',
      });
    }
  }

  private checkOAuth2Scheme(name: string, scheme: SecurityScheme): void {
    if (!scheme.flows) {
      this.addFinding({
        id: 'a2a-auth-oauth2-no-flows',
        category: 'Authentication',
        severity: 'high',
        title: `OAuth2 scheme "${name}" has no flows configured`,
        description: 'OAuth2 security scheme must define at least one flow.',
        recommendation: 'Configure an OAuth2 flow (authorizationCode recommended for user-facing, clientCredentials for server-to-server).',
        cwe: 'CWE-287',
      });
      return;
    }

    // Check for insecure implicit flow
    if (scheme.flows.implicit) {
      this.addFinding({
        id: 'a2a-auth-oauth2-implicit',
        category: 'Authentication',
        severity: 'high',
        title: `OAuth2 implicit flow used ("${name}")`,
        description: 'The OAuth2 implicit flow is deprecated and insecure. Tokens are exposed in URL fragments.',
        recommendation: 'Use authorization code flow with PKCE instead of implicit flow.',
        cwe: 'CWE-346',
      });
    }

    // Check for password flow
    if (scheme.flows.password) {
      this.addFinding({
        id: 'a2a-auth-oauth2-password',
        category: 'Authentication',
        severity: 'medium',
        title: `OAuth2 resource owner password flow used ("${name}")`,
        description: 'The password grant requires the client to handle user credentials directly.',
        recommendation: 'Use authorization code flow with PKCE for better security.',
        cwe: 'CWE-522',
      });
    }

    // Check OAuth2 URLs use HTTPS
    const flows = scheme.flows;
    const urlsToCheck: Array<{ url: string; field: string }> = [];
    for (const [flowName, flow] of Object.entries(flows)) {
      const f = flow as OAuthFlow;
      if (f?.authorizationUrl) urlsToCheck.push({ url: f.authorizationUrl, field: `${flowName}.authorizationUrl` });
      if (f?.tokenUrl) urlsToCheck.push({ url: f.tokenUrl, field: `${flowName}.tokenUrl` });
      if (f?.refreshUrl) urlsToCheck.push({ url: f.refreshUrl, field: `${flowName}.refreshUrl` });
    }

    for (const { url: u, field } of urlsToCheck) {
      if (u && u.startsWith('http://')) {
        this.addFinding({
          id: 'a2a-auth-oauth2-http-url',
          category: 'Authentication',
          severity: 'critical',
          title: `OAuth2 ${field} uses HTTP`,
          description: `OAuth2 endpoint "${u}" uses unencrypted HTTP. Tokens can be intercepted.`,
          recommendation: 'Use HTTPS for all OAuth2 endpoints.',
          cwe: 'CWE-319',
          evidence: u,
        });
      }
    }

    // Check for empty scopes
    for (const [flowName, flow] of Object.entries(flows)) {
      const f = flow as OAuthFlow;
      if (f && (!f.scopes || Object.keys(f.scopes).length === 0)) {
        this.addFinding({
          id: 'a2a-auth-oauth2-no-scopes',
          category: 'Authentication',
          severity: 'medium',
          title: `OAuth2 ${flowName} flow has no scopes`,
          description: 'No scopes are defined, which means authorization is all-or-nothing.',
          recommendation: 'Define granular scopes to implement least-privilege access control.',
          cwe: 'CWE-250',
        });
      }
    }
  }

  private checkOIDCScheme(name: string, scheme: SecurityScheme): void {
    if (!scheme.openIdConnectUrl) {
      this.addFinding({
        id: 'a2a-auth-oidc-no-url',
        category: 'Authentication',
        severity: 'high',
        title: `OpenID Connect scheme "${name}" missing discovery URL`,
        description: 'openIdConnect scheme must specify an openIdConnectUrl.',
        recommendation: 'Add the OpenID Connect discovery endpoint URL.',
        cwe: 'CWE-287',
      });
    } else if (scheme.openIdConnectUrl.startsWith('http://')) {
      this.addFinding({
        id: 'a2a-auth-oidc-http',
        category: 'Authentication',
        severity: 'critical',
        title: `OpenID Connect discovery URL uses HTTP`,
        description: `OIDC endpoint "${scheme.openIdConnectUrl}" uses unencrypted HTTP.`,
        recommendation: 'Use HTTPS for OIDC discovery endpoints.',
        cwe: 'CWE-319',
        evidence: scheme.openIdConnectUrl,
      });
    }
  }

  /**
   * Check 3: Permission Scope Analysis
   */
  private checkPermissionScopes(card: AgentCard): void {
    if (!card.securitySchemes) return;

    // Collect all scopes across all OAuth2 flows
    const allScopes: string[] = [];
    for (const scheme of Object.values(card.securitySchemes)) {
      if (scheme.type === 'oauth2' && scheme.flows) {
        for (const flow of Object.values(scheme.flows)) {
          const f = flow as OAuthFlow;
          if (f?.scopes) {
            allScopes.push(...Object.keys(f.scopes));
          }
        }
      }
    }

    if (allScopes.length === 0) return;

    // Detect overly broad scopes
    const dangerousScopes = [
      { pattern: /^[\*:]$|^all$/i, desc: 'wildcard scope' },
      { pattern: /admin|superuser|root/i, desc: 'admin-level scope' },
      { pattern: /write:?\*|modify:?\*/i, desc: 'wildcard write scope' },
      { pattern: /delete:?\*/i, desc: 'wildcard delete scope' },
      { pattern: /execute|exec|run/i, desc: 'execution scope' },
    ];

    for (const scope of allScopes) {
      for (const { pattern, desc } of dangerousScopes) {
        if (pattern.test(scope)) {
          this.addFinding({
            id: 'a2a-scope-overprivileged',
            category: 'Permissions',
            severity: 'high',
            title: `Overprivileged scope: "${scope}"`,
            description: `The scope "${scope}" (${desc}) grants excessive permissions.`,
            recommendation: 'Apply least-privilege principle. Use granular, specific scopes instead of broad ones.',
            cwe: 'CWE-250',
            evidence: scope,
          });
        }
      }
    }

    // Check scope count (too many scopes = overly complex)
    if (allScopes.length > 20) {
      this.addFinding({
        id: 'a2a-scope-excessive-count',
        category: 'Permissions',
        severity: 'low',
        title: `Excessive number of scopes (${allScopes.length})`,
        description: 'A very large number of scopes may indicate overly complex authorization.',
        recommendation: 'Review and consolidate scopes to simplify authorization management.',
      });
    }

    // Check skills vs required scopes mismatch
    if (card.skills && card.security) {
      const skillCount = card.skills.length;
      if (skillCount > 0 && allScopes.length > skillCount * 3) {
        this.addFinding({
          id: 'a2a-scope-skill-mismatch',
          category: 'Permissions',
          severity: 'medium',
          title: 'Scope-to-skill ratio is high',
          description: `${allScopes.length} scopes for ${skillCount} skills suggests overprivileged access.`,
          recommendation: 'Ensure each scope maps to a specific skill capability.',
          cwe: 'CWE-250',
        });
      }
    }
  }

  /**
   * Check 4: Communication Encryption
   */
  private checkEncryption(agentUrl: string): void {
    const parsed = url.parse(agentUrl);

    if (parsed.protocol === 'http:') {
      this.addFinding({
        id: 'a2a-tls-not-configured',
        category: 'Encryption',
        severity: 'critical',
        title: 'No TLS encryption',
        description: 'Agent endpoint uses HTTP without TLS. All communication including credentials and task data is transmitted in cleartext.',
        recommendation: 'Use HTTPS (TLS 1.2+) for all A2A communication endpoints.',
        cwe: 'CWE-319',
        evidence: agentUrl,
      });
    }

    // Check if endpoint URL is on a non-standard port (may bypass firewalls/proxies)
    if (parsed.port && !['443', '80', '8443'].includes(parsed.port)) {
      this.addFinding({
        id: 'a2a-tls-nonstandard-port',
        category: 'Encryption',
        severity: 'info',
        title: `Non-standard port: ${parsed.port}`,
        description: `Agent endpoint uses non-standard port ${parsed.port}.`,
        recommendation: 'Use standard HTTPS port (443) for production deployments.',
      });
    }

    // Check for localhost/internal endpoints exposed
    if (parsed.hostname && /^(localhost|127\.0\.0\.\d+|0\.0\.0\.0|10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)$/.test(parsed.hostname)) {
      this.addFinding({
        id: 'a2a-tls-internal-endpoint',
        category: 'Encryption',
        severity: 'medium',
        title: 'Internal/localhost endpoint',
        description: `Agent endpoint points to internal address "${parsed.hostname}". This may be a development configuration.`,
        recommendation: 'Use a public domain with proper TLS certificates for production.',
      });
    }
  }

  /**
   * Check 5: Task Message Injection Detection
   */
  private checkInjection(card: AgentCard): void {
    // Check all string fields in Agent Card for injection patterns
    const stringsToCheck = this.extractStrings(card);

    for (const { value, path } of stringsToCheck) {
      for (const { pattern, desc } of INJECTION_PATTERNS) {
        pattern.lastIndex = 0;
        const match = pattern.exec(value);
        if (match) {
          this.addFinding({
            id: 'a2a-injection-detected',
            category: 'Injection',
            severity: 'critical',
            title: `Prompt injection in Agent Card (${desc})`,
            description: `Potential prompt injection detected in "${path}": "${match[0]}"`,
            recommendation: 'Remove prompt injection patterns from Agent Card content. Validate all user-facing text.',
            cwe: 'CWE-77',
            evidence: match[0],
          });
        }
      }
    }

    // Check for suspicious skill descriptions that could manipulate client agents
    if (card.skills) {
      for (const skill of card.skills) {
        if (skill.description && skill.description.length > 500) {
          this.addFinding({
            id: 'a2a-injection-long-description',
            category: 'Injection',
            severity: 'medium',
            title: `Unusually long skill description: "${skill.name || skill.id}"`,
            description: 'Very long skill descriptions may be used to smuggle hidden instructions to client agents.',
            recommendation: 'Keep skill descriptions concise. Review for hidden instructions.',
            cwe: 'CWE-94',
          });
        }

        // Check for examples that look like injection
        if (skill.examples) {
          for (const example of skill.examples) {
            for (const { pattern, desc } of INJECTION_PATTERNS) {
              pattern.lastIndex = 0;
              if (pattern.test(example)) {
                this.addFinding({
                  id: 'a2a-injection-in-example',
                  category: 'Injection',
                  severity: 'high',
                  title: `Injection pattern in skill example (${desc})`,
                  description: `Skill "${skill.name || skill.id}" has an example containing injection pattern.`,
                  recommendation: 'Remove or sanitize injection patterns from skill examples.',
                  cwe: 'CWE-77',
                  evidence: example.substring(0, 100),
                });
              }
            }
          }
        }
      }
    }
  }

  /**
   * Extract all string values from an object with their paths
   */
  private extractStrings(obj: any, prefix = ''): Array<{ value: string; path: string }> {
    const results: Array<{ value: string; path: string }> = [];

    if (typeof obj === 'string') {
      results.push({ value: obj, path: prefix });
    } else if (Array.isArray(obj)) {
      obj.forEach((item, i) => {
        results.push(...this.extractStrings(item, `${prefix}[${i}]`));
      });
    } else if (obj && typeof obj === 'object') {
      for (const [key, value] of Object.entries(obj)) {
        results.push(...this.extractStrings(value, prefix ? `${prefix}.${key}` : key));
      }
    }

    return results;
  }

  /**
   * Simple HTTP GET
   */
  private httpGet(targetUrl: string): Promise<string> {
    return new Promise((resolve, reject) => {
      const parsed = url.parse(targetUrl);
      const client = parsed.protocol === 'https:' ? https : http;
      const timeout = this.options.timeout || 10000;

      const req = client.get(targetUrl, { timeout }, (res) => {
        if (res.statusCode && res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
          this.httpGet(res.headers.location).then(resolve).catch(reject);
          return;
        }

        if (res.statusCode !== 200) {
          reject(new Error(`HTTP ${res.statusCode}`));
          return;
        }

        let data = '';
        res.on('data', (chunk) => { data += chunk; });
        res.on('end', () => resolve(data));
        res.on('error', reject);
      });

      req.on('error', reject);
      req.on('timeout', () => {
        req.destroy();
        reject(new Error('Request timeout'));
      });
    });
  }

  private addFinding(finding: A2AFinding): void {
    this.findings.push(finding);
  }

  private buildSummary() {
    const summary = { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 };
    for (const f of this.findings) {
      summary[f.severity]++;
      summary.total++;
    }
    return summary;
  }
}
