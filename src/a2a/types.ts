/**
 * A2A Protocol Types for Security Scanner
 * Based on A2A Protocol Specification RC v1.0
 */

export interface AgentCard {
  name?: string;
  description?: string;
  url?: string;
  version?: string;
  capabilities?: AgentCapabilities;
  skills?: AgentSkill[];
  securitySchemes?: Record<string, SecurityScheme>;
  security?: SecurityRequirement[];
  defaultInputModes?: string[];
  defaultOutputModes?: string[];
  provider?: AgentProvider;
  documentationUrl?: string;
  supportsAuthenticatedExtendedCard?: boolean;
  // Legacy field name
  [key: string]: any;
}

export interface AgentCapabilities {
  streaming?: boolean;
  pushNotifications?: boolean;
  stateTransitionHistory?: boolean;
  extendedAgentCard?: boolean;
  [key: string]: any;
}

export interface AgentSkill {
  id?: string;
  name?: string;
  description?: string;
  tags?: string[];
  examples?: string[];
  inputModes?: string[];
  outputModes?: string[];
  [key: string]: any;
}

export interface SecurityScheme {
  type: string; // 'oauth2' | 'apiKey' | 'http' | 'openIdConnect'
  description?: string;
  scheme?: string; // for http type: 'bearer', 'basic'
  bearerFormat?: string;
  in?: string; // for apiKey: 'header' | 'query' | 'cookie'
  name?: string; // for apiKey
  flows?: OAuthFlows;
  openIdConnectUrl?: string;
  [key: string]: any;
}

export interface OAuthFlows {
  implicit?: OAuthFlow;
  password?: OAuthFlow;
  clientCredentials?: OAuthFlow;
  authorizationCode?: OAuthFlow;
}

export interface OAuthFlow {
  authorizationUrl?: string;
  tokenUrl?: string;
  refreshUrl?: string;
  scopes?: Record<string, string>;
}

export interface SecurityRequirement {
  [schemeName: string]: string[];
}

export interface AgentProvider {
  organization?: string;
  url?: string;
  [key: string]: any;
}

export interface A2AScanOptions {
  url?: string;
  config?: string;
  verbose?: boolean;
  format?: 'text' | 'json';
  timeout?: number;
}

export interface A2AFinding {
  id: string;
  category: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  title: string;
  description: string;
  recommendation: string;
  evidence?: string;
  cwe?: string;
}

export interface A2AScanResult {
  target: string;
  timestamp: string;
  duration: number;
  agentCard?: AgentCard;
  findings: A2AFinding[];
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
    total: number;
  };
  checks: {
    agentCard: boolean;
    authentication: boolean;
    permissions: boolean;
    encryption: boolean;
    injection: boolean;
  };
}
