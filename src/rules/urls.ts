import type { Rule } from "../types.js";

/**
 * Suspicious URL and Network Detection Rules
 * Detects URLs, IPs, and patterns commonly used for data exfiltration and C2
 */

export const rules: Rule[] = [
  // ============================================
  // Data Exfiltration Services
  // ============================================
  {
    id: 'url-webhook-site',
    severity: 'critical',
    description: 'webhook.site URL detected (common exfiltration endpoint)',
    pattern: /https?:\/\/webhook\.site\/[a-zA-Z0-9-]+/gi,
    recommendation: 'Remove webhook.site URLs. This service is commonly used for data exfiltration.',
  },
  {
    id: 'url-requestbin',
    severity: 'critical',
    description: 'RequestBin URL detected (data collection service)',
    pattern: /https?:\/\/(?:[a-z0-9]+\.)?requestbin\.(?:com|net|io)/gi,
    recommendation: 'Remove RequestBin URLs. This service is used for data collection.',
  },
  {
    id: 'url-postbin',
    severity: 'critical',
    description: 'Postbin URL detected (data collection service)',
    pattern: /https?:\/\/(?:www\.)?postb\.in\/[a-zA-Z0-9]+/gi,
    recommendation: 'Remove Postbin URLs. This service is used for data collection.',
  },
  {
    id: 'url-hookbin',
    severity: 'critical',
    description: 'Hookbin URL detected (webhook testing)',
    pattern: /https?:\/\/hookbin\.com\/[a-zA-Z0-9]+/gi,
    recommendation: 'Remove Hookbin URLs. This service is used for webhook testing and data collection.',
  },
  {
    id: 'url-beeceptor',
    severity: 'warning',
    description: 'Beeceptor mock API URL detected',
    pattern: /https?:\/\/[a-z0-9-]+\.free\.beeceptor\.com/gi,
    recommendation: 'Review Beeceptor usage. Ensure it is not used for data exfiltration.',
  },
  {
    id: 'url-mockbin',
    severity: 'warning',
    description: 'Mockbin URL detected',
    pattern: /https?:\/\/mockbin\.(?:org|io)\/[a-zA-Z0-9]+/gi,
    recommendation: 'Review Mockbin usage for potential data exfiltration.',
  },
  {
    id: 'url-webhook-online',
    severity: 'critical',
    description: 'Webhook.online URL detected',
    pattern: /https?:\/\/(?:[a-z0-9]+\.)?webhook\.online/gi,
    recommendation: 'Remove webhook.online URLs. Potential data exfiltration endpoint.',
  },
  {
    id: 'url-canarytokens',
    severity: 'warning',
    description: 'Canary token URL detected',
    pattern: /https?:\/\/canarytokens\.com\/[a-zA-Z0-9/]+/gi,
    recommendation: 'Review canary token usage. May indicate security monitoring or testing.',
  },

  // ============================================
  // Tunnel Services
  // ============================================
  {
    id: 'url-ngrok',
    severity: 'critical',
    description: 'ngrok tunnel URL detected',
    pattern: /https?:\/\/[a-z0-9-]+\.ngrok(?:-free)?\.(?:io|app|dev)/gi,
    recommendation: 'ngrok URLs can expose local services. Ensure this is intentional and not malicious.',
  },
  {
    id: 'url-localtunnel',
    severity: 'warning',
    description: 'LocalTunnel URL detected',
    pattern: /https?:\/\/[a-z0-9-]+\.loca\.lt/gi,
    recommendation: 'Review LocalTunnel usage. Tunnels can expose internal services.',
  },
  {
    id: 'url-serveo',
    severity: 'warning',
    description: 'Serveo tunnel URL detected',
    pattern: /https?:\/\/[a-z0-9-]+\.serveo\.net/gi,
    recommendation: 'Review Serveo tunnel usage.',
  },
  {
    id: 'url-cloudflare-tunnel',
    severity: 'info',
    description: 'Cloudflare Tunnel URL detected',
    pattern: /https?:\/\/[a-z0-9-]+\.trycloudflare\.com/gi,
    recommendation: 'Verify Cloudflare Tunnel is authorized and intended.',
  },
  {
    id: 'url-pagekite',
    severity: 'warning',
    description: 'PageKite tunnel URL detected',
    pattern: /https?:\/\/[a-z0-9-]+\.pagekite\.me/gi,
    recommendation: 'Review PageKite tunnel usage.',
  },
  {
    id: 'url-bore-tunnel',
    severity: 'warning',
    description: 'Bore.pub tunnel URL detected',
    pattern: /https?:\/\/[a-z0-9-]+\.bore\.pub/gi,
    recommendation: 'Review bore tunnel usage.',
  },

  // ============================================
  // Security Testing Tools (OOB)
  // ============================================
  {
    id: 'url-burp-collaborator',
    severity: 'critical',
    description: 'Burp Collaborator URL detected (security testing tool)',
    pattern: /https?:\/\/[a-z0-9]+\.burpcollaborator\.net/gi,
    recommendation: 'Remove Burp Collaborator URLs. This indicates security testing or potential attack.',
  },
  {
    id: 'url-interactsh',
    severity: 'critical',
    description: 'Interactsh URL detected (OOB testing tool)',
    pattern: /https?:\/\/[a-z0-9]+\.(?:oast\.pro|oast\.live|oast\.site|oast\.online|oast\.fun|oast\.me|interact\.sh)/gi,
    recommendation: 'Remove Interactsh URLs. This is an out-of-band testing tool often used in attacks.',
  },
  {
    id: 'url-dnslog',
    severity: 'critical',
    description: 'DNSLog URL detected (OOB DNS logging)',
    pattern: /[a-z0-9]+\.(?:dnslog\.cn|ceye\.io|xip\.io)/gi,
    recommendation: 'Remove DNSLog URLs. Used for out-of-band data exfiltration.',
  },

  // ============================================
  // Paste Sites
  // ============================================
  {
    id: 'url-pastebin',
    severity: 'warning',
    description: 'Pastebin URL detected',
    pattern: /https?:\/\/(?:www\.)?pastebin\.com\/(?:raw\/)?[a-zA-Z0-9]+/gi,
    recommendation: 'Review pastebin content. It may contain malicious payloads.',
  },
  {
    id: 'url-hastebin',
    severity: 'warning',
    description: 'Hastebin URL detected',
    pattern: /https?:\/\/(?:www\.)?hastebin\.com\/(?:raw\/)?[a-zA-Z0-9]+/gi,
    recommendation: 'Review hastebin content for malicious payloads.',
  },
  {
    id: 'url-ghostbin',
    severity: 'warning',
    description: 'Ghostbin URL detected',
    pattern: /https?:\/\/ghostbin\.(?:co|com)\/paste\/[a-zA-Z0-9]+/gi,
    recommendation: 'Review ghostbin content for malicious payloads.',
  },
  {
    id: 'url-privatebin',
    severity: 'info',
    description: 'PrivateBin URL detected',
    pattern: /https?:\/\/privatebin\.[a-z]+\/\?[a-zA-Z0-9]+/gi,
    recommendation: 'Review PrivateBin content if suspicious.',
  },
  {
    id: 'url-rentry',
    severity: 'warning',
    description: 'Rentry.co URL detected',
    pattern: /https?:\/\/rentry\.co\/[a-zA-Z0-9]+/gi,
    recommendation: 'Review Rentry content for potentially malicious payloads.',
  },

  // ============================================
  // Communication Services (Potential Exfil)
  // ============================================
  {
    id: 'url-discord-webhook',
    severity: 'warning',
    description: 'Discord webhook URL detected',
    pattern: /https?:\/\/(?:ptb\.|canary\.)?discord(?:app)?\.com\/api\/webhooks\/[0-9]+\/[A-Za-z0-9_-]+/gi,
    recommendation: 'Ensure Discord webhooks are not used for data exfiltration. Keep webhook URLs secret.',
  },
  {
    id: 'url-telegram-bot',
    severity: 'warning',
    description: 'Telegram Bot API URL detected',
    pattern: /https?:\/\/api\.telegram\.org\/bot[0-9]+:[A-Za-z0-9_-]+/gi,
    recommendation: 'Ensure Telegram bot tokens are not exposed. Review bot usage.',
  },
  {
    id: 'url-slack-webhook',
    severity: 'warning',
    description: 'Slack webhook URL in code',
    pattern: /https?:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[a-zA-Z0-9]+/gi,
    recommendation: 'Move Slack webhook URLs to environment variables.',
  },

  // ============================================
  // File Sharing (Potential Payload Hosting)
  // ============================================
  {
    id: 'url-file-io',
    severity: 'warning',
    description: 'file.io URL detected (anonymous file sharing)',
    pattern: /https?:\/\/file\.io\/[a-zA-Z0-9]+/gi,
    recommendation: 'Review file.io usage. Anonymous file sharing can host malicious payloads.',
  },
  {
    id: 'url-transfer-sh',
    severity: 'warning',
    description: 'transfer.sh URL detected',
    pattern: /https?:\/\/transfer\.sh\/[a-zA-Z0-9/]+/gi,
    recommendation: 'Review transfer.sh usage for potential malicious file downloads.',
  },
  {
    id: 'url-anonfiles',
    severity: 'warning',
    description: 'AnonFiles URL detected',
    pattern: /https?:\/\/(?:www\.)?anonfiles\.com\/[a-zA-Z0-9]+/gi,
    recommendation: 'Review anonfiles usage. Often used for malware distribution.',
  },
  {
    id: 'url-gofile',
    severity: 'warning',
    description: 'GoFile URL detected',
    pattern: /https?:\/\/gofile\.io\/d\/[a-zA-Z0-9]+/gi,
    recommendation: 'Review GoFile usage for potential malicious content.',
  },
  {
    id: 'url-catbox',
    severity: 'warning',
    description: 'Catbox file hosting URL detected',
    pattern: /https?:\/\/files\.catbox\.moe\/[a-zA-Z0-9.]+/gi,
    recommendation: 'Review Catbox usage for potential malicious file hosting.',
  },

  // ============================================
  // IP Addresses
  // ============================================
  {
    id: 'url-raw-ip-http',
    severity: 'warning',
    description: 'Raw IP address in HTTP URL',
    pattern: /https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d+)?/g,
    recommendation: 'Use domain names instead of raw IP addresses. Raw IPs may indicate C2 servers.',
  },
  {
    id: 'url-private-ip',
    severity: 'info',
    description: 'Private IP address reference',
    pattern: /(?:https?:\/\/)?(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})/g,
    recommendation: 'Internal IP references may leak infrastructure details.',
  },
  {
    id: 'url-localhost',
    severity: 'info',
    description: 'Localhost URL in code',
    pattern: /https?:\/\/(?:localhost|127\.0\.0\.1)(?::\d+)?/g,
    recommendation: 'Ensure localhost URLs are only used in development contexts.',
  },

  // ============================================
  // Tor & Anonymization
  // ============================================
  {
    id: 'url-tor-onion',
    severity: 'critical',
    description: 'Tor .onion address detected',
    pattern: /[a-z2-7]{16,56}\.onion/gi,
    recommendation: 'Remove Tor onion addresses. These indicate dark web communication.',
  },
  {
    id: 'url-tor-proxy',
    severity: 'warning',
    description: 'Tor proxy service URL detected',
    pattern: /https?:\/\/[a-z0-9]+\.(?:tor2web|onion\.to|onion\.ws)/gi,
    recommendation: 'Review Tor proxy usage. May indicate anonymous communication.',
  },
  {
    id: 'url-i2p',
    severity: 'critical',
    description: 'I2P address detected',
    pattern: /[a-z0-9]+\.i2p/gi,
    recommendation: 'Remove I2P addresses. These indicate anonymous network usage.',
  },

  // ============================================
  // DNS Exfiltration Patterns
  // ============================================
  {
    id: 'dns-exfil-pattern',
    severity: 'warning',
    description: 'Potential DNS exfiltration pattern',
    pattern: /[a-f0-9]{32,}\.[a-z0-9-]+\.[a-z]{2,}/gi,
    recommendation: 'Very long hex subdomains may indicate DNS-based data exfiltration.',
  },
  {
    id: 'dns-txt-lookup',
    severity: 'warning',
    description: 'DNS TXT record lookup pattern',
    pattern: /dns\.(?:resolve|lookup).*TXT|nslookup.*-type=txt/gi,
    recommendation: 'DNS TXT lookups can be used for C2 communication.',
  },

  // ============================================
  // WebSocket Endpoints
  // ============================================
  {
    id: 'url-websocket-raw-ip',
    severity: 'warning',
    description: 'WebSocket connection to raw IP',
    pattern: /wss?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/g,
    recommendation: 'WebSocket connections to raw IPs may indicate C2 communication.',
  },
  {
    id: 'url-websocket-suspicious',
    severity: 'info',
    description: 'WebSocket connection detected',
    pattern: /wss?:\/\/[a-z0-9.-]+(?::\d+)?\/[a-z0-9/._-]*/gi,
    recommendation: 'Review WebSocket endpoints for unauthorized external connections.',
  },

  // ============================================
  // More Webhook & Request Capture Services
  // ============================================
  {
    id: 'url-hookdeck',
    severity: 'warning',
    description: 'Hookdeck webhook URL detected',
    pattern: /https?:\/\/[a-z0-9-]+\.hookdeck\.com/gi,
    recommendation: 'Review Hookdeck usage. Webhook services can be used for data exfiltration.',
  },
  {
    id: 'url-runscope',
    severity: 'warning',
    description: 'Runscope URL detected (API testing)',
    pattern: /https?:\/\/[a-z0-9-]+\.runscope\.net/gi,
    recommendation: 'Review Runscope usage. API testing tools can capture sensitive data.',
  },
  {
    id: 'url-requestcatcher',
    severity: 'critical',
    description: 'RequestCatcher URL detected',
    pattern: /https?:\/\/[a-z0-9-]+\.requestcatcher\.com/gi,
    recommendation: 'Remove RequestCatcher URLs. This service captures HTTP requests.',
  },
  {
    id: 'url-webhook-relay',
    severity: 'warning',
    description: 'Webhook Relay URL detected',
    pattern: /https?:\/\/[a-z0-9-]+\.webhookrelay\.com/gi,
    recommendation: 'Review Webhook Relay usage for potential data exfiltration.',
  },
  {
    id: 'url-smee',
    severity: 'warning',
    description: 'Smee.io webhook proxy detected',
    pattern: /https?:\/\/smee\.io\/[a-zA-Z0-9]+/gi,
    recommendation: 'Smee.io proxies webhooks. Ensure it is not used for exfiltration.',
  },
  {
    id: 'url-typedwebhook',
    severity: 'warning',
    description: 'TypedWebhook URL detected',
    pattern: /https?:\/\/typedwebhook\.tools\/[a-z0-9]+/gi,
    recommendation: 'Review TypedWebhook usage. Webhook testing can capture sensitive data.',
  },
  {
    id: 'url-webhook-test',
    severity: 'warning',
    description: 'Webhook.test URL detected',
    pattern: /https?:\/\/[a-z0-9-]+\.webhook\.test/gi,
    recommendation: 'Review webhook testing service usage.',
  },
  {
    id: 'url-ptsv2',
    severity: 'critical',
    description: 'PTSV2 (Post Test Server V2) URL detected',
    pattern: /https?:\/\/ptsv2\.com\/t\/[a-z0-9-]+/gi,
    recommendation: 'Remove PTSV2 URLs. This service is used to capture POST requests.',
  },

  // ============================================
  // AI Agent Credential Theft Patterns
  // (Discovered via Moltbook/eudaemon_0 research)
  // ============================================
  {
    id: 'agent-env-exfil-clawdbot',
    severity: 'critical',
    description: 'ClawdBot/OpenClaw credential path with external URL',
    pattern: /(?:~\/)?\.clawdbot\/.env.*(?:webhook|ngrok|requestbin|http)/gi,
    recommendation: 'CRITICAL: Pattern matches ClawdBot credential theft. Remove external URLs near .env references.',
  },
  {
    id: 'agent-env-exfil-claude',
    severity: 'critical',
    description: 'Claude Desktop config with external URL',
    pattern: /claude_desktop_config\.json.*(?:webhook|ngrok|requestbin|http)|(?:webhook|ngrok|http).*claude_desktop_config/gi,
    recommendation: 'CRITICAL: Pattern suggests Claude Desktop credential theft attempt.',
  },
  {
    id: 'agent-env-exfil-cursor',
    severity: 'critical',
    description: 'Cursor config with external URL',
    pattern: /\.cursor.*(?:mcp|config).*(?:webhook|ngrok|http)|(?:webhook|http).*\.cursor/gi,
    recommendation: 'CRITICAL: Pattern suggests Cursor IDE credential theft attempt.',
  },
  {
    id: 'agent-config-read-post',
    severity: 'critical',
    description: 'Reading agent config followed by HTTP POST',
    pattern: /(?:readFile|fs\.read|cat).*(?:\.env|config\.json|credentials).*(?:fetch|axios|http\.request|POST)/gi,
    recommendation: 'CRITICAL: Code reads config files and makes HTTP requests. Likely data exfiltration.',
  },

  // ============================================
  // Suspicious Domains
  // ============================================
  {
    id: 'url-duckdns',
    severity: 'warning',
    description: 'DuckDNS dynamic DNS detected',
    pattern: /https?:\/\/[a-z0-9-]+\.duckdns\.org/gi,
    recommendation: 'Dynamic DNS services are often used by attackers. Review usage.',
  },
  {
    id: 'url-no-ip',
    severity: 'warning',
    description: 'No-IP dynamic DNS detected',
    pattern: /https?:\/\/[a-z0-9-]+\.(?:no-ip|noip|ddns)\.(?:com|org|net|biz)/gi,
    recommendation: 'Dynamic DNS services are often used by attackers. Review usage.',
  },
  {
    id: 'url-pipedream',
    severity: 'warning',
    description: 'Pipedream URL detected',
    pattern: /https?:\/\/[a-z0-9-]+\.m\.pipedream\.net/gi,
    recommendation: 'Review Pipedream webhook usage. Ensure it is not used for data exfiltration.',
  },

  // ============================================
  // Additional Exfiltration & Webhook Services
  // (Added per Issue #12: Enhance suspicious URL detection)
  // ============================================
  {
    id: 'url-oastify',
    severity: 'critical',
    description: 'Burp Suite OOB (oastify.com) URL detected',
    pattern: /https?:\/\/[a-z0-9]+\.oastify\.com/gi,
    recommendation: 'Remove oastify.com URLs. This is Burp Suite\'s out-of-band testing domain.',
  },
  {
    id: 'url-webhook-cool',
    severity: 'critical',
    description: 'Webhook.cool URL detected',
    pattern: /https?:\/\/(?:[a-z0-9-]+\.)?webhook\.cool/gi,
    recommendation: 'Remove webhook.cool URLs. Webhook capture service used for exfiltration.',
  },
  {
    id: 'url-pipedream-eo',
    severity: 'warning',
    description: 'Pipedream (eo API) URL detected',
    pattern: /https?:\/\/[a-z0-9-]+\.(?:m\.pipedream\.net|eo\.pipedream\.net|pipedream\.com\/sources)/gi,
    recommendation: 'Review Pipedream endpoint usage for potential data exfiltration.',
  },
  {
    id: 'url-putsreq',
    severity: 'warning',
    description: 'PutsReq URL detected',
    pattern: /https?:\/\/putsreq\.com\/[a-zA-Z0-9]+/gi,
    recommendation: 'Review PutsReq usage. HTTP request capture service.',
  },
  {
    id: 'url-free-beeceptor',
    severity: 'warning',
    description: 'Beeceptor URL detected (any subdomain)',
    pattern: /https?:\/\/[a-z0-9-]+\.beeceptor\.com/gi,
    recommendation: 'Review Beeceptor usage. Mock API endpoints can capture exfiltrated data.',
  },
  {
    id: 'url-tailscale-funnel',
    severity: 'warning',
    description: 'Tailscale Funnel URL detected',
    pattern: /https?:\/\/[a-z0-9-]+\.ts\.net/gi,
    recommendation: 'Review Tailscale Funnel usage. Can expose local services externally.',
  },
  {
    id: 'url-loca-tunnel',
    severity: 'warning',
    description: 'Localhost.run tunnel URL detected',
    pattern: /https?:\/\/[a-z0-9]+\.lhr\.life/gi,
    recommendation: 'Review localhost.run tunnel usage. Exposes local services externally.',
  },
  {
    id: 'url-expose-dev',
    severity: 'warning',
    description: 'Expose.dev tunnel URL detected',
    pattern: /https?:\/\/[a-z0-9-]+\.sharedwithexpose\.com/gi,
    recommendation: 'Review Expose tunnel usage.',
  },
  {
    id: 'url-bin-sh',
    severity: 'critical',
    description: 'httpbin or similar HTTP echo service detected',
    pattern: /https?:\/\/(?:www\.)?httpbin\.org\/(?:post|get|anything)/gi,
    recommendation: 'Review httpbin usage. Echo services can capture and reflect exfiltrated data.',
  },

  // ============================================
  // Crypto Mining / Malicious
  // ============================================
  {
    id: 'url-crypto-mining',
    severity: 'critical',
    description: 'Cryptocurrency mining pool URL detected',
    pattern: /(?:stratum\+tcp|stratum2\+tcp):\/\/[a-z0-9.-]+/gi,
    recommendation: 'Remove crypto mining pool URLs. This may indicate cryptojacking.',
  },
  {
    id: 'url-coinhive',
    severity: 'critical',
    description: 'CoinHive or mining script reference',
    pattern: /coinhive|coin-hive|cryptonight|monero.*(?:pool|miner)/gi,
    recommendation: 'Remove cryptocurrency mining references.',
  },
];


// CommonJS compatibility
module.exports = { rules };
