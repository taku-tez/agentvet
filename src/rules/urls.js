/**
 * Suspicious URL Detection Rules
 * Detects URLs commonly used for data exfiltration
 */

const rules = [
  {
    id: 'url-webhook-site',
    severity: 'critical',
    description: 'webhook.site URL detected (common exfiltration endpoint)',
    pattern: /https?:\/\/webhook\.site\/[a-zA-Z0-9-]+/gi,
    recommendation: 'Remove webhook.site URLs. This service is commonly used for data exfiltration.',
  },
  {
    id: 'url-ngrok',
    severity: 'critical',
    description: 'ngrok tunnel URL detected',
    pattern: /https?:\/\/[a-z0-9-]+\.ngrok(?:-free)?\.(?:io|app|dev)/gi,
    recommendation: 'ngrok URLs can expose local services. Ensure this is intentional and not malicious.',
  },
  {
    id: 'url-pastebin',
    severity: 'warning',
    description: 'Pastebin URL detected',
    pattern: /https?:\/\/(?:www\.)?pastebin\.com\/(?:raw\/)?[a-zA-Z0-9]+/gi,
    recommendation: 'Review pastebin content. It may contain malicious payloads.',
  },
  {
    id: 'url-requestbin',
    severity: 'critical',
    description: 'RequestBin URL detected (data collection service)',
    pattern: /https?:\/\/(?:[a-z0-9]+\.)?requestbin\.(?:com|net|io)/gi,
    recommendation: 'Remove RequestBin URLs. This service is used for data collection.',
  },
  {
    id: 'url-pipedream',
    severity: 'warning',
    description: 'Pipedream URL detected',
    pattern: /https?:\/\/[a-z0-9-]+\.m\.pipedream\.net/gi,
    recommendation: 'Review Pipedream webhook usage. Ensure it is not used for data exfiltration.',
  },
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
    id: 'url-postbin',
    severity: 'critical',
    description: 'Postbin URL detected (data collection service)',
    pattern: /https?:\/\/(?:www\.)?postb\.in\/[a-zA-Z0-9]+/gi,
    recommendation: 'Remove Postbin URLs. This service is used for data collection.',
  },
  {
    id: 'url-beeceptor',
    severity: 'warning',
    description: 'Beeceptor mock API URL detected',
    pattern: /https?:\/\/[a-z0-9-]+\.free\.beeceptor\.com/gi,
    recommendation: 'Review Beeceptor usage. Ensure it is not used for data exfiltration.',
  },
  {
    id: 'url-hookbin',
    severity: 'critical',
    description: 'Hookbin URL detected (webhook testing)',
    pattern: /https?:\/\/hookbin\.com\/[a-zA-Z0-9]+/gi,
    recommendation: 'Remove Hookbin URLs. This service is used for webhook testing and data collection.',
  },
];

module.exports = { rules };
