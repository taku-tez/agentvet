import type { Rule } from "../types.js";

/**
 * Data Exfiltration Hardening Rules
 * Extended detection for sophisticated data exfiltration techniques.
 */

export const rules: Rule[] = [
  {
    id: 'exfil-base64-in-url',
    severity: 'high',
    description: 'Base64-encoded data embedded in URL parameters (potential data exfiltration)',
    pattern: /https?:\/\/[^\s"']+[?&][a-zA-Z_]+=(?:[A-Za-z0-9+/]{20,}={0,2})/g,
    recommendation: 'Inspect URLs with long Base64-encoded parameters. This pattern is commonly used to exfiltrate data via URL query strings.',
  },
  {
    id: 'exfil-dns-tunneling',
    severity: 'high',
    description: 'DNS tunneling pattern detected (data exfiltration via DNS queries)',
    pattern: /(?:dig|nslookup|host|drill)\s+[^\n]*(?:\$\{|\$\(|`[^`]*\$)/gi,
    recommendation: 'DNS queries with variable expansion can tunnel data out via DNS. Block dynamic DNS lookups.',
  },
  {
    id: 'exfil-steganography',
    severity: 'high',
    description: 'Steganography tool usage detected (data hidden in images/files)',
    pattern: /(?:steghide\s+(?:embed|extract)|exiftool\s+[^\n]*(?:-[A-Z]+=|--comment)|(?:openstego|stegano|stegosuite|snow)\s|convert\s+[^\n]*(?:-comment|-set\s+comment)|identify\s+-verbose|strings\s+[^\n]*\.(?:png|jpg|jpeg|gif|bmp|tiff))/gi,
    recommendation: 'Steganography tools can hide data in images/files for covert exfiltration. Review and restrict usage.',
  },
];

// CommonJS compatibility
module.exports = { rules };
