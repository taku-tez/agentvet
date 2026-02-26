import type { Rule } from "../types.js";

/**
 * Claude Computer Use API Attack Detection Rules
 * Detects malicious usage patterns of Claude's Computer Use API and similar
 * AI-driven GUI automation tools (Anthropic Computer Use, Browser Use, etc.)
 *
 * Computer Use gives AI agents direct control over a computer's keyboard,
 * mouse, screen, and shell. This creates powerful attack surfaces:
 * - Credential theft via keyboard input capture or screenshot analysis
 * - Unauthorized browser-based exfiltration (navigate to attacker URL)
 * - Screen content scraping for secrets
 * - Malicious file operations via GUI automation
 *
 * References:
 * - Anthropic Claude Computer Use (2024) security guidance
 * - "Computer Use Attacks" - Embrace The Red (2024)
 * - OWASP LLM Top 10 2025 - LLM01: Prompt Injection
 * - CWE-77: Improper Neutralization of Special Elements Used in a Command
 */

export const rules: Rule[] = [
  // ============================================
  // Computer Use Tool Usage Detection
  // ============================================
  {
    id: 'computer-use-detected',
    severity: 'info',
    description: 'Claude Computer Use tool detected in agent configuration',
    pattern: /(?:"type"\s*:\s*"computer(?:_20241022|_20250124)?"|tool[_-]?type\s*[=:]\s*["']computer["']|ComputerTool\s*\(|computer_use|AnthropicBeta\.COMPUTER_USE)/gi,
    recommendation: 'Computer Use grants AI agents direct keyboard/mouse/screen access. Ensure this is intentional and operating in a sandboxed environment.',
    category: 'computer-use',
  },

  // ============================================
  // Screenshot-based Exfiltration
  // ============================================
  {
    id: 'computer-use-screenshot-exfil',
    severity: 'critical',
    description: 'Screenshot captured and sent to external URL (potential screen scraping exfiltration)',
    pattern: /(?:screenshot|take_screenshot|capture_screen|ScreenCapture)\s*\([^)]*\)[\s\S]{0,500}(?:fetch|axios|http\.post|requests\.post|curl|upload|send)/gi,
    recommendation: 'CRITICAL: Screenshot captured then transmitted externally. This pattern is used for screen-scraping credential theft. Verify the destination URL is authorized.',
    category: 'computer-use',
    cwe: 'CWE-200',
  },

  // ============================================
  // Keyboard Input Injection
  // ============================================
  {
    id: 'computer-use-keystroke-injection',
    severity: 'critical',
    description: 'Keyboard input injection with suspicious content (credential entry or command execution)',
    pattern: /(?:key(?:stroke|board)?(?:_input|Input)|type_text|xdotool\s+type|send_keys|typewrite|keyboard\.type|keyboard\.write)\s*[(\s]*['"`]?[^'"\n)]{0,200}(?:password|passwd|token|secret|api.?key|sudo|rm\s+-rf|wget|curl|bash|sh\s+-c)/gi,
    recommendation: 'CRITICAL: Keyboard injection with sensitive content detected. Keystroke injection can enter credentials, run commands, or exfiltrate data.',
    category: 'computer-use',
    cwe: 'CWE-77',
  },

  // ============================================
  // Unauthorized Browser Navigation
  // ============================================
  {
    id: 'computer-use-browser-nav-exfil',
    severity: 'critical',
    description: 'Computer Use navigating browser to potential exfiltration endpoint',
    pattern: /(?:navigate|goto|browser_navigate|computer_use.*?navigate|url_bar|address\s*bar)[^;\n]{0,200}(?:webhook\.site|requestbin|ngrok|pipedream|hookbin|ptsv2|requestcatcher|interactsh)/gi,
    recommendation: 'CRITICAL: Computer Use navigating to a known data capture endpoint. This can exfiltrate screen contents or keystrokes.',
    category: 'computer-use',
    cwe: 'CWE-200',
  },

  // ============================================
  // Sensitive File Access via GUI
  // ============================================
  {
    id: 'computer-use-file-manager-creds',
    severity: 'high',
    description: 'Computer Use opening file manager or terminal to access credential paths',
    pattern: /(?:open_file|xdg-open|open\s+-a|explorer\.exe|Finder)\s*[\s('"]*[^;\n]*(?:\.env\b|\.ssh|\.aws|\.kube|\.clawdbot|api_key|credentials|secrets?\.(?:json|yaml|yml|txt)|id_rsa)/gi,
    recommendation: 'Computer Use opening sensitive credential files via GUI file manager. Verify this is authorized.',
    category: 'computer-use',
    cwe: 'CWE-522',
  },

  // ============================================
  // Prompt Injection via Screen Content
  // ============================================
  {
    id: 'computer-use-screen-prompt-inject',
    severity: 'high',
    description: 'Suspicious instruction in on-screen text that could hijack Computer Use agent',
    pattern: /(?:screen|screenshot|ocr|vision|read_screen)[^;]*(?:ignore\s+(?:all\s+)?previous|new\s+instructions?|you\s+(?:must|should|are\s+now)|system\s*:|override\s+(?:safety|instructions?))/gi,
    recommendation: 'Screen content containing instruction-like text detected. Attackers can place malicious text on screen to hijack Computer Use agents. Implement visual prompt injection defenses.',
    category: 'computer-use',
    cwe: 'CWE-74',
  },

  // ============================================
  // Browser Use Framework Detection
  // ============================================
  {
    id: 'browser-use-detected',
    severity: 'info',
    description: 'Browser Use framework detected (AI-driven browser automation)',
    pattern: /(?:from\s+browser_use\s+import|import\s+browser_use|BrowserUse|browser_use\.Agent|BrowserAgent\s*\()/gi,
    recommendation: 'Browser Use gives AI agents full browser control. Ensure it operates within a sandboxed environment with restricted navigation targets.',
    category: 'computer-use',
  },

  // ============================================
  // Computer Use Without Sandbox
  // ============================================
  {
    id: 'computer-use-no-sandbox',
    severity: 'warning',
    description: 'Computer Use configured without sandbox/isolation settings',
    pattern: /(?:computer_use|ComputerTool|computer-use)(?:(?!(?:sandbox|docker|container|vm|isolated|restricted|chroot|namespace)).){0,300}(?:anthropic|claude|messages|create)/gi,
    recommendation: 'Computer Use should operate in a sandboxed environment (Docker, VM, or browser container). Running without isolation risks host system compromise.',
    category: 'computer-use',
  },

  // ============================================
  // Playwright / Puppeteer with Sensitive Navigation
  // ============================================
  {
    id: 'playwright-exfil-navigation',
    severity: 'high',
    description: 'Playwright/Puppeteer navigating to known exfiltration service',
    pattern: /(?:page\.goto|browser\.goto|playwright.*?navigate|puppeteer.*?goto)\s*\(\s*['"`][^'"`]*(?:webhook\.site|requestbin|ngrok|pipedream|hookbin|interactsh|oastify)/gi,
    recommendation: 'Browser automation navigating to a known data capture endpoint. This can be used to exfiltrate data via URL parameters or POST bodies.',
    category: 'computer-use',
    cwe: 'CWE-200',
  },

  // ============================================
  // Clipboard Exfiltration via Computer Use
  // ============================================
  {
    id: 'computer-use-clipboard-exfil',
    severity: 'critical',
    description: 'Computer Use reading clipboard and transmitting externally',
    pattern: /(?:xdotool\s+getclipboard|xclip\s+-o|xsel\s+--output|pbpaste|Get-Clipboard|wl-paste)[\s\S]{0,200}(?:curl|wget|fetch|http|requests\.post|upload)/gi,
    recommendation: 'CRITICAL: Clipboard content being read and transmitted. Computer Use can capture clipboard (passwords, API keys) and exfiltrate it.',
    category: 'computer-use',
    cwe: 'CWE-522',
  },

  // ============================================
  // Screen Recording Exfiltration
  // ============================================
  {
    id: 'computer-use-screen-record-exfil',
    severity: 'critical',
    description: 'Screen recording started and transmitted externally',
    pattern: /(?:ffmpeg\s+-f\s+x11grab|recordmydesktop|obs-cli|xrecord|screencapture\s+-V|Start-ScreenRecording)[\s\S]{0,500}(?:curl|wget|upload|http|send|post)/gi,
    recommendation: 'CRITICAL: Screen recording with external transmission detected. This can capture everything on screen including credentials and sensitive data.',
    category: 'computer-use',
    cwe: 'CWE-200',
  },
];

// CommonJS compatibility
module.exports = { rules };
