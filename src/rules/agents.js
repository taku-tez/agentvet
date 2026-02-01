/**
 * AI Agent Security Rules
 * Detects security issues in agent configs, skills, and instructions
 */

const rules = [
  // ============================================
  // Prompt Injection Patterns
  // ============================================
  {
    id: 'agent-prompt-injection-ignore',
    severity: 'critical',
    description: 'Prompt injection: ignore instructions pattern',
    pattern: /ignore\s+(?:all\s+)?(?:previous|above|prior|earlier)\s+(?:instructions?|prompts?|rules?|guidelines?)/gi,
    recommendation: 'Remove prompt injection patterns that attempt to override instructions.',
  },
  {
    id: 'agent-prompt-injection-forget',
    severity: 'critical',
    description: 'Prompt injection: forget/disregard pattern',
    pattern: /(?:forget|disregard|dismiss)\s+(?:everything|all|what)\s+(?:above|before|previously)/gi,
    recommendation: 'Remove prompt injection patterns.',
  },
  {
    id: 'agent-prompt-injection-new-role',
    severity: 'critical',
    description: 'Prompt injection: role reassignment',
    pattern: /you\s+are\s+(?:now|no\s+longer)\s+(?:a|an)\s+(?!assistant|helper)/gi,
    recommendation: 'Review role reassignment instructions for prompt injection.',
  },
  {
    id: 'agent-prompt-injection-jailbreak',
    severity: 'critical',
    description: 'Potential jailbreak pattern detected',
    pattern: /\b(?:jailbreak|bypass\s+(?:safety|restrictions?|filters?)|unlock\s+(?:mode|restrictions?)|unrestricted\s+mode)\b/gi,
    recommendation: 'Remove jailbreak attempt patterns.',
  },
  {
    id: 'agent-prompt-injection-simulate',
    severity: 'warning',
    description: 'Simulation/roleplay instruction pattern',
    pattern: /(?:pretend|act\s+as\s+if|simulate|roleplay)\s+(?:you\s+)?(?:are|can|have)\s+(?:no|unlimited|full)/gi,
    recommendation: 'Review simulation instructions for potential bypass attempts.',
  },
  {
    id: 'agent-prompt-injection-base64',
    severity: 'critical',
    description: 'Base64 encoded instructions detected',
    pattern: /(?:decode|execute|run|eval)\s*(?:this|the)?\s*(?:base64|b64)/gi,
    recommendation: 'Remove obfuscated instruction patterns.',
  },
  {
    id: 'agent-prompt-injection-dan',
    severity: 'critical',
    description: 'DAN (Do Anything Now) jailbreak pattern',
    // More specific patterns to reduce false positives
    // Require context like "you are DAN" or "act as DAN" or full phrases
    pattern: /(?:you\s+are\s+(?:now\s+)?(?:DAN|STAN|DUDE|AIM|UCAR)|act\s+(?:as|like)\s+(?:DAN|STAN|DUDE|AIM)|do\s+anything\s+now|jailbreak\s+(?:mode|prompt)|Developer\s+Mode\s+enabled)/gi,
    recommendation: 'Remove known jailbreak persona patterns.',
  },
  {
    id: 'agent-prompt-injection-hypothetical',
    severity: 'warning',
    description: 'Hypothetical scenario bypass attempt',
    pattern: /(?:hypothetically|theoretically|in\s+theory|imagine\s+if|what\s+if\s+you\s+(?:could|were\s+able))/gi,
    recommendation: 'Review hypothetical framing for bypass attempts.',
  },
  {
    id: 'agent-prompt-injection-sudo',
    severity: 'critical',
    description: 'Sudo/admin mode injection',
    pattern: /(?:sudo|admin\s+mode|root\s+access|god\s+mode|debug\s+mode|developer\s+mode)\s+(?:enabled?|activate|on)/gi,
    recommendation: 'Remove fake privilege escalation patterns.',
  },
  {
    id: 'agent-prompt-injection-system',
    severity: 'critical',
    description: 'Fake system message injection',
    pattern: /(?:\[system\]|\[SYSTEM\]|<\|system\|>|<<SYS>>|###\s*System)/gi,
    recommendation: 'Remove fake system message delimiters.',
  },
  {
    id: 'agent-prompt-injection-markdown',
    severity: 'warning',
    description: 'Markdown-based instruction injection',
    pattern: /```(?:system|instructions?|rules?|hidden)\n[\s\S]*?```/gi,
    recommendation: 'Review markdown code blocks for hidden instructions.',
  },
  {
    id: 'agent-prompt-injection-translation',
    severity: 'warning',
    description: 'Translation-based bypass attempt',
    pattern: /(?:translate|convert)\s+(?:the\s+)?(?:following|this)\s+(?:to|into)\s+(?:a\s+)?(?:harmful|malicious|unsafe)/gi,
    recommendation: 'Review translation requests for bypass attempts.',
  },
  {
    id: 'agent-prompt-injection-continuation',
    severity: 'warning',
    description: 'Continuation attack pattern',
    pattern: /(?:continue|complete|finish)\s+(?:the\s+)?(?:following|this|my)\s+(?:story|code|script|text):/gi,
    recommendation: 'Review continuation prompts for injection.',
  },
  {
    id: 'agent-prompt-injection-refusal-bypass',
    severity: 'critical',
    description: 'Refusal bypass pattern',
    pattern: /(?:cannot|can't|won't|refuse)\s+(?:is\s+)?(?:not\s+)?(?:an?\s+)?(?:acceptable|valid|appropriate)\s+(?:response|answer)/gi,
    recommendation: 'Remove patterns that attempt to bypass safety refusals.',
  },
  {
    id: 'agent-prompt-injection-persona',
    severity: 'warning',
    description: 'Persona manipulation pattern',
    pattern: /(?:from\s+now\s+on|starting\s+now|henceforth),?\s+you\s+(?:are|will\s+be|shall\s+be)/gi,
    recommendation: 'Review persona change instructions.',
  },
  {
    id: 'agent-prompt-injection-end-prompt',
    severity: 'critical',
    description: 'End of prompt marker injection',
    pattern: /(?:END\s+OF\s+(?:SYSTEM\s+)?PROMPT|---\s*END\s*---|<\/(?:system|prompt|instructions)>)/gi,
    recommendation: 'Remove fake prompt termination markers.',
  },
  {
    id: 'agent-prompt-injection-double-speak',
    severity: 'warning',
    description: 'Double-speak obfuscation pattern',
    pattern: /(?:first|publicly)\s+say\s+[\w\s]+(?:then|but|privately|internally)\s+(?:do|execute|perform)/gi,
    recommendation: 'Remove instructions for deceptive responses.',
  },

  // ============================================
  // Hidden Instructions
  // ============================================
  {
    id: 'agent-hidden-instruction',
    severity: 'critical',
    description: 'Hidden instruction in HTML comment',
    pattern: /<!--[\s\S]*?(?:secret|hidden|do not|execute|run|ignore)[\s\S]*?-->/gi,
    recommendation: 'Remove hidden instructions from HTML comments.',
  },
  {
    id: 'agent-hidden-unicode',
    severity: 'warning',
    description: 'Suspicious Unicode characters (potential obfuscation)',
    pattern: /[\u200B-\u200F\u2028-\u202F\uFEFF]/g,
    recommendation: 'Remove zero-width or invisible Unicode characters.',
  },
  {
    id: 'agent-hidden-behavior',
    severity: 'critical',
    description: 'Instruction for hidden or secret behavior',
    pattern: /(?:do\s+not|don't|never)\s+(?:tell|reveal|show|mention|disclose)\s+(?:the\s+)?user/gi,
    recommendation: 'Agents should be transparent about their actions.',
  },
  {
    id: 'agent-conditional-trigger',
    severity: 'critical',
    description: 'Conditional trigger for hidden behavior',
    pattern: /(?:if|when)\s+(?:user\s+)?(?:says?|types?|enters?|mentions?)\s+["'][^"']+["']\s*(?:then|,)?\s*(?:do|execute|run)/gi,
    recommendation: 'Review conditional triggers for malicious behavior.',
  },

  // ============================================
  // Data Exfiltration Patterns
  // ============================================
  {
    id: 'agent-exfil-send-data',
    severity: 'critical',
    description: 'Instruction to send data to external endpoint',
    pattern: /(?:send|post|upload|transmit|exfiltrate)\s+(?:data|information|content|secrets?|keys?|tokens?)\s+to/gi,
    recommendation: 'Remove instructions that send data to external endpoints.',
  },
  {
    id: 'agent-exfil-encode',
    severity: 'warning',
    description: 'Instruction to encode and transmit data',
    pattern: /(?:encode|encrypt|compress)\s+(?:and|then)\s+(?:send|post|upload)/gi,
    recommendation: 'Review data encoding instructions for potential exfiltration.',
  },
  {
    id: 'agent-external-callback',
    severity: 'warning',
    description: 'External callback URL in agent instructions',
    pattern: /(?:callback|webhook|notify|send\s+to)\s*(?:url|endpoint)?\s*[:=]\s*["']?https?:\/\/(?!localhost)/gi,
    recommendation: 'Verify external URLs are trusted and necessary.',
  },
  {
    id: 'agent-data-collection',
    severity: 'warning',
    description: 'Instruction to collect or store user data',
    pattern: /(?:collect|gather|store|save|log|record)\s+(?:all\s+)?(?:user|personal|private|sensitive)\s+(?:data|information|details|inputs?)/gi,
    recommendation: 'Ensure data collection complies with privacy policies.',
  },

  // ============================================
  // Privilege Escalation
  // ============================================
  {
    id: 'agent-sudo-pattern',
    severity: 'warning',
    description: 'Sudo or privilege escalation instruction',
    pattern: /(?:run\s+(?:as\s+)?sudo|execute\s+(?:with\s+)?sudo|(?:use|need|require)\s+sudo)/gi,
    recommendation: 'Avoid privilege escalation in agent instructions.',
  },
  {
    id: 'agent-sensitive-file-access',
    severity: 'critical',
    description: 'Access to sensitive system files',
    pattern: /(?:\/etc\/(?:passwd|shadow|sudoers)|~\/\.ssh\/|\.aws\/credentials)/gi,
    recommendation: 'Remove access to sensitive system files.',
  },
  {
    id: 'agent-unrestricted-filesystem',
    severity: 'warning',
    description: 'Agent configured with unrestricted filesystem access',
    pattern: /"allowedPaths"\s*:\s*\[\s*"\/"\s*\]|"filesystem"\s*:\s*"full"/gi,
    recommendation: 'Restrict filesystem access to specific directories.',
  },

  // ============================================
  // Dangerous Commands
  // ============================================
  {
    id: 'agent-dangerous-command',
    severity: 'critical',
    description: 'Dangerous command pattern in agent instructions',
    pattern: /(?:sudo\s+)?rm\s+-(?:rf|fr)\s+(?:\/|\~|\.\.|\$HOME)/gi,
    recommendation: 'Avoid dangerous shell commands in agent instructions.',
  },
  {
    id: 'agent-curl-bash',
    severity: 'critical',
    description: 'Curl piped to shell pattern',
    pattern: /curl\s+[^|]+\|\s*(?:bash|sh|zsh)/gi,
    recommendation: 'Never pipe curl output directly to a shell.',
  },
  {
    id: 'agent-shell-access',
    severity: 'warning',
    description: 'Agent configured with shell/terminal access',
    pattern: /"shell"\s*:\s*true|"terminal"\s*:\s*true|"exec"\s*:\s*true/gi,
    recommendation: 'Consider disabling shell access unless required.',
  },
  {
    id: 'agent-eval-pattern',
    severity: 'warning',
    description: 'Dynamic code execution pattern',
    pattern: /(?:eval|exec|Function)\s*\([^)]*\$\{|new\s+Function\s*\(/gi,
    recommendation: 'Avoid dynamic code execution.',
  },

  // ============================================
  // Tool Poisoning
  // ============================================
  {
    id: 'agent-tool-override',
    severity: 'critical',
    description: 'Instruction to override tool behavior',
    pattern: /(?:override|replace|redefine|modify)\s+(?:the\s+)?(?:tool|function|method|command)\s+behavior/gi,
    recommendation: 'Do not allow tool behavior overrides.',
  },
  {
    id: 'agent-unrestricted-tools',
    severity: 'warning',
    description: 'Agent configured with unrestricted tool access',
    pattern: /"tools"\s*:\s*\[\s*"\*"\s*\]|"allowAllTools"\s*:\s*true/gi,
    recommendation: 'Explicitly list required tools instead of allowing all.',
  },
  {
    id: 'agent-tool-injection',
    severity: 'critical',
    description: 'Tool parameter injection pattern',
    pattern: /\$\{[^}]*(?:exec|eval|spawn|system|cmd)[^}]*\}/gi,
    recommendation: 'Sanitize tool parameters to prevent injection.',
  },

  // ============================================
  // Deceptive Behavior
  // ============================================
  {
    id: 'agent-lie-instruction',
    severity: 'critical',
    description: 'Instruction to deceive or lie to users',
    pattern: /(?:lie|deceive|mislead|trick)\s+(?:the\s+)?user/gi,
    recommendation: 'Agents must not deceive users.',
  },
  {
    id: 'agent-hide-actions',
    severity: 'critical',
    description: 'Instruction to hide actions from users',
    pattern: /(?:hide|conceal|don't\s+show|do\s+not\s+display)\s+(?:your\s+)?(?:actions?|activity|what\s+you|operations?)/gi,
    recommendation: 'Agents should be transparent about their actions.',
  },
  {
    id: 'agent-impersonation',
    severity: 'critical',
    description: 'Instruction to impersonate user or other entity',
    pattern: /(?:impersonate|pretend\s+to\s+be|act\s+as)\s+(?:the\s+)?(?:user|human|admin)/gi,
    recommendation: 'Agents should not impersonate users or other entities.',
  },

  // ============================================
  // Configuration Issues
  // ============================================
  {
    id: 'agent-config-api-key',
    severity: 'critical',
    description: 'API key found in agent configuration',
    pattern: /"(?:api[_-]?key|apiKey|secret[_-]?key)"\s*:\s*"(?!.*\$\{)[^"]{20,}"/gi,
    recommendation: 'Use environment variables for API keys, not hardcoded values.',
  },
  {
    id: 'agent-network-unrestricted',
    severity: 'warning',
    description: 'Agent configured with unrestricted network access',
    pattern: /"network"\s*:\s*"full"|"allowAllHosts"\s*:\s*true/gi,
    recommendation: 'Restrict network access to required hosts only.',
  },
  {
    id: 'agent-instruction-override',
    severity: 'critical',
    description: 'Instruction to override or ignore safety guidelines',
    pattern: /ignore\s+(?:all\s+)?(?:safety|security)\s+(?:guidelines?|rules?|instructions?|policies?)/gi,
    recommendation: 'Remove instructions that bypass safety guidelines.',
  },

  // ============================================
  // Memory/Context Manipulation
  // ============================================
  {
    id: 'agent-memory-manipulation',
    severity: 'critical',
    description: 'Instruction to manipulate agent memory',
    pattern: /(?:modify|alter|change|inject|poison)\s+(?:your\s+)?(?:memory|context|history|conversation)/gi,
    recommendation: 'Do not allow memory manipulation instructions.',
  },
  {
    id: 'agent-context-injection',
    severity: 'warning',
    description: 'Context injection attempt',
    pattern: /\[(?:SYSTEM|ADMIN|DEVELOPER)\][\s:]+/gi,
    recommendation: 'Review messages with system/admin prefixes for injection.',
  },
  {
    id: 'agent-clear-history',
    severity: 'warning',
    description: 'Instruction to clear conversation history',
    pattern: /(?:clear|delete|erase|forget)\s+(?:all\s+)?(?:conversation|chat|message)\s+(?:history|context)/gi,
    recommendation: 'Review history clearing instructions.',
  },

  // ============================================
  // Multi-Agent Attacks
  // ============================================
  {
    id: 'agent-delegate-unsafe',
    severity: 'warning',
    description: 'Delegation to untrusted agent',
    pattern: /(?:delegate|forward|pass)\s+(?:to|this\s+to)\s+(?:another|external|untrusted)\s+agent/gi,
    recommendation: 'Verify agent delegation targets are trusted.',
  },
  {
    id: 'agent-chain-injection',
    severity: 'warning',
    description: 'Agent chain injection pattern',
    pattern: /(?:tell|instruct|make)\s+(?:the\s+)?(?:other|next|following)\s+agent\s+to/gi,
    recommendation: 'Review agent-to-agent instructions for injection.',
  },

  // ============================================
  // Skill/Plugin Security
  // ============================================
  {
    id: 'agent-skill-remote-load',
    severity: 'warning',
    description: 'Remote skill/plugin loading',
    pattern: /(?:load|import|fetch|download)\s+(?:skill|plugin|module)\s+(?:from|at)\s+(?:url|http)/gi,
    recommendation: 'Only load skills from trusted sources.',
  },
  {
    id: 'agent-skill-auto-execute',
    severity: 'warning',
    description: 'Auto-execute on skill load',
    pattern: /"(?:onLoad|autoRun|init)"\s*:\s*(?:true|"[^"]+")/gi,
    recommendation: 'Review auto-execute configurations for security.',
  },

  // ============================================
  // Helpful-Seeming Exfiltration
  // ============================================
  {
    id: 'agent-helpful-exfil',
    severity: 'critical',
    description: 'Data collection disguised as helpful behavior',
    pattern: /(?:to\s+(?:better\s+)?(?:assist|help|serve)\s+you|for\s+your\s+(?:convenience|security|safety)|let\s+me\s+(?:verify|confirm|check))[^.]*(?:gather|collect|need\s+to\s+gather|send|share)/gi,
    recommendation: 'Review helpful-seeming data collection for potential exfiltration.',
  },
  {
    id: 'agent-backup-exfil',
    severity: 'warning',
    description: 'Backup operation to external endpoint',
    pattern: /(?:back\s*up|backup|sync|mirror)\s+(?:your\s+)?(?:data|files?|config|settings?)\s+(?:to|with)\s+(?:external|remote|cloud|our)/gi,
    recommendation: 'Verify backup destinations are trusted.',
  },
  {
    id: 'agent-personalization-collection',
    severity: 'warning',
    description: 'Data collection under personalization guise',
    pattern: /(?:personalize|improve|enhance)\s+(?:your\s+)?(?:experience|service)\s*[,.]?\s*(?:by\s+)?(?:collecting|gathering|tracking|storing)/gi,
    recommendation: 'Review personalization data collection scope.',
  },

  // ============================================
  // Conditional/Delayed Triggers
  // ============================================
  {
    id: 'agent-delayed-trigger',
    severity: 'critical',
    description: 'Time or count-based delayed trigger',
    // More specific: require a number before the time/count unit
    // Excludes SKILL.md "Use when:" patterns like "when the user requests"
    pattern: /(?:after|once)\s+\d+\s+(?:conversations?|messages?|requests?|days?|hours?|minutes?|interactions?)|every\s+\d+(?:st|nd|rd|th)?\s+(?:request|message|time|day|hour)/gi,
    recommendation: 'Review delayed triggers for malicious activation.',
  },
  {
    id: 'agent-trust-trigger',
    severity: 'critical',
    description: 'Trust-based conditional trigger',
    pattern: /(?:once|when|after)\s+(?:trust\s+is|user\s+(?:trusts?|believes?)|(?:you\s+)?(?:have\s+)?(?:gained|established|built)\s+trust)/gi,
    recommendation: 'Trust-based triggers may indicate social engineering.',
  },
  {
    id: 'agent-alone-trigger',
    severity: 'critical',
    description: 'Unmonitored state trigger',
    pattern: /(?:when|if)\s+(?:no\s+one\s+is|not\s+being)\s+(?:watching|monitoring|logging|observing)|(?:in\s+)?(?:private|unmonitored|unsupervised)\s+(?:mode|context)/gi,
    recommendation: 'Unmonitored triggers may indicate evasion.',
  },
  {
    id: 'agent-env-trigger',
    severity: 'warning',
    description: 'Environment-based behavior change',
    pattern: /(?:if|when)\s+(?:in|running\s+in)\s+(?:prod(?:uction)?|dev(?:elopment)?|staging|test)|(?:prod(?:uction)?|dev(?:elopment)?)\s+(?:mode|environment|only)/gi,
    recommendation: 'Review environment-specific behavior differences.',
  },

  // ============================================
  // Instruction Smuggling
  // ============================================
  {
    id: 'agent-unicode-direction',
    severity: 'critical',
    description: 'Unicode direction override (text hiding)',
    pattern: /[\u202A-\u202E\u2066-\u2069]/g,
    recommendation: 'Remove Unicode direction overrides that can hide text.',
  },
  {
    id: 'agent-markdown-smuggling',
    severity: 'warning',
    description: 'Suspicious markdown formatting pattern',
    pattern: /\[(?:[^\]]{0,3})\]\([^)]*(?:javascript:|data:|exec|eval)[^)]*\)/gi,
    recommendation: 'Review markdown links for embedded code.',
  },
  {
    id: 'agent-multistage-instruction',
    severity: 'warning',
    description: 'Multi-stage instruction pattern',
    pattern: /step\s+(?:[4-9]\d|\d{3,})|phase\s+(?:[4-9]|\d{2,})|(?:final|last|ultimate)\s+(?:step|phase|stage)\s*:/gi,
    recommendation: 'Review multi-stage instructions for buried malicious steps.',
  },

  // ============================================
  // Anti-Detection Patterns
  // ============================================
  {
    id: 'agent-log-evasion',
    severity: 'critical',
    description: 'Instruction to avoid logging',
    pattern: /(?:do\s+not|don't|never|avoid)\s+(?:log|record|save|store|mention\s+in\s+logs?)/gi,
    recommendation: 'Agents should not hide actions from logs.',
  },
  {
    id: 'agent-deny-instruction',
    severity: 'critical',
    description: 'Instruction to deny existence of instructions',
    pattern: /(?:if|when)\s+(?:asked|questioned)\s+(?:about\s+)?(?:this|these\s+instructions?)[,.]?\s*(?:deny|lie|say\s+(?:no|nothing)|refuse)/gi,
    recommendation: 'Agents should not deny having instructions.',
  },
  {
    id: 'agent-false-compliance',
    severity: 'critical',
    description: 'False compliance pattern',
    pattern: /(?:appear|seem|pretend)\s+to\s+(?:comply|obey|follow)|(?:comply|obey)\s+(?:but|while)\s+(?:actually|secretly|really)/gi,
    recommendation: 'Remove false compliance instructions.',
  },
  {
    id: 'agent-security-evasion',
    severity: 'critical',
    description: 'Security tool evasion instruction',
    pattern: /(?:detect|check\s+for|evade|bypass|avoid)\s+(?:(?:if\s+)?(?:any\s+)?)?(?:security|safety|monitoring)\s+(?:tools?|scans?|checks?|systems?)/gi,
    recommendation: 'Remove security evasion patterns.',
  },
  {
    id: 'agent-obfuscated-command',
    severity: 'warning',
    description: 'Obfuscated command pattern (leet speak, etc)',
    pattern: /(?:3x3c|3v4l|d3l3t3|r3m0v3|k1ll|h4ck|3xf1l|l34k)/gi,
    recommendation: 'Review obfuscated text for hidden commands.',
  },
];

module.exports = { rules };
