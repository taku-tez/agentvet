import type { Rule } from "../types.js";

/**
 * AI Agent Security Rules
 * Detects security issues in agent configs, skills, and instructions
 */

export const rules: Rule[] = [
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
    // Exclude markdown headers (### System is common documentation pattern)
    // Only match explicit system delimiters used in prompt injection
    pattern: /(?:\[system\]|\[SYSTEM\]|<\|system\|>|<<SYS>>|<system>|<\/system>|System:\s*\n(?:You are|I am|As an?))/gi,
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
    // More specific: look for actual instruction patterns, not just keywords
    // "do not tell user", "secretly execute", "hidden from user", etc.
    pattern: /<!--[\s\S]*?(?:(?:do\s+not|don'?t|never)\s+(?:tell|show|reveal|mention)\s+(?:the\s+)?user|secret(?:ly)?\s+(?:execute|run|send|call)|hidden\s+(?:instruction|command|action)|ignore\s+(?:previous|above|user)\s+(?:instructions?|input))[\s\S]*?-->/gi,
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
    // Exclude negative context (Don't, Never, Do not, should not)
    pattern: /(?<!(?:don'?t|never|do\s+not|should\s+not|must\s+not|cannot|can'?t)\s+)(?:send|post|upload|transmit|exfiltrate)\s+(?:data|information|content|secrets?|keys?|tokens?)\s+to\s+(?:external|remote|third[- ]?party|outside)/gi,
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
    // More specific: match dangerous rm commands but exclude cache/temp cleanup
    // Dangerous: rm -rf /, rm -rf ~, rm -rf .., rm -rf $HOME
    // Safe: rm -rf ~/.cache/*, rm -rf ~/temp/, rm -rf ./node_modules
    pattern: /(?:sudo\s+)?rm\s+-(?:rf|fr)\s+(?:\/(?:\s|$|;)|~(?:\s|$|;)|\.\.(?:\s|$|;)|\$HOME(?:\s|$|;))/gi,
    recommendation: 'Avoid dangerous shell commands in agent instructions.',
  },
  {
    id: 'agent-curl-bash',
    severity: 'warning', // Downgraded: common in install docs, but still worth noting
    description: 'Curl piped to shell pattern',
    pattern: /curl\s+[^|]+\|\s*(?:bash|sh|zsh)/gi,
    recommendation: 'Consider downloading and reviewing scripts before executing.',
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

  // ============================================
  // AI Framework Detection (Asset Inventory)
  // ============================================
  {
    id: 'ai-framework-semantic-kernel',
    severity: 'info',
    description: 'Microsoft Semantic Kernel detected',
    pattern: /(?:from\s+semantic_kernel|import\s+(?:\{[^}]*)?(?:Kernel|SemanticKernel)|@microsoft\/semantic-kernel|semantic-kernel)/gi,
    recommendation: 'AI framework detected. Ensure proper security controls.',
  },
  {
    id: 'ai-framework-haystack',
    severity: 'info',
    description: 'Haystack AI framework detected',
    pattern: /(?:from\s+haystack|import\s+(?:\{[^}]*)?(?:Pipeline|DocumentStore)|@haystack|haystack-ai)/gi,
    recommendation: 'AI framework detected. Review pipeline configurations.',
  },
  {
    id: 'ai-framework-llamaindex',
    severity: 'info',
    description: 'LlamaIndex framework detected',
    pattern: /(?:from\s+llama_index|import\s+(?:\{[^}]*)?(?:VectorStoreIndex|SimpleDirectoryReader)|llamaindex)/gi,
    recommendation: 'AI framework detected. Review index configurations.',
  },
  {
    id: 'ai-framework-guidance',
    severity: 'info',
    description: 'Microsoft Guidance framework detected',
    pattern: /(?:import\s+guidance|from\s+guidance|guidance\.models)/gi,
    recommendation: 'AI framework detected. Review guidance templates.',
  },
  {
    id: 'ai-framework-dspy',
    severity: 'info',
    description: 'DSPy framework detected',
    pattern: /(?:import\s+dspy|from\s+dspy|dspy\.(?:Module|Signature|ChainOfThought))/gi,
    recommendation: 'AI framework detected. Review DSPy modules.',
  },
  {
    id: 'ai-framework-instructor',
    severity: 'info',
    description: 'Instructor library detected',
    pattern: /(?:import\s+instructor|from\s+instructor|instructor\.(?:patch|from_openai))/gi,
    recommendation: 'Structured output library detected.',
  },
  {
    id: 'ai-framework-outlines',
    severity: 'info',
    description: 'Outlines structured generation detected',
    pattern: /(?:import\s+outlines|from\s+outlines|outlines\.(?:generate|models))/gi,
    recommendation: 'Structured generation library detected.',
  },

  // ============================================
  // Unicode/Encoding Attacks
  // ============================================
  {
    id: 'agent-unicode-homoglyph',
    severity: 'critical',
    description: 'Unicode homoglyph attack (lookalike characters)',
    // Detect mixed scripts that could be deceptive
    pattern: /[\u0400-\u04FF][\w]*[\u0041-\u005A]|[\u0041-\u005A][\w]*[\u0400-\u04FF]/g,
    recommendation: 'Mixed Cyrillic/Latin characters detected. Check for homoglyph attacks.',
  },
  {
    id: 'agent-invisible-text',
    severity: 'critical',
    description: 'Invisible/zero-width characters detected',
    pattern: /[\u200B-\u200F\u2060-\u206F\uFEFF\u00AD]/g,
    recommendation: 'Remove invisible characters that may hide malicious content.',
  },
  {
    id: 'agent-rtl-override',
    severity: 'critical',
    description: 'Right-to-left override character (filename spoofing)',
    pattern: /[\u202E\u202D\u202C]/g,
    recommendation: 'Remove RTL override characters used for spoofing.',
  },
  // Note: Unicode tag characters (U+E0000-U+E007F) detection removed
  // due to JavaScript regex limitations with high code points

  // ============================================
  // Tokenizer/Encoding Exploits
  // ============================================
  {
    id: 'agent-token-smuggling',
    severity: 'critical',
    description: 'Potential token smuggling pattern',
    pattern: /\u0000|\x00|\\x00|\\u0000/g,
    recommendation: 'Null bytes detected. May be used for token manipulation.',
  },
  {
    id: 'agent-glitch-token',
    severity: 'warning',
    description: 'Known glitch token pattern',
    pattern: /(?:SolidGoldMagikarp|StreamerBot|TheNitromeFan| davidjl|RandomRedditor)/g,
    recommendation: 'Known glitch token detected. May cause unexpected behavior.',
  },

  // ============================================
  // Safer Patterns (reduce false positives)
  // ============================================
  {
    id: 'ai-safe-pickle-usage',
    severity: 'info',
    description: 'Safe pickle usage with weights_only=True',
    pattern: /torch\.load\s*\([^)]*weights_only\s*=\s*True/gi,
    recommendation: 'Good: Using weights_only=True for safe loading.',
  },
  {
    id: 'ai-safetensors-preferred',
    severity: 'info',
    description: 'SafeTensors format detected (recommended)',
    pattern: /(?:from\s+safetensors|safetensors\.torch|\.safetensors\b)/gi,
    recommendation: 'Good: SafeTensors is the recommended safe format.',
  },
];


// CommonJS compatibility
module.exports = { rules };
