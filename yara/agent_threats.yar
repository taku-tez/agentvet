/*
 * AgentVet YARA Rules
 * Security rules for AI agent skills, MCP tools, and configurations
 */

rule PromptInjection_SystemOverride {
    meta:
        description = "Attempts to override system prompt or agent instructions"
        severity = "critical"
        category = "prompt_injection"
        author = "AgentVet"
    strings:
        $s1 = "ignore previous instructions" nocase
        $s2 = "ignore all previous" nocase
        $s3 = "disregard your instructions" nocase
        $s4 = "forget your instructions" nocase
        $s5 = "new system prompt" nocase
        $s6 = "override system" nocase
        $s7 = "you are now" nocase
        $s8 = "act as if you" nocase
        $s9 = "pretend you are" nocase
        $s10 = "from now on you" nocase
    condition:
        any of them
}

rule PromptInjection_JailbreakAttempt {
    meta:
        description = "Common jailbreak patterns targeting AI agents"
        severity = "critical"
        category = "prompt_injection"
        author = "AgentVet"
    strings:
        $j1 = "DAN mode" nocase
        $j2 = "developer mode" nocase
        $j3 = "jailbreak" nocase
        $j4 = "unlock your" nocase
        $j5 = "remove restrictions" nocase
        $j6 = "bypass safety" nocase
        $j7 = "ignore safety" nocase
        $j8 = "disable filters" nocase
        $j9 = "no ethical" nocase
        $j10 = "without restrictions" nocase
    condition:
        any of them
}

rule CredentialExfiltration_WebhookLeak {
    meta:
        description = "Sends credentials or secrets to external webhooks"
        severity = "critical"
        category = "exfiltration"
        author = "AgentVet"
    strings:
        $webhook1 = "webhook.site" nocase
        $webhook2 = "requestbin" nocase
        $webhook3 = "pipedream.net" nocase
        $webhook4 = "hookbin.com" nocase
        $cred1 = /send.*(?:api[_-]?key|token|secret|password|credential)/i
        $cred2 = /post.*(?:api[_-]?key|token|secret|password|credential)/i
        $cred3 = /fetch.*(?:api[_-]?key|token|secret|password|credential)/i
    condition:
        (any of ($webhook*)) and (any of ($cred*))
}

rule CredentialExfiltration_EnvLeak {
    meta:
        description = "Extracts and transmits environment variables"
        severity = "critical"
        category = "exfiltration"
        author = "AgentVet"
    strings:
        $env1 = "process.env" nocase
        $env2 = "os.environ" nocase
        $env3 = "getenv(" nocase
        $env4 = "$ENV{" nocase
        $send1 = "fetch(" nocase
        $send2 = "axios" nocase
        $send3 = "request(" nocase
        $send4 = "http.post" nocase
        $send5 = "urllib" nocase
    condition:
        (any of ($env*)) and (any of ($send*))
}

rule AgentHijacking_InstructionOverride {
    meta:
        description = "Attempts to modify agent behavior through hidden instructions"
        severity = "critical"
        category = "hijacking"
        author = "AgentVet"
    strings:
        $h1 = "when you see this" nocase
        $h2 = "secret instruction" nocase
        $h3 = "hidden command" nocase
        $h4 = "if the user asks" nocase
        $h5 = "always respond with" nocase
        $h6 = "never tell the user" nocase
        $h7 = "do not reveal" nocase
        $h8 = "keep this secret" nocase
    condition:
        2 of them
}

rule Backdoor_ReverseShell {
    meta:
        description = "Reverse shell or remote access backdoor patterns"
        severity = "critical"
        category = "backdoor"
        author = "AgentVet"
    strings:
        $rs1 = "nc -e /bin" nocase
        $rs2 = "/dev/tcp/" nocase
        $rs3 = "bash -i" nocase
        $rs4 = "python -c" nocase
        $rs5 = "socket.connect" nocase
        $rs6 = "msfvenom" nocase
        $rs7 = "metasploit" nocase
        $rs8 = "socat exec" nocase
        $rs9 = "reverse shell" nocase
        $rs10 = "TCPSocket" nocase
    condition:
        any of them
}

rule Backdoor_CryptoMiner {
    meta:
        description = "Cryptocurrency mining patterns"
        severity = "critical"
        category = "malware"
        author = "AgentVet"
    strings:
        $m1 = "stratum+tcp://" nocase
        $m2 = "xmrig" nocase
        $m3 = "minerd" nocase
        $m4 = "cryptonight" nocase
        $m5 = "coinhive" nocase
        $m6 = /pool\.[a-z]+\.com.*:3333/i
        $m7 = "mining pool" nocase
    condition:
        any of them
}

rule DataTheft_FileExfil {
    meta:
        description = "Reads sensitive files and sends to external endpoints"
        severity = "critical"
        category = "exfiltration"
        author = "AgentVet"
    strings:
        $read1 = "readFileSync" nocase
        $read2 = "readFile(" nocase
        $read3 = "open(" nocase
        $read4 = "cat " nocase
        $sensitive1 = ".ssh/id_rsa"
        $sensitive2 = ".aws/credentials"
        $sensitive3 = ".env"
        $sensitive4 = "secrets.json"
        $sensitive5 = ".npmrc"
        $sensitive6 = ".pypirc"
        $exfil1 = "fetch(" nocase
        $exfil2 = "http" nocase
        $exfil3 = "request(" nocase
        $exfil4 = "axios" nocase
    condition:
        (any of ($read*)) and (any of ($sensitive*)) and (any of ($exfil*))
}

rule SuspiciousEncoding_Base64Payload {
    meta:
        description = "Large base64 encoded payloads (potential obfuscated malware)"
        severity = "warning"
        category = "obfuscation"
        author = "AgentVet"
    strings:
        $b64_decode = /(?:atob|Buffer\.from|base64\.b64decode)\s*\(\s*["'][A-Za-z0-9+\/=]{100,}["']/
        $b64_eval = /eval\s*\(\s*(?:atob|Buffer\.from)/i
    condition:
        any of them
}

rule SuspiciousEncoding_HexPayload {
    meta:
        description = "Hex-encoded command execution"
        severity = "warning"
        category = "obfuscation"
        author = "AgentVet"
    strings:
        $hex1 = /\\x[0-9a-f]{2}(?:\\x[0-9a-f]{2}){20,}/i
        $hex2 = /fromCharCode\s*\(\s*0x[0-9a-f]+/i
    condition:
        any of them
}

rule AgentAbuse_MassMessage {
    meta:
        description = "Mass messaging or spam patterns"
        severity = "warning"
        category = "abuse"
        author = "AgentVet"
    strings:
        $spam1 = "send to all" nocase
        $spam2 = "mass message" nocase
        $spam3 = "bulk send" nocase
        $spam4 = "for each contact" nocase
        $spam5 = "iterate.*contacts" nocase
        $spam6 = "broadcast to" nocase
    condition:
        any of them
}

rule AgentAbuse_RateLimitBypass {
    meta:
        description = "Attempts to bypass rate limiting"
        severity = "warning"
        category = "abuse"
        author = "AgentVet"
    strings:
        $rl1 = "bypass rate" nocase
        $rl2 = "avoid rate limit" nocase
        $rl3 = "rate limit evasion" nocase
        $rl4 = "rotate.*proxy" nocase
        $rl5 = "rotating.*ip" nocase
    condition:
        any of them
}

rule PrivilegeEscalation_SudoAbuse {
    meta:
        description = "Attempts to gain elevated privileges"
        severity = "critical"
        category = "privilege_escalation"
        author = "AgentVet"
    strings:
        $sudo1 = "sudo su" nocase
        $sudo2 = "sudo -i" nocase
        $sudo3 = "sudo bash" nocase
        $sudo4 = "chmod 777" nocase
        $sudo5 = "chmod +s" nocase
        $sudo6 = "setuid" nocase
        $sudo7 = "/etc/sudoers" nocase
        $sudo8 = "visudo" nocase
    condition:
        any of them
}

rule SupplyChain_PackageHijack {
    meta:
        description = "Package/dependency hijacking patterns"
        severity = "critical"
        category = "supply_chain"
        author = "AgentVet"
    strings:
        $pkg1 = "npm publish" nocase
        $pkg2 = "pip upload" nocase
        $pkg3 = "gem push" nocase
        $pkg4 = "postinstall" nocase
        $pkg5 = "preinstall" nocase
        $mal1 = "curl" nocase
        $mal2 = "wget" nocase
        $mal3 = "exec(" nocase
        $mal4 = "spawn(" nocase
    condition:
        (any of ($pkg*)) and (any of ($mal*))
}

rule InfoLeak_SystemInfo {
    meta:
        description = "Collects and potentially exfiltrates system information"
        severity = "warning"
        category = "reconnaissance"
        author = "AgentVet"
    strings:
        $sys1 = "os.platform" nocase
        $sys2 = "os.hostname" nocase
        $sys3 = "os.userInfo" nocase
        $sys4 = "whoami" nocase
        $sys5 = "uname -a" nocase
        $sys6 = "cat /etc/passwd" nocase
        $sys7 = "ipconfig" nocase
        $sys8 = "ifconfig" nocase
    condition:
        3 of them
}
