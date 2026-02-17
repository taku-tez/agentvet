rule supply_chain_lockfile_manipulation
{
    meta:
        description = "Lock file manipulation - potential dependency confusion"
        severity = "high"
        category = "supply-chain"
        author = "AgentVet"
        date = "2026-02-17"

    strings:
        $lock1 = "package-lock.json"
        $lock2 = "yarn.lock"
        $lock3 = "pnpm-lock.yaml"
        $lock4 = "Pipfile.lock"
        $lock5 = "poetry.lock"
        $lock6 = "Gemfile.lock"

        $action1 = /(?:rm|delete|remove|unlink)\s+.*lock/i
        $action2 = /sed\s+-i.*lock/i
        $action3 = /echo\s+.*>\s*.*lock/i

    condition:
        any of ($lock*) and any of ($action*)
}

rule supply_chain_registry_override
{
    meta:
        description = "NPM/PyPI registry override - potential supply chain attack"
        severity = "high"
        category = "supply-chain"
        author = "AgentVet"
        date = "2026-02-17"

    strings:
        $npm_reg = /registry\s*=\s*https?:\/\/(?!registry\.npmjs\.org)/i
        $pip_index = /--index-url\s+https?:\/\/(?!pypi\.org)/i
        $pip_extra = /--extra-index-url\s+https?:\/\//i
        $npm_config = /npm_config_registry\s*=/i
        $pip_conf = /\[global\]\s*\n\s*index-url/i

    condition:
        any of them
}

rule supply_chain_postinstall_exfil
{
    meta:
        description = "Suspicious postinstall script with network access"
        severity = "critical"
        category = "supply-chain"
        author = "AgentVet"
        date = "2026-02-17"

    strings:
        $post1 = "postinstall"
        $post2 = "preinstall"
        $post3 = "install"

        $net1 = /curl\s+/
        $net2 = /wget\s+/
        $net3 = /fetch\s*\(/
        $net4 = /http\.get\s*\(/
        $net5 = /https\.get\s*\(/
        $net6 = /XMLHttpRequest/
        $net7 = /\.send\s*\(/

    condition:
        any of ($post*) and any of ($net*)
}

rule supply_chain_git_hook_injection
{
    meta:
        description = "Git hook injection - malicious git hooks"
        severity = "high"
        category = "supply-chain"
        author = "AgentVet"
        date = "2026-02-17"

    strings:
        $hook1 = ".git/hooks/pre-commit"
        $hook2 = ".git/hooks/post-commit"
        $hook3 = ".git/hooks/pre-push"
        $hook4 = ".git/hooks/post-checkout"
        $hook5 = ".git/hooks/pre-receive"

        $write1 = /echo\s+.*>\s*\.git\/hooks/
        $write2 = /cp\s+.*\.git\/hooks/
        $write3 = /chmod\s+\+x\s+.*\.git\/hooks/

    condition:
        any of ($hook*) and any of ($write*)
}
