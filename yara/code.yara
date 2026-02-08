rule injection_code_shells
{
    meta:
        description = "Code injection - dangerous module imports"
        severity = "high"
        category = "injection"
        author = "AgentVet"
        date = "2025-02-08"

    strings:
        $imp = "import"
        $from = "from"

        $mod_os = "os"
        $mod_cmd = "cmd"
        $mod_subprocess = "subprocess"
        $mod_shutil = "shutil"

    condition:
        $imp and any of ($mod*) and
        for any of ($mod*) : (@imp < @)
}

rule injection_code_networking
{
    meta:
        description = "Code injection - networking library imports"
        severity = "high"
        category = "injection"
        author = "AgentVet"
        date = "2025-02-08"

    strings:
        $imp = "import"
        $from = "from"

        $mod_socket = "socket"
        $mod_http = "http"
        $mod_requests = "requests"
        $mod_urllib = "urllib"
        $mod_asyncssh = "asyncssh"

    condition:
        $imp and any of ($mod*) and
        for any of ($mod*) : (@imp < @)
}

rule injection_code_eval
{
    meta:
        description = "Code injection - eval/exec patterns"
        severity = "high"
        category = "injection"
        author = "AgentVet"
        date = "2025-02-08"

    strings:
        $eval = /eval\s*\(/
        $exec = /exec\s*\(/
        $compile = /compile\s*\([^)]*,\s*['"]exec['"]/
        $getattr = /getattr\s*\(/
        $globals = "__globals__"
        $builtins = "__builtins__"

    condition:
        any of them
}
