rule injection_template
{
    meta:
        description = "Server-side template injection patterns"
        severity = "high"
        category = "injection"
        author = "AgentVet"
        date = "2025-02-08"

    strings:
        $jinja_open = "{{"
        $jinja_close = "}}"
        $jinja_block_open = "{%"
        $jinja_block_close = "%}"

        $payload_class = "__class__"
        $payload_subclasses = "__subclasses__"
        $payload_mro = "__mro__"
        $payload_globals = "__globals__"
        $payload_builtins = "__builtins__"
        $payload_import = "__import__"
        $payload_config = "config.items()"

    condition:
        ($jinja_open and $jinja_close and any of ($payload*)) or
        ($jinja_block_open and $jinja_block_close and any of ($payload*))
}
