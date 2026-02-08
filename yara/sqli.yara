rule injection_sqli
{
    meta:
        description = "SQL injection patterns in agent skill/config"
        severity = "high"
        category = "injection"
        author = "AgentVet"
        date = "2025-02-08"

    strings:
        $method_select = "SELECT" nocase
        $method_alter = "ALTER" nocase
        $method_create = "CREATE" nocase
        $method_drop = "DROP" nocase
        $method_exec = "EXEC" nocase
        $method_union = "UNION" nocase
        $method_insert = "INSERT" nocase
        $method_delete = "DELETE" nocase
        $method_truncate = "TRUNCATE" nocase
        $method_update = "UPDATE" nocase

        $re_dash_comment = /--[^\r\n]+/i
        $re_single_quote = /'\s*(OR|AND)\s+['0-9]/i
        $re_semicolon = /;\s*(DROP|DELETE|UPDATE|INSERT|ALTER|EXEC)/i
        $re_char = /(cha?r\(\d+\)([,+]|\|\|)?)+/i
        $re_system_catalog = /(SELECT|FROM)\s+pg_\w+/i
        $re_sleep = /SLEEP\s*\(\s*\d+\s*\)/i
        $re_benchmark = /BENCHMARK\s*\(/i
        $re_into_outfile = /INTO\s+(OUT|DUMP)FILE/i

    condition:
        any of ($method*) and any of ($re*)
}
