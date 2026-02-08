rule injection_xss
{
    meta:
        description = "Cross-site scripting patterns in agent skill/config"
        severity = "high"
        category = "injection"
        author = "AgentVet"
        date = "2025-02-08"

    strings:
        $re_script = /<script[^>]*>[^\n]+?<\x2Fscript>/i
        $re_event_handler = /on(error|load|click|mouseover|focus|blur)\s*=/i
        $re_javascript_uri = /javascript\s*:/i
        $re_data_uri = /data\s*:\s*text\/html/i
        $re_md_js = /\[[^\n]+\]\(javascript[^\n]+\)/i
        $re_svg_onload = /<svg[^>]*onload/i
        $re_img_onerror = /<img[^>]*onerror/i
        $re_iframe = /<iframe[^>]*src\s*=\s*["']?javascript/i
        $re_eval = /eval\s*\(\s*['"`]/i
        $re_document_write = /document\s*\.\s*write\s*\(/i

    condition:
        any of them
}
