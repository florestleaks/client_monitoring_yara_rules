rule internalMonitoramentoLeak12

{    meta:
        author = "FlorestLeaks"
        description = "Matches HTML content of a specific example domain page"
        reference = "https://florestleaks.com"

    
    strings:
        $html_open = "<!doctype html>" nocase
        $title = "<title>Example Domain</title>" nocase
        $body_start = "<body>" nocase
        $h1_content = "<h1>Example Domain</h1>" nocase
        $p_content = "This domain is for use in illustrative examples in documents." nocase
        $link = "href=\"https://www.iana.org/domains/example\"" nocase
        $style_body = "body {" nocase
        $style_div = "div {" nocase
        $media_query = "@media (max-width: 700px) {" nocase

    condition:
        $html_open and $title and $body_start and $h1_content and
        $p_content and $link and $style_body and $style_div and
        $media_query
}
