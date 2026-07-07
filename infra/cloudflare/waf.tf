# WAF custom rules for mkit.sh
#
# mkit.sh runs entirely on Cloudflare Workers (Waku SSR web app, MCP server,
# keys/repo/og workers) — no WordPress, PHP, Java, Apache, or nginx. Requests
# for those paths are definitively malicious scanner probes and can be
# blocked outright.
#
# Cloudflare plan limits: Free=5, Pro=20, Business=100, Enterprise=1000 rules.
# These rules use `contains`/`starts_with`/`ends_with` (no regex) for
# compatibility with Free/Pro plans.
#
# Custom block responses require Pro+. On Free, blocked requests get
# Cloudflare's default 403 page.

resource "cloudflare_ruleset" "waf_custom" {
  zone_id     = var.zone_id
  name        = "mkit WAF custom rules"
  description = "Block scanner probes, exploit attempts, and malicious paths"
  kind        = "zone"
  phase       = "http_request_firewall_custom"

  rules = [
    {
      ref         = "block_dotfiles"
      description = "Block dotfile and config file access"
      expression  = <<-EXPR
        (http.request.uri.path contains "/.env")
        or (http.request.uri.path contains "/.git")
        or (http.request.uri.path contains "/.svn")
        or (http.request.uri.path contains "/.aws")
        or (http.request.uri.path contains "/.config")
        or (http.request.uri.path contains "/.htaccess")
        or (http.request.uri.path contains "/.htpasswd")
        or (http.request.uri.path contains "/.DS_Store")
        or (http.request.uri.path contains "/.vscode")
        or (http.request.uri.path contains "/.idea")
      EXPR
      action      = "block"
    },
    {
      ref         = "block_wordpress_cms"
      description = "Block WordPress and CMS scanner probes"
      expression  = <<-EXPR
        (starts_with(http.request.uri.path, "/wp-"))
        or (http.request.uri.path contains "/xmlrpc")
        or (http.request.uri.path contains "/phpmyadmin")
        or (http.request.uri.path contains "/pma")
        or (http.request.uri.path contains "/adminer")
        or (http.request.uri.path contains "/administrator")
        or (http.request.uri.path contains "/joomla")
        or (http.request.uri.path contains "/drupal")
        or (http.request.uri.path contains "/magento")
      EXPR
      action      = "block"
    },
    {
      ref         = "block_exploit_paths"
      description = "Block common exploit, backdoor, and debug paths"
      expression  = <<-EXPR
        (starts_with(http.request.uri.path, "/cgi-bin"))
        or (starts_with(http.request.uri.path, "/cgi-sys"))
        or (http.request.uri.path contains "/actuator")
        or (http.request.uri.path contains "/jenkins")
        or (http.request.uri.path contains "/solr")
        or (http.request.uri.path contains "/struts")
        or (http.request.uri.path contains "/telescope")
        or (http.request.uri.path contains "/elfinder")
        or (http.request.uri.path contains "/vendor/phpunit")
        or (http.request.uri.path contains "/_profiler")
        or (http.request.uri.path contains "/server-status")
        or (http.request.uri.path contains "/server-info")
      EXPR
      action      = "block"
    },
    {
      ref         = "block_script_extensions"
      description = "Block PHP, ASP, JSP, and other server-side script probes"
      expression  = <<-EXPR
        (ends_with(http.request.uri.path, ".php"))
        or (ends_with(http.request.uri.path, ".asp"))
        or (ends_with(http.request.uri.path, ".aspx"))
        or (ends_with(http.request.uri.path, ".jsp"))
        or (ends_with(http.request.uri.path, ".cgi"))
        or (ends_with(http.request.uri.path, ".pl"))
      EXPR
      action      = "block"
    },
    {
      ref         = "block_sensitive_files"
      description = "Block backup, credential, and database dump file access"
      expression  = <<-EXPR
        (ends_with(http.request.uri.path, ".sql"))
        or (ends_with(http.request.uri.path, ".bak"))
        or (ends_with(http.request.uri.path, ".key"))
        or (ends_with(http.request.uri.path, ".pem"))
        or (ends_with(http.request.uri.path, ".log"))
        or (ends_with(http.request.uri.path, ".conf"))
        or (ends_with(http.request.uri.path, ".ini"))
        or (ends_with(http.request.uri.path, ".tar.gz"))
        or (ends_with(http.request.uri.path, ".zip"))
        or (http.request.uri.path contains "/backup")
        or (http.request.uri.path contains "/dump")
      EXPR
      action      = "block"
    },
  ]
}
