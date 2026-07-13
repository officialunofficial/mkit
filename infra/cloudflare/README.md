# Cloudflare infrastructure

Terraform configuration for Cloudflare WAF rules on `mkit.sh` (Free plan).

## Setup

```bash
cd infra/cloudflare
terraform init
```

## Plan / apply

The token needs **Zone WAF Write** and **Zone Read**. Get the zone ID from the
Cloudflare dashboard (Overview → API section) or:

```bash
curl -s -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
  "https://api.cloudflare.com/client/v4/zones?name=mkit.sh" \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['result'][0]['id'])"
```

```bash
terraform plan \
  -var="cloudflare_api_token=$CLOUDFLARE_API_TOKEN" \
  -var="zone_id=$CLOUDFLARE_ZONE_ID"

terraform apply \
  -var="cloudflare_api_token=$CLOUDFLARE_API_TOKEN" \
  -var="zone_id=$CLOUDFLARE_ZONE_ID"
```

Secrets and state are gitignored; only the `.tf` definitions are committed.

## WAF custom rules (5/5 Free plan limit)

| Rule | Action | Blocks |
|------|--------|--------|
| `block_dotfiles` | block | `/.env`, `/.git`, `/.aws`, `/.config`, … |
| `block_wordpress_cms` | block | `/wp-*`, `/xmlrpc`, `/phpmyadmin`, `/adminer`, … |
| `block_exploit_paths` | block | `/cgi-bin`, `/actuator`, `/jenkins`, `/_profiler`, … |
| `block_script_extensions` | block | `.php`, `.asp`, `.aspx`, `.jsp`, `.cgi`, `.pl` |
| `block_sensitive_files` | block | `.sql`, `.bak`, `.key`, `.pem`, `.zip`, … |

All expressions use `contains`/`starts_with`/`ends_with` (no regex) for
Free/Pro compatibility.

## Free plan notes

Custom JSON block responses, the managed WAF ruleset, and rate-limiting rules
require Pro+. On Free, blocked requests get Cloudflare's default 403 page.
