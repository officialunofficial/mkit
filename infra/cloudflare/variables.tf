variable "cloudflare_api_token" {
  description = "Cloudflare API token with Zone WAF Write permission"
  type        = string
  sensitive   = true
}

variable "zone_id" {
  description = "Cloudflare zone ID for mkit.sh"
  type        = string
}
