# Upload key rotation runbook

Upload ticket tokens and multipart part receipts use different BLAKE3 derived
MAC keys from each configured deployment secret. The key id identifies the
secret for both formats. The first configured key signs new tokens and
receipts; all configured keys verify old ones.

1. Add a new, unique key id and secret as the first entry in the ticket-key
   configuration. Keep existing entries below it.
2. Deploy the same ordered key set to every server instance that serves the
   audience. Confirm new BeginUpload tickets and part receipts carry the new id.
3. Keep each old key id in the verification set for **at least seven days**
   after the rotation, the maximum ticket lifetime. Only then remove it from
   every instance. An invalid receipt during that window indicates forgery,
   rather than an expected rotation failure.

The token and receipt formats expose the key id, not the deployment secret.
Handle all entries as secrets under the native `--ticket-key-file` or Worker
`TICKET_KEYS` configuration rules. A session already in progress keeps its
original token and receipts; clients do not need to restart it on rotation.
