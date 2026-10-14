Public TLS regression fixtures. `ca.crt` is a self-signed test CA;
`server.crt` is its localhost-only leaf certificate. `server-pk8.der` is the
unprotected leaf test key, never a deployment credential. Certificates are
valid from 2026-10-01 through 2036-09-28. The CA private key is not committed.
Tests use the installed rustls verifier and real Connect RPC/pack streams;
no verification override is used. A URL with 127.0.0.1 deliberately fails
hostname verification against the localhost-only SAN.
