`selfsigned-cert.der` and `selfsigned-pk8.der` (DER, since the repository ignores
`*.pem` and `*.key`): a self-signed certificate for `localhost` (CN=localhost, SAN localhost and
127.0.0.1, valid 100 years) and its private key, for `tests/hook_channel.rs`:
the hook channel must refuse a server whose certificate the platform verifier
does not trust. Test fixture only; the key protects nothing. Regenerate with:

    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
      -keyout k.key -out c.crt -days 36500 -subj "/CN=localhost" \
      -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
      -addext "basicConstraints=critical,CA:FALSE" -addext "keyUsage=critical,digitalSignature" \
      -addext "extendedKeyUsage=serverAuth"
    openssl x509 -in c.crt -outform DER -out selfsigned-cert.der
    openssl pkcs8 -topk8 -nocrypt -in k.key -outform DER -out selfsigned-pk8.der
