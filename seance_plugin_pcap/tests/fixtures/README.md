# TLS handshake fixtures

Four files of **real handshake bytes**, one per direction of two connections,
and the certificate the server presented in both DER and PEM. The handshakes
are the bytes as they crossed a loopback socket — captured by a byte-forwarding
proxy between an OpenSSL client and an OpenSSL server, not hand-written — so the
parser in
`seance_plugin_pcap/src/tls.rs` is graded against what a client actually sends
rather than against a fixture written to match it.

| File | What it holds |
|------|---------------|
| `tls12_client_to_server.bin` | ClientHello (SNI `lab.seance.invalid`), ClientKeyExchange, ChangeCipherSpec, then encrypted records |
| `tls12_server_to_client.bin` | ServerHello, **Certificate**, ServerKeyExchange, ServerHelloDone, NewSessionTicket, then encrypted records |
| `tls13_client_to_server.bin` | ClientHello (SNI, ALPN `h2`/`http/1.1`, `supported_versions` naming TLS 1.3), then application-data records |
| `tls13_server_to_client.bin` | ServerHello, then application data only — **the certificate is encrypted in TLS 1.3 and is not in the capture** |
| `lab_certificate.der` | The same certificate as DER, which is the form `x509_tests.rs` parses — a certificate crosses the wire as DER |
| `lab_certificate.pem` | The self-signed certificate the server presented, for grading the X.509 fields against `openssl x509 -text` |

No private key is here. `scripts/make-tls-fixtures.sh` regenerates the whole
set with a fresh key and certificate; the bytes change (a new random, a new
modulus) and so do the certificate's serial, dates and fingerprint, so a
regenerated set needs the per-certificate expectations in
`seance_plugin_pcap/src/x509_tests.rs` re-taken from `openssl x509 -text`.
The files in the tree were generated with OpenSSL 3.5.5 on 2026-09-15.

The oracle for the handshake fields is `openssl s_client -trace`, which prints
OpenSSL's own decode of the same ClientHello: the cipher list, the extension
list in order, the supported groups and the EC point formats. The JA3 fields
asserted in `tls_tests.rs` are those lists.
