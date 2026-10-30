#!/usr/bin/env bash
# Regenerate seance_plugin_pcap/tests/fixtures: real TLS handshake bytes.
#
# An OpenSSL client and an OpenSSL server, with a byte-forwarding proxy in
# between dumping each direction to a file. Nothing leaves this machine: both
# ends are on the loopback interface, and the certificate is generated here.
#
# The certificate is written twice, PEM and DER: x509_tests.rs parses the DER,
# and the PEM is what `openssl x509 -text` is run against to re-take the
# expectations. Writing one and not the other would leave the set describing
# two different certificates.
#
# Regenerating changes the bytes (a fresh random, a fresh RSA modulus), so the
# certificate expectations in seance_plugin_pcap/src/x509_tests.rs must be
# re-taken from `openssl x509 -text -in lab_certificate.pem` afterwards.
set -euo pipefail

here="$(cd "$(dirname "$0")/.." && pwd)"
out="$here/seance_plugin_pcap/tests/fixtures"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
cd "$work"

openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out cert.pem -days 3650 \
    -subj "/C=IE/ST=Dublin/O=Seance Lab/OU=Forensics/CN=lab.seance.invalid" \
    -addext "subjectAltName=DNS:lab.seance.invalid,DNS:alt.seance.invalid,IP:127.0.0.1" \
    >/dev/null 2>&1

cat > proxy.py <<'PYEOF'
import socket, sys, threading
listen_port, target_port, tag = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3]
c2s, s2c = open(f"{tag}-c2s.bin", "wb"), open(f"{tag}-s2c.bin", "wb")
srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", listen_port))
srv.listen(1)
cli, _ = srv.accept()
up = socket.create_connection(("127.0.0.1", target_port))
def pump(a, b, f):
    try:
        while True:
            d = a.recv(65536)
            if not d:
                break
            f.write(d)
            f.flush()
            b.sendall(d)
    except Exception:
        pass
    try:
        b.shutdown(socket.SHUT_WR)
    except Exception:
        pass
threads = [threading.Thread(target=pump, args=(cli, up, c2s)),
           threading.Thread(target=pump, args=(up, cli, s2c))]
for t in threads:
    t.start()
for t in threads:
    t.join()
PYEOF

run() { # version listen upstream tag extra-client-flags...
    local version="$1" upstream="$2" listen="$3" tag="$4"; shift 4
    openssl s_server -accept "$upstream" -cert cert.pem -key key.pem "$version" \
        -www -naccept 1 >/dev/null 2>&1 &
    sleep 1
    python3 proxy.py "$listen" "$upstream" "$tag" >/dev/null 2>&1 &
    sleep 1
    echo | timeout 20 openssl s_client -connect "127.0.0.1:$listen" \
        -servername lab.seance.invalid "$version" -CAfile cert.pem "$@" \
        > "$tag-client.log" 2>&1 || true
    sleep 1
}

run -tls1_2 44300 44301 tls12
run -tls1_3 44302 44303 tls13 -alpn h2,http/1.1

cp tls12-c2s.bin "$out/tls12_client_to_server.bin"
cp tls12-s2c.bin "$out/tls12_server_to_client.bin"
cp tls13-c2s.bin "$out/tls13_client_to_server.bin"
cp tls13-s2c.bin "$out/tls13_server_to_client.bin"
cp cert.pem "$out/lab_certificate.pem"
# The DER of the same certificate, which is what x509_tests.rs parses.
openssl x509 -in cert.pem -outform der -out "$out/lab_certificate.der"
echo "Wrote $out:"
ls -l "$out"
echo
echo "The oracle for the handshake fields, for re-taking the expectations:"
echo "  openssl s_client -connect 127.0.0.1:PORT -tls1_2 -trace"
