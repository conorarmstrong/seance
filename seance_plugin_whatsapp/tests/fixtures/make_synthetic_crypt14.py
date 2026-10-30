"""Make the synthetic crypt14 fixtures (run from this directory).

Synthetic: a made-up key and a made-up 4 KiB "database" (the SQLite magic and
filler), laid out the way the real Pixel 7a backups in VALIDATION.md
WHATSAPP-CRYPT14-1 are: [protobuf length][0x01][protobuf][AES-256-GCM
ciphertext of the zlib stream][16-byte tag][MD5 of everything before it].
The protobuf is the minimum the reader needs: field 2 holding the cipher
version (1), key version (2), server salt (3), Google ID (4) and IV (5).
Encryption is OpenSSL's, through Python's `cryptography`, so the fixture does
not come from the code it tests. It pins the mechanism only.
"""
import hashlib, zlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

key = bytes(range(0x40, 0x60))
salt = bytes(range(0x10, 0x30))
gid = bytes(range(0xA0, 0xB0))
iv = bytes(range(0x70, 0x80))

def ld(field, data):
    return bytes([field << 3 | 2, len(data)]) + data

c14 = ld(1, b"\x00\x01") + ld(2, b"2") + ld(3, salt) + ld(4, gid) + ld(5, iv)
proto = b"\x08\x00" + ld(2, c14)
db = b"SQLite format 3\x00" + bytes(4096 - 16)
ct = AESGCM(key).encrypt(iv, zlib.compress(db), None)
body = bytes([len(proto), 1]) + proto + ct
open("synthetic.crypt14", "wb").write(body + hashlib.md5(body).digest())

payload = b"\x00\x01\x02" + salt + gid + bytes(32) + bytes(16) + key
assert len(payload) == 131
java = bytes.fromhex("aced0005757200025b42acf317f8060854e00200007870") + (131).to_bytes(4, "big")
open("synthetic.key", "wb").write(java + payload)
open("synthetic.db", "wb").write(db)

# A backup that holds a real Android message store (the modern `message` /
# `chat` / `jid` schema, three made-up messages), under the same key, for the
# ingest pairing tests; and a key file of the same shape whose server salt is
# another install's, which the pairing must refuse by its salt.
import os, sqlite3, tempfile
path = os.path.join(tempfile.mkdtemp(), "msgstore.db")
conn = sqlite3.connect(path)
conn.executescript("""
CREATE TABLE message (_id INTEGER PRIMARY KEY, chat_row_id INTEGER, from_me INTEGER DEFAULT 0,
  key_id TEXT, sender_jid_row_id INTEGER, status INTEGER DEFAULT 0, timestamp INTEGER DEFAULT 0,
  message_type INTEGER DEFAULT 0, text_data TEXT);
CREATE TABLE chat (_id INTEGER PRIMARY KEY, jid_row_id INTEGER, subject TEXT);
CREATE TABLE jid (_id INTEGER PRIMARY KEY, user TEXT, server TEXT, raw_string TEXT);
INSERT INTO jid VALUES (1, '15551234567', 's.whatsapp.net', '15551234567@s.whatsapp.net');
INSERT INTO chat VALUES (1, 1, NULL);
INSERT INTO message VALUES (1, 1, 0, 'k1', 0, 0, 1672848000000, 0, 'Synthetic backup message one');
INSERT INTO message VALUES (2, 1, 1, 'k2', 0, 5, 1672848060000, 0, 'Synthetic backup message two');
INSERT INTO message VALUES (3, 1, 0, 'k3', 0, 0, 1672848120000, 0, 'Synthetic backup message three');
""")
conn.commit()
conn.close()
store = open(path, "rb").read()
ct = AESGCM(key).encrypt(iv, zlib.compress(store), None)
body = bytes([len(proto), 1]) + proto + ct
open("synthetic_msgstore.db.crypt14", "wb").write(body + hashlib.md5(body).digest())

other_salt = bytes(range(0x30, 0x50))
payload = b"\x00\x01\x02" + other_salt + gid + bytes(32) + bytes(16) + bytes(range(0x60, 0x80))
open("synthetic_other_install.key", "wb").write(java + payload)
