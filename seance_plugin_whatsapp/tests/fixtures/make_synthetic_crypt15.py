"""Make the synthetic crypt15 fixtures (run from this directory).

Synthetic: a made-up 32-byte root key and made-up payloads, laid out the way
the crypt15 backups in VALIDATION.md WHATSAPP-CRYPT15-1 are:
[protobuf length][0x01, when a feature list is present][protobuf]
[AES-256-GCM ciphertext][16-byte tag][MD5 of everything before it, when present].
The protobuf is the minimum the reader needs: field 1 (key type 1), field 3
holding the IV (field 3.1), field 4 holding the WhatsApp version (field 4.1).
The AES key is HKDF-SHA256 of the root (salt 32 zero bytes, info
"backup encryption"), computed here with Python's `cryptography`, and the
encryption is OpenSSL's through the same library, so the fixtures do not come
from the code they test. They pin the mechanism only; the real backups grade it.
"""
import hashlib, io, os, sqlite3, tempfile, zipfile, zlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

root = bytes(range(0x90, 0xB0))
iv = bytes(range(0xC0, 0xD0))
key = HKDF(algorithm=hashes.SHA256(), length=32, salt=bytes(32),
           info=b"backup encryption").derive(root)

def ld(field, data):
    return bytes([field << 3 | 2, len(data)]) + data

proto = b"\x08\x01" + ld(3, ld(1, iv)) + ld(4, ld(1, b"2.99.1.1"))

def backup(name, payload, feature=True, md5=True):
    ct = AESGCM(key).encrypt(iv, payload, None)
    body = bytes([len(proto)]) + (b"\x01" if feature else b"") + proto + ct
    if md5:
        body += hashlib.md5(body).digest()
    open(name, "wb").write(body)

java = bytes.fromhex("aced0005757200025b42acf317f8060854e00200007870") + (32).to_bytes(4, "big")
open("synthetic_encrypted_backup.key", "wb").write(java + root)

# A message store with the modern schema and three made-up messages.
path = os.path.join(tempfile.mkdtemp(), "msgstore.db")
conn = sqlite3.connect(path)
conn.executescript("""
CREATE TABLE message (_id INTEGER PRIMARY KEY, chat_row_id INTEGER, from_me INTEGER DEFAULT 0,
  key_id TEXT, sender_jid_row_id INTEGER, status INTEGER DEFAULT 0, timestamp INTEGER DEFAULT 0,
  message_type INTEGER DEFAULT 0, text_data TEXT);
CREATE TABLE chat (_id INTEGER PRIMARY KEY, jid_row_id INTEGER, subject TEXT);
CREATE TABLE jid (_id INTEGER PRIMARY KEY, user TEXT, server TEXT, raw_string TEXT);
INSERT INTO jid VALUES (1, '15557654321', 's.whatsapp.net', '15557654321@s.whatsapp.net');
INSERT INTO chat VALUES (1, 1, NULL);
INSERT INTO message VALUES (1, 1, 0, 'c15-1', 0, 0, 1700000000000, 0, 'Synthetic crypt15 message one');
INSERT INTO message VALUES (2, 1, 1, 'c15-2', 0, 5, 1700000060000, 0, 'Synthetic crypt15 message two');
""")
conn.commit()
conn.close()
store = open(path, "rb").read()
open("synthetic_crypt15_msgstore.db", "wb").write(store)
backup("synthetic_msgstore.db.crypt15", zlib.compress(store))
# No 0x01 feature byte after the length byte (the wa.db shape).
backup("synthetic_nofeature.db.crypt15", zlib.compress(store), feature=False)

# A ZIP payload: raw with no MD5 trailer (the stickers shape), and zlib-wrapped
# with one (the incremental-backup shape).
buf = io.BytesIO()
with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as z:
    z.writestr("sticker.webp", b"RIFF\x00\x00\x00\x00WEBPsynthetic")
archive = buf.getvalue()
open("synthetic_crypt15_archive.zip", "wb").write(archive)
backup("synthetic_stickers.backup.crypt15", archive, md5=False)
backup("synthetic_increment.crypt15", zlib.compress(archive))
