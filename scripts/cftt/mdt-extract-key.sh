#!/usr/bin/env bash
# Regenerate the MDT expectation file for the NIST HTC Desire S JTAG image.
#
# ROADMAP §5.2 / VALIDATION.md "CFTT-MDT-1". NIST publishes the handset's
# population as an example/template, not an itemised key, so the expectations
# are the handset's OWN stored values, decoded independently of Séance with
# The Sleuth Kit (mmls/icat) and the sqlite3 CLI, and compared with the
# population PDF. Where the two disagree the row says so (`pdf_agrees: false`).
#
#   scripts/cftt/mdt-extract-key.sh ~/forensic_corpora/cftt_mobile \
#       seance_validate/tests/fixtures/cftt_mdt/htc_desire_s_contacts.json
#
# The data volume is the ext4 at sector 1343488 (found with `mmls` + `fsstat`);
# contacts2.db is inode 30484 and its write-ahead log inode 30493. Both are
# extracted side by side so sqlite3 replays the log, as Android does.
set -euo pipefail

DIR="${1:?corpus dir (holds HTC_Desire_S_JTAG.bin and the population PDF)}"
OUT="${2:?output json}"
IMG="$DIR/HTC_Desire_S_JTAG.bin"
PDF="$DIR/Mobile_Device_Data_Population_HTC_Desire_S.pdf"
OFFSET=1343488
for t in icat sqlite3 pdftotext sha256sum python3; do
    command -v "$t" >/dev/null || { echo "$t is required" >&2; exit 3; }
done
[ -s "$IMG" ] && [ -s "$PDF" ] || { echo "missing image or PDF in $DIR" >&2; exit 3; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
icat -o "$OFFSET" "$IMG" 30484 > "$WORK/c2.db"
icat -o "$OFFSET" "$IMG" 30493 > "$WORK/c2.db-wal"
pdftotext -layout "$PDF" "$WORK/pdf.txt"
sqlite3 -json "$WORK/c2.db" "
  SELECT r._id AS raw_id, r.display_name AS display_name, r.deleted AS deleted,
         m.mimetype AS mimetype, d.data1 AS data1
  FROM raw_contacts r
  LEFT JOIN data d ON d.raw_contact_id = r._id
  LEFT JOIN mimetypes m ON m._id = d.mimetype_id
  ORDER BY r._id, d._id" > "$WORK/rows.json"

python3 -I - "$WORK/rows.json" "$WORK/pdf.txt" "$IMG" "$PDF" "$OFFSET" "$OUT" <<'PY'
import hashlib, json, os, re, sys, unicodedata
rows_p, pdf_p, img, pdf, offset, out = sys.argv[1:7]

def sha(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 22), b""):
            h.update(b)
    return h.hexdigest()

contacts = {}
for r in json.load(open(rows_p, encoding="utf-8")):
    c = contacts.setdefault(r["raw_id"], {
        "raw_id": r["raw_id"], "display_name": r["display_name"] or "",
        "deleted": bool(r["deleted"]), "numbers": [], "emails": []})
    mt, v = r["mimetype"] or "", r["data1"]
    if v is None:
        continue
    if mt.endswith("/phone_v2") and v not in c["numbers"]:
        c["numbers"].append(v)
    elif mt.endswith("/email_v2") and v not in c["emails"]:
        c["emails"].append(v)

# What the population PDF says each entry is: (label, name, digits, emails).
# Typed from the PDF text; the comparison below is what is recorded.
pdf_text = re.sub(r"\s+", " ", open(pdf_p, encoding="utf-8").read())
PDF = {
    "John Jacob Jingle Heimer Schmidt That’s My Name Too Whenever I GoOut The People Always Shout John Jacob Jingle Heimer Schmidt":
        ("Long Name (50 chars), Mobile Number",
         "John Jacob Jingle Heimer Schmidt That’s My Name Too Whenever I Go Out The People Always Shout John Jacob Jingle Heimer Schmidt",
         "8988675309", []),
    "Jimi Hendrix": ("Regular Name, Mobile Number, email, website, picture",
                     "Jimi Hendrix", "7691234560", ["hendrix@experienced.com"]),
    "*": ("Special Character Name, Home Number", "*", "8887771212", []),
    "8785551111": ("Blank Name, Work Number", "", "8785551111", []),
    "Stevie Ray Vaughn": ("Regular Name, Mobile Number, email, deleted picture, address, birthday",
                          "Stevie Ray Vaughn", "1234567890", ["stevie@srv.com"]),
    "John Bonham": ("Deleted Entry, Home Number", "John Bonham", "9878767654", []),
    "阿恶哈拉": ("Non-ASCII Entry, Mobile Number", "阿恶哈拉", "+86 35 8 763 30 07", []),
    "Aurélien": ("Non-ASCII Entry, Number", "Aurélien", "+33 22 6 555 20 20", []),
}
digits = lambda s: re.sub(r"\D", "", s)
nfc = lambda s: unicodedata.normalize("NFC", s)

key = []
for rid in sorted(contacts):
    c = contacts[rid]
    p = PDF.get(c["display_name"])
    if p is None:
        c["pdf_label"] = None
        c["pdf_agrees"] = None
        c["note"] = "on the handset, not itemised in the population PDF"
    else:
        label, pname, pdigits, pemails = p
        # PDF entry present: does it say the same thing the handset stored?
        same_name = nfc(pname) == nfc(c["display_name"])
        same_nums = sorted(digits(n) for n in c["numbers"]) == [digits(pdigits)]
        same_mail = sorted(c["emails"]) == sorted(pemails)
        c["pdf_label"] = label
        c["pdf_agrees"] = bool(same_name and same_nums and same_mail)
        c["note"] = "" if c["pdf_agrees"] else (
            "handset and PDF differ: handset name %r, PDF name %r" % (c["display_name"], pname))
    c["source"] = "handset contacts2.db via icat+sqlite3"
    key.append(c)

doc = {
    "source": "handset contacts2.db (+ write-ahead log) read with TSK icat and sqlite3, independent of Seance",
    "image": os.path.basename(img),
    "image_sha256": sha(img),
    "image_length": os.path.getsize(img),
    "population_pdf": os.path.basename(pdf),
    "population_pdf_sha256": sha(pdf),
    "volume_offset_sectors": int(offset),
    "contacts2_inode": 30484,
    "contacts": key,
}
os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
with open(out, "w", encoding="utf-8") as f:
    json.dump(doc, f, ensure_ascii=False, indent=2)
    f.write("\n")
print("wrote %s: %d contacts" % (out, len(key)))
PY
