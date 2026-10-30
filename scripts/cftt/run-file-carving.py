#!/usr/bin/env python3
"""Run NIST CFTT's Forensic File Carving images against Seance (ROADMAP 5.2).

    scripts/cftt/run-file-carving.py --corpus ~/forensic_corpora/cftt_file_carving \
        --out /tmp/cftt-fc [--images L0_Graphic,L0_Archive] [--bin target/release/seance]

The corpus is NIST's set (https://cfreds-archive.nist.gov/FileCarving/): 30
images LEVEL_Type.dd, each documented as "file, size, start sector, end sector"
in ImageLayouts.htm, and the original files in TestFiles/. NIST publishes NO
hash for any of it, so the run states that rather than implying a verification.

WHAT IS GRADED. Only L0 (non-fragmented) is a conformance target: L1-L5 need
fragment reordering or nesting recovery, and non-sequential reordering is on
this project's deliberately-out-of-scope list (documentation/VALIDATION.md).
For each non-Fill file of each image graded:
  found_at_start  a carved object starts at exactly start_sector * 512
  exact           the bytes of the image from that offset for the carved
                  object's own size hash to the ORIGINAL file's MD5 (the
                  original from TestFiles/, not from the layout)
  contains        the carved object is at least the original's size and its
                  leading bytes are the original (extra trailing bytes allowed)
  overshoot       carved size minus the original size
Carved objects that begin at no file's start are counted as extra; the run says
how many fall inside a Fill region, and does not call them false positives
(Fill is NIST's own data, of no stated content).

Running a published methodology is NOT third-party validation.
"""
import argparse, hashlib, json, os, re, signal, sqlite3, subprocess, sys, time, urllib.request, uuid

def api(port, method, path, body=None):
    req = urllib.request.Request(f"http://127.0.0.1:{port}/api/v1{path}", method=method,
        data=json.dumps(body).encode() if body is not None else None,
        headers={"content-type": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.load(r)

def wait_settled(port, db, case, timeout):
    t0 = time.time(); idle = stable = 0; last = -2
    def count():
        try:
            c = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
            n = c.execute("SELECT COUNT(*) FROM artifacts WHERE case_id=?", (uuid.UUID(case).bytes,)).fetchone()[0]
            c.close(); return n
        except Exception:
            return -1
    for _ in range(60):  # let the work begin
        st = api(port, "GET", "/status")
        if st.get("active_tasks", 0) != 0 or count() > 1: break
        time.sleep(1)
    while True:
        st = api(port, "GET", "/status"); n = count()
        idle = idle + 1 if st.get("active_tasks", -1) == 0 else 0
        stable = stable + 1 if n == last else 0
        last = n
        if idle >= 4 and stable >= 5: return True, n
        if time.time() - t0 > timeout: return False, n
        time.sleep(2)

def ingest(binp, image, out, port, timeout):
    ws = os.path.join(out, "ws", os.path.basename(image)); os.makedirs(ws + "/tmp", exist_ok=True)
    env = dict(os.environ, SEANCE_AUTH_ENABLED="false", SEANCE_EVIDENCE_ROOTS=os.path.dirname(image), TMPDIR=ws + "/tmp")
    log = open(os.path.join(out, os.path.basename(image) + ".server.log"), "w")
    p = subprocess.Popen([binp, "--headless", "--workspace", ws, "--port", str(port), "-l", "2"], env=env, stdout=log, stderr=log)
    try:
        for _ in range(120):
            try: api(port, "GET", "/status"); break
            except Exception: time.sleep(1)
        case = api(port, "POST", "/cases", {"name": "CFTT FC " + os.path.basename(image), "examiner_name": "scripts/cftt/run-file-carving.py"})["id"]
        src = api(port, "POST", f"/cases/{case}/ingest", {"path": image, "profile": "deep"})["artifact_id"]
        ok, n = wait_settled(port, ws + "/seance.sqlite", case, timeout)
        # A raw NIST image has no file system and no partition table, so the
        # ingest finds nothing to parse and the whole-source carve route has no
        # FileSystem/UnallocatedSpace descendant to queue. Carving is opt-in and
        # is asked for by name on the source itself.
        api(port, "POST", f"/cases/{case}/artifacts/{src}/run_module", {"module_id": "plugin.recovery.file_carver"})
        time.sleep(5)
        ok2, n = wait_settled(port, ws + "/seance.sqlite", case, timeout)
        ok = ok and ok2
        c = sqlite3.connect(f"file:{ws}/seance.sqlite?mode=ro", uri=True)
        rows = c.execute("SELECT artifact_type, metadata_json FROM artifacts WHERE case_id=?", (uuid.UUID(case).bytes,)).fetchall()
        c.close()
        return ok, n, rows
    finally:
        p.send_signal(signal.SIGTERM)
        try: p.wait(20)
        except Exception: p.kill()
        subprocess.run(["rm", "-rf", ws])

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", required=True); ap.add_argument("--out", required=True)
    ap.add_argument("--images", default="L0_Graphic,L0_Documents,L0_Archive,L0_Audio,L0_Video")
    ap.add_argument("--bin", default=os.environ.get("SEANCE_BIN", "target/release/seance"))
    ap.add_argument("--port", type=int, default=8241); ap.add_argument("--timeout", type=int, default=1800)
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    layout = json.load(open(os.path.join(a.out, "layout.json"))) if os.path.exists(os.path.join(a.out, "layout.json")) else parse_layout(a.corpus, a.out)
    originals = {}
    for root, _, fs in os.walk(os.path.join(a.corpus, "TestFiles")):
        for f in fs: originals[f.lower()] = os.path.join(root, f)
    report = []
    for name in a.images.split(","):
        image = os.path.abspath(os.path.join(a.corpus, "Images", name + ".dd"))
        key = name.replace("Documents", "Document") + ".dd"
        files = [r for r in layout[key] if not r["file"].startswith("Fill")]
        ok, n, rows = ingest(os.path.abspath(a.bin), image, a.out, a.port, a.timeout)
        carved = []
        for t, mj in rows:
            m = json.loads(mj)
            if "carving_offset_absolute" in m or m.get("carved"):
                # On a raw image with no file system the object carries only
                # `carving_offset`, which is then the image offset.
                m["_off"] = m.get("carving_offset_absolute", m.get("carving_offset"))
                carved.append(m)
        starts = {}
        for m in carved:
            starts.setdefault(m["_off"], []).append(m)
        fill = [(r["start"] * 512, (r["end"] + 1) * 512) for r in layout[key] if r["file"].startswith("Fill")]
        img = open(image, "rb")
        res = []
        for f in files:
            base = re.sub(r" \(\d+\)$", "", f["file"])
            orig = open(originals[base.lower()], "rb").read()
            off = f["start"] * 512
            img.seek(off); disk = img.read(len(orig))
            hits = starts.get(off, [])
            row = {"file": f["file"], "start_sector": f["start"], "size": len(orig), "layout_size": f["size"],
                   "disk_equals_original": disk == orig, "found_at_start": bool(hits)}
            if hits:
                h = hits[0]; sz = h.get("carving_size") or h.get("size")
                img.seek(off); body = img.read(sz) if sz else b""
                row.update(signature=h.get("carving_signature"), carved_size=sz, validated=h.get("carving_validated"),
                           exact=hashlib.md5(body).hexdigest() == hashlib.md5(orig).hexdigest(),
                           contains=bool(sz) and sz >= len(orig) and body[:len(orig)] == orig,
                           overshoot=(sz - len(orig)) if sz else None)
            res.append(row)
        keyed = {f["start"] * 512 for f in files}
        extra = [m for m in carved if m["_off"] not in keyed]
        in_fill = [m for m in extra if any(lo <= (m["_off"] if m["_off"] is not None else -1) < hi for lo, hi in fill)]
        summary = {"image": name, "ingest_settled": ok, "artifacts": n, "files": len(files),
                   "found_at_start": sum(r["found_at_start"] for r in res),
                   "exact": sum(bool(r.get("exact")) for r in res),
                   "contains": sum(bool(r.get("contains")) for r in res),
                   "extra_carved_objects": len(extra), "extra_in_fill": len(in_fill),
                   "extra_by_signature": {k: sum(1 for m in extra if m.get("carving_signature") == k)
                                          for k in sorted({m.get("carving_signature") for m in extra}, key=str)}}
        print(json.dumps(summary)); report.append({"summary": summary, "files": res})
    json.dump(report, open(os.path.join(a.out, "report.json"), "w"), indent=1)

def parse_layout(corpus, out):
    import html
    t = open(os.path.join(corpus, "ImageLayouts.htm"), errors="replace").read()
    lines = [l.strip() for l in html.unescape(re.sub(r"<[^>]+>", "\n", t)).splitlines() if l.strip() not in ("", "\xa0")]
    imgs, cur, i = {}, None, 0
    num = lambda s: re.fullmatch(r"[\d,]+", s)
    while i < len(lines):
        m = re.match(r"(L\d_\w+\.dd) drive layout", lines[i])
        if m: cur = m.group(1); imgs[cur] = []; i += 1; continue
        if cur and i + 3 < len(lines) and num(lines[i+1]) and num(lines[i+2]) and num(lines[i+3]):
            imgs[cur].append({"file": lines[i], "size": int(lines[i+1].replace(",", "")), "start": int(lines[i+2].replace(",", "")), "end": int(lines[i+3].replace(",", ""))}); i += 4; continue
        i += 1
    json.dump(imgs, open(os.path.join(out, "layout.json"), "w"), indent=1)
    return imgs

if __name__ == "__main__":
    main()
