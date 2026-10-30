/// <reference types="node" />
// This test reads the source tree (node fs/path); the reference pulls in Node
// typings for this file only, since the app tsconfig is DOM-scoped.
import fs from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";

/**
 * HELP SYNC MECHANISM (layer 1 of 2 — coverage).
 *
 * The online help (HelpPage.tsx) makes hundreds of claims about the codebase.
 * This test enforces the mechanically-checkable half of "keep the help in
 * sync": COVERAGE. The CODE is the source of truth. Every user-facing
 * capability that can be enumerated from the source tree (parser plugins,
 * evidence-container crates, the carving-signature count, the entity-extractor
 * kinds) must be MENTIONED in the help, and the maps below must not reference
 * anything that no longer exists.
 *
 * This is what catches the biggest, most common class of drift:
 *   - a NEW capability shipped but never documented (how VSS slipped through), and
 *   - a capability REMOVED but still documented.
 *
 * It does NOT verify prose ACCURACY (e.g. BitLocker "detect only" vs "decrypt")
 * — that isn't mechanically decidable. For that, see the targeted fact
 * assertions in HelpPage.test.tsx and the on-demand accuracy audit documented in
 * frontend/src/pages/help/HELP_SYNC.md.
 *
 * WHEN THIS TEST FAILS:
 *   - "plugin X not covered" → document X in HelpPage.tsx and add its keyword(s)
 *     to PLUGIN_HELP_KEYWORDS below, OR add it to INTENTIONALLY_OMITTED with a
 *     reason if it is genuinely internal/infrastructure with nothing to tell a user.
 *   - "map entry for a plugin that no longer exists" → remove the stale entry.
 *   - "signature count mismatch" → update the number stated in the carving section.
 */

function findRepoRoot(): string {
  let dir = process.cwd();
  for (let i = 0; i < 8; i++) {
    if (fs.existsSync(path.join(dir, "seance_carving", "src", "formats")))
      return dir;
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  throw new Error(
    "could not locate the workspace root (no seance_carving/src/formats)",
  );
}

const repoRoot = findRepoRoot();
const helpSrc = fs.readFileSync(
  path.join(repoRoot, "frontend/src/pages/help/HelpPage.tsx"),
  "utf8",
);

/** Directory suffixes for crates named `<prefix><suffix>` at the repo root. */
function crateSuffixes(prefix: string): string[] {
  return fs
    .readdirSync(repoRoot, { withFileTypes: true })
    .filter((e: fs.Dirent) => e.isDirectory() && e.name.startsWith(prefix))
    .map((e: fs.Dirent) => e.name.slice(prefix.length))
    .sort();
}

/**
 * Each parser plugin (keyed by the suffix after `seance_plugin_`) mapped to the
 * keyword(s) that, if present anywhere in the help, prove it is documented. Any
 * one match is sufficient.
 */
const PLUGIN_HELP_KEYWORDS: Record<string, string[]> = {
  amcache: ["Amcache"],
  findings: ["investigative lead", "what this build looks for"],
  bulk: ["Feature extraction", "AES keys from RAM", "Network packet carving"],
  squashfs: ["SquashFS"],
  perceptual: ["Perceptual hashing", "PDQ", "Safe view"],
  android_apps: ["Android calendar"],
  mobile_device: ["device facts", "build.prop"],
  host_identity: ["/etc/hostname", "os-release"],
  directory: ["folder", "logical acquisition"],
  media: ["how long a recording runs", "movie header"],
  android_backup: ["adb backup", "ANDROID BACKUP"],
  android_sms: ["Android SMS"],
  apfs: ["APFS"],
  badclus: ["$BadClus", "BadClus"],
  sdb: ["shim database", "sdbinst"],
  setupapi: ["setupapi", "device-install log"],
  stickynotes: ["Sticky Notes", "sticky note"],
  bitlocker: ["BitLocker"],
  browser_history: ["Browser history", "browser history"],
  btrfs: ["Btrfs"],
  call_history: ["Call History", "call log"],
  macos_artifacts: ["TCC", "quarantine", "launchd"],
  carver: ["carving", "carve"],
  chrome_cache: ["cached URL", "Chrome cache"],
  clipboard: ["Clipboard history", "clipboard history"],
  bits: ["BITS job queue"],
  rdp_cache: ["RDP bitmap cache"],
  winsearch_edb: ["Windows Search index"],
  contacts: ["Contacts"],
  desktop_artifacts: ["Shell history", "shell history"],
  dsstore: [".DS_Store"],
  email: ["email"],
  evtx: ["EVTX"],
  exif: ["EXIF"],
  ext4: ["ext4"],
  fbmessenger: ["Facebook Messenger"],
  f2fs: ["F2FS"],
  fat: ["FAT"],
  fsevents: ["FSEvents"],
  file_analysis: ["file-signature analysis", "extension-content mismatch"],
  hash: ["MD5"],
  hfsplus: ["HFS+"],
  i30: ["$I30", "I30"],
  ical: ["iCalendar"],
  imessage: ["iMessage"],
  installed_apps: ["Installed applications"],
  instagram: ["Instagram"],
  ios_artifacts: ["PowerLog"],
  ios_backup: ["iOS"],
  iso9660: ["ISO 9660", "ISO9660"],
  udf: ["UDF"],
  jumplists: ["Jump Lists"],
  kik: ["Kik"],
  leveldb: ["Local Storage", "localStorage"],
  line: ["LINE"],
  lnk: ["LNK"],
  logfile: ["$LogFile", "LogFile"],
  luks: ["LUKS"],
  mft: ["$MFT", "MFT"],
  ocr: ["OCR"],
  office: ["Office document", "Word / Excel / PowerPoint"],
  partition: ["partition"],
  pcap: ["pcapng", "Packet captures"],
  wlan: ["Windows wireless profiles", "Wlansvc"],
  pe: ["Authenticode"],
  plist: ["property list", "plist"],
  prefetch: ["Prefetch"],
  recyclebin: ["Recycle Bin"],
  registry: ["Registry"],
  asep: ["Autostart (ASEP)", "RunOnce"],
  memory_windows: ["Memory analysis", "pool scanning"],
  memory_linux: ["Linux", "kernel banner"],
  memory_macos: ["Mach task queue", "kernel extensions"],
  secure_sds: ["Security descriptors", "$Secure"],
  utmp: ["Linux login accounting", "btmp"],
  shellbags: ["ShellBags"],
  shimcache: ["Shimcache"],
  signal: ["Signal"],
  skype: ["Skype"],
  snapchat: ["Snapchat"],
  sqlite: ["SQLite"],
  srum: ["SRUM"],
  sum: ["User Access Logging", "UAL"],
  telegram: ["Telegram"],
  thumbcache: ["Thumbnail cache", "thumbcache"],
  twitter: ["Twitter"],
  usnjrnl: ["$UsnJrnl", "UsnJrnl"],
  viber: ["Viber"],
  vss: ["Volume Shadow"],
  webcache: ["WebCacheV01", "IE/Edge history"],
  wechat: ["WeChat"],
  win_timeline: ["Windows Timeline", "ActivitiesCache"],
  whatsapp: ["WhatsApp"],
  xfs: ["XFS"],
  yara: ["YARA"],
};

/**
 * Plugins deliberately NOT documented (internal/infrastructure with nothing a
 * user would act on). Each MUST carry a reason. Empty today — every plugin is
 * user-facing — but the mechanism is here so a future internal plugin does not
 * force a spurious help entry.
 */
const INTENTIONALLY_OMITTED: Record<string, string> = {
  // `memory_macos` sat here while it was registered by no binary and could not
  // reach an examiner. It is registered now, so it is documented like every
  // other plugin (above) rather than excused here -- and the help has to carry
  // the warning that goes with it: nothing that tier produces has ever been
  // checked against a capture of a real Mac.
};

/** Evidence-container crates (suffix after `seance_container_`) → help keyword(s). */
const CONTAINER_HELP_KEYWORDS: Record<string, string[]> = {
  aff4: ["AFF4"],
  archive: ["bzip2", "7z"],
  e01: ["E01", "EWF"],
  raid: ["RAID / LVM reconstruction", "assemble-raid"],
  sparseimage: ["sparseimage"],
  vdisk: ["VMDK", "QCOW2", "VHD"],
  zip: ["ZIP", "zip"],
};

describe("help coverage — the code inventory is documented", () => {
  it("every parser plugin is mentioned in the help (or explicitly omitted)", () => {
    const undocumented: string[] = [];
    for (const p of crateSuffixes("seance_plugin_")) {
      if (p in INTENTIONALLY_OMITTED) continue;
      const kws = PLUGIN_HELP_KEYWORDS[p];
      if (!kws) {
        undocumented.push(
          `${p} — no mapping (document it + add to PLUGIN_HELP_KEYWORDS, or INTENTIONALLY_OMITTED with a reason)`,
        );
      } else if (!kws.some((k) => helpSrc.includes(k))) {
        undocumented.push(
          `${p} — mapped keyword(s) [${kws.join(", ")}] not found in the help`,
        );
      }
    }
    expect(
      undocumented,
      `parser plugins missing from the online help:\n  ${undocumented.join("\n  ")}`,
    ).toEqual([]);
  });

  it("the plugin/omission maps have no entries for plugins that no longer exist", () => {
    const plugins = new Set(crateSuffixes("seance_plugin_"));
    const stale = [
      ...Object.keys(PLUGIN_HELP_KEYWORDS),
      ...Object.keys(INTENTIONALLY_OMITTED),
    ].filter((k) => !plugins.has(k));
    expect(
      stale,
      `stale map entries (plugin removed?): ${stale.join(", ")}`,
    ).toEqual([]);
  });

  it("every evidence-container crate is mentioned in the help", () => {
    const undocumented: string[] = [];
    for (const c of crateSuffixes("seance_container_")) {
      const kws = CONTAINER_HELP_KEYWORDS[c];
      if (!kws || !kws.some((k) => helpSrc.includes(k))) {
        undocumented.push(c);
      }
    }
    expect(
      undocumented,
      `container crates missing from the help: ${undocumented.join(", ")}`,
    ).toEqual([]);
  });

  it("the carving-signature count stated in the help matches the code", () => {
    const formatsDir = path.join(repoRoot, "seance_carving/src/formats");
    const count = fs
      .readdirSync(formatsDir)
      .filter((f: string) => f.endsWith(".rs") && f !== "mod.rs").length;
    const m = helpSrc.match(/(\d[\d,]*)\s+file signatures/);
    expect(
      m,
      'help must state a count as "<N> file signatures"',
    ).not.toBeNull();
    const stated = Number(m![1].replace(/,/g, ""));
    expect(
      stated,
      `help says ${stated} file signatures but seance_carving/src/formats has ${count}`,
    ).toBe(count);
  });
});
