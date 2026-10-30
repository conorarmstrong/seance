import { useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { NAV_SECTIONS } from "../../app/nav";
import { SQLITE_QUERY_ROW_CAP } from "../analysis/SqliteQueryApi";
import { SQLITE_HISTORY_MAX } from "../analysis/SqliteQueryHistory";
import { SQLITE_QUERY_TEMPLATES } from "../analysis/SqliteTemplates";
import "./help.css";

type Section = { id: string; title: string };

const GROUPS: { label: string; items: Section[] }[] = [
  {
    label: "Foundations",
    items: [
      { id: "getting-started", title: "Getting started" },
      { id: "navigation", title: "Navigating a case" },
      { id: "ingestion", title: "Evidence ingestion" },
      { id: "users", title: "Users and access control" },
      { id: "settings", title: "Case settings and profiles" },
    ],
  },
  {
    label: "Analysis",
    items: [
      { id: "dashboard", title: "Dashboard and case overview" },
      { id: "timeline", title: "Timeline analysis" },
      { id: "search", title: "Search" },
      { id: "file-browser", title: "File browser" },
      { id: "carving", title: "File carving and recovery" },
      { id: "artifacts", title: "Artifact parsers" },
      { id: "memory-analysis", title: "Memory analysis" },
      { id: "analysis-records", title: "Records analysis" },
      { id: "filters", title: "Filters" },
      { id: "visualisers", title: "Visualisers" },
      { id: "execution-comms", title: "Execution and communications" },
      { id: "entities", title: "Entities and link analysis" },
      { id: "media-geo", title: "Gallery and geolocation" },
      { id: "mobile", title: "Mobile: backups, chat, calls, contacts" },
    ],
  },
  {
    label: "Findings and output",
    items: [
      { id: "review-ledger", title: "Review ledger: opened and reviewed" },
      { id: "bookmarks", title: "Bookmarks" },
      { id: "hash-sets", title: "Hash sets" },
      { id: "reporting", title: "Reporting and exports" },
    ],
  },
  {
    label: "Formats reference",
    items: [
      { id: "filesystems", title: "Filesystems and containers" },
      { id: "encryption", title: "Encrypted volumes" },
    ],
  },
  {
    label: "Assurance",
    items: [
      { id: "integrity", title: "Integrity and audit" },
      { id: "soundness", title: "Forensic soundness" },
    ],
  },
  {
    label: "Reference",
    items: [
      { id: "shortcuts", title: "Keyboard shortcuts" },
      { id: "tips", title: "Tips and good practice" },
    ],
  },
];

/** Which group each section belongs to, for highlighting the active group. */
const GROUP_OF: Record<string, string> = Object.fromEntries(
  GROUPS.flatMap((g) => g.items.map((s) => [s.id, g.label])),
);

/**
 * Placeholder for a UI screenshot. The dashed frame is captured and replaced
 * with a real screenshot via browser automation; the `data-screenshot` id is
 * the capture target and the caption describes the intended view.
 */
function Shot({ id, caption }: { id: string; caption: string }) {
  // Render the captured screenshot when one exists for this id; fall back to a
  // labelled placeholder frame otherwise (some views need a populated case).
  const [hasImage, setHasImage] = useState(true);
  return (
    <figure className="help-shot">
      {hasImage ? (
        <img
          className="help-shot-img"
          src={`/help-shots/${id}.png`}
          alt={caption}
          loading="lazy"
          onError={() => setHasImage(false)}
        />
      ) : (
        <div className="help-shot-frame" data-screenshot={id}>
          Screenshot
        </div>
      )}
      <figcaption>{caption}</figcaption>
    </figure>
  );
}

/**
 * A drawn diagram of the case sidebar's grouped navigation — used in place of a
 * screenshot for the information architecture, which a labelled schematic
 * communicates better than a photo of the rail and which never goes stale
 * through the screenshot pipeline. Theme-aware: every colour is a CSS token, so
 * it reads on either ground.
 */
function NavDiagram() {
  // Derived from the rail itself, never restated. This used to be a hand-kept
  // copy of NAV_SECTIONS, and it fell three items behind the moment the rail
  // grew: the diagram in the help showed the Analyse group ending at
  // Duplicates while the product had five more surfaces in it, which is exactly
  // the wrong way round for a page an examiner consults BECAUSE they cannot
  // find something. The badge is the only thing invented here — it illustrates
  // the count Memory carries in a case holding more than one capture.
  const RAIL: { label: string; items: { name: string; badge?: string }[] }[] =
    NAV_SECTIONS.map((section) => ({
      label: section.section,
      items: section.items.map((item) => ({
        name: item.label,
        badge: item.to === "memory" ? "2" : undefined,
      })),
    }));

  const ROW = 19;
  const GAP = 10;
  type Row =
    | { kind: "label"; text: string; y: number }
    | { kind: "item"; name: string; badge?: string; y: number };
  const rows: Row[] = [];
  let y = 22;
  for (const group of RAIL) {
    rows.push({ kind: "label", text: group.label, y });
    y += ROW;
    for (const item of group.items) {
      rows.push({ kind: "item", name: item.name, badge: item.badge, y });
      y += ROW;
    }
    y += GAP;
  }
  const height = y + 6;

  return (
    <figure className="help-diagram">
      {/* The description is built from the same source as the drawing, so a
          screen-reader user and a sighted one are told about the same rail. A
          hand-written description of a derived diagram would be the drift this
          component just removed, reintroduced one attribute lower down. */}
      <svg
        viewBox={`0 0 260 ${height}`}
        role="img"
        aria-label={`The case sidebar, in ${RAIL.length} groups. ${RAIL.map(
          (group) =>
            `${group.label}: ${group.items.map((i) => i.name).join(", ")}.`,
        ).join(
          " ",
        )} Memory carries a count of the case's memory captures when it holds more than one.`}
        className="help-diagram-svg"
      >
        <rect
          x="6"
          y="6"
          width="248"
          height={height - 12}
          rx="10"
          fill="var(--bg-1)"
          stroke="var(--border-0)"
        />
        {rows.map((row, i) =>
          row.kind === "label" ? (
            <text
              key={i}
              x="18"
              y={row.y}
              fill="var(--text-2)"
              fontSize="9"
              fontWeight="600"
              letterSpacing="1"
              style={{ textTransform: "uppercase" }}
            >
              {row.text.toUpperCase()}
            </text>
          ) : (
            <g key={i}>
              {row.badge && (
                <rect
                  x="14"
                  y={row.y - 12}
                  width="232"
                  height="17"
                  rx="4"
                  fill="var(--accent-bg)"
                />
              )}
              <circle
                cx="24"
                cy={row.y - 4}
                r="2.5"
                fill={row.badge ? "var(--accent)" : "var(--text-2)"}
              />
              <text
                x="34"
                y={row.y}
                fill={row.badge ? "var(--accent)" : "var(--text-1)"}
                fontSize="12"
                fontWeight={row.badge ? "600" : "400"}
              >
                {row.name}
              </text>
              {row.badge && (
                <>
                  <rect
                    x="218"
                    y={row.y - 11}
                    width="20"
                    height="15"
                    rx="7.5"
                    fill="var(--accent)"
                  />
                  <text
                    x="228"
                    y={row.y - 0.5}
                    fill="var(--bg-0)"
                    fontSize="10"
                    fontWeight="700"
                    textAnchor="middle"
                  >
                    {row.badge}
                  </text>
                </>
              )}
            </g>
          ),
        )}
      </svg>
      <figcaption>
        The case sidebar, grouped by the question each item answers. Memory is
        filed under <strong>Evidence</strong> beside System Info — a RAM capture
        is acquired evidence, not a tool — and carries a count when a case holds
        more than one capture.
      </figcaption>
    </figure>
  );
}

export function HelpPage() {
  const navigate = useNavigate();
  const [query, setQuery] = useState("");
  // Accordion: exactly one group open at a time (first open by default).
  const [openGroup, setOpenGroup] = useState<string | null>(GROUPS[0].label);
  // Section currently in view (scrollspy), highlighted in the menu.
  const [activeId, setActiveId] = useState("");
  const contentRef = useRef<HTMLDivElement>(null);
  const layoutRef = useRef<HTMLDivElement>(null);
  // Lowercased searchable text per section id, read once from the rendered
  // prose so the static content is searchable without duplicating it as data.
  const [index, setIndex] = useState<Record<string, string>>({});

  useEffect(() => {
    const root = contentRef.current;
    if (!root) return;
    const map: Record<string, string> = {};
    root.querySelectorAll("section[id]").forEach((el) => {
      map[el.id] = (el.textContent ?? "").toLowerCase();
    });
    setIndex(map);
  }, []);

  const q = query.trim().toLowerCase();

  // Show only sections whose text matches the query (all of them when the query
  // is empty). Imperative because the sections are static prose, not a list.
  useEffect(() => {
    const root = contentRef.current;
    if (!root) return;
    root.querySelectorAll<HTMLElement>("section[id]").forEach((el) => {
      el.hidden = q !== "" && !(index[el.id] ?? "").includes(q);
    });
  }, [q, index]);

  // Scrollspy: mark the section nearest the top of the scroll area active so the
  // menu tracks where you are as you read. Guarded for environments without
  // IntersectionObserver (jsdom); clicks in the menu also set it directly.
  useEffect(() => {
    if (typeof IntersectionObserver === "undefined") return;
    const root = layoutRef.current;
    const content = contentRef.current;
    if (!root || !content) return;
    const sections = Array.from(
      content.querySelectorAll<HTMLElement>("section[id]"),
    );
    const visible = new Set<string>();
    const observer = new IntersectionObserver(
      (entries) => {
        for (const e of entries) {
          const id = (e.target as HTMLElement).id;
          if (e.isIntersecting) visible.add(id);
          else visible.delete(id);
        }
        const top = sections.find((s) => visible.has(s.id));
        if (top) setActiveId(top.id);
      },
      { root, rootMargin: "0px 0px -80% 0px", threshold: 0 },
    );
    sections.forEach((s) => observer.observe(s));
    return () => observer.disconnect();
  }, []);

  const sectionMatches = (id: string, title: string) =>
    id in index ? index[id].includes(q) : title.toLowerCase().includes(q);
  const results = GROUPS.flatMap((g) => g.items).filter((s) =>
    sectionMatches(s.id, s.title),
  );

  const tocLink = (s: Section) => (
    <li key={s.id}>
      <a
        href={`#${s.id}`}
        className={activeId === s.id ? "help-toc-active" : undefined}
        aria-current={activeId === s.id ? "true" : undefined}
        onClick={() => setActiveId(s.id)}
      >
        {s.title}
      </a>
    </li>
  );

  return (
    <div className="help-fullscreen">
      <header className="help-topbar">
        <button
          type="button"
          className="help-back"
          onClick={() => navigate(-1)}
        >
          ← Back
        </button>
        <h1 className="help-title">Help</h1>
        <input
          type="search"
          className="help-search"
          placeholder="Search help…"
          aria-label="Search help"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
        />
      </header>

      <div className="help-layout" ref={layoutRef}>
        <nav className="help-toc" aria-label="Contents">
          {q ? (
            results.length > 0 ? (
              <ul className="help-toc-results">{results.map(tocLink)}</ul>
            ) : (
              <p className="help-toc-empty">No matching sections.</p>
            )
          ) : (
            <ul className="help-toc-groups">
              {GROUPS.map((group) => {
                const open = openGroup === group.label;
                return (
                  <li key={group.label}>
                    <button
                      type="button"
                      className={`help-toc-group-btn${
                        GROUP_OF[activeId] === group.label
                          ? " help-toc-group-active"
                          : ""
                      }`}
                      aria-expanded={open}
                      onClick={() => setOpenGroup(open ? null : group.label)}
                    >
                      <span className="help-toc-caret" aria-hidden="true">
                        {open ? "▾" : "▸"}
                      </span>
                      {group.label}
                    </button>
                    {open && <ul>{group.items.map(tocLink)}</ul>}
                  </li>
                );
              })}
            </ul>
          )}
        </nav>

        <div className="help-content" ref={contentRef}>
          <p className="help-lead">
            Séance is a modular digital-forensics workbench: ingest an image or
            device, and its plugin pipeline parses filesystems, carves deleted
            data, and normalises artifacts into one searchable case. This guide
            covers each view and the methodology behind it.
          </p>

          <section id="getting-started">
            <h2>Getting started</h2>
            <p>
              Work in Séance is organised around cases. A case holds evidence
              sources, everything parsed from them, and the record of what you
              did.
            </p>
            <ul>
              <li>
                Create a case from the cases list. Record the reference number
                and examiner name; both appear in reports and the audit log.
              </li>
              <li>
                Ingest an evidence source with the{" "}
                <strong>Ingest Evidence</strong> button in the sidebar. Pick the
                file on the server filesystem and, if needed, an analysis
                profile to control which modules run.
              </li>
              <li>
                Watch the <strong>Processing</strong> panel in the sidebar.
                Modules run in a pipeline: each artifact a module produces can
                trigger further modules, so counts grow until the queue drains.
                Click the panel's heading to collapse it — the heading still
                names the phase, so a collapsed panel goes on reporting that a
                run is live. Once a run finishes, dismiss its summary with the{" "}
                <strong>×</strong> in the corner to reclaim sidebar space — the
                next run brings the panel back automatically.
              </li>
            </ul>
            <p>
              Once processing settles, the sidebar{" "}
              <strong>Evidence Sources</strong> tree shows each source with its
              partitions and filesystems, <strong>Parsed Records</strong> groups
              parsed records by type, and the timeline fills with dated events.
              Press <span className="help-kbd">⌘</span>
              <span className="help-kbd">K</span> at any time to jump between
              views or start a search.
            </p>
          </section>

          <section id="navigation">
            <h2>Navigating a case</h2>
            <p>
              The sidebar is grouped by the question each item answers, rather
              than presented as one flat list. Reading top to bottom:
            </p>
            <ul>
              <li>
                <strong>Overview</strong> — the Dashboard: the case at a glance
                and the front door to everything else.
              </li>
              <li>
                <strong>Analyse</strong> — the cross-cutting views that
                deliberately span all the evidence, in four runs.{" "}
                <strong>Findings</strong> first, because it is the answer to
                &ldquo;where do I start&rdquo; — and it is the one view in the
                rail that carries Séance&rsquo;s own claims rather than
                transcriptions of the evidence, which the page itself says
                before its first row. Then the two universal entry points,{" "}
                <strong>Timeline</strong> and <strong>Search</strong>; then the
                four question-shaped subject views — <strong>Communications</strong> (who did they talk to),{" "}
                <strong>Gallery</strong> (what pictures are here),{" "}
                <strong>Map</strong> (where has this device been) and{" "}
                <strong>Execution</strong> (what ran); then the derived
                analyses, <strong>Connections</strong>,{" "}
                <strong>Entities</strong> and <strong>Duplicates</strong>; then{" "}
                <strong>Parsed Records</strong>, the index of everything parsed.
                It groups record types by what they are <em>about</em> — people
                and messages, places and times, activity, the device, files and
                media, then what Séance derived and, last, what could not be
                read — rather than by how many of each there are, so a case does
                not open on whichever type the tool happened to produce most of.
                A record type no group claims still appears, under &ldquo;Other
                records&rdquo;.
              </li>
              <li>
                <strong>Evidence</strong> — readers scoped to what was acquired:
                System Info and <strong>Memory</strong>. A memory capture is
                acquired evidence — an image with a hash and a chain of custody
                — not a tool, so it lives here rather than among the analyses.
                When a case holds more than one capture, Memory shows a count so
                you can see at a glance how many machines' RAM is in the case.
              </li>
              <li>
                <strong>Curate</strong> — the artifacts you author: Bookmarks,
                Filters, and Hash Sets.
              </li>
              <li>
                <strong>Admin</strong> — Audit Log, case Settings, and this
                Help.
              </li>
            </ul>
            <NavDiagram />
            <h3>The evidence navigator</h3>
            <p>
              Below the rail, the navigator browses the evidence itself through
              two lenses, and drives the workbench content pane:
            </p>
            <ul>
              <li>
                <strong>Physical</strong> — the acquisition tree: each source
                with its partitions, filesystems, and files, as they were laid
                out on the media. A source a RAM capture was decoded from
                carries a <strong>RAM</strong> tag; clicking it opens that
                capture's memory analysis directly, so you move from the
                acquisition into its memory without leaving the tree. The node
                itself stays browsable — a capture's source can be a whole disk,
                or a single file a dump was carved from.
              </li>
              <li>
                <strong>Logical</strong> — the same records grouped by examiner
                category (Chats, Web, Program Execution, and so on) with live
                counts. In a case that holds more than one source, a{" "}
                <strong>Source</strong> filter at the top attributes what you
                see to the acquisition it came from: choosing a source rescopes
                every count to that acquisition, and a record type opened from
                it lists only that source's rows. Media and the aggregate views
                (gallery, map, communications, execution) are case-wide and are
                withheld while a single source is selected rather than shown
                under a per-source lens.
              </li>
            </ul>
            <p>
              System Info offers the same source filter: a case holding more
              than one machine's registry can be read one machine at a time,
              instead of as a merged view that can only report where two
              machines' identities disagree.
            </p>
            <p>
              A <strong>folder</strong> is evidence too. Point Séance at an
              unpacked extraction, a Google Takeout, a logical acquisition or a
              mounted share and it walks the tree, carrying what the filesystem
              knows about each file — size, all three timestamps, permissions
              and the owning ids, which on a logical acquisition is the only
              history a file has. Symlinks are recorded and never followed:
              following one would leave the evidence and pull the examining
              machine into the case. Anything the walk could not list is stated
              on the source rather than left as a gap you would have to notice.
            </p>
            <p>
              Media files carry two facts a case turns on more often than their
              bytes do: <strong>how long a recording runs</strong> and{" "}
              <strong>when the device wrote it</strong>. Séance reads the movie
              header of the MP4 family (MP4, M4A, M4V, MOV, 3GP) for both. The
              format counts time from 1904, so a reader that treats it as a Unix
              time dates every recording 66 years early; and a file whose header
              was never finished — an interrupted recording — is reported as
              having no duration in the evidence, never as a recording of zero
              seconds.
            </p>
            <p>
              On a phone, System Info opens with the{" "}
              <strong>device facts</strong>
              instead: manufacturer, model, Android version, build, serial,
              encryption state — read from the device&rsquo;s own{" "}
              <code>build.prop</code> and its siblings — and, for an Apple
              device, the name, model, iOS version, build, serial and UDID out
              of the backup manifest, which names the device in the clear
              whether or not the backup has been unlocked. Every fact shows the
              file and the key it was read from, because a fact you cannot
              source is a fact you cannot testify to. Where two property files
              give different answers, <em>both</em> are shown and neither is
              presented as the answer: a device whose partitions disagree is a
              finding, not a tie to break.
            </p>
            <p>
              A Mac&rsquo;s <strong>installed applications</strong> are read
              from each bundle&rsquo;s own <code>Info.plist</code>: identifier,
              name, version and build, and where the bundle sat &mdash; an
              application in <code>/Applications</code> is a different statement
              from one running out of a user&rsquo;s Downloads folder. Only the
              bundle&rsquo;s top level counts, so the services and frameworks
              inside an application are not listed as applications of their own,
              and where the path in the case does not say where a bundle sat,
              that field is left out rather than guessed.
            </p>
            <p>
              A <strong>phone backed up to a computer</strong> that was then
              imaged is read too: a backup folder&rsquo;s{" "}
              <code>Manifest.plist</code> and <code>Info.plist</code> name the
              device, its iOS version, serial, UDID and IMEI, and when it was
              backed up &mdash; even when the backup is encrypted, because the
              manifest is readable without the password. Its{" "}
              <code>Manifest.db</code> puts the stored files back at the paths
              they had on the phone &mdash; <code>sms.db</code> is found as{" "}
              <code>sms.db</code>, under its app domain, with its bytes &mdash;
              when the backup sits in a folder or a ZIP the case can open
              neighbours in. When it cannot (a backup inside a disk image), or
              the backup is encrypted, each file is still listed at its device
              path with no content and the reason, so a phone whose messages
              are not in the case is never presented as a phone that had none.
            </p>
            <p>
              On a <strong>Linux</strong> exhibit the same panel answers the
              same question from the machine&rsquo;s own identity files: the
              host name from <code>/etc/hostname</code>, the distribution and
              its version from <code>os-release</code> and{" "}
              <code>lsb-release</code>, the machine ID, the system time zone,
              and the people with accounts on the box from{" "}
              <code>/etc/passwd</code> (uid 0 and uid 1000 and above &mdash;
              service accounts are read but not listed as people). Only the
              system&rsquo;s own paths are read: a script or a manual page that
              merely has <code>hostname</code> in its name never states what the
              machine is called. <code>/etc/os-release</code> is usually a
              symlink to <code>/usr/lib/os-release</code>, and where the two
              differ &mdash; a machine upgraded in place &mdash; both readings
              are shown. On a <strong>Mac</strong> the same panel reads{" "}
              <code>SystemVersion.plist</code> for the macOS version and the
              build it was assembled from, and{" "}
              <code>SystemConfiguration/preferences.plist</code> for the names:
              the computer name someone typed and the local host name the
              network sees are different strings and are shown as different
              facts.
            </p>
            <p>
              It lists <strong>local accounts</strong> and{" "}
              <strong>user profiles</strong> separately, because they are
              different populations. Local accounts come from the SAM hive and
              are every account the machine holds; user profiles come from{" "}
              <code>ProfileList</code> and are only those that have logged on
              and been given a profile directory. A machine with five accounts,
              two of which never logged on, shows five and three. Reading either
              number as the other under-reports the inventory.
            </p>
            <p>
              <strong>Sticky Notes</strong> are read in both of the formats
              Windows has used — <code>StickyNotes.snt</code>, an OLE2 compound
              file with one storage per note, and the newer app's{" "}
              <code>plum.sqlite</code>. The two formats have met different
              evidence, and each record says which. A{" "}
              <code>.snt</code> record has been checked against one real
              Windows 7 file holding one plain-text note, and its validation
              notice says exactly that much: a file with several notes, a note
              with a picture, or a file from a later Windows has not been met.
              A <code>plum.sqlite</code> record from a database whose schema
              version (<code>user_version</code>) is 13 has been checked against{" "}
              <strong>one lab-made database</strong> written by Sticky Notes
              6.1.4.0 on a test machine — not seized evidence — and its notice
              says exactly that; a record from any other schema version{" "}
              <strong>says in as many words that it has never been
              validated</strong>, and its row carries that notice as its
              marker; treat those values as unverified. That app can keep the
              whole database in <code>plum.sqlite-wal</code>, and the reader
              reads the two together from a copy, never the evidence in place.
              Times are the file's own, converted from .NET ticks and not
              corrected for a wrong clock. The app deletes a note by removing
              its row and records no deletion time, so a deleted note appears
              in its own <strong>recovered sticky notes</strong> list, read
              from an older write-ahead-log frame: its row names the frame, and
              its marker says the deletion is inferred from the row being gone,
              not recorded. The{" "}
              <code>.snt</code> reader is
              deliberately built so that no stream name is load-bearing: it
              lists every storage and every stream it found, with names and
              lengths, and a storage it could not read is{" "}
              <em>listed</em> rather than skipped — a note that would not read
              is not the same as no note. An embedded picture is reported as
              present and never rendered as text, and a note whose RTF does not
              close keeps what was read and says so.
            </p>
            <p>
              A device's first connection has a <strong>second, independent</strong>{" "}
              source beside the registry: Windows writes a{" "}
              <strong>device-install log</strong> as it installs each one —{" "}
              <code>setupapi.dev.log</code> and its siblings under{" "}
              <code>%WINDIR%\INF</code>. Séance reads them by their first line
              rather than by their name, and reports one event per section that
              concerns a device, with a complete histogram of every section kind
              beside it — on a real log the two commonest kinds are the driver
              store's own housekeeping and account for 154 of 194 sections, so
              burying them would be as misleading as hiding them.
            </p>
            <p>
              These times are <strong>local to the machine that wrote the log</strong>,
              and <em>no timezone or offset is recorded anywhere in the file</em>.
              So Séance never converts them and raises <em>no timeline event</em>{" "}
              from them: a local time placed on a UTC timeline is wrong by exactly
              the offset nobody recorded. Comparing a log time with a registry
              time is the examiner's inference to make, shown to them rather than
              made for them. Boot sessions are listed in <strong>file order</strong>{" "}
              and never sorted — on real evidence they are not in chronological
              order, and one measured log has a session 9 h 19 m earlier than the
              one before it. A section that starts <em>before</em> the boot session
              it sits under is reported as written rather than clamped, because on
              real evidence that is Windows Update replaying an earlier-clock
              install, and three device installs hang on it.
            </p>
            <p>
              Each local account also carries its <strong>RID</strong>, its{" "}
              <strong>last logon</strong>, how many times it has logged on and
              whether it is <strong>enabled</strong> — read from the{" "}
              <code>F</code> and <code>V</code> binary values on the account's
              own SAM key. An account that has never logged on shows{" "}
              <em>no date and the reason there is none</em>, rather than an
              empty cell or the 1601 date an unguarded conversion produces:
              zero in that field is what Windows leaves when the thing never
              happened. Fields the reference hive could not establish — the
              expiry slot, the bad-password time, the failed-logon count — are
              named on the record as not read, so their absence is never
              mistaken for the account having none.
            </p>
            <h3>Three ways to the same view</h3>
            <p>
              Communications, Gallery, Map and Execution are each reachable{" "}
              <strong>three ways</strong>, and all three land on the same
              address:
            </p>
            <ul>
              <li>
                from the <strong>Analyse</strong> group in the rail;
              </li>
              <li>
                from the command palette (<span className="help-kbd">⌘</span>
                <span className="help-kbd">K</span>), which matches the words an
                examiner actually says as well as the label on the rail —{" "}
                <em>chats</em>, <em>whatsapp</em> or <em>texts</em> find
                Communications, <em>gps</em> or <em>where</em> find Map,{" "}
                <em>prefetch</em> or <em>what ran</em> find Execution — and
                tells you, on the row, which view the word you typed belongs to;
              </li>
              <li>
                from the <strong>Logical</strong> navigator, where the category
                that owns the view opens it: Chats opens Communications, Program
                Execution opens Execution, and the media categories open the
                gallery and the map.
              </li>
            </ul>
            <p>
              Parsed Records is in the rail and the palette; the navigator is
              where you reach an individual record type inside it.{" "}
              <strong>Videos</strong> and <strong>Audio</strong> are the gallery
              under a different filter rather than pages of their own, so they
              are deliberately not rail rows — ask the palette for{" "}
              <em>video</em> or <em>audio</em>, or open them under Media in the
              Logical navigator. Their absence from the rail is a layout
              decision, not a missing capability.
            </p>
            <h3>Addresses</h3>
            <p>
              Each view has <strong>one address</strong>, which is what the
              rail, the palette and the navigator all point at, and what a
              report or a handover note can quote without a query string to
              explain. Links written against the older workbench form —{" "}
              <code>workbench?view=…</code>, <code>workbench?type=…</code> —
              still work and redirect onto the canonical address, carrying any
              source scope with them, so nothing written down before the change
              has gone dead.
            </p>
            <p>
              An address inside a case that matches no view keeps you{" "}
              <em>inside</em> the case: the page{" "}
              <strong>quotes the address that matched nothing</strong>, says
              plainly that the case is not missing anything, and offers a
              destination — rather than throwing you out to a bare &ldquo;page
              not found&rdquo; and costing you the rail, the palette and the
              navigator. Where a truncated address is genuinely ambiguous it is
              offered as a question and never resolved by guess:{" "}
              <code>/cases/&lt;id&gt;/image</code> could mean a disk image or a
              RAM capture, so Séance asks rather than choosing one for you.
            </p>
          </section>

          <section id="ingestion">
            <h2>Evidence ingestion</h2>
            <p>
              Open <strong>Ingest Evidence</strong> to browse the server
              filesystem and select one or more sources. Choose an{" "}
              <strong>Evidence type</strong> (Auto-detect, Raw evidence, a
              Container, or a Single file) and an{" "}
              <strong>Analysis profile</strong> (Default runs all modules;
              Triage is fast; Deep runs everything). Séance parses the following
              source formats:
            </p>
            <ul>
              <li>
                Forensic images: EnCase <code>E01</code>/EWF (with acquisition
                hash metadata), AFF4, and raw <code>dd</code> images. An EnCase
                logical evidence file (<code>.L01</code>) is not an image: its
                entries are listed and each served as a file, never as a disk.
              </li>
              <li>
                Virtual disks: <code>VMDK</code>, <code>VHD</code>,{" "}
                <code>VHDX</code>, <code>QCOW2</code>.
              </li>
              <li>
                Apple disk images: <code>.sparseimage</code> (the format FUJI,
                RECON and ASLA produce when imaging a Mac).
              </li>
              <li>
                Archives: <code>zip</code>, <code>gzip</code>,{" "}
                <code>bzip2</code>, <code>xz</code>, <code>7z</code>, and OLE2
                compound files; contents are expanded and processed recursively.
              </li>
              <li>iOS device backups (iTunes/Finder), encrypted or plain.</li>
            </ul>
            <p>
              Ingest returns immediately and hashing starts in the background,
              so a large image does not block the UI. Partition tables and file
              systems inside images are walked automatically, and deleted or
              carved files are flagged in the file browser.
            </p>
            <Shot
              id="ingest-modal"
              caption="Ingest Evidence: server file browser with evidence type and analysis profile selectors."
            />
          </section>

          <section id="users">
            <h2>Users and access control</h2>
            <p>
              Every session is authenticated. Sign in on the login page; the
              server issues a JWT that authorises API calls for the length of
              the session. Your username shows at the foot of the sidebar, and{" "}
              <strong>Sign out</strong> ends the session.
            </p>
            <h3>Roles</h3>
            <ul>
              <li>
                <strong>Examiner</strong> — the standard working role. Opens
                cases, ingests evidence, and performs analysis. Every action is
                attributed to the signed-in examiner in the audit log.
              </li>
              <li>
                <strong>Admin</strong> — additionally manages user accounts:
                creating examiners, resetting passwords, deactivating and
                deleting accounts, and changing roles.{" "}
                <strong>
                  There is no screen for this in the web interface
                </strong>
                ; it is done through the administrative API (
                <code>/api/v1/users</code> and the routes beneath it), which
                rejects non-admin callers. This help used to describe the
                capability without saying where it lived, which read as a screen
                the product does not have.
              </li>
            </ul>
            <p>
              The initial admin account is seeded automatically on first start.
              If <code>SEANCE_ADMIN_PASSWORD</code> is set, that password is
              used with no forced change. Otherwise, a server bound to loopback
              seeds the default password <strong>seance</strong>; a server
              reachable over the network generates a random password and prints
              it once to the server log. Either way, that account must change
              its password before doing anything else — a full-screen prompt
              blocks every other action until a new password is set.
            </p>
            <p>
              Account provisioning is an administrative function; deactivating
              an account revokes future logins without erasing that user's audit
              history.
            </p>
          </section>

          <section id="settings">
            <h2>Case settings and profiles</h2>
            <p>
              The <strong>Settings</strong> view manages the case itself, apart
              from its evidence.
            </p>
            <ul>
              <li>
                <strong>Case details</strong> &mdash; edit the case name and
                examiner name; both flow through to reports and the audit log.
                The <strong>Case record</strong> panel shows read-only metadata
                such as the creation date.
              </li>
              <li>
                <strong>Appearance</strong> &mdash; the one panel here that is
                not about the case. Séance ships six themes &mdash;{" "}
                <strong>Opus</strong>, <strong>Candle</strong>,{" "}
                <strong>Win11</strong>, <strong>Nature</strong>,{" "}
                <strong>Cyber</strong> and <strong>Relax</strong> &mdash; each
                in a light and a dark mode, alongside the default, which is Opus
                light. <strong>Candle</strong> is the look this product shipped
                with before that: its dark mode is that palette exactly, so
                nothing was taken away when the default moved into daylight.
                Your choice is stored <em>against your account</em> rather than
                in this browser, so it follows you to another workstation and
                survives clearing site data; it changes nothing about the
                evidence, the reports, or what any other examiner sees. Every
                theme is held to the same WCAG AA contrast floor as the default,
                measured in the test suite rather than reviewed by eye, so none
                of them makes a screen harder to read than the one it replaces.
                If a choice is applied but cannot be saved, the panel says so
                rather than letting it appear to be remembered.
              </li>
              <li>
                <strong>Ingestion profiles</strong> — profiles control which
                modules run during ingest (the Default, Triage, and Deep
                profiles offered in the ingest dialog). Activate a profile as
                the case default, or delete one you no longer need.
              </li>
              <li>
                <strong>Danger zone</strong> — delete the case and everything
                parsed from it. The case leaves the case list at once; its rows
                are removed in the background, so a large case may take minutes
                to release its disk space. The audit log survives case deletion
                so the record of who did what is preserved.
              </li>
            </ul>
          </section>

          <section id="dashboard">
            <h2>Dashboard and case overview</h2>
            <p>
              The dashboard is the case landing page. It summarises everything
              parsed so far and the state of the processing pipeline.
            </p>
            <ul>
              <li>
                <strong>Stat cards</strong> show the total artifact count and a
                breakdown by artifact type.
              </li>
              <li>
                <strong>Artifacts by type</strong> and{" "}
                <strong>File size distribution</strong> charts give the shape of
                the data set at a glance.
              </li>
              <li>
                <strong>Evidence sources</strong> lists each ingested source and
                renders a <strong>disk map</strong> of its partitions; expand a
                filesystem to see an <strong>allocation map</strong> of used and
                free clusters. Keyboard-focus a cell and press{" "}
                <span className="help-kbd">Enter</span> to open it. Beside each
                count sit two independent states: the acquisition (was the
                baseline hash recorded) and the processing (did the walk that
                produced the count end). A source whose processing was{" "}
                <strong>interrupted</strong> by a stopped server, or{" "}
                <strong>cancelled</strong>, carries a red chip and a note: its
                count is what had been recorded when it stopped, what the walk
                had not reached is absent from the case and not from the
                evidence, and re-ingesting the source completes it. The next
                server start is what marks a run interrupted, and the source
                is counted by the incompleteness census and the report from
                then on. A third chip is the <strong>mobile label</strong>:{" "}
                <em>Android device</em>, <em>Android backup</em>,{" "}
                <em>iOS device</em> or <em>iOS backup</em> (several joined by
                +), read from marker records the parsers wrote under that
                source and never from its name &mdash; hover it for the records
                it rests on. A laptop holding an iPhone backup is labelled{" "}
                <em>iOS backup</em>, not <em>iOS device</em>.{" "}
                <em>No mobile marker recognised</em> appears only for a source
                whose walk completed and produced records, and names each
                test it applied (the record type, the field value it must
                carry, the path its store must sit at) &mdash; a record of one
                of those types that failed its test may be there and was not
                counted. Any other source says{" "}
                <em>mobile: not assessed</em> with the reason (walk still
                running, interrupted or cancelled, no ingest run recorded,
                nothing recorded under it, a marker listing that hit its cap,
                a mobile store that could not be read, or a marker record in
                the case that could not be traced to its source). The label is
                re-read when the source&apos;s walk state changes. If the label
                request fails the chip says <em>mobile label unavailable</em>.
              </li>
              <li>
                <strong>Recent activity</strong> lists the newest artifacts;{" "}
                <strong>Processing jobs</strong> lists each module run with its
                status (pending, running, complete, failed) and artifact count.
                An evidence ingest is not a module run and does not appear
                there; its progress is in the sidebar's Processing panel, and
                the jobs panel says so while one is going on. A job that was
                still pending or running when the server stopped is not resumed:
                the next start marks it failed, with a message saying the
                process stopped before the job finished, so a job shown as
                running is one the running server is actually doing.
              </li>
              <li>
                <strong>Export HTML</strong>, <strong>Export PDF</strong>,{" "}
                <strong>Export DOCX</strong>, <strong>Export RTF</strong>,{" "}
                <strong>Export XML</strong> and <strong>Export XLSX</strong>{" "}
                generate the full case report in that format (see Reporting).
              </li>
            </ul>
            <Shot
              id="dashboard-overview"
              caption="Case dashboard: artifact stat cards, distribution charts, and the processing-jobs panel."
            />
          </section>

          <section id="timeline">
            <h2>Timeline analysis</h2>
            <p>
              The timeline is a <strong>consolidated super-timeline</strong>: it
              merges dated events from every module into a single paged view,
              each keeping a link back to the artifact that produced it. Switch
              between the <strong>activity</strong> histogram, per-module{" "}
              <strong>swimlanes</strong>, and a weekday-by-hour{" "}
              <strong>heatmap</strong> above the table, and drag across the
              histogram or swimlanes to zoom to a window. Filter by{" "}
              <code>source_module</code> to isolate one source, or leave it open
              to correlate across all of them. In the swimlanes, a lane's colour
              is a property of the view and not of the evidence: the colours
              follow the theme in force, so the same case under another theme
              draws the same lanes in the same order in different colours. Each
              lane is named beside its swatch, which is what identifies it.
            </p>
            <p>
              Where a case carries an outlier timestamp &mdash; a FAT epoch date
              in 1980, a corrupt far-future stamp &mdash; the activity chart{" "}
              <strong>focuses its axis on where the events are</strong> rather
              than stretching across the decades between and drawing the whole
              case as one bar. The bars are then drawn at a resolution chosen
              for that window rather than for the decades: a fortnight of work
              is a fortnight of bars, not one bar a year wide. It says so
              underneath, naming how many events fall outside the drawn range
              and the dates they run to. Those events are not filtered out: they
              are still in the table below, still counted in the total above the
              chart, and still in every export. The swimlanes below share the
              window, so both charts of one case read on one axis. Dragging to
              zoom selects within the range you can see.
            </p>
            <h3>What feeds the timeline</h3>
            <p>
              Every parser that recovers a timestamp contributes events, so a
              single timeline correlates filesystem, execution, and user
              activity from:
            </p>
            <ul>
              <li>
                <strong>NTFS filesystem</strong> — <code>$MFT</code> MAC times
                (created / modified / accessed / MFT-changed) and the{" "}
                <code>$UsnJrnl:$J</code> change journal. (The{" "}
                <code>$LogFile</code> transaction journal is parsed for its
                records but carries LSNs, not wall-clock times, so it does not
                feed the timeline.)
              </li>
              <li>
                <strong>Program execution</strong> — Prefetch run times and SRUM
                application resource usage. <strong>Amcache</strong> and{" "}
                <strong>Shimcache</strong> are read, but neither records an
                execution: Amcache records that Windows <em>catalogued</em> a
                file (no run count, no last-run time) and a shimcache entry
                means Windows <em>looked at</em> it. Amcache's only timeline
                contribution is its <code>LinkDate</code>, a PE build attribute
                rather than host activity, and it is labelled as one.
              </li>
              <li>
                <strong>Application-compatibility shim databases</strong> —
                a <code>.sdb</code> file's contents: the database's name,
                version and creation time, and one record per shimmed
                executable with the application name, the vendor and the
                matching criteria. Recognised by content, not by filename, and
                both container forms are read (the plain one and the
                zlib-compressed one Windows ships <code>appraiser.sdb</code>
                in). A custom database installed with{' '}
                <code>sdbinst</code> is a documented persistence technique,
                because a shim can inject a DLL into a process the shimmed
                program starts. Two things these records deliberately do not
                say: a database <em>file</em> on disk is not a{' '}
                <em>registered</em> database — that is recorded in the registry
                and is a separate fact — and a shim entry is not evidence the
                program it names ever ran. Tags whose meaning this build cannot
                establish from the data are listed by numeric id and counted on
                a coverage record, rather than given a guessed name.
              </li>
              <li>
                <strong>User activity</strong> — ShellBags folder access, LNK
                shortcuts and Jump Lists, browser history visits, and Recycle
                Bin deletions.
              </li>
              <li>
                <strong>Server access</strong> — User Access Logging (UAL), from{" "}
                <code>System32\LogFiles\SUM\*.mdb</code> on Windows Server.
                Records which account reached which server role, from which IP
                address, how many times and on which days. Windows keeps it for
                up to three years, so it frequently survives long after the
                Security event log has rolled — often the only remaining record
                that an account authenticated at all. A database that was not shut
                down cleanly can read as empty here while its transaction log
                (<code>Svc.log</code>, not replayed) holds the rows; such a
                record is marked incomplete and says so.
              </li>
              <li>
                <strong>System / accounts</strong> — Windows Event Logs (EVTX),
                Registry key last-write times, and email message dates.
              </li>
            </ul>
            <h3>Advanced search syntax</h3>
            <ul>
              <li>
                <code>+required</code> — term must be present.
              </li>
              <li>
                <code>-excluded</code> — term must be absent.
              </li>
              <li>
                <code>"exact phrase"</code> — match the phrase as written.
              </li>
              <li>
                <code>column:value</code> — restrict a term to one column, e.g.{" "}
                <code>source_module:registry</code>.
              </li>
            </ul>
            <h3>Working the timeline</h3>
            <ul>
              <li>
                Date ranges narrow the view to the window under examination.
              </li>
              <li>
                Tag events of interest with a note; tags are per-case and
                exportable.
              </li>
              <li>
                Virtual columns lift fields out of module-specific details (for
                example a registry key path or a URL) into their own sortable
                column.
              </li>
              <li>
                Export the current, filtered view as CSV, JSON, or a PDF
                timeline report.
              </li>
              <li>
                <strong>Export body file</strong> writes the events shown
                &mdash; memory events included &mdash; as a Sleuth Kit body
                file for <code>mactime</code>, and it honours the filters you
                have applied. An event has one time, so each row carries it in
                the column its kind names (created or started in{" "}
                <code>crtime</code>, accessed in <code>atime</code>, exited,
                closed or changed in <code>ctime</code>, anything else in{" "}
                <code>mtime</code>) and the other three are 0. The last line
                says whether every matching event was written; a file without
                it is refused as a fragment. The list of files in the case is
                the different body file on the Files page.
              </li>
            </ul>
            <Shot
              id="timeline-view"
              caption="Timeline: activity histogram over a filtered, paged events table."
            />
          </section>

          <section id="search">
            <h2>Search</h2>
            <p>
              Case search runs over a full-text index of artifact names and
              content.
            </p>
            <h3>What a search covers</h3>
            <p>
              A search that finds nothing has only looked where the index
              reaches, so every search states that reach: under the count on a
              page of hits (<em>What this search covers</em>), beside{" "}
              <strong>No results</strong> on an empty one, and in both
              exports. It is built from the indexer&rsquo;s own settings, from
              the match mode of the search, and from which build indexed the
              case, and it says:
            </p>
            <ul>
              <li>
                The metadata of the artifacts ingest hands to the search
                indexer, plus text read from the <strong>first 16 MiB</strong>{" "}
                of the bytes of file artifacts (<code>FileEntry</code> and{" "}
                <code>FileContent</code>) only. Slack space, unallocated space
                and raw images are not read into the index.
              </li>
              <li>
                <strong>Timeline events are not in the index</strong> after
                ingest: the pipeline does not hand them to the indexer. Their
                metadata is added only when the case is re-indexed with the
                backfill (<code>POST /api/v1/cases/:id/search/backfill</code>),
                and a document the backfill adds holds metadata only, never
                file text. A case ingested with a profile that leaves the
                indexer out has no index at all, and nothing marks it
                incomplete.
              </li>
              <li>
                Text is indexed as runs of at least{" "}
                <strong>4 characters</strong>. In UTF-8, letters and digits in
                any script.
              </li>
              <li>
                In <strong>UTF-16</strong> (either byte order): ASCII, accented
                Latin letters (U+00C0&ndash;U+00FE, e.g. <em>cañón</em>,{" "}
                <em>Schönheit</em>), and Greek, Cyrillic, Armenian, Hebrew,
                Arabic or Japanese kana &mdash; one of those alphabets per run,
                mixed freely with ASCII. A word that changes alphabet is split
                where it changes: a Cyrillic word containing a Cyrillic
                Supplement letter (U+0500&ndash;U+052F) is indexed as two
                pieces. <strong>Chinese, Japanese kanji and
                Korean text stored as UTF-16 is not indexed</strong>, nor is any
                other script &mdash; Latin letters beyond U+00FE (<em>Łódź</em>,{" "}
                <em>Dvořák</em>), Indic and Thai included: two bytes of binary data look like one of those
                characters far too often, and admitting them fills the index
                with false text. A search for such a term that finds nothing
                has not searched UTF-16.
              </li>
              <li>
                <strong>That coverage is this build&rsquo;s, and holds only for
                documents this build indexed.</strong> The index records which
                text extractor built each case&rsquo;s file documents. Builds
                before 2026-09-26 read UTF-16 as ASCII only, so a case one of
                them ingested may hold a UTF-16 term outside ASCII (such as{" "}
                <em>Россия</em>) and still not find it. Its statement says so,
                and says that the backfill does not repair it (the backfill adds
                metadata only); a re-ingest of the evidence does, and the byte
                sweep searches those bytes now. In the API the field is{" "}
                <code>universe.index_text_extractor</code>:{" "}
                <code>current</code>, <code>earlier</code>,{" "}
                <code>no_file_documents</code>, or <code>not_assessed</code> when
                the index could not be checked.
              </li>
              <li>
                Matching ignores letter case (the index and the query are both
                lowercased) but is otherwise exact-form; see below for accented
                text. A <strong>fuzzy</strong> search is not exact-form: each
                term matches any word within edit distance 1 or 2 of it, so a
                hit need not contain the term as typed, and the statement says
                so. A regular-expression search matches its pattern, ignoring
                case.
              </li>
              <li>
                <strong>A kana hit can be hex text.</strong> Hex digits stored
                one byte each, such as <code>0D0A0D0A</code>, are byte for byte
                the UTF-16 encoding of hiragana, so they are indexed as kana.
                Check a kana hit against its bytes before reading it as
                Japanese. The statement lists this with what it does not cover.
              </li>
              <li>
                To search for those, or anywhere the index does not reach, the
                case-wide <strong>byte sweep</strong> searches a term&rsquo;s
                UTF-8, UTF-16LE and UTF-16BE bytes in any script, including
                unallocated space. It is the <strong>Byte sweep of the evidence
                bytes</strong> panel on this screen, the REPL&rsquo;s{" "}
                <code>/sweep</code> command, and the API route{" "}
                <code>POST /api/v1/cases/:id/search/sweep</code>; see{" "}
                <em>The byte sweep</em> below. For a single artifact,{" "}
                <strong>Find bytes</strong> in the hex viewer searches its raw
                bytes for a hex pattern.
              </li>
            </ul>
            <h3>The byte sweep</h3>
            <p>
              The <strong>Byte sweep of the evidence bytes</strong> panel, below
              the index-maintenance panel, reads the bytes of every object the
              case holds rather than the index. Give it a <em>Sweep text</em>{" "}
              (searched as UTF-8, UTF-16LE and UTF-16BE, and under every code
              page named in <em>Sweep code pages</em>, as WHATWG labels such as{" "}
              <code>windows-1252</code>), a <em>Sweep bytes (hex)</em> pattern, or
              both; narrow it by <em>Sweep extensions</em> and by region, and cap
              it with <em>Sweep max hits</em>. The REPL&rsquo;s{" "}
              <code>/sweep &lt;text&gt; [--bytes &lt;hex&gt;] [--codepage
              &lt;label&gt;] [--ext .txt] [--region live,slack] [--type
              FileContent] [--path &lt;prefix&gt;] [--glob &lt;glob&gt;]
              [--max-hits n] [--max-bytes n] [--resume id:offset]</code> sends
              the same request and prints the same answer.
            </p>
            <ul>
              <li>
                Every hit names its <strong>region</strong>: <em>live</em> (a
                live file&rsquo;s content), <em>slack</em> (the unused tail of a
                live file&rsquo;s last cluster), <em>unallocated</em>,{" "}
                <em>recovered</em> (carved or deleted content) or <em>raw</em>{" "}
                (a whole image, partition or container, located by offset only).
                A table gives objects offered and searched per region, and the
                server&rsquo;s slack sentence is printed beside it on every
                answer: slack is offered only as the regions the NTFS, FAT,
                exFAT, ext4, HFS+ and APFS parsers publish, so a slack count of 0 on any
                other file system means slack was not looked at, not that it held nothing.
              </li>
              <li>
                The status line is the server&rsquo;s own verdict:{" "}
                <strong>Complete</strong> only when every admitted object was
                read to its end and no ceiling was reached; otherwise{" "}
                <strong>Incomplete</strong>, with each ceiling that was reached
                named with its number (hits, fresh bytes, objects per call). A
                cut sweep offers <strong>Resume from where this sweep
                stopped</strong>, which re-sends the same request from the
                server&rsquo;s cursor; in the REPL the answer prints the{" "}
                <code>--resume</code> token. Each page shows its own hits only.
              </li>
              <li>
                Short reads, read failures and bytes past an object&rsquo;s
                declared size (not searched) are listed under the answer, not
                hidden.
              </li>
              <li>
                A UTF-16 hit whose bytes also read as the pattern in both UTF-16
                byte orders one byte away is listed once, naming both encodings
                and both offsets: the bytes do not say which byte order wrote
                them, so neither reading should be quoted alone.
              </li>
              <li>
                A request the server refuses (for instance a pattern that
                duplicates another) shows the server&rsquo;s own message.
              </li>
            </ul>
            <ul>
              <li>
                Full-text mode tokenizes the query and ranks by relevance;
                fastest for names, words, and identifiers. It understands{" "}
                <strong>boolean operators</strong> (<code>AND</code>,{" "}
                <code>OR</code>, <code>NOT</code>, grouping with{" "}
                <code>( )</code>, and <code>+</code>/<code>-</code> prefixes),{" "}
                <strong>exact phrases</strong> (
                <code>&quot;error code&quot;</code>
                ), and <strong>proximity</strong> (
                <code>&quot;report analysis&quot;~3</code> — within N words).
              </li>
              <li>
                Tick <strong>Fuzzy</strong> to match typos and spelling variants
                (edit distance up to 2): <code>forensik</code> finds{" "}
                <em>forensics</em>.
              </li>
              <li>
                The <strong>Patterns</strong> menu holds a built-in regex preset
                library (email, IPv4, URL, US SSN, credit-card, phone, MAC,
                Bitcoin address) — pick one to fill and run the query.
              </li>
              <li>
                Regex mode applies a Rust regular expression to stored values.
                Use it for patterns that cross word boundaries (card numbers,
                paths, hostnames). It scans the case, so expect it to be slower
                — and a scan that stops at its budget before it has finished
                counting says so, by stating the match count as a floor rather
                than as a total (see <em>What the match count means</em> below).
              </li>
              <li>
                <strong>Keyword lists</strong>: paste or import a newline list
                of terms, then <strong>Run all</strong> to search every term at
                once and get a per-term hit-count table; export the list to
                share it.
              </li>
              <li>
                Extension filters limit results to given file extensions, e.g.{" "}
                <code>exe, dll</code>.
              </li>
              <li>
                <strong>Pivot</strong> turns the current query into a breakdown:
                a panel groups every artifact matching the value by the kind of
                record each is — the same hits the table shows, read as &ldquo;6
                network flows, 2 DNS resolutions, 1 registry hive&rdquo; instead
                of a flat list. It is the fastest way to see <em>what kind</em>{" "}
                of evidence a value appears in. (Not available in regex mode,
                which matches a pattern rather than a literal value.)
              </li>
              <li>
                Export the result set with <strong>Export JSON</strong> or{" "}
                <strong>Export CSV</strong> — of the whole match set, not of the
                page on screen. See <em>What an export covers</em> below.
              </li>
              <li>
                <strong>Accented text is matched in the form you type it.</strong>{" "}
                An accented letter can be stored precomposed (NFC: one
                character, <code>ñ</code>) or decomposed (NFD: <code>n</code>{" "}
                followed by a combining tilde). The two look identical on screen
                and are different bytes, and search applies no Unicode
                normalisation to the index or the query: a precomposed{" "}
                <em>mañana</em> finds precomposed text and a decomposed one finds
                decomposed text, but neither finds the other. A search for an
                accented word that returns nothing has not ruled out the other
                form &mdash; search for both. That holds for a plain query. In
                a quoted phrase or other structured query the tokenizer splits a
                decomposed word at its combining mark, so a quoted decomposed{" "}
                <em>mañana</em> also matches the two words <em>man ana</em>.
              </li>
            </ul>
            <p>
              To search the raw <em>bytes</em> of a specific artifact (rather
              than the text index), use <strong>Find bytes</strong> in the
              artifact hex viewer — see below.
            </p>

            <h3>What the match count means</h3>
            <p>
              The figure above the table counts matching{" "}
              <strong>artifacts</strong>, not the rows below it. Where the
              search could not finish counting, it is shown as{" "}
              <strong>at least N</strong> and a note says the number is a floor:
              more artifacts match than the number shown, so do not record it as
              a prevalence figure. The keyword list marks the same distinction
              per term, with a <em>lower bound</em> badge beside the count.
            </p>
            <p>
              A floored count bounds the counting and not the walking. The usual
              causes — a scan stopping at its per-page budget, a full candidate
              window on an extension-filtered ranked query — stop the count
              where it stood and leave the enumeration intact, so{" "}
              <strong>Next</strong> still reaches the end of the matches. There
              is one cause that does mean rows are missing: an index the server
              knows failed to take some documents. This screen is not told which
              of the three it was; an export of the same query is, and its final
              row says so in as many words.
            </p>

            <h3>Search index maintenance</h3>
            <p>
              <strong>Repair display names</strong>, under{" "}
              <em>Search index maintenance</em>, recomputes the display name of
              every document this case <em>already has</em> in its search index,
              from the metadata stored beside it. The control is offered only to
              an examiner the server would let run one — the case&rsquo;s owner
              or an admin — rather than offered to everyone and refused.
            </p>
            <p>
              It <strong>adds nothing that was never indexed</strong>. An ingest
              that missed evidence leaves a short index, and it is still short
              afterwards. A repair therefore cannot make a case&rsquo;s search
              coverage complete, and &ldquo;the index was repaired&rdquo; is not
              a statement about coverage.
            </p>
            <p>
              <strong>Backfill missing documents</strong> is the operation that
              can add them. It walks the case&rsquo;s artifacts in the database,
              finds the ones with no document in the search index, and indexes
              those — so a case whose ingest dropped documents can be made
              findable again without re-ingesting the evidence.
            </p>
            <p>
              What it adds carries <strong>metadata only</strong>. An artifact
              read back from the database has no bytes behind it, so the text
              extracted from a file at ingest is not reconstructed: a backfilled
              file is findable by its name, path and metadata, and a keyword{" "}
              <em>inside</em> it is not found until the evidence is re-ingested.
              That sentence is in the response, and in every audit record the
              pass writes — <code>search_index_backfill_requested</code>, then{" "}
              <code>search_index_backfill_completed</code> with the examined,
              already-indexed, added and failed counts, or{" "}
              <code>search_index_backfill_failed</code> — because an empty
              search over a backfilled file must not be read as evidence that
              the term is absent from the evidence.
            </p>
            <p>
              While a repair runs, everyone working the case is told so above
              the results, because the names in the table may change under them.
              How it <em>ended</em> is not something the search screen is told:
              the outcome is written to the case&rsquo;s{" "}
              <strong>audit log</strong> — as{" "}
              <code>search_index_repair_completed</code>, with the renamed,
              total and undecodable document counts, or{" "}
              <code>search_index_repair_failed</code> — and that record, not
              this screen, is what says whether the pass finished.
            </p>

            <h3>How deep a result set you can reach</h3>
            <p>
              The table holds one page of the match set, and the bar beneath it
              says which page. <strong>Next</strong> and <strong>Prev</strong>{" "}
              move one page; the page numbers jump straight to one.{" "}
              <strong>Jumping is the part that is bounded.</strong> The server
              answers a page number by walking the case from the start and
              discarding what it passes, so it enforces a ceiling on how deep a
              jump may land; when a query has more matches than that, the screen
              states the match jumping stops at and how many further matching
              artifacts exist beyond it. That ceiling is the optimistic figure:
              under an <strong>extension filter</strong> on a ranked search the
              filter is applied after retrieval over a bounded window, and on a
              plain or regex search the walk has a per-page budget, so how deep
              a jump can actually land depends on the data. A page number the
              server cannot reach that way is <strong>refused</strong> rather
              than shown empty, and the refusal states how deep a jump reaches
              on that search and that the match set does not end there. Go to
              the first page and use <strong>Next</strong>, or export.
            </p>
            <p>
              Those further matches are reachable.{" "}
              <strong>Next keeps walking</strong> past that point, one page at a
              time, each page fetched by resuming where the last one stopped
              rather than by counting from the start again. What is not
              available past the ceiling is random access:{" "}
              <strong>no page number</strong>, and no <strong>Prev</strong> step
              — that control is disabled, and says why rather than looking
              broken. Your browser&rsquo;s <strong>Back</strong> button still
              returns to the pages you have already walked, because every page
              visited is pushed onto the tab&rsquo;s history.
            </p>
            <p>
              A walk belongs to one state of the index, and the index moves
              while a case is being ingested or its display names repaired. Two
              consequences are stated on screen rather than absorbed. If the
              index changes while you are paging, a note says that the pages
              before this one were taken from a different state of it — across
              that seam an artifact may have been shown twice or not at all —
              and that going back to the first page walks one consistent set.
              And a walked position opened later, from a link in a note or a
              handover, is <strong>refused</strong> rather than answered out of
              a re-ordered index: the page says the position can no longer be
              shown, and offers the first page so you can start again. Rows that
              merely looked like a continuation would be the worse answer.
            </p>

            <h3>What an export covers</h3>
            <p>
              An export is of the <strong>match set</strong>: whichever page you
              are on, the file starts at the first match and{" "}
              <strong>walks the whole match set</strong> by resuming from page
              to page. It has no row limit, and it says so in its own preamble
              rather than leaving you to infer it from silence. The server
              streams it a page at a time, so a case with millions of matches
              costs it no more memory than a small one.
            </p>
            <p>
              Before the first row the file states what produced it: the case,
              the query, every filter in force, the population as the search
              reported it (marked as a floor if that is what it was), the index
              snapshot, and the time of export. That snapshot is{" "}
              <strong>held open for the whole export</strong>, so every row in
              the file comes from one state of the index — an artifact indexed
              after the export began is not in it, which is a property of the
              exhibit rather than a defect in it.
            </p>
            <p>
              Every export ends with a verdict row whose first cell begins{" "}
              <code>### END OF EXPORT ### VERDICT:</code>,{" "}
              <strong>including a complete one</strong>. That is the point of
              it: a download that stopped part-way is byte-for-byte a shorter,
              entirely plausible file, so the presence of the last row is the
              only test that survives the file being saved to disk and opened a
              week later. In the CSV the row is always quoted, so the last line
              of a whole file begins with a double quote and then the marker; no
              hit row can begin a line that way, and the marker's appearance in
              the preamble's own reading note is not that row. The JSON ends
              with a <code>completeness</code> object whose{" "}
              <code>statement</code> begins with the marker. The verdict is one
              of three:
            </p>
            <ul>
              <li>
                <strong>COMPLETE</strong> — the file holds the whole match set
                as it stood in the named snapshot.
              </li>
              <li>
                <strong>COMPLETE, STATED TOTAL WAS A FLOOR</strong> — the rows
                are all of them, and the file&rsquo;s own row count is the exact
                size of the match set: the walk ran to the end, so the
                preamble&rsquo;s &ldquo;at least N&rdquo; was the lower bound it
                was standing in for. The two figures differ deliberately, and
                the row says which to believe.
              </li>
              <li>
                <strong>INCOMPLETE</strong> — and it names the cause: the index
                is known to be missing documents (so matches exist that no
                export of this query can produce until it is repaired), a purge
                landed while the file was being written and the walk was stopped
                rather than allowed to read destroyed evidence, the walk lost
                its snapshot, the export failed, or it stopped advancing. Each
                cause calls for a different action, so none of them is flattened
                into &ldquo;incomplete&rdquo;.
              </li>
            </ul>
            <p>
              Séance applies the file&rsquo;s own test at the moment it is
              written. A download that ends without that final row is reported
              as a <strong>fragment</strong> — in a note that stays on the
              search screen, not a toast that clears itself — and never as a
              finished export. The bytes that did arrive are left on disk
              exactly as they were sent: nothing appended, nothing deleted. What
              was retrieved is evidence, and a client that edited an exhibit to
              tidy it up would make it something other than what the server
              sent.
            </p>
            <p>
              Because a large export can be bigger than a browser tab can hold,
              Séance asks where to save it and writes it to that file as it
              arrives, on a browser that supports saving to a chosen file
              (Chrome or Edge, over HTTPS). Dismissing that dialog cancels the
              export before the server is asked for anything. Where the browser
              cannot save as it goes, the whole file must be held in the tab
              first — and for a large or unmeasurable one you are told that, and
              told roughly what it will cost, before a byte is held, so you can
              decline rather than lose the tab.
            </p>
            <Shot
              id="search-results"
              caption="Search: boolean/phrase/fuzzy full-text and regex modes, pattern presets, keyword lists, and export."
            />
          </section>

          <section id="file-browser">
            <h2>File browser</h2>
            <p>
              Open a file system source to browse its full directory listing in
              a sortable, paged grid: name, extension, size, and MAC (modified,
              accessed, created) timestamps, all in UTC.
            </p>
            <ul>
              <li>
                Deleted entries recovered from file system metadata are marked.
              </li>
              <li>Carved files recovered from unallocated space are marked.</li>
              <li>
                Select files to <strong>Export selected (ZIP + hashes)</strong>{" "}
                or <strong>Export CSV of selection</strong>.
              </li>
              <li>
                <strong>Export whole case as mactime body file</strong>, above
                the toolbar, writes a Sleuth Kit body file for{" "}
                <em>every file in the case</em>, from every source &mdash; not
                the filters, folder or source you are looking at, which it
                ignores. It is one line per file carrying that file&rsquo;s own
                MAC times, for <code>mactime</code>, log2timeline or Timesketch;
                the file&rsquo;s last line says whether every file in the case
                was written. Once the file is written the page quotes that
                line; it reports the file saved only when the line reads{" "}
                <code>COMPLETE</code>, and shows it as an error when it reads{" "}
                <code>INCOMPLETE</code> or the file arrived without it. A
                cancelled save dialog is said to have written nothing. The REPL&rsquo;s <code>/export timeline body</code>{" "}
                writes the same file.
              </li>
            </ul>
            <h3>Artifact viewer</h3>
            <p>
              Selecting a file opens the artifact view. Tabs adapt to the
              artifact and can include a hex/text preview, an overview and raw
              properties, image preview with EXIF, extracted children, a
              registry or conversation viewer, and processing history. From the
              header you can <strong>Bookmark</strong>,{" "}
              <strong>Download</strong>, <strong>Verify Integrity</strong>, or
              run another analysis module against the file. Status badges call
              out conditions such as <em>Deleted</em>, <em>Encrypted (EFS)</em>,{" "}
              <em>Unverified recovery</em>, and{" "}
              <em>Content incomplete (fragmented)</em>. Where a parser recorded
              more than one reason a record is incomplete &mdash; a structure
              that would not resolve and a database that was not staged in
              full, say &mdash; the incompleteness note names every one, with
              its meaning, not just the first.
            </p>
            <ul>
              <li>
                <strong>Preview</strong> renders images and video, plays PDFs in
                the browser&rsquo;s native viewer, and pretty-prints structured
                text (JSON and XML indented, CSV/TSV as a grid).
              </li>
              <li>
                <strong>Office document</strong> text is extracted from{" "}
                <strong>Word / Excel / PowerPoint</strong> files (both the
                modern
                <code>.docx</code>/<code>.xlsx</code>/<code>.pptx</code> OOXML
                format and OpenDocument <code>.odt</code>/<code>.ods</code>/
                <code>.odp</code>), along with the document&rsquo;s title,
                author, and created/modified dates. The extracted text is
                full-text searchable and surfaced as an <em>Office document</em>{" "}
                record you can open and read.
              </li>
              <li>
                <strong>Physical location</strong> (right-hand inspector) traces
                where the artifact&rsquo;s bytes actually live on the backing
                device, through the whole container / filesystem chain: the
                device-absolute byte offsets and sectors (copyable),
                fragmentation-aware, with an honest note when the location is
                compressed, encrypted, or reconstructed rather than an exact
                range, plus the annotated evidence chain back to the root
                device.
              </li>
              <li>
                The <strong>Timeline</strong> tab lists the dated events around
                the artifact, newest first: its own, its parent&rsquo;s, its
                children&rsquo;s and its siblings&rsquo;, each with its source
                module. A row names its artifact as <em>this artifact</em>,{" "}
                <em>parent</em>, or <em>child or sibling</em> &mdash; the server
                does not say which of the last two, so the row links to the
                artifact rather than guessing. The list is capped (2,000 events
                today); when it stops at the cap it says it is not the whole
                history, the artifact&rsquo;s own and its parent&rsquo;s and
                children&rsquo;s events having been taken before its
                siblings&rsquo;. Only what a parser put on the case timeline
                appears here.
              </li>
              <li>
                In the hex viewer, <strong>Find bytes</strong> searches the raw
                content for a hex pattern (e.g. <code>ff d8 ff</code>) and lists
                clickable match offsets that jump the view to each hit.
              </li>
              <li>
                <strong>Timestamp analysis</strong> shows the file&rsquo;s{" "}
                <code>$SI</code> and <code>$FN</code> times side by side and
                grades what the comparison found.{" "}
                <strong>Possible timestomping</strong> appears only for a
                pattern no ordinary file operation produces — all four{" "}
                <code>$SI</code> values set to the same second while{" "}
                <code>$FN</code> disagrees, or a whole-second <code>$SI</code>{" "}
                record-change time older than the sub-second <code>$FN</code>{" "}
                creation (the filesystem writes that field itself, at full
                precision, every time the record changes, so a whole-second
                value older than the record&rsquo;s own name was set by a tool).
                Everything else is listed as an <em>indicator</em> with the
                ordinary operation that also produces it: a copy carries a
                modification time older than the name entry, a move or rename
                writes a fresh <code>$FN</code> (every file in the Recycle Bin
                looks like this), and a copy from a FAT volume lands
                whole-second times against sub-second ones. An indicator is
                something to weigh, not a finding.
              </li>
            </ul>
            <Shot
              id="artifact-viewer"
              caption="Artifact viewer: hex + byte-pattern search, integrity verification, and the device-absolute physical-location panel."
            />
          </section>

          <section id="carving">
            <h2>File carving and recovery</h2>
            <p>
              Two mechanisms recover files that are no longer referenced by a
              live directory entry:
            </p>
            <ul>
              <li>
                <strong>Metadata recovery</strong> — deleted entries still
                described by filesystem structures (for example an NTFS MFT
                record or a FAT directory entry) are reconstructed with their
                original name and timestamps and marked deleted.
              </li>
              <li>
                <strong>Signature carving</strong> — a PhotoRec-inspired engine
                scans unallocated space block by block, recognising files by
                their header, data, and footer signatures independently of any
                filesystem. Carved output is marked as such and may be flagged{" "}
                <em>Unverified recovery</em> because it was reconstructed from
                raw bytes.
              </li>
              <li>
                <strong>Carves that end short</strong> — a header whose file
                ran out before the minimum length its signature expects (a
                truncated <code>.clip</code>, <code>.abr</code> or{" "}
                <code>.ds_store</code>, for example) is published rather than
                dropped. It carries <code>carving_below_minimum: true</code>,
                shows <em>Below declared size</em> on the artifact page, and is
                counted as <code>total_below_minimum</code> in the carving
                summary. It records that a header was found and the bytes after
                it ended early; it is not a recovered file.
              </li>
              <li>
                <strong>ext2/ext3 pointer blocks</strong> — ext2 and ext3 write
                a file&apos;s indirect (and double-indirect) pointer blocks in
                line with its content, after its twelfth block, so a carve
                copied straight through comes back the right size and
                byte-wrong. A carve that runs across them is rebuilt without
                them, and only once every pointer in them names exactly the
                blocks that follow; it then carries{" "}
                <code>carving_reconstruction: ext2_indirect</code> and its{" "}
                <code>data_runs</code>, and what you download or hash is the
                rebuilt file. A file whose blocks are scattered across the disk
                is not reassembled.
              </li>
              <li>
                <strong>File slack</strong> — on NTFS, FAT, exFAT, ext4, HFS+ and APFS, the unused
                tail of each live file&apos;s last cluster (from the file&apos;s
                logical end to the end of that cluster) becomes a{" "}
                <code>SlackSpace</code> region when it holds any non-zero byte,
                and is carved automatically from its first 512-byte boundary
                under a profile that runs the automatic carver (the deep
                profile does; triage publishes the regions but carves none of
                them, so no slack finding can arise there). A file carved there
                carries <code>carving_source: slack</code>{" "}
                and the name of the file whose slack held it. Under the
                volume&apos;s cluster size no file starts in slack — a file
                starts on a cluster boundary, and the start of that cluster is
                the live file&apos;s own content — so something carved there
                was part of an earlier file&apos;s content, or was put there
                deliberately. A volume reformatted with larger clusters, or one
                that once held another file system, can leave a former file
                starting part-way through a cluster, and the finding says it
                does not exclude that. Slack is allocated
                to that file, so it is never counted as free space; a carve from
                it is shorter than one cluster. A deleted file, a compressed or
                encrypted NTFS file, a file whose run list is incomplete, and
                every other file system get no slack region, and each
                volume&apos;s <code>slack_space_summary</code> record counts the
                windows offered, emitted, all-zero, unreadable and past the
                250,000-region ceiling, and, as{" "}
                <code>files_not_located</code>, the live files with a tail
                that was never offered because their runs were compressed,
                encrypted, incomplete or shorter than the file.
              </li>
            </ul>
            <p>
              Carving covers 361 file signatures — every format PhotoRec carves
              by default (351 of its 352; its <code>dovecot</code> layout, which
              PhotoRec ships disabled, is not carried), plus Séance's own —
              spanning
              images (<code>JPEG</code>, <code>PNG</code>, <code>GIF</code>,{" "}
              <code>BMP</code>, <code>TIFF</code>, <code>WebP</code>,{" "}
              <code>HEIC</code>, <code>AVIF</code>, <code>JPEG XL</code>),
              documents and archives (<code>PDF</code>, <code>OLE2</code>,{" "}
              <code>ZIP</code>, <code>7z</code>, <code>RAR</code>,{" "}
              <code>GZIP</code>, <code>TAR</code>, <code>Zstandard</code>,{" "}
              <code>LZ4</code>, <code>cpio</code>, <code>Parquet</code>,{" "}
              <code>WARC</code>), audio and video (<code>MP4</code>,{" "}
              <code>MOV</code>, <code>AVI</code>, <code>ASF</code>,{" "}
              <code>MKV</code>, <code>MP3</code>, <code>WAV</code>,{" "}
              <code>FLAC</code>, <code>OGG</code>), and forensic or executable
              types (<code>SQLite</code>, <code>PE</code>, registry hives,{" "}
              <code>EVTX</code>, <code>LNK</code>, <code>PST</code>,{" "}
              <code>Mach-O</code>, <code>ELF</code>, <code>PCAP</code>, and
              more). Recovered files re-enter the pipeline, so a carved SQLite
              database or registry hive is parsed like any other source.
            </p>
            <p>
              <strong>Container formats are named by their contents.</strong> A{" "}
              <code>ftyp</code> header belongs to the ISO Base Media family, not
              to MP4 alone, so the major brand decides the extension: an iPhone
              photograph is recovered as <code>.heic</code> rather than as
              video, and Canon raw as <code>.cr3</code>. The same applies to
              Matroska, where the DocType separates <code>.mkv</code> from{" "}
              <code>.webm</code>. Without this a device's entire camera roll
              lands in a carve as video files, where a filter for images will
              not find it.
            </p>
            <p>
              <strong>Custom carver definitions</strong>: to recover a file type
              the built-in set does not cover, declare it in a small JSON file
              (name, hex header, optional footer and size caps) and start Séance
              with <code>--carver-defs your-defs.json</code>. Each definition is
              registered alongside the built-in signatures — no code change
              needed.
            </p>
            <h3>Feature extraction (bulk_extractor-style)</h3>
            <p>
              Beyond reconstructing whole files, Séance sweeps the raw byte
              stream — unallocated space and decoded memory — for things
              file-oriented parsers never reach, each recorded with the device
              offset it was found at. These appear as records under{" "}
              <strong>Records analysis</strong> and feed search and the
              timeline:
            </p>
            <ul>
              <li>
                <strong>Feature selectors</strong> — email, URL, IPv4, MAC,
                payment card (Luhn + IIN gated), SSN, IBAN (mod-97), VIN, GPS
                and Bitcoin, over unallocated space and memory. Each scan that
                found anything also publishes one <em>Feature histograms</em>{" "}
                record — the bulk_extractor-style most-common-values table: the
                100 most common (kind, value, count) entries, the hits and
                distinct values per selector, and the totals. The histogram
                tracks at most 100,000 distinct values; when that ceiling
                binds the record says so in its own words, with the exact
                number of hits not tallied, and the viewer prints that sentence
                verbatim — counts for the tracked values are exact and the
                distinct total is a floor. A longer table than the 100 shown
                is disclosed by number.
              </li>
              <li>
                <strong>AES keys from RAM</strong> — key schedules verified in a
                memory image, recorded as <em>RecoveredKey</em> records; these
                can feed the decryptors when no password is known.
              </li>
              <li>
                <strong>Network packet carving</strong> (opt-in) — IP packets
                recovered from memory or evidence and reassembled into a{" "}
                <code>.pcap</code> that appears in the file browser, recovering
                traffic the live network view cannot see.
              </li>
              <li>
                <strong>Decode-and-rescan</strong> (opt-in) — base64, gzip and
                XOR-obfuscated spans lifted into child buffers the whole
                pipeline then re-examines, so a JPEG hidden inside base64 is
                found.
              </li>
            </ul>
            <p className="help-note">
              The two opt-in members are triggered per-artifact from the modules
              view, because packet carving writes a file and decode-and-rescan
              multiplies the pipeline's work.
            </p>
          </section>

          <section id="artifacts">
            <h2>Artifact parsers</h2>
            <p>
              Modules detect their input by content, never by filename alone, so
              renamed or extension-stripped artifacts are still parsed. The
              records they produce feed the timeline, search index, entities,
              and reports.
            </p>
            <h3>Windows</h3>
            <ul>
              <li>
                Registry hives (SAM, SECURITY, SOFTWARE, SYSTEM, NTUSER.DAT),
                with a dedicated key/value viewer; IE/Edge{" "}
                <strong>TypedURLs</strong> (addresses typed into the address
                bar) are normalised into browser-history records with their
                typed order and last-typed time. Keys and values still present
                in a hive&apos;s <strong>unallocated cells</strong> are read as
                their own record types, <em>Registry keys (recovered from
                unallocated cells)</em> and <em>Registry values (recovered from
                unallocated cells)</em>, never merged with the live tree. A
                recovered key&apos;s path is an <em>inference</em> from a
                parent offset that may have been reused since, and the column
                says so; when the chain stops at an offset that resolves to no
                cell the row says the path does not reach the root, and when a
                live key of the same name exists under the same parent the row
                says that too — which is not evidence that the key was
                deleted. A freed value records no key, so its Key column reads{" "}
                <em>not inferred</em> rather than a blank; its data is shown
                with its basis — inline in the freed cell, or read from an
                allocated cell the freed value points at, which may have been
                reused since and holds what it holds today. The walk is capped
                at 200,000 cells examined and 50,000 records, and the hive
                record states both numbers.
              </li>
              <li>
                <strong>Recently opened (registry MRU)</strong> — the RecentDocs
                and ComDlg32 lists, each shell item walked through the shell
                item format: the name and path from the item itself, and — from
                the deepest item&apos;s file reference, where its extension
                block carries one — the NTFS <strong>MFT entry and sequence</strong>
                , under the same field names the LNK parser uses so a shortcut
                and an MRU entry to the same file can be set side by side. A
                file reference that is all zero is <em>not</em> reported as
                entry 0 (that would name <code>$MFT</code>); the row says the
                field was zero instead. When <em>k</em> of <em>n</em> items
                could not be read the row is flagged with those numbers; when
                every item decoded the record states exactly which fields were
                read. An item of a class this build has no layout for is
                named <code>UnknownType_0x..</code> and reported unread, never
                given a name taken from bytes it cannot place; a
                users-property-view item is named as such and its property
                stores are not decoded.
              </li>
              <li>
                Execution and usage: Prefetch, Amcache, Shimcache
                (AppCompatCache), SRUM, Jump Lists, LNK shortcuts, ShellBags.
              </li>
              <li>
                <strong>Jump lists</strong> (
                <code>automaticDestinations-ms</code>) are read as the OLE
                compound files they are: each numbered stream becomes a
                shortcut artifact of its own, and the <code>DestList</code>{" "}
                stream is decoded into one record per entry — <em>Jump list
                entries (DestList)</em> — carrying the entry&apos;s{" "}
                <strong>MRU position</strong> (its index in stream order, on the
                stated basis that the stream is kept most-recently-used first),
                the path and NetBIOS host, the <strong>last recorded time</strong>{" "}
                (an unset time is reported as unavailable, never as 1601), and
                whether the entry is <strong>pinned</strong>. The application is
                named from the AppID where this build knows it, and reported as{" "}
                <em>not established</em> where it does not. The DestList layout
                is chosen by its version and never guessed: version 1 (Windows
                7 and 8) and versions 2–4 (Windows 10 and later); any other
                version is refused by number. The 32-bit field at offset 116
                of a version 2+ entry — which the format documentation marks
                as unknown and only possibly an access count — is shown under
                exactly that heading and is never called an access count. The
                Windows 7 layout has no such field, and the row says so. When
                the OLE directory cannot be read the file is carved for
                shortcut signatures instead, and those records say they were
                carved. When it can be read, the sectors the file itself marks
                free are also scanned, and a shortcut found there — one the
                directory no longer references, such as a removed entry — is
                reported as carved from an <em>unreferenced sector</em>, with
                nothing tying it to a DestList entry. That scan stops at 10,000
                shortcuts, and if it does, the jump list is marked incomplete
                and the count is a floor.
              </li>
              <li>
                <strong>Windows Timeline</strong> (
                <code>ActivitiesCache.db</code>) — the activity feed Windows 10
                and 11 record per user: which application was in focus, the
                document or web page it had open, how long it was focused, and
                clipboard captures. Activities are surfaced as records, on the
                unified timeline, and alongside the other execution evidence.
              </li>
              <li>
                Windows Event Logs (EVTX) and the Recycle Bin ($I / INFO2).
                After the intact walk of a log, its bytes are scanned end to
                end for <code>ElfChnk</code> chunk signatures at any offset —
                chunks the file header no longer counts, chunk slack, and the
                chunks of a rotated or partly overwritten log — and every event
                read that way is a record of its own type,{" "}
                <em>Windows Event Log (recovered)</em>, shown apart from the
                live log and never counted with it. Each recovered row states
                where it came from (a carved chunk, chunk slack or a loose
                record), the state of its chunk header (present, or its tables
                discarded), the chunk&apos;s header and data checksums (valid,
                failed, absent, or unverifiable because the chunk is
                truncated; <em>not applicable</em> on a chunk-slack row, because
                no checksum covers slack — the record keeps the containing
                chunk&apos;s own states under separate names and says why),
                whether the template it was rendered with was its
                own or <strong>borrowed</strong> from another chunk, and — when
                it is <strong>partial</strong> — which substitutions could not
                be bound, by index. A companion record,{" "}
                <em>Windows Event Log recovery status</em>, carries the counts
                for the file: bytes scanned against bytes declared (a short
                read is flagged as such), chunks by checksum state, records
                recovered, partial, header-only and borrowed, and every bound
                the scan hit — a bound hit makes every count a floor, and the
                row says so. A log that ends part-way through a chunk says so
                on the live log&apos;s own status row, naming the chunk&apos;s
                offset and how many of its bytes survive: that chunk&apos;s
                events appear only as recovered rows. A chunk lying on its own
                in unallocated space is carved as an{" "}
                <em>EVTX chunk (Windows event log)</em> file and its events
                are recovered the same way.
              </li>
              <li>
                <strong>Autostart (ASEP)</strong> — every place Windows will
                execute something at boot or logon, enumerated by category: Run
                and RunOnce across all hives and users, Winlogon Shell and
                Userinit, AppInit_DLLs, Image File Execution Options debuggers,
                auto-start services, scheduled tasks, startup folders, WMI event
                subscriptions, LSA packages, print monitors, COM hijacks and
                shell extensions. Each entry states what it points at and
                whether that target exists. A category Séance could not read is
                reported as unexamined rather than as empty, because "nothing
                runs at boot from here" and "we could not look" are different
                answers. WMI event subscriptions (
                <code>__EventFilter</code>, the event consumers and the{" "}
                <code>__FilterToConsumerBinding</code> that joins them) are
                read from the CIM repository&apos;s <code>OBJECTS.DATA</code>{" "}
                by a record-level scan of its pages, decoded against the class
                definitions found in the same file. When the repository&apos;s
                page mapping (<code>MAPPING1/2/3.MAP</code>, or{" "}
                <code>OBJECTS.MAP</code> on XP) sits beside it, the newest
                well-formed one is read and the pages are walked through it: a
                record that runs past its page is read whole, and a record in a
                page the mapping no longer uses is reported as a superseded
                copy. A record no descriptor table lists is residue even in a
                mapped page, and is never called current or in force. A binding
                is resolved to the current copy of its filter and consumer where
                one was found; when an end was found only as a superseded or
                residue copy, the binding is marked incomplete and is not called
                in force, and a superseded binding is listed apart from the ones
                a filter or consumer is currently bound to. A mapping
                file whose name occurs twice in its directory is withheld and
                reported as withheld, not as missing. Without the mapping, a record found is one the repository
                holds, not necessarily one it currently maps. The index (
                <code>INDEX.BTR</code>) is never read. Every record, and the
                coverage record for the file, says which applied. A subscription
                recovered from repository bytes nothing references, or found in
                a superseded page, is its own record type,{" "}
                <em>Autostart entries (ASEP, recovered)</em>, and is never
                counted among the live ones. When any autostart entry&apos;s
                command runs <code>powershell</code> or <code>pwsh</code> with
                an encoded command (<code>-enc</code>, <code>-e</code>,{" "}
                <code>-EncodedCommand</code> and the other forms PowerShell
                accepts), the argument is decoded as PowerShell decodes it and
                the record carries the script as{" "}
                <code>powershell_encoded_command_decoded</code> — what the
                command holds, not proof that it ran. An argument that does not
                decode is reported as undecodable with the reason, and no script
                is shown.
              </li>
              <li>
                <strong>Security descriptors</strong> (<code>$Secure:$SDS</code>
                ) — NTFS stores each file's owner, group and access-control list
                once in the <code>$Secure</code> metafile, referenced by a
                security id in the MFT record. Each unique descriptor is listed
                as its own record, keyed by that security id, with well-known
                SIDs and access-mask bits resolved to names. A file's record
                carries its <code>security_id</code> when its{" "}
                <code>$STANDARD_INFORMATION</code> is the NTFS 3.x form that
                holds one (an NTFS 1.2 record has none, and none is
                invented). A file&apos;s page shows it beside its descriptor:
                the Inspector&apos;s <em>Owner and permissions</em> section looks
                up the descriptor with the same security id from the same
                volume&apos;s <code>$Secure:$SDS</code> (ids on two volumes are
                unrelated) and shows the owner, the group and each DACL and SACL
                entry, labelled with the stream, the descriptor&apos;s hash as
                read and its offset in the stream. It says so when the entry
                has no security id, when the id is 0 (which names no
                descriptor), when no store from that volume was examined, when
                the store could not be read and why, and when the store holds
                no descriptor with that id — and, if the store listing is
                incomplete, that the id is not thereby shown absent. Account
                names come only from the well-known SID table; the SAM is not
                read. An{" "}
                <code>$SDS</code> that could not be read — for example from a
                bare <code>$MFT</code> with no volume — is listed as an unread
                store, never as a volume with no descriptors.
              </li>
              <li>
                NTFS metadata: the <code>$MFT</code>, <code>$LogFile</code>,{" "}
                <code>$I30</code> directory indexes — including names of
                deleted files recovered from index slack, marked{" "}
                <code>from_slack</code>. A slack name may be a stale copy of an
                entry that still exists, so each carries{" "}
                <code>slack_status</code>: <code>copy_of_live_entry</code>,{" "}
                <code>reference_live_under_other_name</code>,{" "}
                <code>live_name_reference_unknown</code> (its file reference is
                blank where NTFS overwrote it) or <code>no_live_entry</code>{" "}
                — a candidate deleted name, compared only against the index
                entries that were read. An index from a bare{" "}
                <code>$MFT</code> is listed as not read, never as empty — the <code>$UsnJrnl</code> change
                journal, and the <code>$BadClus</code> bad-cluster map (a <code>$BadClus:$Bad</code>{" "}
                stream that arrives without its run list is listed as not read,
                never as a volume with no bad clusters). A bare{" "}
                <code>$MFT</code> without its volume yields every file's
                metadata and resident content only: the content of a file
                stored outside its MFT record is marked unavailable, not shown.
                On a volume, files are listed only from the <code>$MFT</code>{" "}
                itself, read through its own run list: an older copy of an MFT
                record left in free space or in a shadow copy&apos;s storage is
                never listed as a live file. If the table&apos;s first record is
                damaged its <code>$MFTMirr</code> copy is used, and if neither
                can be read no file is listed; either way the volume&apos;s{" "}
                <code>mft_parse_summary</code> record says so.
              </li>
              <li>
                Volume Shadow Copies (VSS): enumerates shadow-copy snapshots
                from the VSS catalog and reconstructs each snapshot&apos;s
                volume as one byte stream. Each snapshot&apos;s{" "}
                <code>$MFT</code> is compared with the live volume&apos;s, and
                every record that differs (a reused record, a file deleted
                since, a changed name, size or timestamp) is listed under{" "}
                <strong>Prior Versions (Shadow Copies)</strong>, each row marked
                as a shadow-copy version with the snapshot it came from and the
                fields that differ; its content is served from the snapshot,
                not the live volume. A snapshot is <strong>not</strong> walked
                as a file system: files unchanged since the snapshot, and
                anything in its indexes, journals or unallocated space, are not
                listed from it.
              </li>
              <li>
                PE / <strong>Authenticode</strong> analysis (a SigCheck-style
                view of Windows executables): the digital signature&apos;s
                publisher, certificate issuer and validity dates, and whether
                the signed hash still matches the file (tamper detection), plus
                the import hash (<code>imphash</code>), version-resource company
                and product strings, and a packed/high-entropy flag.
              </li>
              <li>
                <strong>Thumbnail cache</strong> (<code>thumbcache_*.db</code>):
                each cached thumbnail&apos;s entry hash, source identifier,
                image format, and size — evidence that a file or folder existed
                even after it was deleted.
              </li>
            </ul>
            <h3>macOS and Linux</h3>
            <ul>
              <li>
                <strong>Linux login accounting</strong> — <code>utmp</code> (who
                was logged in when the image was taken), <code>wtmp</code> (the
                login and logout history) and <code>btmp</code> (failed login
                attempts, with the host they came from). The record layout
                differs between 32- and 64-bit and between C libraries, so the
                stride is detected from the file rather than assumed, and a file
                whose size is not a whole number of records of any known layout
                is refused rather than parsed at the wrong offset. Failed logins
                from <code>btmp</code> are among the most valuable records in an
                intrusion case.
              </li>
              <li>
                macOS <strong>FSEvents</strong> (the volume&apos;s
                <code>/.fseventsd</code> logs): per-path filesystem change
                records (create, modify, rename, delete) with their event IDs —
                a history of activity independent of file timestamps.
              </li>
              <li>
                <strong>.DS_Store</strong> folder metadata: the files a Finder
                folder once contained, recovered from its buddy-allocated B-tree
                — names persist here even after the files themselves are gone.
              </li>
              <li>
                <strong>Shell history</strong>: <code>zsh</code> and{" "}
                <code>bash</code> command history (with timestamps when the
                shell recorded them), the freedesktop <strong>Trash</strong> (
                <code>.trashinfo</code> original paths and deletion times), and
                GTK <strong>recently-used</strong> files (
                <code>recently-used.xbel</code>), and the freedesktop{" "}
                <strong>thumbnail cache</strong> (
                <code>~/.cache/thumbnails</code> PNGs — each thumbnail&apos;s{" "}
                <code>Thumb::URI</code> names the original file and{" "}
                <code>Thumb::MTime</code> dates it, evidence a file existed even
                after deletion).
              </li>
              <li>
                macOS <strong>behavioural &amp; provenance artifacts</strong>:
                download <strong>quarantine</strong> (
                <code>LSQuarantineEventsV2</code> — where a file came from, and
                the app that fetched it), <strong>TCC</strong> privacy grants (
                <code>TCC.db</code> — which app was allowed camera / mic / disk,
                and why), <strong>launchd</strong> persistence (
                <code>LaunchAgents</code>/<code>LaunchDaemons</code> — what runs
                at login or boot), <strong>knowledgeC</strong> app-usage
                activity, <strong>Wi-Fi</strong> joined-network history,{" "}
                <strong>install history</strong>, package <strong>BOM</strong>{" "}
                file inventories, and Notification Center messages.{" "}
                The <strong>Spotlight</strong> index (
                <code>.Spotlight-V100/Store-V2</code>) is decoded per item: the
                path, content type, sizes, owner, download source and dates of
                every file it saw — <em>including files since deleted</em>, so
                an item here is not a file that is on the volume now, and the
                screen says so on the row. The unified log's{" "}
                <strong>format-string catalogue</strong> (
                <code>/var/db/uuidtext</code>) is read as what it is: an
                inventory of the code on the machine that logs — each binary's
                path, UUID and load address. A catalogue is <em>not</em> a log,
                and a catalogue entry is <em>not</em> a record that the binary
                ran, which every row says. The <strong>logs</strong> themselves
                (<code>.tracev3</code>) are read to their entries and counted —
                chunks, catalogs, every chunkset decompressed, and every firehose
                tracepoint by kind, with the processes and subsystems that
                logged and the entries the log says it dropped. When the log was
                added as loose files or a ZIP (a collected{" "}
                <code>.logarchive</code>, or <code>/var/db/diagnostics</code>{" "}
                beside <code>/var/db/uuidtext</code>), each message is also
                decoded against the log's own tree and shown as its own row
                (a child of the file's row): the text, process, subsystem and a time dated
                through the timesync database (<code>time_source</code> says
                which clock dated it). A message whose format string is not in
                the tree says why instead of showing empty text; the{" "}
                <strong>Unified Log Messages</strong> screen marks such a row
                &ldquo;not resolved&rdquo; and shows no text for it. Statedump and
                simpledump entries are rows of their own; a statedump whose
                data is a protocol buffer or custom object keeps the bytes and
                says they are not decoded. A{" "}
                <code>.tracev3</code> <em>inside an APFS or HFS+ disk image</em>{" "}
                is given the tree listed from the same volume; one whose
                source cannot reach its tree shows no message text, and its
                row says{" "}
                <code>messages_decoded: false</code> and &ldquo;tree not
                reachable, not decoded&rdquo;. The <strong>timesync</strong>{" "}
                database (<code>timesync/*.timesync</code>) is also read as one
                row per boot with its clock anchors.
              </li>
            </ul>
            <h3>Cross-platform and application data</h3>
            <ul>
              <li>
                Browsers: history for Chrome/Edge, Firefox and Safari;
                downloads and bookmarks for Chrome/Edge and Firefox (Safari's{" "}
                <code>Downloads.plist</code> and <code>Bookmarks.plist</code>{" "}
                are not read); plus (Chrome &amp; Firefox){" "}
                <strong>cookies</strong> (host, path, flags, expiry),{" "}
                <strong>autofill</strong> / form-history values, Chrome{" "}
                <strong>saved-login metadata</strong> (which accounts were saved
                for which sites — usernames are plaintext, passwords are not
                surfaced), Firefox <strong>session restore</strong> (the tabs
                that were open, from <code>sessionstore.jsonlz4</code>), and the
                Chrome/Edge <strong>extension inventory</strong> (name, version,
                permissions, enabled state, and install time from the profile{" "}
                <code>Preferences</code>), the <strong>Chrome cache</strong>{" "}
                (the <em>cached URL</em> of each entry — what the browser
                fetched — from both the modern Simple Cache and the legacy
                blockfile <code>data_#</code> files; a split-cache key also
                gives the top-frame and frame sites the resource was fetched
                under, each blockfile key is checked against the hash its
                entry carries, and an entry in a block the file marks free is
                shown as a freed entry; the cached content itself is not
                recovered), and{" "}
                <strong>Local Storage</strong> (Chromium{" "}
                <code>localStorage</code> key/values recovered from the LevelDB
                write-ahead log and the compacted <code>.ldb</code> tables, per
                origin, including deleted entries). For legacy Internet Explorer
                and EdgeHTML, <strong>IE/Edge history</strong> and cache are
                read from the <code>WebCacheV01.dat</code> ESE database (each
                container's visited/cached URLs with access and modified times).
              </li>
              <li>
                <strong>Clipboard history</strong> — what was copied on Windows
                10 and 11 with clipboard history enabled, from{" "}
                <code>%LOCALAPPDATA%\Microsoft\Windows\Clipboard</code>. Both
                stores are read and kept apart, because they mean different
                things: a <em>pinned</em> item was deliberately kept by the user
                and survives the reboot that clears the rest, while{" "}
                <em>history data</em> is the ordinary rolling buffer. Each
                item's format is recovered from its filename, which Windows
                writes in base64 — so a record can say{" "}
                <em>an image was copied</em> or <em>text was copied</em> without
                touching the payload.
                <br />
                The payloads themselves are{" "}
                <strong>encrypted by Windows</strong> before they are written,
                and Séance does not decrypt them. What it does read is the part
                deliberately left in the clear: the protection descriptor in the
                blob's own header, which names the account the item was
                protected to. So a clipboard entry answers <em>who</em>,{" "}
                <em>when</em> and <em>what kind</em> even where the content
                itself cannot be recovered.
              </li>
              <li>
                <strong>BITS job queue</strong> — the Background Intelligent
                Transfer Service queue under{" "}
                <code>ProgramData\Microsoft\Network\Downloader</code>. From{" "}
                <code>qmgr0.dat</code>/<code>qmgr1.dat</code> (before Windows
                10), each job's name, owner SID, state, source URL, local and
                temporary paths and its creation and modification times. From
                the <code>qmgr.db</code> database (Windows 10 and later), only
                each job's header — name, owner SID, state and type — is read:
                its files and times are <em>not read</em>, and the job says so
                rather than showing no files. The database's file rows are
                listed separately, not tied to their job. A file named like a
                queue that cannot be read, or is not a queue, is reported as
                not decoded rather than as an empty queue. Stored credentials
                and custom headers are reported present and never decrypted.
                File records found outside the live queue —
                past its end in a <code>.dat</code> file, or in database pages
                no row points at — are listed as <em>carved</em> and are not
                jobs. The database's transaction logs are not replayed, so a{" "}
                <code>qmgr.db</code> copied from a running machine is marked{" "}
                <em>incomplete</em> rather than shown as an empty queue.
              </li>
              <li>
                <strong>Windows Search index</strong> — what the Windows indexer
                recorded in <code>Windows.edb</code> (Windows 7 and 10): for
                each file, folder, Outlook message or Internet Explorer entry
                this build could reach in the index, a fixed set of properties —
                the path, size, times and owner, and for mail the sender,
                recipients, subject and dates — not every property the indexer
                stored. Where the database's own page tree could not be walked
                in full, the item count is stated as a floor. A row can name a
                file that is no longer on the disk. The content summary Windows 7 keeps in an
                encoded form is shown where this build decodes that form and is
                listed under <em>not decoded</em>, with the property named,
                where it does not. Changes still in the index&apos;s transaction
                logs are not read, and an index copied from a running machine is
                marked <em>incomplete</em>. Windows 11&apos;s newer{" "}
                <code>Windows.db</code> is recognised and not read.
              </li>
              <li>
                <strong>RDP bitmap cache</strong> — the screen fragments the
                Remote Desktop client kept in{" "}
                <code>Terminal Server Client\Cache\Cache####.bin</code>. Each
                tile appears in the <strong>Gallery</strong> as a small PNG
                named <code>…_tile_NNNNN.png</code>, and every tile in the file
                is also laid out, 64 across, in one collage named{" "}
                <code>…_collage_cache_order_not_a_reconstruction.png</code>. The
                collage is <strong>not a reconstruction</strong>: tiles sit in
                the order the cache stores them, not where they were on the
                remote screen, a tile that could not be read leaves its cell
                black, and its record says so. The older <code>bcache*.bmc</code> files are
                recognised but not decoded; an empty one reads as empty.
              </li>
              <li>
                Generic SQLite databases (the schema, and every row of each
                table up to 50,000 per table — not a sample) and macOS/iOS
                property lists (binary and XML).
              </li>
              <li>
                Messaging and communications: iMessage, WhatsApp, Signal
                (including decrypting a Signal Android <code>.backup</code> with
                its passphrase), Android SMS, Viber, Kik, Skype, and email
                stores. <strong>WeChat</strong> (<code>EnMicroMsg.db</code>) is
                parsed when decrypted, and can be{" "}
                <strong>SQLCipher-decrypted in place</strong> when the device
                key is supplied (the IMEI + uin it derives from, or a raw key);
                a wrong key is rejected rather than producing wrong rows.{" "}
                <strong>LINE</strong> (<code>naver_line</code>) is parsed when
                decrypted. Both are otherwise flagged as an encrypted database
                for triage. <strong>Facebook Messenger</strong> (
                <code>threads_db2</code>) messages are parsed with their sender
                and thread. <strong>Telegram</strong> (<code>cache4.db</code>)
                yields a communication timeline (dialog, time, direction); its
                message text is a version-specific TL blob and is left undecoded
                rather than guessed. <strong>Instagram</strong> Direct (
                <code>direct.db</code>), <strong>Twitter</strong>/X direct
                messages and search history (the account&apos;s{" "}
                <code>&lt;id&gt;-*.db</code> stores; searches are read from the
                main store&apos;s own search table as well as from a separate
                search database), and <strong>Snapchat</strong> (<code>arroyo.db</code>{" "}
                messages and
                <code>main.db</code> friends) are parsed with sender, thread,
                and direction; where a body is a protobuf blob or ephemeral, the
                text is recovered when present and flagged when not. Each parser
                detects its schema at runtime and emits nothing on a mismatch,
                so a wrong schema never yields wrong records. Where the Viber,
                Kik, LINE, Instagram, Facebook Messenger, Snapchat or Twitter/X
                parser has found its table and read its columns and the query
                that reads the rows still will not run, it files an{" "}
                <em>unreadable</em> record naming the table and carrying the
                database&apos;s own error, rather than an empty list that would
                read as a device with no messages.
              </li>
              <li>
                Installed applications: the Android package inventory (
                <code>packages.xml</code> / <code>packages.list</code>) and the
                iOS <code>applicationState.db</code> bundle inventory are parsed
                into an Installed Apps list — package name, install path, user
                ID, version, and install/update times — so you can see what was
                on the device and which app databases to examine.
              </li>
              <li>
                EXIF metadata (including GPS) from images, iCalendar events, and
                the Android calendar app database, and Google Keep notes. An
                event the calendar stored with no start or end time has none
                on the record, rather than a 1970 date; a calendar or Keep
                database that will not open or query is listed as unreadable,
                with the database&apos;s own error, rather than as a device
                with no events or notes.
              </li>
              <li>
                iOS device databases: <strong>Voicemail</strong> (
                <code>voicemail.db</code> — caller, callback number, duration,
                and whether it was deleted), Apple <strong>Notes</strong> (
                <code>NoteStore.sqlite</code> titles and snippets), the
                <code>Calendar.sqlitedb</code> event store, the
                <code>Photos.sqlite</code> camera-roll catalog (filename,
                capture time, favourite and trashed state, and whether the asset
                carries GPS), and <strong>PowerLog</strong> (
                <code>CurrentPowerlog.PLSQL</code>) events including flashlight
                (torch) on/off with their timestamps. A store that holds none
                of the tables its reader is built on gets a status record
                naming the tables looked for, and one whose catalogue or query
                will not read gets an unreadable record with the error, so
                neither reads as a device with no voicemails, events, notes or
                photos. A deleted or favourite flag the store left empty shows
                as <em>not recorded</em>, not as &ldquo;no&rdquo;. The PowerLog
                summary says whether the torch table was read, was absent, or
                could not be read, and why.
              </li>
              <li>
                OCR: recognised text inside pictures (screenshots of notes,
                passwords, chats) is extracted and fed into full-text search, so
                images become searchable. The recognition engine runs entirely
                in-process with a bundled neural model, so there is nothing to
                install and no data leaves the machine.
              </li>
              <li>
                <strong>YARA</strong> content scanning: when you supply a YARA
                rule set, every file&apos;s bytes (and carved objects) are
                scanned and each matching rule is recorded against the file — a
                flagged aid for triage, never an assertion of maliciousness.
                Séance ships no rules of its own, so the scanner is inert until
                you configure one. Powered by <code>yara-x</code>, the pure-Rust
                YARA engine. Beyond a plain file, the rules also reach NTFS{" "}
                <strong>alternate data streams</strong>, the{" "}
                <strong>value inventory of a registry hive</strong> (each value
                scanned on the stored bytes the registry parser published where
                the record carries them, and otherwise on bytes rebuilt from a
                lossless rendering or text re-encoded as UTF-16LE — a capped
                multi-string from its element list — with the basis stated on
                every hit and counted in its own column of the registry
                coverage table), and{" "}
                <strong>unallocated space</strong> from allocation bitmaps and
                partition-table gaps, <strong>carved objects</strong>,{" "}
                <strong>deleted files</strong>, <strong>file slack</strong>{" "}
                and <strong>whole volumes</strong>{" "}
                (a partition, file system or evidence image scanned end to
                end). Every match carries a <em>surface</em> from a closed
                vocabulary of eight surfaces — <code>file</code>,{" "}
                <code>ads</code>, <code>registry_value</code>,{" "}
                <code>unallocated</code>, <code>carved</code>,{" "}
                <code>deleted_file</code>, <code>volume</code> and{" "}
                <code>slack</code> — because the
                same rule firing on the same bytes means something different
                in each place. <code>file</code> is the narrow case, not the
                default: it is stamped only on an object its producer marked
                neither carved nor deleted nor a stream, and whose type the
                file system (or, for a file added on its own, the ingest path)
                serves as a file — so a hit stamped <code>file</code> is one
                on a live file&apos;s own content. A{" "}
                <code>carved</code> hit is on an object the carver cut out by
                signature — no file system served it, its start and size are
                the carver&apos;s inference, and the hit carries the carving
                signature, offset and validation where the carver wrote them;
                a <code>deleted_file</code> hit is on what a deleted
                file&apos;s record still points at, whose clusters may have
                been reallocated since; a <code>volume</code> hit is a byte
                offset in the image, attributed to no file — it may lie in a
                live file, a deleted file, slack or free space. The Surface
                column shows the word on every match, and the viewer adds a
                warning sentence to a hit in free space, in a stream or in
                slack, so none can be read as a hit in a live file&apos;s own
                content. A{" "}
                <code>slack</code> hit is in the slack region the NTFS, FAT or
                exFAT parser published for a live file — the bytes past its
                logical end, to the end of its last cluster — and names that
                file; the bytes are not the file&apos;s content and may be an
                earlier file&apos;s. Each slack region is scanned on its own, so
                a string that crosses its edge (half in the file, half in the
                slack) is not found there; only a <code>volume</code> scan
                finds it. A slack hit&apos;s offset is into the file system, not
                the evidence: on a partitioned image, add the partition&apos;s
                own offset to reach the image offset — the scanner does not do
                that sum. Slack the parser did not publish is not scanned: an
                all-zero tail; a resident, compressed, encrypted or deleted
                file&apos;s; a tail that could not be read in full; clusters
                allocated past the one holding the file&apos;s last byte; slack
                on any other file system; and every region past the parser&apos;s
                ceiling of 250,000 per volume. No slack hit therefore means
                &ldquo;none in the slack that was published&rdquo;, not
                &ldquo;none in slack&rdquo;: the volume&apos;s{" "}
                <code>slack_space_summary</code> record counts the unread tails,
                the files past the ceiling and the live files whose tail could
                not be located, and marks{" "}
                <code>content_incomplete</code> where the parser could not look.
                Each match also states the Shannon{" "}
                <strong>entropy</strong> of
                the bytes it was measured over (with the byte count), the
                number of pattern hits (0 is a real answer: a rule can be true
                with no string found), and whether the bytes matched were{" "}
                <strong>decoded</strong> — base64 or gzip spans lifted out of
                the object and scanned one level deep — in which case the
                pattern was never stored in that form. Three companion records
                state coverage: one per region scanned (its entropy, whether
                the read reached the declared size, and the decoded spans found
                and scanned), one per hive whose values were scanned (values
                scanned by basis, not scanned by reason, and the byte budget),
                and one per file whose decoded spans were not all scanned,
                emitted only when a ceiling was hit.
              </li>
            </ul>
            <h3>Wireless networks</h3>
            <ul>
              <li>
                <strong>Windows wireless profiles</strong> — the XML the WLAN
                service writes under{" "}
                <code>ProgramData\Microsoft\Wlansvc\Profiles</code>, one file
                per configured network, recognised by its own root element
                rather than by its path. Each becomes a{" "}
                <em>WifiNetwork</em> record — the same record type the macOS
                known-networks parser emits — carrying the SSID in both the
                text and hex forms the file gives, whether the network was
                hidden, the authentication and encryption, and whether the
                machine was set to join it <em>automatically</em>. A wireless
                SSID is geolocatable through the public wardriving databases,
                so a profile list places a laptop at a house, an office and a
                hotel without a single GPS fix.
                <br />
                The pre-shared key is reported <strong>when the file holds it
                in the clear</strong> — which is what an export with{" "}
                <code>key=clear</code> and some deployment tooling leave
                behind. Where it is DPAPI-protected the record names the master
                key it was encrypted under and exactly what recovering it would
                need (the boot key from the SYSTEM hive, the{" "}
                <code>DPAPI_SYSTEM</code> secret from SECURITY, and the
                master-key file under <code>S-1-5-18\User</code>, where
                Windows keeps it);{" "}
                <em>this build does not decrypt it</em>.
                <br />
                <strong>
                  The profile carries no timestamps, so no record here says
                  when the machine joined, or that it ever did
                </strong>
                : it says the machine was configured to.
                <br />
                <strong>When it actually joined is read separately.</strong>{" "}
                The <code>NetworkList</code> registry keys give the first and
                last time the machine was on each network, as a{" "}
                <em>Networks joined</em> record — and those times are written
                in the machine&apos;s local time with no zone in them, so the
                record carries an instant only where the offset could be{" "}
                <em>measured</em> against the profile key&apos;s own
                last-written timestamp, and says so where it could not. The{" "}
                <code>Microsoft-Windows-WLAN-AutoConfig/Operational</code>{" "}
                event channel gives every connection, attempt and failure as
                its own event, with the SSID and the cipher in it; an
                <em> attempt</em> is kept apart from a connection, because a
                report that confused the two would put a machine on a network
                it never joined.
              </li>
            </ul>

            <h3>Network captures</h3>
            <ul>
              <li>
                <strong>Packet captures</strong> — classic <code>pcap</code>{" "}
                (microsecond and nanosecond) and <code>pcapng</code>, recognised
                by their header bytes whether the capture was ingested on its
                own or found as a file inside an image. A file named{" "}
                <code>.pcap</code> that is really pcapng is read as pcapng.
                Ethernet (including VLAN-tagged), raw IP and Linux
                &quot;cooked&quot; frames are decoded to IPv4 / IPv6 and TCP /
                UDP; an interface whose link type Séance does not decode is
                reported as a refusal, by number, rather than skipped in
                silence.
                <br />
                Traffic is reported as <strong>flows</strong>, not packets:{" "}
                <em>one record per conversation</em> (protocol, local and remote
                endpoint, whether the peer is a routable external address,
                packet and byte counts each way, TCP state, first seen and
                duration) with its own table under{" "}
                <strong>Records analysis</strong>, and a timeline event per
                timed flow. Byte counts are what the capture holds; a flow with
                packets the snaplen cut short says so beside the figure. One{" "}
                <em>NetworkCapture</em> record per file carries the format,
                version, interfaces, and the pcapng section provenance (the
                capturing OS, hardware and application) — which is how a capture
                that was merged by a tool such as Mergecap declares itself as a
                derived product rather than an original.
                <br />
                DNS queries and answers seen <em>in the capture</em> are
                recorded with the client and server that exchanged them.
                Nothing is looked up from the examination host, and there is{" "}
                <em>no geolocation</em> of any address. A capture larger than
                the staging limit is read as a prefix and the capture record is
                stamped incomplete with the byte counts, and a capture that was
                recognised but could not be opened leaves a refusal record
                naming the reason, so an empty result and an unreadable file
                never look alike.
              </li>
              <li>
                <strong>What was said, not just who spoke</strong> — every TCP
                conversation is reassembled: the bytes each side sent, in
                order, with every gap stated. A gap is never filled and never
                closed, and only the bytes before the first missing byte are
                offered to a parser, so a message is never read across a hole.
                Where two segments claimed the same offsets with{" "}
                <em>different</em> bytes, the first are held and the
                disagreement is reported rather than resolved — that is how an
                intrusion sensor is evaded.
                <br />
                <strong>HTTP</strong> is read out of those streams by its start
                line, <em>on any port</em> — so a server on 8443 is read and a
                binary protocol on 80 is not. One{" "}
                <em>HttpTransaction</em> record per request-and-response pair
                carries the URL, the headers, and the{" "}
                <strong>decoded form fields</strong> of a posted form and of
                the query string, which is where &quot;what did they
                send&quot; lives. Each message body is handed on as{" "}
                <em>its own file artifact</em> — inflated where it crossed the
                wire gzip&apos;d or deflated — so YARA, the hasher, the
                file-type detector and the search index see it like any other
                file. A response is
                matched to a request by order, which is how HTTP/1.1 answers on
                one connection, and <em>every transaction carries the basis it
                was paired on</em>: one over a stream with a gap, or over a
                conversation whose start the capture does not hold, says its
                pairing may be wrong.
                <br />
                <strong>TLS</strong> gives up its handshake even though its
                contents are encrypted: the server name the client asked for
                (SNI), the version and cipher agreed, the client&apos;s own
                JA3 fingerprint, and — before TLS 1.3 — the certificate the
                server presented, with its subject, issuer, validity window,
                every alternative name and its SHA-256. A timeline event marks
                each end of a certificate&apos;s validity.{" "}
                <strong>
                  From TLS 1.3 the certificate is encrypted and no capture can
                  hold it
                </strong>
                , so a session with none says which of <em>three</em> reasons
                applies — encrypted by TLS 1.3, absent from a cleartext that
                should have held it, or no server hello in the cleartext at all
                so the version is not even known — rather than showing an empty
                chain. No signature is verified,
                no chain is built and no trust store is consulted: a
                certificate is what a host <em>claimed</em> to be.
                <br />
                <strong>ARP</strong> is read for the claims it carries: one{" "}
                <em>ArpBinding</em> record per address listing every hardware
                address that claimed it, with the times. An address claimed by
                two hardware addresses is the signature of ARP cache
                poisoning — and equally of a failover pair, a DHCP lease handed
                on or a replaced network card, so the record states the claims,
                marks the moment the contest began on the timeline, and reaches
                no verdict. ARP does not authenticate: every binding is an
                announcement that was believed because it arrived.
              </li>
            </ul>
          </section>

          <section id="memory-analysis">
            <h2>Memory analysis</h2>
            <p>
              A RAM capture is evidence a disk image cannot give you: what was
              actually <em>running</em>, what it had open, and what it had
              decrypted. Séance reads memory captures directly — no separate
              tool, no export step — and the results land in the same case,
              timeline and search as everything else.
            </p>
            <p>
              Acquisition formats are detected from the file itself: raw (
              <code>dd</code>) dumps, Windows crash dumps in both the 32-bit and
              64-bit page-dump layouts, LiME, AVML, ELF cores, QEMU saved state
              and VMware snapshots. A raw dump has no header at all, so it is
              analysed only when you declare it as memory at ingest. Where a
              capture is short or a region was never written out, Séance records
              the gap rather than filling it: a page that was not acquired is
              never presented as a page of zeros.
            </p>
            <p>
              A Windows <code>hiberfil.sys</code> is identified, its header read
              — whether an image is present, whether the machine has resumed
              from it, the time it was written and the page size — and its
              physical memory <strong>reconstructed</strong>. Séance walks the
              Windows 10/11 x64 restore sets, decompresses each page block (both
              plain Xpress and Xpress-Huffman) and places every recovered page
              at its physical address, so a hibernation file is analysed like
              any other memory image: processes, modules, connections and the
              rest. A block that does not decode, and older (Windows 7 and
              earlier) layouts, are reported as stated gaps rather than guessed
              — a page is the bytes Windows wrote or an honest hole, never a
              guess. The header facts still appear on the capture&rsquo;s
              profile page; they are not timeline events, so the hibernation
              time will not appear in the case timeline.
            </p>
            <p>
              <strong>
                Swapped-out pages are recoverable on Windows and Linux.
              </strong>{" "}
              On Windows, name a capture&apos;s pagefiles in{" "}
              <code>SEANCE_PAGEFILES</code> as <code>index=path</code> entries;
              on Linux, name its swap areas in <code>SEANCE_SWAPFILES</code>{" "}
              with the same grammar (the index is the area&apos;s{" "}
              <code>swp_type</code>, <code>0</code> for the first{" "}
              <code>swapon</code>). The page-table entries that point into them
              are then followed, so a page written out to disk is read rather
              than left as a hole. On Linux the swap entry is decoded and{" "}
              <em>corroborated against the attached area&apos;s bounds</em>{" "}
              before a byte is read — the x86-64 layout changed once (the L1TF
              mitigation) and a single entry does not say which, so both are
              tried and only the one that lands inside a real area&apos;s bounds
              is used; an ambiguous or uncorroborated entry stays a hole rather
              than being guessed. A swap area must be acquired from its block
              device or partition, for the reason set out under &ldquo;Acquiring
              a Linux swap area&rdquo; below. A page whose area was not
              attached, or could not be corroborated, stays missing and is
              reported as missing — never as a page of zeroes.
            </p>
            <h3>Acquiring a Linux swap area</h3>
            <p>
              Copy a swap <em>file</em> through the filesystem —{" "}
              <code>cp /swapfile</code>, or any acquisition that reads it as a
              file — and its body arrives as zeros, with no error and no
              warning, while the swapped memory sits intact on the disk
              underneath. A swap file is created with <code>fallocate</code>,
              which on ext4 reserves blocks but records the extents as{" "}
              <em>unwritten</em>: nothing has been written to them as far as the
              filesystem is concerned, so it answers any read of them with
              zeros. The kernel never writes swapped pages back through the
              filesystem — it writes them straight to those physical blocks
              through the block layer, using an extent map built at{" "}
              <code>swapon</code>, deliberately bypassing the filesystem&apos;s
              bookkeeping. The header page is the one exception:{" "}
              <code>mkswap</code> wrote it through the filesystem, so it copies
              faithfully. Measured on an Ubuntu host with 4.5 GiB of swap in
              use, a mebibyte read through the filesystem held 0 non-zero bytes;
              the same physical blocks read off the block device held 724,505.
            </p>
            <p>
              That is the worst shape a failure can take, because it passes
              inspection: the copy is the right size, identifies as swap,
              carries the UUID that matches it to the host, attaches, and
              corroborates page-table entries against its bounds. So Séance
              samples the body of every swap area at attach time, before it
              reads a page out of it, and will not report a page as recovered
              from a body that read back as nothing but zeros. The
              capture&apos;s profile record states which of three things was
              found — a body holding data, a body that read as zeros, or a body
              not one of whose sampled pages could be read at all — and carries
              the same explanation and remedy as this page.
            </p>
            <p>
              <strong>The remedy is to acquire from the block device.</strong> A
              swap <em>partition</em> has no such problem: it <em>is</em> the
              block device. For a swap file, <code>filefrag -v /swapfile</code>{" "}
              names its physical extents; read those from the underlying block
              device and reassemble them at their logical offsets. Do it while
              the machine is still in front of you. A profile record is read
              long after the acquisition, and there is nothing in a zero-filled
              copy to recover the body from afterwards.
            </p>
            <p>
              <strong>What the sample cannot tell you.</strong> Zeros are an
              observation, not a diagnosis. An area copied through the
              filesystem, an area that was <code>swapon</code>-ed and never
              written to, and a lightly used area whose sampled pages happen to
              be ones nothing was ever written to all read back the same way,
              and these bytes alone cannot tell the three apart. Séance
              therefore states what it read and the likeliest cause separately,
              and never concludes from the bytes alone that an acquisition was
              faulty — that is a question to put to the acquisition notes, not a
              finding to report. A body whose sampled pages could not be read at
              all is a different finding again, and is recorded as what it is:
              places were chosen across the body and not one of them came back,
              so nothing is concluded about what the area holds. Check the
              copy&apos;s length against the size the header declares.
            </p>
            <h3>A capture that produced nothing</h3>
            <p>
              A memory image that yielded no records at all was usually never
              declared. A live acquisition arrives headerless — the familiar{" "}
              <code>.mem</code>, <code>.vmem</code> or <code>.ram</code> — and a
              headerless file carries no magic bytes, so nothing in it says
              &ldquo;this is physical memory&rdquo;. Séance will not read that
              off the file name, because a name is not evidence: were an
              extension enough, every unidentified file in the case would carry
              a memory record asserting an image that is not there. An
              undeclared capture is therefore ingested as ordinary evidence, no
              memory record is written, and every memory stage reports that it
              did not run — which is indistinguishable from a case that never
              had a capture in it.
            </p>
            <p>
              Ingest it again with the declaration made. In the ingest dialog,
              tick{" "}
              <strong>
                I declare this source to be a capture of physical memory
              </strong>{" "}
              and leave the format on <strong>Raw / dd</strong> for a headerless
              capture, or name the acquisition format when the file has a
              header. From the command line the same two declarations are{" "}
              <code>--memory-image</code> for a headerless capture and{" "}
              <code>--memory-image-format</code> to name one; the names accepted
              are <code>raw</code>, <code>dd</code>, <code>lime</code>,{" "}
              <code>avml</code>, <code>elf</code>, <code>core</code>,{" "}
              <code>qemu</code>, <code>vmware</code>, <code>vmem</code>,{" "}
              <code>crash32</code>, <code>crash64</code> and{" "}
              <code>hibernation</code>. A name the analysis cannot parse is
              refused where you make the declaration rather than dropped, so a
              declaration that will not be honoured is never mistaken for one
              that was. Both travel with the source as the{" "}
              <code>memory_image</code> and <code>memory_image_format</code>{" "}
              metadata keys, and a file named <code>.mem</code>,{" "}
              <code>.vmem</code> or <code>.ram</code> that reaches the memory
              pipeline without them is noted in the run log, naming the keys
              that would have declared it.
            </p>
            <h3>Which operating systems</h3>
            <p>
              <strong>Windows</strong> is covered from XP through 11, including
              the server builds in between. <strong>Linux</strong> is covered
              wherever a matching symbol table is available: Séance finds the
              kernel banner in the capture, derives the page-table root from it,
              and then lists processes, loaded kernel modules, per-process
              environments and recoverable shell history. Each Linux stage
              reports whether its walk completed — a process list that stopped
              early is never presented as the whole list.
            </p>
            <p>
              The Linux <strong>open files</strong>, <strong>process maps</strong>{" "}
              and <strong>mounts</strong> stages publish paths, and every path
              carries its own <em>scope</em>. Where the build&apos;s symbols
              declare the members the walk needs, a path is reconstructed the
              way the kernel does it — climbing to the mount root, stepping
              across each mount point into the parent mount, and stopping at
              the process&apos;s own root or the global root — and the row says{" "}
              <em>mount crossing</em> with how many mounts it crossed and where
              it ended. Where they do not, or a pointer on the way would not
              read, the row says <em>dentry tree relative</em>: the path was
              reconstructed within one mount only and is not an absolute path
              on the machine. A socket, pipe or anonymous inode is rendered as
              the kernel renders it (<code>socket:[ino]</code>,{" "}
              <code>pipe:[ino]</code>) and marked <em>pseudo</em> — not a path
              in any mount. Each stage&apos;s record states which walk the build
              allowed, and the viewers show the scope beside every path,
              because a relative path read as an absolute one names the wrong
              file.
            </p>
            <p>
              <strong>macOS</strong> is covered by four stages and a warning.
              Séance finds the Darwin kernel banner in the capture, recovers the
              kernel slide and the page-table root from it, and then lists the
              BSD process table, the Mach task queue, the difference between
              those two listings, and the loaded kernel extensions. That is the
              whole of it: there is no network state, no per-process handle or
              module table and no credential store for a Mac capture, and the
              coverage table names each of those as a stage that did not run
              rather than showing you an empty page.
            </p>
            <p>
              The warning is this.{" "}
              <strong>
                Nothing the macOS analysis produces has ever been checked
                against a capture of a real Mac.
              </strong>{" "}
              It was written from Apple&apos;s published kernel symbol
              definitions, and it is bounded by the symbol packs that come with
              it: 64-bit kernels from OS X 10.8 to macOS 10.15.4. macOS 11 and
              later, every Apple-silicon Mac, and the old 32-bit kernels have no
              symbols here; where Séance finds a Darwin kernel it cannot match,
              it records the kernel build whose symbols it wanted rather than
              guessing at the layout of anything. Every macOS record therefore
              states on its face that it has never been validated, and the
              coverage table repeats that beside each stage that ran, so treat
              what you find there as a lead to confirm with a second tool rather
              than as a finding to stand behind. Earlier releases withheld this
              analysis altogether for the same reason. That was worse: a Mac
              capture then produced silence, and silence in a case file is
              indistinguishable from a machine that was running nothing.
            </p>
            <Shot
              id="memory-processes"
              caption="Memory: the process list recovered from a capture, with each row graded by how it was found and every absent value naming its own reason. The count is stated as a floor, not a total."
            />
            <Shot
              id="memory-overview"
              caption="Memory overview: which stages ran against this capture, and which did not."
            />
            <Shot
              id="memory-image-profile"
              caption="Image profile: the directory table base, kernel load address and build recovered from the capture's own bytes, each carrying how it was established."
            />
            <Shot
              id="memory-handles"
              caption="Handles: every open object per process, resolved to its type and name — including the files a process had open at the moment of capture."
            />
            <Shot
              id="memory-system"
              caption="Services and hives: the service table and the registry hives found resident in memory."
            />
            <Shot
              id="memory-credentials"
              caption="Credential stores: the accounts located in the capture. The record states plainly that the material was inventoried and not decrypted, so nothing here claims to be a password."
            />
            <Shot
              id="memory-network"
              caption="A stage that could not run says so, and says why. The failure is reported as a reason rather than as an empty list, because an empty list would read as an absence of connections."
            />
            <Shot
              id="memory-findings"
              caption="Findings: what the analysis concluded across the capture, with each finding traceable to the stage that produced it."
            />
            <h3>How a capture is profiled</h3>
            <p>
              Nothing about a memory image is in its header, because it has
              none. Before a single process can be listed, three facts have to
              be established from the bytes: the directory table base that
              translates virtual addresses, the address the kernel is loaded at,
              and a symbol table matching the exact kernel build that was
              running. Séance discovers all three and, crucially,{" "}
              <strong>records how it learned each one</strong> — read from a
              kernel structure and confirmed, derived by scanning and then
              validated, or scanned with no independent check available. That
              grading travels with every finding, so an examiner can see what
              the result rests on instead of being asked to trust it.
            </p>
            <p>
              Symbols are matched on the kernel's PDB GUID and age, never on a
              close name. If the matching symbol file is not present, Séance
              says so and names the GUID you need to fetch — it will not
              substitute a near-enough symbol table, because wrong symbols do
              not fail, they produce a complete and confident wrong answer.
            </p>
            <h3>Windows analysis</h3>
            <ul>
              <li>
                <strong>Processes</strong> — the active process list, the
                parent/child tree, and full command lines read from each
                process's own address space. Parent edges say how they were
                established, because process IDs are reissued and a match on ID
                alone is a guess.
              </li>
              <li>
                <strong>Hidden and terminated processes</strong> — pool scanning
                finds <code>_EPROCESS</code> structures still resident in memory
                that the linked list no longer points at: processes unlinked to
                hide them, and processes that have already exited. A
                cross-referenced view shows which listing found each process, so
                a discrepancy reads at a glance rather than requiring you to
                diff two tables.
              </li>
              <li>
                <strong>Injected and hollowed code</strong> — memory regions
                that are writable and executable but backed by no file on disk,
                with the bytes shown so you can judge them; and processes whose
                in-memory image no longer matches the file they claim to come
                from — including a process that has rewritten, in its own
                memory, the path it publishes for itself, which is compared
                against the path the kernel recorded when it created the
                process and against the file its image is actually mapped from.
                Séance reports the signals and the evidence for each. It does
                not pronounce on maliciousness — a memory image cannot
                establish that, and the conclusion is yours.
              </li>
              <li>
                <strong>Threads that started in injected memory</strong> —
                every live thread&rsquo;s two start addresses placed in its own
                process&rsquo;s memory map, and reported on the stage&rsquo;s
                record (served at <code>/memory/suspicious-threads</code>) when
                the region there is
                backed by no file, was not mapped the way every loaded image is,
                or is another program&rsquo;s executable. A start in private
                memory is a place to look, not a verdict: a JIT compiler runs
                legitimately from private executable memory. An empty list says
                only that the processes judged had no such start; the record
                names every process judged, every one out of scope (a null
                PEB, as System and Registry have, or already exited; a process
                set aside this way is not looked at, not cleared) and every one
                that could not be read, and counts starts it could not place. A
                kernel start on a thread the kernel flags as a kernel thread is
                counted, not judged here; a kernel start on any other thread is
                judged by no part of Séance, and the record says it is
                incomplete rather than calling it a kernel thread. On
                Windows XP a thread&rsquo;s start field can hold a message
                number instead of an address; the thread&rsquo;s own flag says
                which, and a message number is never judged as an address.
              </li>
              <li>
                <strong>Loaded modules</strong> — DLLs per process and drivers
                in the kernel, cross-referenced against the three loader lists
                so a module that has been unlinked from one of them is surfaced.
              </li>
              <li>
                <strong>Network state</strong> — TCP endpoints, listeners and
                UDP sockets recovered from memory, with the owning process, both
                addresses and both ports.
              </li>
              <li>
                <strong>Handles, tokens and services</strong> — what each
                process had open (files, keys, mutexes, pipes), the privileges
                and security identifiers on its token, and the services
                registered on the machine.
              </li>
              <li>
                <strong>The device tree</strong> — which driver owns which
                device, and what is attached on top of each. The attachment is
                the point: Windows lets a driver put its own device above
                another&rsquo;s so every request passes through it first, which
                is how a volume encryptor and an antivirus work and how a
                rootkit intercepts disk or keyboard input without changing any
                code. An attachment is <em>not</em> a finding on its own, and a
                device with no name is shown as unnamed rather than as one whose
                name could not be read — most devices legitimately have none.
              </li>
              <li>
                <strong>Job objects</strong> — which processes were confined to
                a job, which is how a sandbox, a packaged app and a container
                show up in memory. One entry per job object, naming every
                process that pointed at it, with the kernel&rsquo;s own count of
                the job&rsquo;s processes shown beside the list this build
                walked: where the two differ, the job is being torn down or has
                had a member unlinked, and you see both numbers.
              </li>
              <li>
                <strong>Registry in memory</strong> — hives loaded in kernel
                memory, including the volatile hives that exist only in RAM and
                appear in no disk image at all.
              </li>
              <li>
                <strong>Kernel-side tamper checks</strong> — the drivers the
                kernel has unloaded (the last fifty, with the range each
                occupied), every processor&rsquo;s timer table with the routine
                each timer would call, the threads the scheduler is holding
                suspended, the threads carrying hardware debug registers, and
                kernel threads that start outside every loaded driver, and
                whether any process has disabled its own event logging by
                patching the four ETW write functions in its copy of
                <code>ntdll.dll</code>, and whether the part of
                <code>lsass.exe</code> that checks domain passwords has been
                patched to accept one the attacker chose. These are
                listings with signals beside them, not verdicts: a routine or a
                thread start that lands in no loaded module is reported as a
                lead, and a lead that falls inside the range of a driver the
                kernel unloaded is shown with both sides, because that range was
                freed when the driver went and may have been reused since.
                A timer with the shape of PatchGuard&rsquo;s own &mdash; a
                misaligned timer, a routine in no loaded module and a
                non-canonical context, all three &mdash; is listed as
                PatchGuard-shaped and not raised as a lead; it stays on the
                record, and its routine is still checked against the drivers
                the kernel unloaded, because a rootkit could imitate that shape.
                Suspension is not a finding at all — the platform suspends
                apps, debuggers suspend — so it is listed and labelled as such.
                The ETW check needs no stored copy of a clean
                <code>ntdll</code>: it compares each process&rsquo;s copy
                against what the majority of processes on that same machine
                hold, so a patch in one process stands out without any
                reference bytes at all. A process whose
                <code>ntdll</code> pages were not captured is reported as
                <em>not assessed</em>, never as unpatched. The
                <code>lsass</code> check is the one to read most carefully: it
                runs one of the two tests for that attack and says on every
                result that the second is not run, because the structure it
                would read is published by nobody. A clean result there means
                one test found nothing, not that the machine is clean — and the
                screen says so rather than leaving you to know it. What these
                checks find also reaches <strong>Findings</strong> as ranked
                leads, each with the values it rests on, what it does not
                establish, and what the same check said about a machine with
                nothing wrong with it.
              </li>
              <li>
                <strong>Your own YARA rules, over memory</strong> — point
                <code>SEANCE_YARA_RULES</code> at a rule file or directory and
                the rules are run over every process&rsquo;s own address space,
                through the page tables recovered from the capture, and over the
                kernel&rsquo;s. Each match is shown with the allocation that
                held it: its range, its protection, whether it is private
                memory, and the file mapped into it if any. That is the part
                that makes a match usable — the same bytes in private,
                executable, unbacked memory and in the read-only section of a
                mapped system DLL are different findings. S&eacute;ance ships{' '}
                <em>no</em> rules of its own, so with nothing named this stage
                reports that it <em>did not run</em> rather than showing you an
                empty match list, which would read exactly like a rule set that
                ran and found nothing. Two things are stated on every result
                and are worth reading: a rule&rsquo;s condition is evaluated
                over one <em>chunk</em> of the address space at a time rather
                than over a file, so a condition joining two strings only fires
                where both fall in the same chunk and <code>filesize</code>
                means nothing here; and a process whose allocation tree would
                not walk is listed as not searched, with the reason, rather than
                swept as one flat range and reported with matches nothing can
                attribute.
              </li>
              <li>
                <strong>Kernel structures</strong> &mdash; eight further stages
                read the kernel&apos;s own tables, each as one record under{" "}
                <strong>Records analysis</strong> whose rows are the table&apos;s
                entries and whose head is the stage&apos;s own statement. A
                check the build&apos;s symbols could not make is shown as{" "}
                <em>not made</em>, never as passed. <em>Processor blocks</em>:
                every processor the <code>KiProcessorBlock</code> array names,
                each held to three self-checks (its <code>Self</code> pointer,
                its PRCB pointer, its number against the slot), with the thread
                and process it was running at capture; the kernel&apos;s own
                processor count is compared with the array and never preferred
                to it. <em>Big-page pool</em>: every allocation of a page or
                more by tag and size, freed slots told from live ones by a
                word, per-tag totals exact even where the published entries
                are capped (the cap is stated), and the kernel&apos;s in-use
                counter compared with the walk. <em>Kernel virtual-address
                map</em>: the system regions as the kernel assigns them, named
                from the build&apos;s own enumeration (a region the type map
                does not name says so), with the kernel&apos;s load address
                placed in one as the check that the map was read right.{" "}
                <em>Hive cell routines</em>: each loaded hive&apos;s{" "}
                <code>GetCellRoutine</code> and <code>ReleaseCellRoutine</code>{" "}
                placed at a named kernel function, inside another module, or in
                no loaded module &mdash; the last claimed only when the module
                list was walked whole. <em>Image version resources</em>: file
                and product version, company and original file name of every
                kernel module and every process&apos;s loaded images, read from
                the bytes in memory; an image whose headers could not be read,
                or whose resource section is marked discardable (and so was not
                read &mdash; the flag decides, and the bytes there are not
                checked), is reported as such and never as an image with no
                version.{" "}
                <em>Boot sectors</em>: every 512-byte-aligned sector of
                physical memory ending in <code>55 AA</code>, held to six checks
                each reported by name; a well-formed MBR or GPT protective MBR
                is a partition table the machine held in memory &mdash; a disk
                it read or an image it handled, and the bytes do not say
                which; a sector failing the checks is listed with the checks it
                failed and nothing more is claimed of it. <em>Scheduled
                tasks</em>: every task in the in-memory SOFTWARE hive&apos;s
                TaskCache with its path, author, actions decoded from the
                Actions blob, and creation, last-run time and last result from
                DynamicInfo, and when it fires from the
                Triggers blob &mdash; each trigger&apos;s kind (time, boot,
                logon, idle, registration, session change, event with its
                XPath subscription, WNF state change), start, repetition and
                whether it is enabled. A start the task stored as localized is
                shown as local wall-clock
                time, never UTC. A trigger kind the decoder does not know, or a
                record that runs past the blob, stops that task&apos;s decode
                and the row says where. <em>TrueCrypt/VeraCrypt</em>:
                whether either driver is on the loaded-module list and, when it
                is, a sweep of the non-paged pool for verified AES, Serpent and
                Twofish key schedules by address, size and key hash (a Twofish
                key is recovered from its subkeys, since the key itself is not
                stored); two adjacent 256-bit schedules of one cipher are
                reported as a <em>POSSIBLE XTS pair</em> and
                labelled an inference. Where the driver&apos;s own key
                container has one of the layouts read from the VeraCrypt captures
                (an AES, Serpent, Twofish, Camellia or Kuznyechik volume and
                ten cascades of them, on both 1.26.29 and 1.25.9; on 1.22, 1.23, 1.23-Hotfix-2, 1.24, 1.24-Hotfix1, 1.24-Update2, 1.24-Update4, 1.24-Update5, 1.24-Update6, 1.24-Update7, 1.26.7, 1.26.14, 1.26.15, 1.26.18, 1.26.20, 1.26.24 and 1.26.28 Beta4 the five ciphers and two cascades (from 1.26.7 on they are numbered as 1.26.29 numbers them, on the older container layout); on VeraCrypt 1.0e to 1.21, 1.25, 1.25.4 and 1.25.7 the ciphers and cascades each of those versions offers; and
                on every TrueCrypt release from 6.0 to 7.2 an AES, Serpent or Twofish volume and five cascades), the row also gives its
                cipher id, mode id, each cipher&apos;s primary and secondary
                (tweak) key hash and which layout it matched (only the ids
                those captures explain are named); any other layout or id is
                not stated, and a TrueCrypt or VeraCrypt build not named here is not recognised. Other AES-256 schedules in the pool (a BitLocker
                volume&apos;s, say) are reported beside VeraCrypt&apos;s, and the
                positive path has been validated on captures with mounted
                VeraCrypt AES, Serpent, Twofish, Camellia, Kuznyechik and cascade
                volumes (forty-eight product versions, VeraCrypt 1.0e to 1.26.30 and TrueCrypt 6.0 to 7.2, in the builds named above; every capture is a Windows 11 build 26200 guest except three on Windows Server 2022 build 20348.587 (VeraCrypt 1.26.14, 1.26.18 and 1.26.29), two on Windows Server 2019 build 17763 (VeraCrypt 1.26.29 and 1.26.30) and one on Windows 10 build 14393 (VeraCrypt 1.25.9), where the pool region the sweep reads is the one that holds the loader entries, because the virtual-address map names a different region non-paged pool), which the record states.{" "}
                <em>Console history</em>: the commands typed at a console,
                read from the console host&apos;s (<code>conhost.exe</code> or{" "}
                <code>OpenConsole.exe</code>) heap in the order stored. The
                layout is decoded on <strong>one build</strong> of the host
                (Windows 11 26200.6584); on any other build the stage finds
                nothing, and nothing found is <em>not</em> evidence that
                nothing was typed &mdash; the record says so for every host it
                examined. It does not read what a command printed, a line
                still being edited, or a history whose list is empty, and a
                host running under another image name is not examined (the
                console clients it saw are listed so a client with no host
                shows as a gap).
              </li>
              <li>
                <strong>Or a regular expression</strong> &mdash; set{' '}
                <code>SEANCE_MEMORY_REGEX</code> to one pattern and it searches
                the same two address spaces, each match carrying the same
                allocation detail. One pattern rather than a list, because no
                character can separate a list of regular expressions without
                cutting one of them in half; several go in as <code>(a|b)</code>.
                Two things about it are on every result and are not what{' '}
                <code>grep</code> would give you: the match is against{' '}
                <em>raw bytes</em> and knows nothing of Unicode, so a pattern
                typed in ASCII does not find the UTF-16 that most strings in a
                Windows process are actually stored as; and a regular
                expression has no longest match, so one spanning a chunk
                boundary is not guaranteed to be found.
              </li>
              <li>
                <strong>And over the capture itself</strong> &mdash; the same
                rules and patterns also run over an image&rsquo;s <em>own</em>
                address space, which is the only way to search a reconstructed
                hibernation file or a swap area: neither has page tables to plan
                from, and a swap slot belongs to no process until something maps
                it. Those matches carry an address in that image and say plainly
                that they carry no process and no allocation, and each record
                says what an address in it means for that format &mdash; for a
                hibernation file, a physical address in the reconstruction and{' '}
                <em>not</em> an offset in <code>hiberfil.sys</code>, whose pages
                are compressed.
              </li>
            </ul>
            <h3>The Memory workspace</h3>
            <p>
              <strong>Memory</strong> in the sidebar opens a workspace of its
              own. A case can hold more than one RAM capture, so the capture in
              view is part of the address (<code>?image=…</code>) and is carried
              into every lens: a laptop capture and a server capture never
              blend, and any view can be copied into a report as a link that
              reopens exactly what you were looking at. A case with no RAM
              capture opens the same workspace and says so.
            </p>
            <ul>
              <li>
                <strong>Overview</strong> — triage. Which analysis stages ran
                and which did not, counts that link straight into the lens they
                came from, and the tampering signals ranked by severity.
              </li>
              <li>
                <strong>Image</strong> — what the analysis rests on: the capture
                and what the container declared about it, the directory table
                base and kernel base with the evidence grade behind each, the
                kernel build and symbol state, and a table of every analysis
                stage with its outcome.
              </li>
              <li>
                <strong>Processes</strong> — the tree, with each row carrying
                its own reliability and a mark per enumeration strategy.
                Selecting a process opens an inspector with its DLLs, its
                handles and its memory map.
              </li>
              <li>
                <strong>Network</strong>, <strong>Services &amp; hives</strong>,{" "}
                <strong>Credential stores</strong> and <strong>Findings</strong>{" "}
                — one lens each. <strong>Handles</strong> is read one process at
                a time, because that is how the analysis produces it; picking a
                process loads its whole table from the server rather than a
                sample of a merged list.
              </li>
            </ul>
            <p>
              Two memory stages search for nothing of their own, because Séance
              does not choose what you are looking for. The{" "}
              <strong>pattern scan</strong> runs your YARA rules or one regular
              expression over each process&apos;s address space and the
              kernel&apos;s; <strong>strings over memory</strong> takes the
              output of your own <code>strings -t d</code> over the raw capture
              and answers the question an offset on its own cannot — whose
              memory those bytes were in. Each physical offset becomes a{" "}
              <em>MemoryStringsMap</em> answer naming every address space whose
              page tables reach that frame and the virtual address it has in
              each. With nothing named, both stages report that they{" "}
              <strong>did not run</strong>, which is not a statement about what
              the capture holds.
            </p>
            <p>
              Three things that route deliberately will not do. It will not call
              an offset <em>free memory</em>: where no walked address space maps
              it the row says only that, and names every space whose tables
              could not be read whole — on a real Windows capture that is most
              of them, because every address space has suppressed page tables
              and trimmed shared pages in it. It will not show one owner where
              there were two: the count of owners is beside the list whether or
              not the list was cut. And it will not guess the radix your{" "}
              <code>strings</code> run used — a hexadecimal file read as decimal
              rejects every line with a letter in it and reads the rest as
              frames gigabytes away, so you state it and the record reports what
              proportion of the file was rejected.
            </p>
            <h3>Reading uncertainty in the memory views</h3>
            <p>
              Every memory-derived row carries a confidence chip in its first
              column, before the data. It states the weakest of four things —
              how the row was enumerated, how many strategies corroborate it,
              whether every byte behind it could be read, and whether the symbol
              table was proved. Opening the chip explains each one for that row.
            </p>
            <ul>
              <li>
                <strong>linked</strong> — walked from a kernel list, complete
                reads, verified symbols.
              </li>
              <li>
                <strong>scanned</strong> — found by pool scanning rather than a
                list walk. It may belong to a terminated object whose memory has
                been freed and partly reused.
              </li>
              <li>
                <strong>partial</strong> — a range of bytes was missing, or a
                cap stopped enumeration. Counts on such a view are a floor.
              </li>
              <li>
                <strong>approximate</strong> — decoded with a symbol table that
                failed nothing but proved nothing.
              </li>
              <li>
                <strong>unreliable</strong> — carved with no corroboration, no
                admitted symbol table, or a row that arrived carrying no
                confidence information at all.
              </li>
            </ul>
            <p>
              Three distinctions are held to throughout, because collapsing any
              of them would let an incomplete analysis read as a complete one. A
              stage that <em>did not run</em> never renders as a stage that
              found nothing: it shows as a load or stage error, and no empty
              table is drawn under it. A list that was{" "}
              <em>cut short by a cap</em> says so above the rows, so its counts
              read as a floor. And an enumeration strategy that failed marks its
              column <em>unknown</em>, never &ldquo;not seen&rdquo; — a crashed
              scanner is not evidence that a process is hidden.
            </p>
            <p>
              When the analysis cannot establish a profile, the workspace shows
              a screen rather than an empty table: what was identified from the
              capture, the exact PDB name, GUID and age to fetch when the
              failure names one, the directories that were searched, and the
              work that still runs without symbols. If the failure names no
              symbol identity, the screen says so instead of implying symbols
              were the cause.
            </p>
            <p>
              Findings state both sides. Each one gives the observation and the
              innocent explanation that would produce the same observation, and
              a detector that offers no second string is flagged on the card.
            </p>
            <p>
              The <strong>Credential stores</strong> lens starts as an
              inventory. Séance locates the credential stores held in RAM — the
              SAM and SECURITY hives, the LSA secrets, the cached domain logons
              — and lists what is in them: which stores were resident, which
              local accounts exist and under which relative identifiers, what
              the secrets are <em>called</em>, how many cached logons are
              present. Where the SYSTEM and SAM hives are <em>both</em> resident
              it goes further: the boot key is recovered and the local accounts'
              NT hashes are decrypted out of the hives, one record per account,
              and LSA secrets and cached domain logons are decrypted the same
              way. The inventory states how many values were recovered and
              whether the boot key was, so a capture where nothing decrypted
              says that rather than looking like one nobody asked.
            </p>
            <p>
              A recovered value is <strong>masked wherever it is listed</strong>
              . Revealing one is a server round trip that writes an audit event
              naming who asked before it answers, and a reveal that cannot be
              recorded does not happen. Search is the one place the value is
              used without being shown: a hash you already hold finds the record
              that carries it, which is how the same local-administrator
              password is found across a fleet, and the result says a value was
              withheld instead of printing it back.
            </p>
            <p>
              Results are validated against Volatility 3 on public reference
              images for both 32-bit and 64-bit Windows: the same processes, at
              the same addresses. Where Séance deliberately differs it is
              because the reference is wrong — its virtual-address arithmetic
              mislocates a memory range when one field carries into another —
              and the difference is documented and tested rather than left to
              chance.
            </p>
            <p>
              Linux and macOS captures are read and their address spaces
              decoded. The Linux tier walks the task list (processes,
              credentials, and each process's <strong>capability sets</strong> —{" "}
              <code>cap_effective</code>
              and its siblings, decoded to names like <code>CAP_SYS_ADMIN</code>
              ), kernel modules, and bash history/environment. The macOS tier
              walks the BSD process table, the Mach task queue and the loaded
              kernel extensions, and every result it produces carries the
              never-validated warning described above. Séance says which stage
              it reached for a given image rather than presenting an unanalysed
              capture as one that yielded nothing.
            </p>
          </section>

          <section id="analysis-records">
            <h2>Records analysis</h2>
            <p>
              The <strong>Analysis</strong> view groups parsed records by type,
              one card per type with a record count. Opening a type loads a
              viewer tailored to its fields — for example a conversation view
              for messaging records — falling back to a generic key/value table
              when no specialised viewer applies.
            </p>
            <p>
              Forensic record types (Windows event logs, prefetch, shimcache,
              amcache, LNK shortcuts, shellbags, recycle bin, browser history,
              file-signature analysis, USB devices, the{" "}
              <strong>USN journal</strong> and <strong>NTFS $LogFile</strong>{" "}
              transactions, browser{" "}
              <strong>cookies, saved logins, autofill</strong> and restored
              tabs, <strong>YARA matches</strong>, and Linux{" "}
              <strong>login sessions, failed logins</strong> and boot records)
              open in a <strong>rich analytics viewer</strong>: colour-coded
              severity or category tiles, a volume-over-time histogram, top-N
              frequency bars, and a filterable, sortable table. Tiles and bars
              act as one-click cross-filters, and security-relevant rows (a
              cleared audit log, a failed logon, an extension-content mismatch)
              are flagged. The viewer loads records incrementally with{" "}
              <strong>Load more</strong>, so a large dataset never fetches
              whole.
            </p>
            <p>
              Recovered <strong>SQLite rows</strong> open in a per-table grid
              with in-place power tools: reinterpret any column as a{" "}
              <strong>timestamp</strong> (Unix seconds/milliseconds, WebKit,
              Cocoa/Mac, Windows FILETIME, or ISO) to turn a raw integer into a
              date without leaving the grid, filter per column, and hide/show
              columns.
            </p>
            <p>
              <strong>SQL query</strong>, above the grid, opens a read-only SQL
              editor over the selected database. One statement at a time
              (Ctrl+Enter or Cmd+Enter runs it); it is sent to the server,
              which copies the database file&apos;s bytes and, where the source
              can reach one, its <code>-wal</code> sibling into a temporary
              file — the same staging every SQLite parser in Séance uses — and
              opens that copy read-only. SQLite never opens the evidence file,
              and nothing is written to it. Three gates stand in front of the
              statement, in this order. First, the server refuses anything
              that is not a single <code>SELECT</code> or <code>WITH</code>{" "}
              statement: the first keyword after any leading comments must be
              one of those two, checked before SQLite sees it — so every{" "}
              <code>PRAGMA</code> (<code>PRAGMA table_info</code> included),{" "}
              <code>EXPLAIN</code>, <code>ATTACH</code>, transaction control
              and every write are refused at that gate, whether or not the
              table they name exists. Second, the copy is opened under an
              authorizer that admits only reads (read, select, function,
              recursive) and denies every other action — it denies every{" "}
              <code>PRAGMA</code>, read-only or not — so anything a{" "}
              <code>WITH</code> could smuggle past the keyword is refused when
              the statement is prepared. Third, the prepared statement must
              be one SQLite itself reports as read-only. Text after the first
              statement is refused unless it is only a comment; host
              parameters (<code>?</code>, <code>:name</code>) are not
              supported. A copy is
              at most 512 MiB — a larger database is staged as a prefix and the
              result says so. The statement runs under a timeout of at most 10
              seconds and a row ceiling: the editor asks for{" "}
              {SQLITE_QUERY_ROW_CAP.toLocaleString()} rows (the server never
              returns more than 10,000), and every result states the cap that
              applied, whether more rows existed past it, the run time and the
              timeout, and whether the server attested that the run was
              read-only over the staged copy — a result without that
              attestation is shown but not described as one. A BLOB cell is
              shown as its size, never inlined; an integer too large for a
              browser number arrives as text. If the staged copy was not the
              whole database, or its write-ahead log was not staged in full,
              the result says so and why. Every run — answered or refused — is
              written to the case&apos;s audit log with the statement and its
              outcome. Result
              columns take the same <strong>interpret as</strong> timestamp
              formats as the grid. The <strong>Template</strong> picker holds{" "}
              {SQLITE_QUERY_TEMPLATES.length} statements, one per artifact
              database the parsers already read (Chrome/Chromium History,
              Cookies and Web Data; Firefox places; iOS sms.db / macOS chat.db;
              Android mmssms.db and the contacts2.db call log; Skype; Kik;
              Windows ActivitiesCache.db; and the schema of any database), each
              proven against a real sample file the template names. A template
              whose tables the selected database lacks is listed but disabled,
              with the missing tables named; when the database's summary
              carried no table list the check is skipped and the picker says
              so. <strong>Query history</strong> keeps the last{" "}
              {SQLITE_HISTORY_MAX} statements per case, newest first, failures
              included with their error, in this browser only — it is not part
              of the case record and other examiners do not see it. A database
              whose summary carries no artifact id has no staged copy to query
              and the editor says so.
            </p>
            <p>
              <strong>Export all as CSV</strong>, at the head of a record type,
              downloads every record of that type in the case (or, when the
              view is scoped to one acquisition, of that acquisition) as a CSV
              of the current run's records. It is the whole type, not the rows a
              viewer's own search or sort has narrowed to, and the file's own
              preamble says so. The export is bounded to 100,000 rows; when
              that ceiling binds the file carries a notice row saying how many
              of how many it holds. Conversation and other aggregate viewers,
              which load their own records, do not offer it.
            </p>
          </section>

          <section id="filters">
            <h2>Filters</h2>
            <p>
              The <strong>Filters</strong> view manages reusable filter
              conditions over the evidence. Each is a field / operator / value
              test (or a compound of them), evaluated against artifact type and
              metadata.
            </p>
            <ul>
              <li>
                Predefined filters ship ready to use; you can also build a
                condition from the form (for example{" "}
                <code>extension in exe, dll</code> or{" "}
                <code>deleted equals true</code>).
              </li>
              <li>
                <strong>Apply</strong> runs a filter server-side and lists the
                matching artifacts.
              </li>
              <li>
                <strong>Import</strong> / <strong>Export</strong> a filter as
                JSON to share it between cases and examiners.
              </li>
            </ul>
          </section>

          <section id="visualisers">
            <h2>Visualisers</h2>
            <p>
              Structural visualisers appear as extra tabs on an artifact, keyed
              to what the artifact is. They read the same evidence the other
              tabs do — nothing is recomputed or altered.
            </p>
            <ul>
              <li>
                <strong>Disk Map</strong> (disk image / container): a
                proportional bar of partitions, unallocated gaps, and
                filesystems. Click a region to open it.
              </li>
              <li>
                <strong>Allocation Map</strong> (filesystem): a
                cluster-allocation grid, brightest where most heavily allocated
                — the modern equivalent of the old defragmenter view.
              </li>
              <li>
                <strong>Files</strong> (filesystem): a lazy, expand/collapse
                folder tree; each level is fetched on demand.
              </li>
              <li>
                <strong>Treemap</strong> (filesystem): an interactive drill-down
                size map where each tile's area is its bytes. Directory sizes
                are aggregated on the server one level at a time, so even a
                filesystem with millions of files never loads whole.
              </li>
              <li>
                <strong>Entropy</strong> (any readable file): Shannon entropy
                plotted across the file. Flat regions near 8 bits are compressed
                or encrypted; low regions are text or zero-fill. The plot reads
                at most the first 8&nbsp;MiB and says so beneath itself when the
                file is larger, because a region past the end of what was read
                is not a low-entropy region. The single entropy figure in{" "}
                <strong>File Signature Analysis</strong> is measured over at
                most the first 192&nbsp;KiB and is marked <em>sampled</em>, with
                the byte count, whenever that is less than the whole file — a
                prefix does not establish whether the rest of a file is
                encrypted.
              </li>
              <li>
                <strong>Layout</strong> (fragmented files): the file's data-run
                map as a strip of on-disk extents. Sparse runs are hatched, and
                a fragmented file is flagged because contiguous recovery of it
                would be byte-wrong.
              </li>
            </ul>
            <p>
              Case-level visualisers live in the sidebar. The{" "}
              <strong>Timeline</strong> adds a <strong>Heatmap</strong> view — a
              7&times;24 weekday-by-hour grid of activity (UTC) that reveals
              working hours, overnight automation, and quiet periods at a
              glance.
            </p>
          </section>

          <section id="execution-comms">
            <h2>Execution and communications</h2>
            <h3>Execution evidence</h3>
            <p>
              The <strong>Execution</strong> view correlates program-execution
              and access evidence across prefetch, amcache, shimcache, and
              shortcut (.lnk) artifacts into one timeline. Stat tiles break the
              events down by source, a histogram shows execution activity over
              time, and a bar list ranks the most-referenced programs (weighted
              by run count where available). Every filter is one click, and each
              row links back to its source artifact.
            </p>
            <h3>Communications</h3>
            <p>
              The <strong>Comms</strong> view unifies iMessage, WhatsApp, SMS,
              call logs, and email into a single stream: per-channel counts,
              message volume over time, and the most-contacted parties. It
              complements the <strong>Connections</strong> graph, which shows
              the same data as a relationship network.
            </p>
            <p>
              A row&rsquo;s <strong>conversation</strong> cell opens the thread
              that message sits in, at that message. A call gets no link and the
              cell says why: there is no thread view for one, so the record
              itself is the whole of what was recovered.
            </p>
            <h3>Email read as an exchange</h3>
            <p>
              Email has no conversation field the way a chat does. What it has is
              a chain: each message names its parent in{" "}
              <code>In-Reply-To</code> and, by convention, carries its whole
              ancestry in <code>References</code>. Séance walks that chain when
              it parses the message and groups the exchange under the message
              that started it, so a mailbox is read as exchanges rather than one
              record at a time. This works for <code>.eml</code>, Apple
              Mail&apos;s <code>.emlx</code> and <code>mbox</code>, and for{" "}
              <code>.msg</code> and{" "}
              <code>PST</code>/<code>OST</code>, whose stores keep the same
              three headers &mdash; including an Outlook 2013-and-later OST
              (format version 36), whose summary record says how many of its
              pages and blocks were read and names any that were not. In a
              version 14, 15, 23 or 36 store, the space neither of its
              B-trees references is then walked for deleted mail: a message
              found there is listed with <code>recovered</code> and{" "}
              <code>allocation: unallocated</code>, its page and block
              offsets, and whether it read <code>complete</code> or{" "}
              <code>partial</code>. A deletion that left no stale entry behind
              is not found, a recovered fragment that shares its subject and
              delivery time with a live message says it may be an earlier
              state of it, and the summary says when a store could not be
              scanned at all. The older layouts are graded on one real
              version 14 mailbox; no Unicode (version 23) message has yet been
              recovered from real evidence.
            </p>
            <p>
              Each message says <strong>how it was placed</strong> in the
              exchange, because a grouping you cannot see the basis of is one you
              cannot test. A message carrying its own ancestry names its thread
              root, which is the strong case. A message carrying only{" "}
              <code>In-Reply-To</code> is grouped by its parent, and a reply to a
              reply then keys on <em>its</em> parent — so a longer exchange can
              appear as more than one thread, and the pane says so above the
              messages rather than leaving a fragment to read as the whole.
            </p>
            <p>
              A message carrying none of the three headers belongs to no exchange
              the evidence can address. Those are collected at the end of the
              list, under <strong>Not in any exchange</strong>, and the pane
              states outright that being collected together is not a claim that
              they belong together. Grouping them under one invented key would
              put a conversation on screen that never existed, which is worse
              than no thread view at all.
            </p>
            <p>
              <strong>Apple Mail keeps an index, and it is not the mail.</strong>{" "}
              macOS Mail records every message it has seen in{" "}
              <code>~/Library/Mail/V*/MailData/Envelope Index</code>: sender,
              recipients by header, subject, mailbox, the sent, received and
              last-viewed dates, read and flagged state, attachment names, and
              whether the message was deleted. On a machine whose mail lived on
              a server that is often the only record on the disk of who wrote to
              whom — and a message whose <code>.emlx</code> file is gone can
              still have its row here. What it does not hold is a body or a
              single RFC header, so those messages show the reason there is no
              body rather than an empty one, and Mail&apos;s own one-line
              snippet appears in its place, labelled as a preview. Two further
              cautions are printed on every such record: the dates are integers
              read as Unix seconds, which is what Mail writes but which no
              database held here can confirm, and this reader has been run
              against Apple&apos;s schema rather than against a mailbox Apple
              filled.
            </p>
            <p>
              <strong>
                Where the <code>.emlx</code> file survives, it is read as mail.
              </strong>{" "}
              The number on its first line is how many bytes of message follow.
              The property list Mail appends after the message is kept out of
              the body, and its dates, <code>conversation-id</code>,{" "}
              <code>remote-id</code> and <code>flags</code> appear on the
              message as <code>emlx_*</code> fields. <code>flags</code> is shown
              as the raw number and is <strong>not</strong> turned into read,
              flagged or deleted, because Apple has not published what its bits
              mean and no file held here confirms any description of them. The
              index above reports read, flagged and deleted state for its own
              rows, but the two are not linked: nothing on an index row names
              its <code>.emlx</code>, so matching them is your own search. A{" "}
              <code>.partial.emlx</code>{" "}
              is a message Mail did not download in full. Each attachment it
              left behind is looked for beside it as{" "}
              <code>&lt;id&gt;.&lt;part&gt;.emlxpart</code> and put back when it
              is found. The message&apos;s <code>emlx_parts</code> list says,
              part by part, whether the part was <em>reunited</em>,{" "}
              <em>absent</em> or <em>could not be looked for</em>. Only a
              folder on the examiner&apos;s machine or a ZIP entry can be looked
              beside: a file inside a disk image cannot, so a{" "}
              <code>.partial.emlx</code> found in a Mac&apos;s disk image has
              every part marked <em>could not be looked for</em> and its
              attachments are not recovered, as with a carved or in-memory copy.
              Any part that was not
              reunited marks the message incomplete and is named in{" "}
              <code>attachment_absent_reason</code>.
            </p>
            <h3>USB devices</h3>
            <p>
              USB mass-storage devices are recovered from the{" "}
              <code>Enum\USBSTOR</code> keys of a parsed <code>SYSTEM</code>{" "}
              registry hive — only <code>Enum</code>; the driver&apos;s own
              compatibility list under <code>Control\usbstor</code> ships with
              Windows and names no device that was ever attached — and listed
              under the <strong>UsbDevice</strong> record type in Analysis:
              vendor, product, revision, serial, and friendly name for each
              device that was connected. Connection times are not yet on the
              record.
            </p>
            <h3>Installed programs</h3>
            <p>
              Every parsed <code>SOFTWARE</code> and <code>NTUSER.DAT</code>{" "}
              hive yields one <strong>InstalledProgram</strong> record per
              subkey of its <code>Uninstall</code> key — native and{" "}
              <code>Wow6432Node</code>, machine-wide and per-user — with the
              display name, version, publisher, install location, uninstall
              command, estimated size, and the <code>InstallDate</code> value
              decoded to a calendar day (it carries no time or zone, and the
              timeline event made from it says so). A subkey with no display
              name is still listed, by its key name and marked as such: the
              count of records is the count of entries the hive holds. Each
              record names the hive copy it came from (live, RegBack, or a
              shadow copy) and carries that hive&apos;s replay state, so a
              program read from a dirty hive whose logs were not applied is
              flagged as the on-disk state.
            </p>
          </section>

          <section id="entities">
            <h2>Entities and link analysis</h2>
            <p>
              Two views turn parsed records into intelligence about who and what
              appears across the evidence.
            </p>
            <h3>Entities</h3>
            <p>
              The <strong>Entities</strong> view mines identifiers from
              parsed-record text and de-duplicates them: email addresses, URLs,
              IP and MAC addresses, phone numbers, payment cards, and Bitcoin or
              Ethereum addresses. Filter by type and read the occurrence count.
            </p>
            <p>
              Click any value to <strong>pivot</strong> on it: a panel shows
              every artifact in the case that references that value, grouped by
              the kind of record each is — &ldquo;6 network flows, 2 DNS
              resolutions, 1 registry hive&rdquo; — with a sample of each group
              linking straight to the artifact. It is the fastest way to ask
              &ldquo;show me everything that touches this IP / hash /
              account&rdquo;. The count shown is the exact number across the
              whole case; when a value is so common that the panel groups only a
              sample, it says so. <strong>Search</strong> remains one click away
              for the full hit list.
            </p>
            <p>
              <strong>Pin this answer to the case</strong> puts the pivot result
              in the report, under &ldquo;Values Traced Across the
              Evidence&rdquo;, so the answer to &ldquo;everything that touches
              this address&rdquo; survives into the document instead of being
              re-run or re-typed while writing it. Pinning records the answer{" "}
              <em>as it stands</em>, with your name and the time. The report
              also re-checks the value when it is produced and shows both
              figures where they differ &mdash; a case that has grown since you
              pinned it does not silently change what the report says. A value
              that could not be re-checked (a build with no search index, say)
              is reported as <em>not re-checked</em> rather than as matching
              nothing, because those are different facts. Pinned values are
              listed on the <strong>Bookmarks</strong> page, where the marks you
              author live, and can be removed from there or from the pivot panel.
            </p>
            <p>
              The same pivot is on every identifier the product shows, not just
              this screen: each answer of a DNS lookup separately, the hashes,
              accounts, file names, device serials and hosts in the record
              tables, every identifier row of an artifact&rsquo;s{' '}
              <strong>Properties</strong> list, and the extra columns you add to
              the <strong>Timeline</strong>. Values that are not identifiers
              &mdash; a size, a flag, a version, or one of Séance&rsquo;s own
              &ldquo;why this is incomplete&rdquo; notes &mdash; deliberately
              carry no pivot: &ldquo;every artifact that references 4096&rdquo;
              is noise, and an affordance that answers uselessly is one you
              learn to distrust.
            </p>
            <p>
              In a <strong>conversation</strong>, a participant&rsquo;s name is
              itself a pivot: click it to ask what else in the case touches that
              person. The name shown is the contact as the device knew them; the
              pivot is on the handle the chat database actually stored — the
              number, address or account id the rest of the evidence carries.
              Your own messages offer no pivot, because there is no
              counterparty on them to follow.
            </p>
            <h3>Connections</h3>
            <p>
              The <strong>Connections</strong> view builds a communication graph
              from messaging and email records: nodes are participants (device
              owner, contact, or email address), links are weighted by message
              volume, and node size reflects activity. Click a participant to
              see their traffic, then either <strong>pivot</strong> on them —
              everything in the case that touches them, grouped by record kind
              — or <strong>search</strong> for the full hit list. The two answer
              different questions, so both are offered. The device owner has
              neither: every link in the graph is already theirs.
            </p>
            <Shot
              id="connections-graph"
              caption="Connections: force-directed communication graph weighted by message volume."
            />
          </section>

          <section id="media-geo">
            <h2>Gallery and geolocation</h2>
            <h3>Gallery</h3>
            <p>
              The <strong>Gallery</strong> presents image files as lazy-loaded
              thumbnails, filterable by source. A lightbox shows the full image
              with its path, size, MD5 and SHA256 hashes, and EXIF details
              (camera, capture time, and GPS), with a link to the underlying
              artifact. Tiles recovered from the RDP bitmap cache appear here
              too, as PNGs named <code>…_tile_NNNNN.png</code> and{" "}
              one <code>…_collage_cache_order_not_a_reconstruction.png</code>{" "}
              per cache file; the collage is the cache's order, not a picture
              of the screen.
            </p>
            <p>
              When hash sets are loaded, thumbnails that match are flagged in
              place: a red <strong>NOTABLE</strong> badge for a known-bad
              (contraband) set, a neutral <strong>KNOWN</strong> badge
              otherwise. A <strong>Hash matches</strong> filter narrows the grid
              to hits, or to notable hits only, so contraband can be triaged
              without opening each image.
            </p>
            <h3>Safe view (examiner wellbeing)</h3>
            <p>
              A <strong>Safe view</strong> toggle blurs and desaturates every
              preview until you deliberately reveal one (hover or focus). CSAM
              and other distressing material is a real occupational hazard, and
              a gallery that shows it unbidden is a liability. It guards the
              display only; the bytes are still fetched, hashed and searchable.
            </p>
            <p>
              It is <strong>off by default</strong> and{" "}
              <strong>remembered in this browser</strong>. Most cases are
              ordinary disk images where blurring every thumbnail is friction
              and nothing else, so the control is opt-in — and because it is
              opt-in, turning it on has to stick. It does: switch it on once and
              it stays on for the next case and the next session, which is the
              point. Clearing your browser's site data resets it to off.
            </p>
            <h3>Filtering a grid as you type</h3>
            <p>
              Every grid in the product carries a <strong>filter box</strong>{" "}
              above it that narrows the rows as you type — the record-type
              index, an artifact&rsquo;s children, the entity list, the filter
              library, the memory lenses, the timeline. Matching is plain
              case-insensitive substring across the columns the grid shows, and
              deliberately not fuzzy: a filter whose rule you cannot state is
              one whose result you cannot defend.
            </p>
            <p>
              The count beside the box always says{" "}
              <em>what it searched</em>, and this is the part worth reading.
              Most grids here are paged or capped, so the box narrows{" "}
              <strong>what is loaded</strong> rather than the case &mdash; on
              the timeline it narrows one page of a case that may hold millions
              of events. Where that is so, the box says it did not search the
              rest and that a row missing from the list is not a row the case
              does not hold. For a case-wide search, use{" "}
              <strong>Search</strong>.
            </p>
            <h3>Narrowing the case to a period</h3>
            <p>
              The activity chart at the top of every case page is a{" "}
              <strong>control</strong>, not just a picture. Click a bar and the
              case is narrowed to that period; the bars inside the window are
              drawn solid and the rest fade.
            </p>
            <p>
              Because the window is set in the shell rather than on the screen
              you are reading, it says three things in full rather than leaving
              them to be inferred: <strong>what</strong> the window is, in UTC;{" "}
              <strong>which screens</strong> it is in force on, so a screen
              outside that list is visibly outside it; and that those screens
              are showing a <strong>subset</strong> while it is in force &mdash;
              a count under a window is a count inside the window, not a count
              in the case. <strong>Show the whole case</strong> clears it.
            </p>
            <p>
              A window you set on a screen itself &mdash; brushing the
              timeline&rsquo;s own chart &mdash; wins over the one in the bar,
              and the timeline says which of the two narrowed it. The case-wide
              window is remembered per case, so it never follows you from one
              case into another.
            </p>
            <h3>Needs attention</h3>
            <p>
              The <strong>Dashboard</strong> carries a{" "}
              <strong>Needs attention</strong> panel: the problems in a case
              that someone can still do something about, each with what to do.
              A case could previously hold the sentence &ldquo;this iOS backup
              is encrypted and no password was provided: no files from it are in
              this case&rdquo; and offer nowhere to act on it. The statement was
              honest and the next step was invisible.
            </p>
            <p>
              The panel is careful about what it offers, and the distinction
              matters more than the convenience:
            </p>
            <ul>
              <li>
                Where the module takes a secret <em>per artifact</em>, you get a
                field and a button: an encrypted iOS backup&rsquo;s password; a
                locked <strong>BitLocker</strong> volume&rsquo;s 48-digit
                recovery password or its password (a selector picks which); a
                locked <strong>LUKS</strong> volume&rsquo;s passphrase; the
                password of a <code>7z</code> whose header is encrypted; and the{" "}
                <strong>Signal for iOS</strong> store&rsquo;s key spec (the
                keychain item <code>GRDBDatabaseCipherKeySpec</code>, typed as{" "}
                <code>x&apos;…&apos;</code> or as 96 hex digits). The module runs
                again on that one artifact — once per artifact, however many
                records in the row name it — and the field is cleared as soon as
                the secret is sent. Every one of these secrets — the iOS backup
                password included — can also be supplied from the REPL with{" "}
                <code>/unlock &lt;artifact_id&gt; &lt;kind&gt; &lt;secret&gt;</code>;
                the secret is everything after the one space that follows the
                kind, leading and trailing spaces included. The unlock field
                likewise sends a password exactly as typed.
              </li>
              <li>
                If the secret opens it, what it held appears beneath it — the
                decrypted volume, the archive&rsquo;s entry names and sizes, the
                store&rsquo;s messages, conversations and contacts — and the
                record that said it was locked is superseded. If it does not, the
                job fails saying so and <strong>nothing in the case
                changes</strong>: the locked record still stands. Watch the job on
                this page.
              </li>
              <li>
                The secret is held in memory for that one run and never reaches
                the case database, an export, a record, the job or the log. The
                audit log records that you supplied one — which kind, for which
                artifact — and whether it was accepted, never the secret itself.
              </li>
              <li>
                A volume decrypted this way cannot be re-read from the evidence
                afterwards, because the key is not kept: previewing, downloading
                or re-hashing a file beneath it is refused rather than showing you
                the encrypted bytes.
              </li>
              <li>
                A <code>7z</code> whose header was plain already lists its
                entries; their content is encrypted and this build does not
                extract <code>7z</code> content at all, so that row offers{" "}
                <strong>no field</strong> and says why. The Signal for iOS reader
                is graded on a real store that held no messages, so the records
                it produces say their message fields have not yet been checked
                against a real message.
              </li>
              <li>
                Where this build cannot read the content at all — an encrypted{" "}
                <code>adb backup</code> — the row says so and offers nothing, so
                you do not spend an afternoon looking for a password field that
                was never there.
              </li>
            </ul>
            <p>
              An empty panel means <em>nothing recoverable is outstanding</em> —
              not that the examination was complete. What could not be read is
              counted in the completeness census and in the report&rsquo;s
              Result Completeness section, and the panel says so on its face
              rather than leaving an empty queue to read as a clean case.
            </p>
            <h3>Findings</h3>
            <p>
              <strong>Findings</strong> is the answer to &ldquo;where do I
              start&rdquo;: the jump from two million parsed objects to the
              things that look wrong, most confident first. It is also the one
              screen in Séance that shows Séance&rsquo;s own claims rather than
              a transcription of the evidence, and it says so above its first
              row.
            </p>
            <p>
              Every row is an <strong>investigative lead</strong> &mdash; a
              place to look, never a conclusion &mdash; and each is set out in
              three parts that are deliberately never merged:
            </p>
            <ul>
              <li>
                the <strong>observation</strong>: the invariant that broke,
                stated as a fact, which you can check against the artifact it
                names;
              </li>
              <li>
                <strong>what it may indicate</strong>, labelled as
                Séance&rsquo;s reading rather than a fact, and absent entirely
                where the observation speaks for itself;
              </li>
              <li>
                <strong>what it does not establish</strong>, with the ordinary
                causes that produce the same pattern. This is never hidden
                behind a control: a reader who sees only the claim has read half
                the finding.
              </li>
            </ul>
            <p>
              The grade &mdash; <strong>Strong</strong>,{" "}
              <strong>Notable</strong> or <strong>Weak</strong> &mdash; is about
              how much room there is for an innocent explanation, and it is
              three coarse values on purpose: a number like 0.87 invites you to
              read it as a measurement and nothing here measures anything.
              Strong means the pattern is hard to produce by ordinary use of the
              machine. It does not mean anything has been established. Weak
              means there is an ordinary explanation at least as likely as a
              suspicious one, and those leads are on the list because they are
              cheap to check, not because they are probably wrong.
            </p>
            <p>
              <strong>Show what this build looks for</strong> lists every check
              Séance can perform. Read it before reading an empty list: &ldquo;no
              findings&rdquo; means either that nothing in this case matched
              those checks, or that nothing here looks for what you are after,
              and they are completely different answers.
            </p>
            <p>
              Two of the checks compare the whole case against itself &mdash; a
              program that ran with no file left behind, a journal delete the
              MFT contradicts &mdash; so they need a filesystem to compare
              against and they are worked out when you open the screen rather
              than during ingest. The page says whether they ran, what they ran
              against, and anything they could not reach. Their rows carry no
              record of their own, so you can open the artifact a lead is
              <em>about</em> but not the lead itself; the row tells you that
              where you read it.
            </p>
            <p>
              A lead reaches the report too, under{" "}
              <strong>Investigative Leads</strong> &mdash; separate from{" "}
              <strong>Findings / Bookmarks</strong>, which is what you marked
              &mdash; with the same three parts and a Limitations entry stating
              what a rule-generated claim is worth.
            </p>
            <h3>Applications</h3>
            <p>
              The <strong>Analysis</strong> screen opens with{' '}
              <strong>Applications</strong>: the case&rsquo;s records grouped by
              the program each came from, which is the first thing to know
              about a device. Each group says how it was attributed &mdash;
              because the record <em>named</em> the application (Windows
              resource usage, the Windows Timeline, a macOS bundle id) or
              because its <em>kind</em> is an application (a WhatsApp message
              is WhatsApp). Those are different strengths of evidence and the
              chip tells you which.
            </p>
            <p>
              Most of a case belongs to no application at all &mdash; file
              entries, registry keys, network flows &mdash; and those records
              are counted separately and never spread across the apps. So the
              per-application figures and that count add up to the whole, and
              the panel is a breakdown of the case rather than of some unstated
              part of it.
            </p>
            <h3>Unique only</h3>
            <p>
              The file grid&rsquo;s <strong>Unique only</strong> tick shows the
              files this case can <em>demonstrate</em> are one of a kind: their
              SHA-256 is carried by nothing else in the evidence. It is the
              inverse of the Duplicates view.
            </p>
            <p>
              A file with no hash is <strong>not listed</strong>, and the grid
              says how many were set aside. That matters: such a file is neither
              unique nor a duplicate — nobody has established which — so showing
              it here would present an unknown as a finding, and leaving it out
              quietly would make the row count read as the number of unique
              files in the case. It is a <em>floor</em> on that number, and the
              note above the grid says so.
            </p>
            <h3>Perceptual hashing (near-duplicates)</h3>
            <p>
              Every decodable image is given an open <strong>PDQ</strong>{" "}
              perceptual hash. Two images a small Hamming distance apart are
              near-duplicates — a re-encoded, resized or lightly-cropped copy of
              the same picture — which exact MD5/SHA matching cannot find. The
              hash also lets an image be compared against an externally-supplied
              PDQ set. A perceptual match is graded a <em>lead for review</em>,
              never an identification.
            </p>
            <h3>Map</h3>
            <p>
              The <strong>Map</strong> plots every latitude/longitude point
              recovered from the case — geotagged photos and location records —
              on a world map, grouped by record type. Copy coordinates or jump
              to the source artifact from the detail panel.
            </p>
            <p>
              Enable <strong>Movement track</strong> to connect the timed points
              in chronological order and reveal a path. A scrubber walks the
              path forward in time, showing where the device was and when —
              useful for reconstructing movement from geotagged media and
              location records.
            </p>
            <Shot
              id="geo-map"
              caption="Map: GPS points from EXIF and location records plotted on a world map."
            />
          </section>

          <section id="mobile">
            <h2>Mobile: backups, chat, calls, contacts</h2>
            <p>
              Séance ingests iOS and Android device backups and parses the app
              databases inside them. Point <strong>Ingest Evidence</strong> at a
              backup folder or archive; the container is unpacked and each
              extracted database is routed to its parser automatically, so chat,
              call, contact, and browser records appear alongside the rest of
              the case.
            </p>
            <h3>Supported backup formats</h3>
            <ul>
              <li>
                <strong>iOS (iTunes / Finder)</strong> — both{" "}
                <code>Manifest.db</code> (iOS 10+) and legacy{" "}
                <code>Manifest.mbdb</code>/<code>Manifest.mbdx</code> layouts,
                and both <strong>plain and encrypted</strong> backups. For
                encrypted backups, supply the backup password; the keybag is
                unwrapped (PBKDF2 / AES per protection class) and files are
                decrypted on the fly. A class key the keybag also wraps under
                the phone&rsquo;s hardware key is device-bound: no password
                opens it from a backup, and the record saying the backup was
                decrypted lists which classes the password opened and which
                are device-bound, by number. Files are reconstructed by domain
                and relative path.
              </li>
              <li>
                <strong>
                  Android (<code>adb backup</code>)
                </strong>{" "}
                — the <code>.ab</code> container (<code>ANDROID BACKUP</code>{" "}
                header + deflate) is unpacked to its file tree. Encrypted{" "}
                <code>.ab</code> archives are flagged rather than cracked.
              </li>
            </ul>
            <h3>App data recovered</h3>
            <ul>
              <li>
                <strong>Chat / messaging</strong> — iMessage/SMS (
                <code>sms.db</code>/<code>chat.db</code>), WhatsApp (
                <code>ChatStorage.sqlite</code> and Android{" "}
                <code>msgstore.db</code>), and Android SMS/MMS (
                <code>mmssms.db</code>). An Android WhatsApp{" "}
                <code>.crypt14</code> or <code>.crypt15</code> backup is
                decrypted when the phone&apos;s key file is in the same case (
                <code>/data/data/com.whatsapp/files/key</code> for crypt14,{" "}
                <code>encrypted_backup.key</code> beside it for crypt15), or
                when its key is supplied on the backup&apos;s{" "}
                <code>WhatsAppBackup</code> record (the key file as hex, or 64
                hex digits: a crypt14 install&apos;s bare key or a
                crypt15&apos;s end-to-end backup key; credential kind{" "}
                <code>whatsapp_key</code>). A key read from the evidence is
                held in memory for that case for the unlock lifetime (8 hours
                by default) and never written anywhere. Its messages carry{" "}
                <code>provenance: decrypted_backup</code> and may repeat the
                live store&apos;s. A crypt15 that holds a ZIP archive (a
                multi-file or incremental backup) has the archive filed beneath
                it for the archive expander, readable during that run only.
                Without the key, a wrong key, or for <code>.crypt12</code> or
                older backups, a <code>WhatsAppBackup</code> record says it was
                not decrypted.
                Conversations render as threaded bubbles in the messaging viewer
                and as weighted edges in the <strong>Connections</strong> graph.
              </li>
              <li>
                <strong>Call history</strong> — iOS{" "}
                <code>CallHistory.storedata</code> and Android call logs, shown
                in the <strong>Call History</strong> records view (direction,
                number, duration, time) and fed into the Connections graph.
              </li>
              <li>
                <strong>Contacts</strong> — iOS{" "}
                <code>AddressBook.sqlitedb</code> and Android{" "}
                <code>contacts2.db</code>, listed and searchable in the{" "}
                <strong>Contacts</strong> records view.
              </li>
              <li>
                <strong>Browser history</strong> — Safari, Firefox, and
                Chrome/Chromium visit histories, which also contribute visit
                events to the timeline.
              </li>
              <li>
                <strong>Safari on iOS</strong> — bookmarks and folders from{" "}
                <code>Bookmarks.db</code> (validated on schema version 43; a
                store outside that carries a parser schema warning and still
                parses), with the folder path, reading-list membership and the
                tri-state <em>read</em> flag left <em>not recorded</em> where
                Safari never set it; <strong>open tabs</strong> from{" "}
                <code>SafariTabs.db</code> — title, URL, tab group, window,
                whether the tab is active and whether it is a{" "}
                <strong>private-browsing</strong> tab, the last visit time from
                the tab&apos;s attribute plist, and the tab&apos;s{" "}
                <strong>back/forward list</strong> decoded from its session
                state, capped at 500 entries with the cap on the row; a session
                state that will not decode is reported as present and unread;
                and <strong>recent web searches</strong> from{" "}
                <code>com.apple.mobilesafari.plist</code>, each with its time —
                the plist records the query and when, not which engine served
                it, and the row says <em>not recorded</em> rather than naming
                one. <code>BrowserState.db</code> is read too, but on iOS 15 its
                tabs table is empty (the tabs live in SafariTabs.db) and it has
                been validated on that empty table only.
              </li>
              <li>
                <strong>HealthKit</strong> — samples from{" "}
                <code>healthdb_secure.sqlite</code>: type, quantity, start and
                end, and from that same file&apos;s{" "}
                <code>data_provenances</code> row the originating product
                type, build and the{" "}
                <strong>timezone name the sample was recorded under</strong>{" "}
                (what the provenance row says, not an inference about where
                the phone was). The source&apos;s human-readable name is the
                one field read from the neighbouring{" "}
                <code>healthdb.sqlite</code>, where it is present, and the
                record says when that lookup could not be made. Only three sample
                types are named (step count, walking/running distance, flights
                climbed), each marked as asserted from one iOS 15 build rather
                than read from the file; every other type is shown by number
                as <em>not named by this build</em>. The unit is what the file
                says or nothing: on the device this was validated on the unit
                table is empty, so every sample reads <em>not recorded</em>,
                and no canonical unit is guessed from the type. Workouts, sleep
                and category samples are counted and not decoded, and the
                store&apos;s summary record says so.
              </li>
            </ul>
            <p className="help-note">
              Chat, Call History, and Contacts surface under{" "}
              <strong>Analysis</strong> as record types (open a case and pick
              the type), so they use the same search, export, and bookmarking as
              every other artifact.
            </p>
            <h3>When a parser meets a schema it was not validated on</h3>
            <p>
              A parser that checks a store&apos;s schema version was validated
              against the versions of real stores and declares the range it was
              read from. What every such parser has in common: when the version
              seen is outside that range the records still parse, and the
              parser files a <strong>parser schema warning</strong> beside them
              — under <em>Parser schema warnings</em>, or under the app&apos;s
              own incompleteness type carrying a warning class of that name —
              stating the version seen against the validated range. Beyond
              that, two paths exist and a warning says only what its path
              recorded.
            </p>
            <p>
              A version outside the range is a <strong>disclosure</strong>, not
              a claim that records are missing: the warning does not mark the
              parse incomplete for the version alone. Most ranges are a single
              version, read from the few real stores held for that app, so a
              newer store whose every column still resolves is not evidence
              that anything was lost. What does mark the parse incomplete is
              the signal that something was: a required field no column
              carries, or a table that is absent. One exception: a Chrome or
              Edge store whose own <code>last_compatible_version</code> is
              past the highest version this parser was validated on — Chromium
              stating that an older reader cannot read it — is marked
              incomplete.
            </p>
            <p>
              The app-store parsers — the chat apps (Signal, Kik, Telegram,
              Viber, WhatsApp, Snapchat, Instagram, LINE, Skype, WeChat,
              iMessage, Twitter/X direct messages), Android SMS and the
              Android call log, and the contacts family (Contacts, Android
              apps, browser history, installed apps, mobile device) — read the
              version three ways and say which: a version found is compared to
              the range; a store recording no version (<code>PRAGMA
              user_version</code> is 0, SQLite&apos;s unset default) is
              reported as <em>not recorded</em>, never ranked as older than the
              range; a version that could not be read is reported as{" "}
              <em>undetermined</em>, never spent as in range. These parsers
              also resolve each logical field to a column before reading, and
              a field no column carries is omitted from the records, never
              guessed: the warning then names the table, the unresolved
              fields, and how many records were recovered regardless (Facebook
              Messenger does this column check but declares no version range,
              so it files no version warning). Every one of these warnings
              that states a range also names the real file(s) the range was
              read from, so the warning leads back to the store that set it.
              Each chat-app parser for which no readable real store is held
              declares no range and says so on the warning rather than
              inventing one.
            </p>
            <p>
              The iOS <strong>Safari and HealthKit</strong> parsers above use
              the shared check instead. It reads the version the same three
              ways — a <code>user_version</code> of 0 is reported as{" "}
              <em>not recorded</em>, never as older than the range, and a
              version that would not read is reported as{" "}
              <em>undetermined</em> — and files a warning for every answer
              except a version inside the range, naming the real file the
              range was read from. It does less than the app-store parsers in
              one respect: it carries the app, the version, the range and one
              sentence, with no table, no field list and no record count,
              because these parsers resolve no columns; a renamed column there
              makes the store unreadable instead.
            </p>
          </section>

          <section id="review-ledger">
            <h2>Review ledger: opened and reviewed</h2>
            <p>
              The review ledger records two different things about a record, and
              keeps them apart everywhere they are shown.
            </p>
            <ul>
              <li>
                <strong>Opened</strong> — a screen showing this record was
                displayed. It is a fact about attention, and it is recorded for
                you rather than pressed: today the act that records one is
                following a row&rsquo;s <strong>conversation</strong> link in
                the Communications table, which genuinely puts the record in
                front of you. Scrolling a row past does not record anything.
              </li>
              <li>
                <strong>Reviewed</strong> — you pressed{" "}
                <strong>Mark reviewed</strong> to say you had finished examining
                it. This is the one an advocate would put to you, so it is the
                one that is never inferred. Pressing it again withdraws{" "}
                <em>your</em> review; a colleague&rsquo;s is untouched, and only
                they can withdraw it.
              </li>
            </ul>
            <p>
              <strong>Opening a record is not examining it</strong>, and the two
              counts are <strong>never added</strong>: every reviewed record is
              also an opened one, so the reviewed set is a subset of the opened
              set. Both count distinct records, so two examiners opening the
              same record is one record.
            </p>
            <h3>Where the marks live, and whose they are</h3>
            <p>
              The ledger is <strong>stored with the case on the server</strong>,
              not in your browser. Every examiner with access to the case sees
              the same marks, and each is filed under the name of whoever was
              signed in when it was made — including yours. That is what the
              ledger is for: at handover, the question &ldquo;what did the last
              examiner actually look at&rdquo; is one a browser-local ledger
              answered with &ldquo;nothing&rdquo;.
            </p>
            <p>
              Withdrawing a review removes it from the counts but not from the
              case&rsquo;s <strong>review history</strong>, which keeps every
              opening, review and withdrawal with the examiner who made it. That
              is what keeps a review that was made and later withdrawn
              distinguishable from one that was never made.
            </p>
            <p>
              The ledger appears as a <strong>Review</strong> column on each row
              of the Communications table, with the case-wide panel above it,
              and in full on the <strong>Bookmarks</strong> page.
            </p>
            <h3>Which examiner reviewed this record</h3>
            <p>
              A row a colleague has reviewed reads{" "}
              <em>reviewed by another examiner</em> and offers a{" "}
              <strong>who?</strong> control. It is read only when you{" "}
              <strong>press</strong> it — not on hover and not on focus, because
              naming the examiner costs one request against that record&rsquo;s
              own history, and a pointer dragged down a table would fire one per
              row for a question nobody asked.
            </p>
            <p>
              The answer arrives with the <strong>UTC time it was read</strong>,
              shown in the row and not in a tooltip, because the stamp is the
              claim: &ldquo;at 11:02:14 UTC this record&rsquo;s history said
              alice held the review&rdquo; is still true after alice withdraws,
              where &ldquo;alice holds this review&rdquo; is not. Nothing
              re-reads on its own and nothing expires — a name that changed with
              no act of yours behind it could not be accounted for afterwards.
              Press the stamp to take a new reading, at a moment you can name.
            </p>
            <p>
              A new reading that <em>disagrees</em> with the one the row was
              showing says so on the row, naming both readings and both times,
              so an examiner who quoted the earlier name can account for it. A
              reading that agrees says nothing, and retires the notice the
              previous reading left — that notice described a reading the row
              has stopped showing. A reading that did not complete replaces
              nothing: the earlier reading stays on the row with its own date,
              and the failed attempt is dated beside it.
            </p>
            <h3>Not known is not &ldquo;not opened&rdquo;</h3>
            <p>
              A row whose standing has not been read says{" "}
              <strong>not known</strong>, never &ldquo;not opened&rdquo;. The
              case-wide listings the marks are matched against have a{" "}
              <strong>ceiling</strong>, and they can fail or still be in flight;
              a row past that ceiling is a row the listing never reached. On a
              shared ledger &ldquo;nobody has opened this&rdquo; is a claim
              about the whole case, and it is not manufactured out of a claim
              about the network. Where a listing stopped at its ceiling, the
              panel says so above the table.
            </p>
            <h3>Counts, and why there is no percentage</h3>
            <p>
              The panel shows two counts and, where the surface it sits on knows
              and can name one, a population to read them against. It is{" "}
              <strong>never a proportion</strong> and never a progress bar. The
              case-wide population counts rows nobody opens individually —
              containers, filesystems, partitions — so coverage read off it is a{" "}
              <strong>floor</strong> rather than a measure, and a screen that
              does not know its own population says the population is not stated
              rather than borrowing one that does not fit. A per-examiner
              breakdown says who opened and reviewed what.
            </p>
            <h3>Reading it again is something you do</h3>
            <p>
              Nothing re-reads the ledger on a timer. A read that failed and
              then quietly succeeded would leave the screen saying something
              different with no moment you could point to as the one it changed
              — and both sentences may have been quoted by then. So{" "}
              <strong>Read the ledger again</strong> is a button, and what comes
              back is the answer to your asking.
            </p>
            <p>
              The ledger is four separate responses that fail independently, and
              a re-read asks for <strong>only the parts</strong> that could not
              be read — re-fetching a hundred-thousand-id listing to recover a
              roll-up that failed on its own would cost you a wait for figures
              nobody doubted. That is safe only because the panel says what it
              did: it names the parts the re-read covered, and{" "}
              <strong>says when each part was read</strong>, so three figures
              from the first reading and one from the re-read are never
              presented as one reading.
            </p>
            <p className="help-note">
              The ledger is <strong>not the audit log</strong>, and a mark is
              not a finding: it says{" "}
              <strong>what was looked at, not what was found</strong>. The two
              are joined deliberately loosely. The audit log takes{" "}
              <em>one summarising entry per batch</em> of marks —{" "}
              <code>artifact_reviews_recorded</code>, carrying how many
              openings, reviews and withdrawals it made and how many marks were
              rejected — while the per-record detail lives in the review
              history, written in the same transaction as the mark itself. One
              hash-chained audit row per opening would bury every deliberate act
              in the case under bursts of them.
            </p>
            <h3>Assigned work</h3>
            <p>
              A case <strong>owner</strong> (or an admin) can assign the
              bookmarks listed on the <strong>Bookmarks</strong> page to a named
              examiner with <strong>Assign N listed artifacts</strong>. Only
              examiners who can record reviews — <code>read_write</code> or{" "}
              <code>owner</code> on the case — are offered; an examiner with{" "}
              <code>read_only</code> access cannot file a review, so the server
              refuses to assign review work to them and records nothing. An
              assignment is a fixed set of records, not a saved filter, and
              creating or withdrawing one each writes an entry to the audit log.
              A withdrawn assignment stays on the record, marked withdrawn.
            </p>
            <p>
              The <strong>Due</strong> field sets an optional due date, taken
              as the end of that day in your own time zone; a date already past
              is refused. <strong>Overdue</strong> is not stored: the server
              works it out each time from the assignee&rsquo;s own reviews, so
              an assignment is overdue only while it is past due with items the
              assignee has not reviewed, and never once it is withdrawn or
              finished. Under <strong>Assignments</strong>, the owner sees
              every assignment with its progress and can{" "}
              <strong>Withdraw</strong> one or <strong>Reassign</strong> it to
              another examiner who can record reviews. Reassigning gives the
              same records to the new examiner as a new assignment and withdraws
              the old one; the earlier assignment is kept on the record, marked
              withdrawn, and the reassignment is written to the audit log.
            </p>
            <p>
              The assignee sees it under <strong>My queue</strong> on the
              Bookmarks page as <em>X reviewed of N</em>, with the records they
              have not yet reviewed listed below. Progress counts only the
              assignee&rsquo;s own reviews: a colleague reviewing an assigned
              record does not clear it from the assignee&rsquo;s queue, because
              it was not the assignee&rsquo;s examination. If the assignments
              cannot be read the panel says so, and never shows that as
              &ldquo;nothing assigned&rdquo;. An empty queue says{" "}
              <em>you have reviewed every item</em> only when every assigned
              record could be read; if some could not, it says that instead,
              and if the assigned records have since been deleted from the case
              it says the assignment no longer holds any. If an assignment is
              refused (for example a <code>read_only</code> assignee), nothing
              is recorded; if the server fails instead, the panel says the
              assignment may have been recorded and to check the queue before
              assigning again.
            </p>
          </section>

          <section id="bookmarks">
            <h2>Bookmarks</h2>
            <p>
              Bookmarks collect key evidence for reporting, and they are
              captured <strong>where the finding is made</strong> rather than on
              a page you have to go to afterwards: from an artifact&rsquo;s own
              viewer, from the star on any row of the{" "}
              <strong>Communications</strong> table, and in the{" "}
              <strong>gallery</strong> from a cell&rsquo;s right-click menu or
              by pressing <span className="help-kbd">b</span> on the highlighted
              item.
            </p>
            <ul>
              <li>
                The control opens a small form on the spot: a colour-coded{" "}
                <strong>category</strong> (per allegation, per device) and a{" "}
                <strong>note</strong> saying why the item matters, with the note
                box focused so it can be typed straight into. The fast path is
                unchanged — open, <span className="help-kbd">Enter</span>, done
                — and the note is one keystroke away rather than one page away,
                which is the difference between a reasoned record and a list of
                unexplained stars. In the note box{" "}
                <span className="help-kbd">Enter</span> saves and{" "}
                <span className="help-kbd">Shift</span>
                <span className="help-kbd">Enter</span> starts a new line. A
                write that fails leaves the form open with your note in it,
                rather than dismissing over an error you would have to notice
                elsewhere.
              </li>
              <li>
                <span className="help-kbd">Esc</span> dismisses the form and
                writes <em>nothing</em>. A bookmark is an evidential record, so
                the key that ordinarily means &ldquo;cancel&rdquo; does not
                create one out of half-typed reasoning you were in the middle of
                rejecting.
              </li>
              <li>
                A star fills in when the server has stored the capture, never
                before it: nothing on screen claims a bookmark the server
                rejected.
              </li>
              <li>
                In the bookmarks list, a record with no name is listed by the
                identifier its own kind is known by &mdash; a{" "}
                <code>$LogFile</code> transaction by its LSN and record number,
                a YARA match by the rule, a login by the user and terminal
                &mdash; so four bookmarks on four records of one type are four
                distinguishable rows. A record that carries nothing identifying
                at all is still listed as <strong>Unknown</strong>: an invented
                label would be an identity the evidence does not have.
              </li>
              <li>
                Export bookmarks as CSV or JSON for inclusion in a report.
              </li>
              <li>
                <strong>Folders nest.</strong> <strong>New category</strong>{" "}
                takes an optional <strong>Parent folder</strong>, so a category
                can sit under another one of the same case, up to five levels
                deep; the list shows them indented and the bookmark form names
                each by its whole path. The server refuses a parent from another
                case, a folder under itself or one of its own subfolders, and a
                sixth level, and records nothing when it does. Deleting a folder
                moves its subfolders to the top level and leaves its bookmarks
                uncategorised &mdash; nothing filed is lost by tidying. The CSV
                export and the report name a bookmark&rsquo;s folder by its
                whole path (<code>Parent / Child</code>); two folders in a
                case still cannot share a name.
              </li>
              <li>
                <strong>Shared and personal.</strong> The bookmarks above are
                the case&rsquo;s <em>shared</em> set: everyone on the case sees
                them and they are what the report prints. <strong>Mark
                privately</strong>, beside the Bookmark button in an
                artifact&rsquo;s viewer, adds a <em>personal</em> bookmark
                instead — a scratch mark only you see, listed under{" "}
                <strong>Mine (personal)</strong> on the Bookmarks page. A
                personal bookmark is never included in a report; the
                report&rsquo;s Findings / Bookmarks section states how many
                exist and were left out, so the exclusion is on the record.{" "}
                <strong>Add to shared bookmarks</strong> promotes one, and that
                step is written to the audit log. It is refused when the record
                already has a shared bookmark, rather than overwrite a
                colleague&rsquo;s note. A promoted mark shows{" "}
                <em>in shared bookmarks</em> only while that shared bookmark
                exists; if it is deleted, the mark says so, is counted in the
                report as left out again, and can be added again. The XLSX
                export carries the same count, on its Summary sheet and at the
                foot of its Bookmarks sheet. Personal bookmarks need a user
                account; a <code>read_only</code> grant cannot create them.
              </li>
            </ul>
            <Shot
              id="bookmarks"
              caption="Bookmarks organised into colour-coded categories with examiner notes."
            />
          </section>

          <section id="hash-sets">
            <h2>Hash sets</h2>
            <p>
              Hash sets classify files by their MD5, SHA1, or SHA256 digest. Two
              set types serve opposite purposes:
            </p>
            <ul>
              <li>
                <strong>Known good</strong> sets (e.g. NSRL RDS operating system
                baselines) filter noise: matching files are safe to
                de-prioritise.
              </li>
              <li>
                <strong>Notable</strong> sets flag files that demand attention:
                contraband, malware, or case-specific IOCs.
              </li>
            </ul>
            <p>
              Import hashes from plain CSV (<code>hash</code> or{" "}
              <code>hash,product</code> per line) or NSRL RDS exports. Matches
              surface automatically as files are hashed and appear as{" "}
              <em>Notable</em> or <em>Known</em> badges on the artifact.
            </p>
            <h3>Project VIC / CAID (VICS)</h3>
            <p>
              <strong>Import VICS</strong> loads a Project VIC (US) or CAID (UK)
              hash set in the VICS 2.0 JSON format. Each media hash keeps its
              VIC
              <em>category</em> (1 = CAM, 2 = child exploitive, and so on) and
              its attributes (victim identified, series, tags); a set containing
              any pertinent category is flagged <em>notable</em> automatically.
              Per row, <strong>Export VICS</strong> writes the set back out as a
              VICS-compatible JSON, so an import → match → export cycle is
              lossless and the result is shareable with Project VIC or another
              tool.
            </p>
            <p className="help-note">
              VIC/CAID hash sets are law-enforcement restricted and are never
              shipped with Séance — you load a set your unit already holds. The
              matching maths is exact-hash; near-duplicate (perceptual/PhotoDNA)
              matching is a separate capability.
            </p>
            <Shot
              id="hash-sets"
              caption="Hash sets: known-good and notable sets with import and hit counts, and VICS import/export."
            />
          </section>

          <section id="reporting">
            <h2>Reporting and exports</h2>
            <p>
              From the dashboard, <strong>Export HTML</strong> and{" "}
              <strong>Export PDF</strong> produce a self-contained,
              court-defensible case report; <strong>Export DOCX</strong>{" "}
              produces the same report as a Word document, <strong>Export
              RTF</strong> as Rich Text and <strong>Export XML</strong> as
              structured XML for tools that read the report as data; and{" "}
              <strong>Export XLSX</strong> produces it as a workbook: a Summary
              sheet carrying the case, examiner and audit-chain details, then
              one sheet per section that has content. Every format renders the
              same sections under the same conditions from the same statements,
              and each export is written to the audit log with its format. The
              report is assembled from the case record and includes:
            </p>
            <ul>
              <li>
                An <strong>executive summary</strong> narrative generated from
                the case contents.
              </li>
              <li>
                Evidence sources with an <strong>integrity check</strong>{" "}
                (computed vs. acquisition hashes).
              </li>
              <li>
                Per-category detail sections (web history, email, chat, and
                other artifact categories).
              </li>
              <li>
                Bookmarked findings, GPS points, timeline highlights and the
                full timeline.
              </li>
              <li>
                Two <strong>figures</strong> — the communications network and
                events over time — drawn into the HTML (inline SVG), DOCX (an
                SVG picture) and PDF reports, each with its data as a table
                beneath it; RTF and XML carry the data as tables and elements
                without the drawing. A timeline listing that was capped is
                marked incomplete on the figure with the case total. The DOCX
                picture is SVG only: Word 2016 and later and LibreOffice 7.4
                and later render it, an older Word shows an empty picture frame,
                and the table beneath carries the numbers either way.
              </li>
              <li>
                Notable and known-good hash-set matches, stated in both
                directions.
              </li>
              <li>
                An embedded <strong>chain of custody</strong> drawn from the
                audit log.
              </li>
              <li>
                A <strong>declaration and statement of truth</strong>, naming
                the examiner and the report reference, and a{" "}
                <strong>glossary</strong> defining the terms whose misreading
                would change a conclusion.
              </li>
            </ul>
            <h3>How times are expressed</h3>
            <p>
              Every report states, in each format it is produced in, that its
              times are <strong>UTC</strong>. This is not optional and cannot be
              switched off. An unqualified timestamp in a forensic report is
              challengeable on its face: the same instant is a different wall
              clock in every jurisdiction the evidence may have crossed, and
              local time is ambiguous twice a year. Séance normalises timestamps
              to UTC on ingest; where the original timezone could not be
              established, the record says so rather than assuming one.
            </p>
            <h3>Examiner details and handling markings</h3>
            <p>
              The report carries the examiner's name, role, organisation,
              qualifications and contact details, and the case's handling
              marking — all recorded against the case and editable through the
              case settings. An instance where every case belongs to the same
              body can set a fallback organisation in{" "}
              <code>SEANCE_ORGANISATION</code>, and a default handling marking
              in <code>SEANCE_REPORT_CLASSIFICATION</code>; the case's own
              values take precedence.
            </p>
            <p>
              Anything not recorded is left <em>absent</em> rather than filled
              with a default, and a field left blank counts as not recorded. A
              report that states a qualification the examiner does not hold is
              worse than one that states none. For the same reason a report does
              not number its own revision, because Séance does not track how
              many times a case has been reported on — an unnumbered report is
              honest, one calling itself "Revision 1" when it is the third to
              leave the building is not.
            </p>
            <h3>Digital signatures</h3>
            <p>
              When the server is configured with an X.509 certificate and key,
              exported PDFs are signed with a <strong>PKCS#7</strong> signature
              so any later tampering is detectable. If signing is not
              configured, reports are produced unsigned — no assurance is
              implied or displayed.
            </p>
            <h3>Other exports</h3>
            <p>
              Views export their own data for use in other tools: the timeline
              as CSV, JSON, or PDF; a record type as CSV; search results as CSV
              or JSON; bookmarks as CSV or JSON; the audit log as CSV; and file
              selections as a ZIP with a manifest of hashes. The reporting engine additionally emits
              Google Earth <strong>KML</strong>/GeoJSON for mapped points.
            </p>
            <p>
              Each of these exports the set you filtered to rather than the page
              on screen. The search export and the timeline CSV and JSON exports
              go further and{" "}
              <strong>state their own completeness in their last row</strong>,
              so a file cut short in transit can be told from a whole one long
              after the download — see <em>What an export covers</em> under{" "}
              <strong>Search</strong>.
            </p>
            <p>
              The timeline CSV and JSON exports open with a preamble that names
              the case, the filters in force, the number of matching events
              counted before the first row, and the timezone convention: the{" "}
              <code>Timestamp</code> column is Unix epoch seconds in UTC with no
              offset applied, <code>Timestamp (ISO-8601 UTC)</code> is the same
              instant as text, <code>Subsecond Nanoseconds</code> carries the
              sub-second part, and <code>Source UTC Offset Seconds</code>{" "}
              carries the offset the source itself recorded, empty where the
              source gave a bare Unix timestamp. The file ends with a quoted
              verdict row whose first cell begins{" "}
              <code>### END OF EXPORT ### VERDICT:</code> and says whether every
              matching event is in it. The timeline PDF is bounded to the newest
              50,000 matching events; it states how many events it holds out of
              how many matched, wraps long Source and Description values rather
              than shortening them, and shows timestamps in UTC to the second.
            </p>
          </section>

          <section id="filesystems">
            <h2>Filesystems and containers</h2>
            <p>
              Séance walks partition tables and detects filesystem types
              automatically. Support covers the major Windows, Linux, macOS, and
              optical filesystems, and the common evidence container and virtual
              disk formats.
            </p>
            <div className="help-table-wrap">
              <table className="help-table">
                <caption>Filesystems</caption>
                <thead>
                  <tr>
                    <th>Filesystem</th>
                    <th>Notes</th>
                  </tr>
                </thead>
                <tbody>
                  <tr>
                    <td>NTFS</td>
                    <td>
                      $MFT with resident/non-resident data, ADS, runlists; plus
                      $LogFile, $I30, $UsnJrnl, $BadClus.
                    </td>
                  </tr>
                  <tr>
                    <td>FAT12 / 16 / 32, exFAT</td>
                    <td>Directory walk with deleted-entry recovery.</td>
                  </tr>
                  <tr>
                    <td>ext4</td>
                    <td>Inode table, directory entries, extent trees.</td>
                  </tr>
                  <tr>
                    <td>APFS</td>
                    <td>
                      Container → object map → volume → FS B-tree. Encrypted
                      (FileVault) volumes are detected and skipped.
                    </td>
                  </tr>
                  <tr>
                    <td>HFS+ / HFSX</td>
                    <td>
                      Catalog B-tree with data-fork extent reconstruction.
                    </td>
                  </tr>
                  <tr>
                    <td>XFS</td>
                    <td>
                      Shortform/block/leaf/node dirs, B-tree extents. Deleted
                      names from directory free space and freed inodes from the
                      inode B+tree, with owner and times but no content (the
                      kernel clears a freed inode&apos;s extents). A root inode
                      that will not read is flagged on the file-system record.
                    </td>
                  </tr>
                  <tr>
                    <td>Btrfs</td>
                    <td>B-tree traversal with chunk mapping.</td>
                  </tr>
                  <tr>
                    <td>F2FS</td>
                    <td>
                      Flash-friendly filesystem (modern Android{" "}
                      <code>/data</code>): NAT/inode walk with inline and
                      block-mapped file content.
                    </td>
                  </tr>
                  <tr>
                    <td>SquashFS</td>
                    <td>
                      Read-only compressed filesystem (Android system
                      partitions, live-CD/appliance roots, firmware):
                      superblock, metadata blocks, the inode/directory tree and
                      regular-file extraction, from an image file or a
                      partition. gzip today; other codecs are named as
                      unsupported rather than read as empty. A zero
                      modification time is published as not recorded, not as
                      1 January 1970.
                    </td>
                  </tr>
                  <tr>
                    <td>ISO 9660</td>
                    <td>
                      Optical (ECMA-119) with contiguous and multi-extent files.
                      A disc carrying a Joliet tree is named from it (UCS-2 long
                      names, the names the author gave the files); a disc
                      carrying Rock Ridge is named from that instead, with each
                      file&rsquo;s POSIX mode, owner, times and symlink target,
                      and a deep directory the mastering tool relocated is shown
                      where it belongs (if that directory cannot be read, its
                      placeholder is marked incomplete rather than shown as
                      empty). Every entry records which tree its name
                      came from. Rock Ridge sparse and zisofs-compressed files
                      are flagged, not decoded.
                    </td>
                  </tr>
                  <tr>
                    <td>UDF</td>
                    <td>
                      UDF on a physical partition (authored DVDs, the UDF half
                      of a UDF-bridge disc), on a burned CD-R/DVD-R/BD-R (VAT),
                      on rewritable media (sparable) and at UDF 2.50+ (metadata
                      partition), with 512-, 2,048- or 4,096-byte sectors. Only
                      UDF 1.02 has been graded on a real disc; the other kinds
                      are graded on self-made volumes of UDF 1.50, 2.01 and 2.50.
                      A bridge disc (every Windows install ISO) shows both
                      halves, ISO 9660 and UDF, each marked as a bridge and
                      neither as a hidden filesystem; the ISO half may hold only
                      a README while the UDF half holds the files. Content of any
                      size is served from its extents. A deleted directory entry
                      is listed as deleted. A partition map of another kind, or a
                      VAT, sparing table or metadata file that cannot be read,
                      is refused, and the volume record names why rather than
                      showing an empty disc. A file whose extents run past the
                      end of a truncated image, or whose recorded content is
                      shorter than its size, is marked incomplete. On a
                      multisession burned disc the last session is read and
                      earlier sessions&apos; tables are located but not listed;
                      other multisession discs are read only as the session the
                      anchor names, and further sessions are not detected.
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
            <div className="help-table-wrap">
              <table className="help-table">
                <caption>Containers and images</caption>
                <thead>
                  <tr>
                    <th>Format</th>
                    <th>Notes</th>
                  </tr>
                </thead>
                <tbody>
                  <tr>
                    <td>
                      <code>E01</code> / EWF
                    </td>
                    <td>
                      Multi-segment, compression, and acquisition metadata via
                      libewf. A logical evidence file (<code>.L01</code>, told
                      apart by its <code>LVF</code> signature) has its entry
                      tree walked through libewf and every entry published as a
                      file with its recorded name, path, size, times and stored
                      MD5, up to 1,000,000 entries and 256 levels, a ceiling
                      reached being stated on its inventory record. Data EnCase
                      stores against a directory entry is not served, an entry
                      flagged sparse is marked unvalidated, and an{" "}
                      <code>.Lx01</code> is not read.
                    </td>
                  </tr>
                  <tr>
                    <td>AFF4</td>
                    <td>
                      ZIP container with RDF metadata; ImageStream and Map
                      reconstruction.
                    </td>
                  </tr>
                  <tr>
                    <td>
                      Raw <code>dd</code>
                    </td>
                    <td>Bit-for-bit images.</td>
                  </tr>
                  <tr>
                    <td>VMDK</td>
                    <td>
                      Sparse.{" "}
                      <span className="no">
                        StreamOptimized/compressed rejected, not misread.
                      </span>
                    </td>
                  </tr>
                  <tr>
                    <td>VHD / VHDX</td>
                    <td>
                      Fixed and dynamic (VHDX Hyper-V v2).{" "}
                      <span className="no">
                        Differencing disks unsupported.
                      </span>
                    </td>
                  </tr>
                  <tr>
                    <td>QCOW2</td>
                    <td>
                      L1/L2 cluster mapping.{" "}
                      <span className="no">
                        Compressed and backing images unsupported.
                      </span>
                    </td>
                  </tr>
                  <tr>
                    <td>Apple sparseimage</td>
                    <td>
                      Band-mapped <code>.sparseimage</code>; unwritten bands
                      read as zeros, truncated bands fail closed.
                    </td>
                  </tr>
                  <tr>
                    <td>ZIP / archives</td>
                    <td>
                      ZIP, gzip, bzip2, xz, 7z, OLE2 — expanded recursively.
                    </td>
                  </tr>
                  <tr>
                    <td>iOS backup</td>
                    <td>iTunes/Finder backups, encrypted or plain.</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </section>

          <section id="encryption">
            <h2>Encrypted volumes</h2>
            <p>
              Séance is honest about the difference between{" "}
              <strong>detecting</strong> encryption and being able to{" "}
              <strong>decrypt</strong> it. Detected-but-locked volumes are
              flagged so they are never silently skipped, and never presented as
              if their contents had been read.
            </p>
            <div className="help-table-wrap">
              <table className="help-table">
                <caption>Encryption handling</caption>
                <thead>
                  <tr>
                    <th>Scheme</th>
                    <th>Support</th>
                    <th>Detail</th>
                  </tr>
                </thead>
                <tbody>
                  <tr>
                    <td>LUKS 1 / 2</td>
                    <td className="yes">Decrypt with passphrase</td>
                    <td>
                      PBKDF2 / Argon2 keyslot unlock over the AES-XTS default
                      cipher; other ciphers are reported unsupported. With no
                      passphrase the volume is reported as locked and reaches
                      the Needs attention queue.
                    </td>
                  </tr>
                  <tr>
                    <td>iOS backup</td>
                    <td className="yes">Decrypt with password</td>
                    <td>
                      Keybag class keys, PBKDF2-derived unwrap, per-file
                      AES-CBC.
                    </td>
                  </tr>
                  <tr>
                    <td>BitLocker</td>
                    <td className="yes">
                      Decrypt with password or recovery key
                    </td>
                    <td>
                      AES-XTS 128/256 (Windows 8+) and AES-CBC with the Elephant
                      diffuser 128/256 (Vista/7/8). Each cipher family is
                      validated against a real Windows volume of its own era:
                      XTS-AES-256 against a Windows 11 25H2 system disk, the
                      diffuser against a Vista-era BitLocker To Go volume.
                      Volumes still mid-encryption are recognised too, and the
                      decrypted view puts the relocated boot sectors back so the
                      filesystem mounts. Plain AES-CBC without the diffuser has
                      its keys recovered but is not decrypted, and says so
                      rather than emitting bytes.
                    </td>
                  </tr>
                  <tr>
                    <td>FileVault 2 / APFS</td>
                    <td className="partial">Detect only</td>
                    <td>
                      Encrypted volumes flagged; only volume metadata is
                      emitted.
                    </td>
                  </tr>
                  <tr>
                    <td>NTFS EFS</td>
                    <td className="partial">Detect only</td>
                    <td>
                      Encrypted files flagged <em>Encrypted (EFS)</em> from MFT
                      metadata.
                    </td>
                  </tr>
                  <tr>
                    <td>Encrypted ZIP</td>
                    <td className="partial">Detect only</td>
                    <td>Flagged from the local-file-header encryption bit.</td>
                  </tr>
                </tbody>
              </table>
            </div>
            <p>
              A general encryption detector additionally flags high-entropy
              regions as <em>possibly encrypted</em>. A LUKS passphrase is
              supplied at ingestion. An encrypted iOS backup, a Signal for
              Android backup and a WhatsApp <code>.crypt14</code> backup can
              also be opened <em>afterwards</em>, from the record itself. The
              unlock box is offered on those three locked records only — an
              encrypted iOS backup, a Signal for Android backup, and a
              WhatsApp backup still waiting for its key — and on nothing else
              that ingests locked; an iOS backup that decrypted with parts
              missing gets no box, because a password already worked there.
              The artifact shows the box, and the
              secret you type there is held in memory for that one run only
              and cleared when it ends — it is never written to the job, the
              audit detail or the artifact, and no restart is needed. The audit
              log records that a password was supplied and whether it opened
              the backup, never the password. The box reports the job&rsquo;s
              outcome: <em>Passphrase accepted</em> when the run completes, or{" "}
              <em>Not decrypted</em> with the server&rsquo;s reason when it
              fails — a wrong password changes nothing in the case. The box
              reads the job, not the audit verdict: a backup that holds nothing
              the password can be tested against (an iOS keybag with no
              passcode-wrapped class key, a Signal backup that ends after its
              header) completes and shows <em>Passphrase accepted</em> while
              the audit log records no verdict — the audit is the record of
              whether the password was tested.
            </p>
            <p>
              <strong>Reading an encrypted iOS backup&rsquo;s files later.</strong>{" "}
              The password is not kept after the run that opened the backup, and
              the only bytes on disk are ciphertext, so preview, hex, download,
              export and re-hash of those files are refused afterwards, with a
              message naming the unlock route. The Inspector of such a file
              shows <em>Encrypted iOS backup file</em> with a password field
              and <em>Unlock to read</em>. The server checks the password
              against the backup&rsquo;s keybag and, if it opens it, holds the
              backup&rsquo;s unwrapped class keys in its own memory — for this
              case only, for 8 hours by default (the server&rsquo;s{" "}
              <code>SEANCE_UNLOCK_TTL_SECS</code>) — and the backup&rsquo;s
              files then read as their plaintext, except a file whose manifest
              entry carries no key or no protection class, or whose class has
              no key: that one is refused, as it was at ingest. <em>Lock again</em> forgets the keys
              at once, and so do deleting the case and a server restart. Once
              the time limit passes the keys are no longer used, and the server
              drops them from memory within about a minute. After any of these
              the refusal returns. The password itself is not kept, and neither
              it nor the keys are written to the case, an export or the audit
              log; the audit log records each unlock, its outcome, and each
              forget (a lock, a case delete or the time limit) by kind. It needs
              read-write access to the case. Nothing is re-run and nothing is
              added to the case.
            </p>
            <p>
              <strong>Revealing an iOS keychain secret.</strong>{" "}
              An encrypted backup&rsquo;s keychain is listed as{" "}
              <em>iOS Keychain Items</em>: each item&rsquo;s attributes are
              shown, and its secret is withheld — it is not stored in the case,
              shown, exported or searchable. Open an item and its Inspector
              shows <em>Keychain secret</em>. For an item that was read and
              has a secret, <em>Reveal secret</em> asks the server, which
              re-derives the secret from the backup (so the backup must be
              unlocked for reading, as above, from any of its files) and
              records <code>ios_keychain_secret_revealed</code> in the case
              audit log against your account — naming the item, never the
              value — before it answers. If the backup is locked, the audit
              write fails, or your access is read-only, nothing is shown but
              the server&rsquo;s reason after <em>Not revealed</em>. A secret
              whose bytes are not UTF-8 is shown as hex and says so. The value
              stays on screen only until you open another item or leave the
              page; seeing it again is another audited reveal. A device-bound
              item (a ThisDeviceOnly class, whose key is wrapped under the
              phone&rsquo;s hardware key), an item that did not authenticate,
              and an item with no secret have no button, and the panel says
              which.
            </p>
            <p>
              <strong>Revealing a macOS keychain secret.</strong>{" "}
              A macOS keychain&rsquo;s password items (<em>generic</em> and{" "}
              <em>internet</em> passwords) are listed with their attributes and
              their secret withheld, as above. Open one and its Inspector shows{" "}
              <em>Keychain secret</em> with a password field:{" "}
              <em>Reveal secret</em> sends the keychain password to the server
              (<code>POST /api/v1/cases/&#123;case&#125;/keychain/&#123;item&#125;/reveal</code>),
              which uses it for that one request and keeps it nowhere &mdash;
              the field is cleared as it is sent, and each reveal asks again.
              The server re-reads the keychain file, opens its{" "}
              <code>DbBlob</code> with the password, decrypts the one item, and
              records <code>macos_keychain_secret_revealed</code> in the audit
              log against your account (naming the item, never the value)
              before it answers. A wrong password, a read-only grant, or an
              audit write that fails shows only the server&rsquo;s reason after{" "}
              <em>Not revealed</em>, and a refusal is audited as{" "}
              <code>macos_keychain_reveal_refused</code>. Password items and private
              keys are decrypted (a key comes back as hex, its PKCS#8 bytes);
              a certificate, which is not secret, and the symmetric keys that
              wrap the passwords have no button. A{" "}
              <code>System.keychain</code> is opened with{" "}
              <code>/var/db/SystemKey</code> instead of a password: choose{" "}
              <em>SystemKey (hex)</em> in the credential list and paste the
              file&rsquo;s 48 bytes as 96 hex characters. It is sent as{" "}
              <code>system_key</code>, used for that one request and kept
              nowhere, exactly as a password is.
            </p>
            <p>
              <strong>Reading a decrypted BitLocker or LUKS volume later.</strong>{" "}
              A volume decrypted during a run is recorded beneath the locked
              one, but its key is not kept after that run, so the decrypted
              volume and every partition, file system and file beneath it are
              refused afterwards (never shown as ciphertext), with a message
              naming the unlock route. The Inspector of anything on such a
              volume shows <em>On a decrypted BitLocker volume</em> (or LUKS)
              with a field — for BitLocker, a choice of <em>Password</em> or{" "}
              <em>Recovery password</em> — and <em>Unlock to read</em>. The
              server tries the secret on the locked volume and, if it opens it,
              holds the decrypting key in its own memory under the same rules
              as a backup: this case only, 8 hours by default, forgotten by{" "}
              <em>Lock again</em>, deleting the case, a restart or the time
              limit, each audited by kind, never by value. It needs read-write
              access to the case; nothing is re-run or added to the case. The
              REPL does the same with{" "}
              <code>/unlock --read &lt;artifact_id&gt; &lt;kind&gt; &lt;secret&gt;</code>{" "}
              and <code>/unlock --lock &lt;artifact_id&gt;</code>; the secret is
              redacted from the history and scrollback as for{" "}
              <code>/unlock</code>.
            </p>
            <p>
              A locked record says, correctly, that nothing from it is in the
              case. Once a password opens it, that record is marked{" "}
              <strong>superseded</strong> rather than deleted: it is still
              shown, as history, because the fact that the data was once
              unreadable belongs to the case — but it stops counting as missing
              data, so the completeness figures and the report&rsquo;s
              &ldquo;not recovered&rdquo; section describe what is actually
              absent now. The report says how many earlier statements were
              answered that way.
            </p>
            <p>
              The same marking covers <strong>re-running a parser</strong>. When
              you run a module again on an artifact &mdash; after a password, a
              fetched symbol pack, or a fixed parser &mdash; what the earlier
              run wrote under that artifact is marked superseded by the new run
              rather than left standing beside it, so counts are of one run, not
              two. Record tables grow a <strong>Status</strong> column the
              moment any row on screen is superseded, and the badge names the
              re-run that answered it. Only records of the same kind, written by
              the same module, under the same artifact are marked: a re-parse of
              a mailbox says nothing about the file&rsquo;s hashes or the
              pictures inside it.
            </p>
            <h3>Password recovery (LUKS and BitLocker)</h3>
            <p>
              When no passphrase is known, <code>crack-luks</code> and{" "}
              <code>crack-bitlocker</code> recover one by dictionary and/or
              mask. They are <strong>off by default</strong> — running the
              subcommand is the explicit opt-in — and every candidate is tried
              through the real unlock, so a hit is <em>proven</em> (it decrypted
              the volume), never guessed. A wordlist harvested from the
              suspect's own disk or RAM is the highest-yield source; AES keys
              recovered from a memory image feed the same decryptors directly.
              (A 48-digit BitLocker recovery <em>key</em>
              is not dictionary-recoverable; this is for chosen passwords.)
            </p>
            <pre className="help-code">
              seance crack-luks --volume disk.img \{"\n"}
              {"  "}--wordlist words.txt --mask '?d?d?d?d'
            </pre>
            <h3>RAID / LVM reconstruction</h3>
            <p>
              Evidence seized from a server or NAS often arrives as several
              member disks. <code>assemble-raid</code> reconstructs RAID 0/1/5/6
              or JBOD into one logical image the normal <strong>scan</strong>{" "}
              path then examines. RAID 5 rebuilds one dead member from parity;
              RAID 6 rebuilds <em>any two</em> lost members using the Q syndrome
              (Reed- Solomon over GF(2⁸)). Pass <code>MISSING</code> in a dead
              member's position. Volume groups spanning several physical volumes
              are mapped across all of them.
            </p>
            <pre className="help-code">
              seance assemble-raid --level raid6 --chunk 65536 \{"\n"}
              {"  "}--member d1.img --member MISSING --member d3.img \{"\n"}
              {"  "}--member MISSING --member d5.img --out reconstructed.img
            </pre>
          </section>

          <section id="integrity">
            <h2>Integrity and audit</h2>
            <p>
              Evidence integrity is tracked from acquisition through
              examination.
            </p>
            <ul>
              <li>
                Acquisition hashes embedded in E01 images are stored with the
                source artifact.
              </li>
              <li>
                <strong>Verify Integrity</strong> recomputes MD5, SHA1, and
                SHA256 over the evidence and compares them to the stored values,
                reporting Verified, Mismatch, No baseline, or No reference hash.
              </li>
              <li>
                The audit log records every examiner action in the case — with
                timestamp, user, action, and resource — and exports as CSV for
                disclosure.
              </li>
            </ul>
          </section>

          <section id="soundness">
            <h2>Forensic soundness</h2>
            <p>
              The platform is built so that findings hold up to scrutiny. The
              key invariants:
            </p>
            <ul>
              <li>
                <strong>Acquisition hashing.</strong> Every source is hashed on
                ingest before analysis, establishing the baseline that Verify
                Integrity later checks against.
              </li>
              <li>
                <strong>Hash-chained audit log.</strong> Each audit entry is
                linked to the previous one by hash. The chain is tamper-evident
                only when the server holds an audit key (
                <code>SEANCE_AUDIT_HMAC_KEY</code>); unkeyed, a verification
                shows the log is internally consistent, not that it is
                unaltered. <strong>Verify chain</strong> on the Audit Log page
                states which it is, and on a log that was keyed part-way
                through, the entry from which the chain is tamper-evident.
              </li>
              <li>
                <strong>Provenance.</strong> Every artifact records its parent,
                giving an unbroken lineage from a parsed record back to the
                original evidence source.
              </li>
              <li>
                <strong>Content-based detection.</strong> Modules identify data
                by its bytes, not its filename, so disguised files are still
                parsed correctly.
              </li>
              <li>
                <strong>Honest recovery flags.</strong> Deleted, carved,
                fragmented, and reconstructed content is labelled as such —
                including <em>Unverified recovery</em> and{" "}
                <em>Content not reconstructed</em> — so its provenance is never
                overstated.
              </li>
              <li>
                <strong>UTC everywhere.</strong> All timestamps are stored and
                displayed in UTC to avoid timezone ambiguity when correlating
                sources.
              </li>
            </ul>
          </section>

          <section id="shortcuts">
            <h2>Keyboard shortcuts</h2>
            <p className="help-lead">
              Every table and every tree below is a single Tab stop —{" "}
              <strong>one Tab stop for the whole table</strong>, or for the
              whole tree, rather than one per row. Tab reaches it, and the arrow
              keys move inside it. The controls that sit inside a row — a
              checkbox, a star, a caret, a link — are deliberately out of the
              tab order too: a page of 500 timeline events costs one press to
              step past, not the fifteen hundred its checkboxes, stars and note
              buttons would otherwise be. Each of those controls has a key on
              the focused row instead, listed below.
            </p>
            <p>
              Moving with the arrows moves real focus, not just a highlight, so
              a screen reader reads out the row arrived at and the row is
              scrolled into view.
            </p>
            <p>
              Several of these surfaces draw{" "}
              <strong>only the rows near the viewport</strong> and hold the
              height of the rest open, because a case can hold millions of
              records and a table that mounts them all takes the tab down. That
              is a drawing decision, and it is not allowed to decide what you
              can reach: the{" "}
              <strong>keys address the whole set the table is holding</strong>,
              and a row the arrows, Home or End move onto is drawn wherever the
              scroll happens to be. What that SET is differs by surface — a page
              of results here, everything loaded so far there — and each table
              below says which.
            </p>
            <div className="help-table-wrap">
              <table className="help-table">
                <caption>Global</caption>
                <thead>
                  <tr>
                    <th>Keys</th>
                    <th>Action</th>
                  </tr>
                </thead>
                <tbody>
                  <tr>
                    <td>
                      <span className="help-kbd">⌘</span>
                      <span className="help-kbd">K</span> /{" "}
                      <span className="help-kbd">Ctrl</span>
                      <span className="help-kbd">K</span>
                    </td>
                    <td>
                      Open the command palette to jump to a view or search — and
                      press it again to close it. It works from anywhere,
                      including from inside a tree or a table.
                    </td>
                  </tr>
                  <tr>
                    <td>
                      <span className="help-kbd">Esc</span>
                    </td>
                    <td>
                      Close any open modal, right-click menu, command palette,
                      or chart drag-selection.
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
            <div className="help-table-wrap">
              <table className="help-table">
                <caption>Command palette</caption>
                <thead>
                  <tr>
                    <th>Keys</th>
                    <th>Action</th>
                  </tr>
                </thead>
                <tbody>
                  <tr>
                    <td>
                      <span className="help-kbd">↑</span>
                      <span className="help-kbd">↓</span>
                    </td>
                    <td>Move the selection.</td>
                  </tr>
                  <tr>
                    <td>
                      <span className="help-kbd">Enter</span>
                    </td>
                    <td>Open the selected command, or run the typed search.</td>
                  </tr>
                  <tr>
                    <td>
                      <span className="help-kbd">Esc</span>
                    </td>
                    <td>
                      Close it and go nowhere. Focus returns to whatever you
                      were on when you opened it.
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
            <div className="help-table-wrap">
              <table className="help-table">
                <caption>
                  Data tables — Timeline, Audit log, Search results, Parsed
                  records, File browser grid
                </caption>
                <thead>
                  <tr>
                    <th>Keys</th>
                    <th>Action</th>
                  </tr>
                </thead>
                <tbody>
                  <tr>
                    <td>
                      <span className="help-kbd">↑</span>
                      <span className="help-kbd">↓</span>
                    </td>
                    <td>
                      Move to the previous or next row. In the file browser
                      grid, arrowing also selects the row you land on; a
                      ctrl-click or shift-click selection made with the mouse is
                      left alone until you actually move.
                    </td>
                  </tr>
                  <tr>
                    <td>
                      <span className="help-kbd">Home</span>
                      <span className="help-kbd">End</span>
                    </td>
                    <td>
                      First or last row of what the table is holding — which is
                      not the same thing on all five, so the two families are
                      stated separately.
                      <ul>
                        <li>
                          <strong>Timeline</strong>, <strong>Audit log</strong>,{" "}
                          <strong>Search results</strong> and the{" "}
                          <strong>File browser</strong> grid are paged: this is
                          the first or last row <em>of the page you are on</em>,
                          not of the result set. The pager below the table moves
                          between pages.
                        </li>
                        <li>
                          <strong>Parsed records</strong> is not paged. It loads
                          in instalments into one growing table, so End is the{" "}
                          <em>last row loaded so far</em>, which grows as you
                          scroll or press <strong>Load more</strong>. The
                          heading above the table states how many of the
                          type&rsquo;s records are loaded whenever that is fewer
                          than all of them.
                        </li>
                      </ul>
                    </td>
                  </tr>
                  <tr>
                    <td>
                      <span className="help-kbd">Enter</span>
                    </td>
                    <td>
                      Acts on the focused row, and what that means differs by
                      table:
                      <ul>
                        <li>
                          <strong>Timeline</strong> — expands the event&rsquo;s
                          details in place, with a link to open the artifact.
                        </li>
                        <li>
                          <strong>Audit log</strong> — expands the entry&rsquo;s
                          details: the parameters of what was done to the
                          evidence.
                        </li>
                        <li>
                          <strong>Search results</strong> — opens the
                          hit&rsquo;s artifact.
                        </li>
                        <li>
                          <strong>Parsed records</strong> — opens the
                          record&rsquo;s artifact, the same destination as the
                          row&rsquo;s own link.
                        </li>
                        <li>
                          <strong>File browser</strong> — opens the row&rsquo;s
                          artifact, or, in folder view, descends into a folder.
                        </li>
                      </ul>
                    </td>
                  </tr>
                  <tr>
                    <td>
                      <span className="help-kbd">c</span>
                    </td>
                    <td>
                      Copies the focused row&rsquo;s value, in a table that has
                      a <strong>copy column</strong>. It is the keyboard&rsquo;s
                      way to that column&rsquo;s button, which — like every
                      other control inside a row — is deliberately out of the
                      tab order.
                      <ul>
                        <li>
                          One table carries the column today:{" "}
                          <strong>Parsed records</strong> in its{" "}
                          <strong>geotagged photographs</strong> (EXIF) view,
                          where a row copies its{" "}
                          <strong>latitude, longitude</strong> in the form a
                          mapping tool takes. On the other tables the key does
                          nothing, because there is nothing to copy from a row
                          that has no such column.
                        </li>
                        <li>
                          Within that table, a row with nothing to copy — a
                          photograph carrying no GPS — shows no copy button and
                          the key does nothing on it. It never copies a blank or
                          a placeholder.
                        </li>
                        <li>
                          <strong>Ctrl-C</strong> and <strong>&#8984;C</strong>{" "}
                          are untouched: they remain the browser&rsquo;s own
                          copy of whatever text you have selected.
                        </li>
                      </ul>
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
            <div className="help-table-wrap">
              <table className="help-table">
                <caption>Timeline rows</caption>
                <thead>
                  <tr>
                    <th>Keys</th>
                    <th>Action</th>
                  </tr>
                </thead>
                <tbody>
                  <tr>
                    <td>
                      <span className="help-kbd">Space</span>
                    </td>
                    <td>
                      Select or deselect the focused event — the same thing its
                      checkbox does.
                    </td>
                  </tr>
                  <tr>
                    <td>
                      <span className="help-kbd">t</span>
                    </td>
                    <td>Tag or untag the focused event.</td>
                  </tr>
                  <tr>
                    <td>
                      <span className="help-kbd">n</span>
                    </td>
                    <td>
                      Edit the focused event&rsquo;s note. This works{" "}
                      <strong>only on an event you have already tagged</strong>:
                      a note attaches to a tag, so on an untagged event the key
                      deliberately does nothing rather than opening an editor
                      with nothing to save to.
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
            <p className="help-note">
              <strong>These three act on the row.</strong> If focus is inside
              one of the row&rsquo;s own controls the key belongs to that
              control instead. Each control&rsquo;s tooltip names its key, so
              the pairing is discoverable from the row and not only from here.
            </p>
            <div className="help-table-wrap">
              <table className="help-table">
                <caption>
                  Trees — the <strong>Physical</strong> and{" "}
                  <strong>Logical</strong> navigators, and the file
                  browser&rsquo;s <strong>Tree view</strong>
                </caption>
                <thead>
                  <tr>
                    <th>Keys</th>
                    <th>Action</th>
                  </tr>
                </thead>
                <tbody>
                  <tr>
                    <td>
                      <span className="help-kbd">↑</span>
                      <span className="help-kbd">↓</span>
                    </td>
                    <td>
                      Move to the previous or next <em>visible</em> row. Rows
                      that are inside a collapsed branch are not visited, and
                      neither are levels that have not been fetched yet.
                    </td>
                  </tr>
                  <tr>
                    <td>
                      <span className="help-kbd">&rarr;</span>
                    </td>
                    <td>
                      Opens a closed row and leaves focus where it is;{" "}
                      <strong>press it again to step inside</strong>, onto the
                      first child. On a row that holds nothing it does nothing.
                    </td>
                  </tr>
                  <tr>
                    <td>
                      <span className="help-kbd">&larr;</span>
                    </td>
                    <td>
                      Closes an open row; from a row that is already closed, or
                      that holds nothing, it moves to that row&rsquo;s parent.
                    </td>
                  </tr>
                  <tr>
                    <td>
                      <span className="help-kbd">Home</span>
                      <span className="help-kbd">End</span>
                    </td>
                    <td>First or last visible row of the whole tree.</td>
                  </tr>
                  <tr>
                    <td>Type a few letters</td>
                    <td>
                      Jumps to the next row whose name starts with what you
                      typed, wrapping round the end — so pressing the same
                      letter repeatedly walks the matches. Letters typed in
                      quick succession accumulate into one search, which is what
                      lets you separate <code>System32</code> from{" "}
                      <code>SysWOW64</code>; pause, and the next letter starts a
                      new one. If nothing matches what you have typed, nothing
                      moves — you are never silently dropped on a row you did
                      not name. It{" "}
                      <strong>
                        searches only the rows the tree is showing
                      </strong>
                      : a name inside a collapsed branch, or on a level that has
                      not been fetched yet, is not a candidate, so a type-ahead
                      that finds nothing is not evidence that the case holds no
                      such folder. Open the branch and type again.
                    </td>
                  </tr>
                  <tr>
                    <td>
                      <span className="help-kbd">Enter</span>
                    </td>
                    <td>
                      On a row that holds children — a category, a folder, an
                      evidence source — opens or closes it. On a row that holds
                      none, opens it: a record type opens its records, a file
                      opens its artifact.
                    </td>
                  </tr>
                  <tr>
                    <td>
                      <span className="help-kbd">Space</span>
                    </td>
                    <td>
                      Differs between the navigators and the file browser,
                      deliberately. In the <strong>navigator</strong> trees it
                      does what clicking the row&rsquo;s own label does, which
                      is how you open a category that has its own view (Chats,
                      Program Execution, the media categories) without first
                      collapsing it. In the file browser&rsquo;s{" "}
                      <strong>Tree view</strong> it loads the focused file into
                      the <strong>detail pane without leaving the tree</strong>,
                      while Enter commits to opening the artifact — so you can
                      walk a folder reading each file in turn.
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
            <div className="help-table-wrap">
              <table className="help-table">
                <caption>
                  Media gallery — <strong>Gallery</strong>,{" "}
                  <strong>Videos</strong>, <strong>Audio</strong>, and the chat
                  media view
                </caption>
                <thead>
                  <tr>
                    <th>Keys</th>
                    <th>Action</th>
                  </tr>
                </thead>
                <tbody>
                  <tr>
                    <td>
                      <span className="help-kbd">&larr;</span>
                      <span className="help-kbd">&rarr;</span>
                      <span className="help-kbd">↑</span>
                      <span className="help-kbd">↓</span>
                    </td>
                    <td>
                      Move the highlight: left and right by one item, up and
                      down by one row of the grid as it is currently laid out,
                      so the vertical step follows however many columns your
                      window is showing. The highlight stops at the two ends
                      rather than wrapping round. With nothing highlighted yet,
                      the first press highlights the first item.
                    </td>
                  </tr>
                  <tr>
                    <td>
                      <span className="help-kbd">Home</span>
                      <span className="help-kbd">End</span>
                    </td>
                    <td>
                      Jump to the first or the last loaded item — and{" "}
                      <strong>
                        the last loaded item is not the last item there is
                      </strong>
                      . The gallery fetches in pages as you scroll, so End is
                      the end of what has been loaded, not the end of the set:
                      with 4,000 images in the set and 200 fetched, End lands on
                      the 200th. The toolbar states how many of the total are
                      loaded whenever the two differ, and once they are equal
                      End does reach the last item. Home is always the first
                      item of the current sort, because that is where loading
                      starts.
                    </td>
                  </tr>
                  <tr>
                    <td>
                      <span className="help-kbd">Space</span>
                    </td>
                    <td>
                      Opens the lightbox on the highlighted item. With nothing
                      highlighted yet it highlights the first item instead of
                      opening anything, so one press never puts an image on
                      screen that you did not choose. While the lightbox is
                      already open the gallery leaves the key alone — Esc closes
                      it.
                    </td>
                  </tr>
                  <tr>
                    <td>
                      <span className="help-kbd">Enter</span>
                    </td>
                    <td>
                      Opens the lightbox on the highlighted item. Unlike Space
                      it never creates a highlight: with nothing highlighted it
                      does nothing.
                    </td>
                  </tr>
                  <tr>
                    <td>
                      <span className="help-kbd">b</span>
                    </td>
                    <td>
                      Bookmark the highlighted item, or remove its bookmark if
                      it already has one — the same toggle as its right-click
                      menu. An item with no artifact behind it cannot be
                      bookmarked and the key does nothing on it.
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
            <p className="help-note">
              <strong>
                The arrows, Home and End work whether or not the lightbox is
                open
              </strong>
              : it always shows the highlighted item, so these keys page through
              the images inside it as well as in the grid. They are claimed only
              when focus is on the page background or inside the gallery — a
              control elsewhere on the page keeps its own behaviour — and none
              of these keys fire while you are typing in a field or working a
              drop-down.
            </p>
            <p className="help-note">
              An item with no artifact behind it — a chat attachment whose file
              is <strong>not in evidence</strong>, which the cell says on its
              face — has no bytes to show and none to bookmark, so Space, Enter
              and <span className="help-kbd">b</span> all do nothing on it. The
              arrows still move onto it: it is an item in the set, and skipping
              it would hide from the keyboard something the grid shows.
            </p>
            <div className="help-table-wrap">
              <table className="help-table">
                <caption>Right-click menu</caption>
                <thead>
                  <tr>
                    <th>Keys</th>
                    <th>Action</th>
                  </tr>
                </thead>
                <tbody>
                  <tr>
                    <td>
                      <span className="help-kbd">↑</span>
                      <span className="help-kbd">↓</span>
                    </td>
                    <td>
                      Move between the items, wrapping round: past the last item
                      is the first one.
                    </td>
                  </tr>
                  <tr>
                    <td>
                      <span className="help-kbd">Home</span>
                      <span className="help-kbd">End</span>
                    </td>
                    <td>First or last item.</td>
                  </tr>
                  <tr>
                    <td>
                      <span className="help-kbd">Enter</span> /{" "}
                      <span className="help-kbd">Space</span>
                    </td>
                    <td>Run the focused item.</td>
                  </tr>
                  <tr>
                    <td>
                      <span className="help-kbd">Esc</span>
                    </td>
                    <td>
                      Close it. Focus goes back to whatever opened the menu, so
                      you keep your place in the tree or the table.
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
            <div className="help-table-wrap">
              <table className="help-table">
                <caption>Disk map and allocation map</caption>
                <thead>
                  <tr>
                    <th>Keys</th>
                    <th>Action</th>
                  </tr>
                </thead>
                <tbody>
                  <tr>
                    <td>
                      <span className="help-kbd">Tab</span>
                    </td>
                    <td>
                      Step between cells. These maps have{" "}
                      <strong>no arrow-key navigation</strong>: unlike the
                      tables and trees above, every cell is its own tab stop.
                    </td>
                  </tr>
                  <tr>
                    <td>
                      <span className="help-kbd">Enter</span> /{" "}
                      <span className="help-kbd">Space</span>
                    </td>
                    <td>Open the focused cell.</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </section>

          <section id="tips">
            <h2>Tips and good practice</h2>
            <ul>
              <li>
                All timestamps in Séance are displayed in UTC; convert
                deliberately when correlating with local sources.
              </li>
              <li>
                An export is of the set you have filtered to,{" "}
                <strong>not the page you are looking at</strong>: the timeline
                export writes every event matching the filters in force, the
                search export walks the whole match set, the audit-log export
                carries the filters on screen, and the file-browser exports
                carry your selection. Changing the rows per page first changes
                none of them.
              </li>
              <li>
                Deleting an artifact shows its deletion impact first: how many
                child artifacts and timeline events go with it.
              </li>
              <li>
                Prefer notable hash sets over manual searching for recurring
                indicators; matches surface automatically as files are hashed.
              </li>
              <li>
                Bookmark as you go. A well-curated bookmark set with categories
                and notes becomes the backbone of the exported report.
              </li>
            </ul>
          </section>

          {q && results.length === 0 && (
            <p className="help-noresults">No help sections match “{query}”.</p>
          )}
        </div>
      </div>
    </div>
  );
}
