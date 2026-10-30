import { useMemo, useState } from "react";
import type { ReactNode } from "react";
import {
  formatBytes,
  formatCount,
  formatDecimal,
  formatUtc,
} from "../../lib/format";
import type { ParsedRecord, RecordMetadata } from "./api";
import {
  ArtifactLink,
  MonoTrunc,
  PivotList,
  PivotMono,
  Val,
  timeCell,
  toIso,
  type Column,
} from "./cells";
import {
  MISSING,
  humanizeKey,
  metaBool,
  metaFirst,
  metaNum,
  metaStr,
} from "./lib";
import { ScopeBadgeFor } from "../../components/MeasuredScope";
import { incompleteReasonLabel } from "../../lib/incompleteness";
import {
  ENTROPY_SCOPE,
  RECYCLE_ORIGINAL_PATH_SCOPE,
  formatExtent,
  readScope,
  scopeLabelSuffix,
} from "../../lib/measuredScope";
import {
  IMessageViewer,
  WhatsAppViewer,
  AndroidSmsViewer,
  SignalViewer,
  InstagramViewer,
  SnapchatViewer,
  TwitterDmViewer,
  ViberViewer,
  KikViewer,
  SkypeViewer,
  LineViewer,
  TelegramViewer,
  MessengerViewer,
  WeChatViewer,
} from "./MessagingViewer";
import { SqliteViewer } from "./SqliteViewer";
import { makeChatMediaViewer } from "./ChatMediaViewer";
import { CalendarViewer } from "./CalendarViewer";
import { EmailViewer } from "./EmailViewer";
import { CallLogViewer } from "./CallLogViewer";
import { ContactViewer } from "./ContactViewer";
import { PlistViewer } from "./PlistViewer";
import { RecordTable } from "./RecordTable";
import { makeRichViewer } from "./RichRecordViewer";
import { WindowsTimelineViewer } from "./WindowsTimelineViewer";
import { FeatureHistogramViewer } from "./FeatureHistogramViewer";
import {
  LinuxMountsViewer,
  LinuxOpenFilesViewer,
} from "./LinuxMemoryPathViewers";
import {
  MemoryBigPoolViewer,
  MemoryHiveCellRoutinesViewer,
  MemoryMbrScanViewer,
  MemoryProcessorBlocksViewer,
  MemoryScheduledTasksViewer,
  MemoryTrueCryptViewer,
  MemoryConsoleHistoryViewer,
  MemoryVersionInfoViewer,
  MemoryVirtualMapViewer,
} from "./WindowsMemoryStageViewers";
import type { StatTile, StatTone } from "./RichCharts";

export interface ViewerProps {
  records: ParsedRecord[];
  caseId: string;
  type: string;
}

export interface ViewerDef {
  Component: (props: ViewerProps) => ReactNode;
  /**
   * Aggregating viewers fetch the whole dataset across pages themselves; the
   * page shell hides its own pager for them.
   */
  aggregate?: boolean;
  /**
   * The fixed column list a table viewer was built from, where it has one.
   *
   * Exposed so the sort contract can be pinned: a column's `sortKey` is a
   * promise about which metadata key the SERVER is asked to order on, and
   * nothing the plain table shell renders today puts that key in the DOM.
   */
  columns?: Column[];
}

// ---------------------------------------------------------------------------
// Generic table factory + column helpers
// ---------------------------------------------------------------------------

/**
 * Build a viewer that renders a fixed set of columns plus a trailing link to
 * each record's artifact page, through the shared record table: a windowed
 * DOM, one tab stop, and arrow-key movement over every row the viewer holds.
 */
function makeTableViewer(columns: Column[]): (props: ViewerProps) => ReactNode {
  return function TableViewer({ records, caseId }: ViewerProps) {
    return <RecordTable records={records} caseId={caseId} columns={columns} />;
  };
}

const col = (
  key: string,
  header: string,
  render: Column["render"],
): Column => ({
  key,
  header,
  render,
});

/**
 * The key a column of `keys` can be ordered on server-side, or undefined.
 *
 * A column that reads the FIRST PRESENT of several keys cannot be sorted by any
 * one of them: the cell would show a value drawn from the second key while the
 * row was placed by the first, which on a "Time ▼" column is a wrong ordering
 * presented as a chronology. So those columns simply do not offer a sort. One
 * key is one thing the whole record type can be put in order on, and only that
 * gets a header button.
 */
const sortKeyFor = (keys: string[]): string | undefined =>
  keys.length === 1 ? keys[0] : undefined;

/** Plain string column reading the first present of `keys`. */
const strCol = (header: string, keys: string[], mono = false): Column => ({
  ...col(keys[0], header, (m) => {
    const v = metaFirst(m, keys);
    return mono ? (
      <span className="mono">{v ?? MISSING}</span>
    ) : (
      <Val value={v} />
    );
  }),
  sortKey: sortKeyFor(keys),
});

const truncCol = (header: string, keys: string[]): Column => ({
  ...col(keys[0], header, (m) => <MonoTrunc value={metaFirst(m, keys)} />),
  sortKey: sortKeyFor(keys),
});

/**
 * An identifier column: shown like `truncCol`, but every value is a pivot
 * trigger (§1.0). Use it for the things a case is followed by — an address, a
 * hash, an account, a file name, a registry value — and not for a count, a
 * flag or a duration, where "every artifact referencing 4096" is noise.
 */
const pivotCol = (header: string, keys: string[]): Column => ({
  ...col(keys[0], header, (m) => <PivotMono pivotOn={metaFirst(m, keys)} />),
  sortKey: sortKeyFor(keys),
});

/** An identifier column whose value is a list (DNS answers, SIDs). */
const pivotListCol = (header: string, key: string): Column =>
  col(key, header, (m) => {
    const raw = m[key];
    const list = Array.isArray(raw)
      ? raw.filter((a): a is string => typeof a === "string")
      : typeof raw === "string"
        ? [raw]
        : [];
    return <PivotList values={list} />;
  });

const timeCol = (header: string, keys: string[]): Column => ({
  ...col(keys[0], header, (m) => timeCell(m, keys)),
  sortKey: sortKeyFor(keys),
  sortDefaultOrder: "desc",
});

const numCol = (header: string, keys: string[]): Column => ({
  ...col(keys[0], header, (m) => {
    let n: number | null = null;
    for (const k of keys) {
      n = metaNum(m, k);
      if (n != null) break;
    }
    return <span className="mono">{n != null ? formatCount(n) : MISSING}</span>;
  }),
  sortKey: sortKeyFor(keys),
  sortDefaultOrder: "desc",
});

const bytesCol = (header: string, keys: string[]): Column => ({
  ...col(keys[0], header, (m) => {
    let n: number | null = null;
    for (const k of keys) {
      n = metaNum(m, k);
      if (n != null) break;
    }
    return <span className="mono">{n != null ? formatBytes(n) : MISSING}</span>;
  }),
  sortKey: sortKeyFor(keys),
  sortDefaultOrder: "desc",
});

const boolCol = (
  header: string,
  key: string,
  yes: string,
  no: string,
): Column => ({
  // An explicit JSON `null` is a column that recorded nothing (iOS
  // `ZFAVORITE` NULL, HUNT-190): "not recorded", never the `no` answer.
  ...col(key, header, (m) =>
    m[key] === null ? (
      <span className="an-muted">not recorded</span>
    ) : metaBool(m, key) ? (
      <span className="badge badge-accent">{yes}</span>
    ) : (
      <span className="badge">{no}</span>
    ),
  ),
  sortKey: key,
  sortDefaultOrder: "desc",
});

/**
 * The facts one identity file stated, as `key = value` pairs.
 *
 * These records carry a nested `facts` object, and the generic viewer rendered
 * it as one cell of JSON — so "what is this machine called" was answered with a
 * blob. Multi-valued facts (two SIMs, several accounts) are joined, because the
 * record really does hold several values for one question.
 */
const factsCol = (header: string): Column =>
  col("facts", header, (m) => {
    const facts = m.facts;
    if (!facts || typeof facts !== "object" || Array.isArray(facts)) {
      return <span className="muted">{MISSING}</span>;
    }
    const pairs = Object.entries(facts as Record<string, unknown>).map(
      ([key, value]) => {
        const rendered = Array.isArray(value)
          ? value.map(String).join(", ")
          : String(value);
        return `${key} = ${rendered}`;
      },
    );
    if (pairs.length === 0) return <span className="muted">{MISSING}</span>;
    return <span title={pairs.join("\n")}>{pairs.join(" · ")}</span>;
  });

/** Deleted/trashed status: a danger badge when true, muted dash otherwise. */
const delCol = (header: string, key: string): Column => ({
  // `null` is a deletion column that recorded nothing (a NULL voicemail
  // `trashed_date` or Photos `ZTRASHEDSTATE`, HUNT-190), said as such.
  ...col(key, header, (m) =>
    m[key] === null ? (
      <span className="an-muted">not recorded</span>
    ) : metaBool(m, key) ? (
      <span className="badge badge-danger">deleted</span>
    ) : (
      <span className="an-muted">—</span>
    ),
  ),
  sortKey: key,
  sortDefaultOrder: "desc",
});

/**
 * A closed-vocabulary word the parser wrote (`chunk_slack`, `mount_crossing`,
 * `tables_discarded`), shown as a badge with its underscores spaced and the
 * raw word kept in the title. `labels` overrides the spacing where the word
 * needs more than that to read (`unverifiable_truncated`).
 */
const wordCol = (
  header: string,
  key: string,
  labels: Record<string, string> = {},
): Column => ({
  ...col(key, header, (m) => {
    const v = metaStr(m, key);
    if (v == null) return <span className="an-muted">{MISSING}</span>;
    return (
      <span className="badge" title={v}>
        {labels[v] ?? v.replace(/_/g, " ")}
      </span>
    );
  }),
  sortKey: key,
});

/**
 * Shannon entropy as the record states it, over the bytes it was measured on.
 * The byte count travels with the figure: 7.9 bits per byte over 26 bytes and
 * over a mebibyte are different observations.
 */
const entropyCol = (header = "Entropy"): Column => ({
  ...col("entropy_bits_per_byte", header, (m) => {
    const bits = metaNum(m, "entropy_bits_per_byte");
    if (bits == null) return <span className="an-muted">{MISSING}</span>;
    const bytes = metaNum(m, "entropy_bytes");
    return (
      <span className="mono">
        {bits}
        {bytes != null ? ` over ${formatBytes(bytes)}` : ""}
      </span>
    );
  }),
  sortKey: "entropy_bits_per_byte",
  sortDefaultOrder: "desc",
});

/** Recovery sources of an EVTX record, as the parser names them. */
const EVTX_RECOVERY_SOURCE: Record<string, string> = {
  carved_chunk: "carved chunk",
  chunk_slack: "chunk slack",
  loose_record: "loose record",
};

/** Checksum states of a carved chunk, as the parser names them. */
const EVTX_CHECKSUM_STATE: Record<string, string> = {
  unverifiable_truncated: "unverifiable (truncated)",
};

/**
 * How many substitutions of a recovered event could not be bound, with
 * their indices: the partial XML holds a marker at each of those positions,
 * and a reader of the rendered text needs to know which values are missing
 * rather than that "some" are.
 */
function unboundSubstitutions(m: RecordMetadata): string | null {
  const raw = m.incomplete_substitutions;
  if (!Array.isArray(raw) || raw.length === 0) return null;
  const indices = raw
    .map((x) =>
      x && typeof x === "object"
        ? (x as { index?: unknown }).index
        : undefined,
    )
    .filter((i): i is number => typeof i === "number");
  return `${raw.length} (indices ${indices.join(", ")})`;
}

/** The data basis of a recovered registry value, bucketed for the bars. */
function recoveredValueBasis(m: RecordMetadata): string {
  if (m.data_read === false) return "not read";
  const basis = metaStr(m, "data_basis") ?? "";
  if (basis.startsWith("inline")) return "inline in the freed cell";
  if (basis.startsWith("an allocated"))
    return "an allocated cell (may have been reused)";
  if (basis.startsWith("the freed vk")) return "declared empty";
  return basis || MISSING;
}

// ---------------------------------------------------------------------------
// EXIF viewer with offline GPS map
// ---------------------------------------------------------------------------

interface GpsPoint {
  id: string;
  lat: number;
  lon: number;
}

/**
 * Very rough continent outlines in [lon, lat] pairs for an equirectangular
 * projection. Decorative only — the plotted dots carry the accurate data.
 * No external tiles or CDN: fully offline / air-gap safe.
 */
const CONTINENTS: number[][][] = [
  [
    [-168, 65],
    [-160, 71],
    [-95, 72],
    [-82, 63],
    [-64, 60],
    [-55, 47],
    [-80, 26],
    [-98, 18],
    [-106, 23],
    [-124, 40],
    [-130, 54],
    [-168, 65],
  ],
  [
    [-81, 8],
    [-60, 10],
    [-35, -6],
    [-40, -23],
    [-58, -40],
    [-72, -52],
    [-76, -18],
    [-81, 8],
  ],
  [
    [-17, 21],
    [10, 37],
    [32, 31],
    [43, 11],
    [51, 12],
    [40, -5],
    [35, -25],
    [20, -35],
    [12, -18],
    [8, 4],
    [-17, 21],
  ],
  [
    [-10, 36],
    [-9, 44],
    [2, 51],
    [5, 61],
    [30, 60],
    [40, 48],
    [28, 41],
    [15, 40],
    [3, 43],
    [-10, 36],
  ],
  [
    [40, 48],
    [60, 66],
    [100, 76],
    [160, 70],
    [180, 65],
    [140, 45],
    [122, 30],
    [108, 18],
    [95, 20],
    [78, 8],
    [68, 24],
    [55, 25],
    [45, 40],
    [40, 48],
  ],
  [
    [113, -22],
    [131, -12],
    [142, -11],
    [153, -28],
    [146, -39],
    [129, -32],
    [115, -34],
    [113, -22],
  ],
];

const MAP_W = 360;
const MAP_H = 180;

/** Equirectangular projection into the 360x180 SVG viewbox. */
function project(lon: number, lat: number): [number, number] {
  return [lon + 180, 90 - lat];
}

function polygonPoints(ring: number[][]): string {
  return ring
    .map(([lon, lat]) => {
      const [x, y] = project(lon, lat);
      return `${x.toFixed(1)},${y.toFixed(1)}`;
    })
    .join(" ");
}

function GpsMap({
  points,
  active,
  onSelect,
}: {
  points: GpsPoint[];
  active: string | null;
  onSelect: (id: string) => void;
}) {
  const graticule: ReactNode[] = [];
  for (let lon = -180; lon <= 180; lon += 30) {
    const [x] = project(lon, 0);
    graticule.push(
      <line
        key={`v${lon}`}
        x1={x}
        y1={0}
        x2={x}
        y2={MAP_H}
        className="an-map-graticule"
      />,
    );
  }
  for (let lat = -90; lat <= 90; lat += 30) {
    const [, y] = project(0, lat);
    graticule.push(
      <line
        key={`h${lat}`}
        x1={0}
        y1={y}
        x2={MAP_W}
        y2={y}
        className="an-map-graticule"
      />,
    );
  }

  return (
    <div className="an-map-wrap">
      <svg
        className="an-map"
        viewBox={`0 0 ${MAP_W} ${MAP_H}`}
        role="img"
        aria-label="World map of photo GPS locations"
        data-testid="an-gps-map"
      >
        {CONTINENTS.map((ring, i) => (
          <polygon
            key={i}
            className="an-map-land"
            points={polygonPoints(ring)}
          />
        ))}
        {graticule}
        {points.map((p) => {
          const [cx, cy] = project(p.lon, p.lat);
          const isActive = active === p.id;
          return (
            <circle
              key={p.id}
              cx={cx}
              cy={cy}
              r={isActive ? 3.5 : 2.5}
              className={
                isActive ? "an-map-dot an-map-dot-active" : "an-map-dot"
              }
              data-testid={`an-gps-dot-${p.id}`}
              data-lon={p.lon}
              data-lat={p.lat}
              onClick={() => onSelect(p.id)}
            >
              <title>{`GPS ${p.lat}, ${p.lon}`}</title>
            </circle>
          );
        })}
      </svg>
    </div>
  );
}

function exifGps(meta: RecordMetadata): { lat: number; lon: number } | null {
  const lat = metaNum(meta, "gps_lat");
  const lon = metaNum(meta, "gps_lon");
  if (lat == null || lon == null) return null;
  return { lat, lon };
}

/**
 * Columns of the EXIF table.
 *
 * No sort headers: this viewer is mounted by `RecordsViewerPage`, which owns
 * the fetch and does not take an ordering, so there is nothing to hand a
 * header click to. `datetime_original` carries a `sortKey` for the day that
 * changes — it is the one column here that IS a single metadata key. The camera
 * cell joins make and model, and dimensions and coordinates are pairs, so none
 * of those is something the whole record type could be put in order on; a
 * header that re-sorted the loaded rows instead would be ranking a slice.
 */
const EXIF_COLUMNS: Column[] = [
  col("camera", "Camera", (m) => {
    const joined = [metaStr(m, "make"), metaStr(m, "model")]
      .filter(Boolean)
      .join(" ");
    return <Val value={metaStr(m, "camera") ?? (joined || null)} />;
  }),
  {
    key: "datetime_original",
    header: "Taken",
    sortKey: "datetime_original",
    render: (m) => {
      const taken = metaStr(m, "datetime_original");
      return (
        <span className="mono">{formatUtc(taken ? toIso(taken) : null)}</span>
      );
    },
  },
  col("dimensions", "Dimensions", (m) => {
    const w = metaNum(m, "width");
    const h = metaNum(m, "height");
    return (
      <span className="mono">
        {w != null && h != null ? `${w}×${h}` : MISSING}
      </span>
    );
  }),
  col("gps", "GPS", (m) => {
    const g = exifGps(m);
    return g ? (
      <span className="mono">{`${g.lat}, ${g.lon}`}</span>
    ) : (
      <>{MISSING}</>
    );
  }),
];

/** Coordinates as the examiner would paste them into a mapping tool. */
function gpsText(m: RecordMetadata): string | null {
  const g = exifGps(m);
  return g ? `${g.lat}, ${g.lon}` : null;
}

/**
 * Photographs with their EXIF, over an offline world map.
 *
 * The table used to be hand-written, and that cost it everything the shared
 * one provides: every record was a live `<tr>`, each carried its own
 * `tabIndex=0`, and the copy button inside each was a further tab stop — so a
 * case with a hundred thousand photographs built an unbounded DOM and put an
 * unbounded run of tab stops between the map and whatever followed. The one
 * capability it had that the shared table did not was that copy button, which
 * now lives on `RecordTable` for every table to use rather than justifying a
 * bespoke one here.
 *
 * Selection is shared between the map and the table in both directions, and it
 * follows the keyboard as well as the mouse: `RecordTable` reports a row the
 * arrows moved onto, so the pin tracks an examiner who never touches the
 * pointer.
 */
function ExifViewer({ records, caseId }: ViewerProps): ReactNode {
  const [active, setActive] = useState<string | null>(null);

  const points = useMemo<GpsPoint[]>(
    () =>
      records
        .map((r) => {
          const g = exifGps(r.metadata);
          return g ? { id: r.id, lat: g.lat, lon: g.lon } : null;
        })
        .filter((p): p is GpsPoint => p != null),
    [records],
  );

  return (
    <div>
      {points.length > 0 && (
        <GpsMap points={points} active={active} onSelect={setActive} />
      )}
      <RecordTable
        records={records}
        caseId={caseId}
        columns={EXIF_COLUMNS}
        rowClassName="an-gps-row"
        selectedId={active}
        onSelect={(r) => setActive(r.id)}
        copy={{
          header: "",
          label: "Copy coordinates",
          value: (m) => gpsText(m),
        }}
      />
    </div>
  );
}

// ---------------------------------------------------------------------------
// SRUM viewer — flattens aggregate table records into per-row rows
// ---------------------------------------------------------------------------

const SRUM_ROW_HIDDEN = new Set([
  "app",
  "app_id",
  "user",
  "user_id",
  "timestamp",
]);

function SrumViewer({ records, caseId }: ViewerProps): ReactNode {
  const rows: { key: string; parentId: string; row: RecordMetadata }[] = [];
  for (const r of records) {
    const arr = r.metadata["records"];
    if (Array.isArray(arr)) {
      arr.forEach((row, i) => {
        if (row && typeof row === "object") {
          rows.push({
            key: `${r.id}-${i}`,
            parentId: r.id,
            row: row as RecordMetadata,
          });
        }
      });
    }
  }

  if (rows.length === 0) {
    return (
      <div className="empty-state">
        <h3>No SRUM rows</h3>
        <p>These SRUM tables contained no per-application rows.</p>
      </div>
    );
  }

  return (
    <table className="data-table an-table">
      <thead>
        <tr>
          <th>Application</th>
          <th>User</th>
          <th>Time</th>
          <th>Metrics</th>
          <th>Artifact</th>
        </tr>
      </thead>
      <tbody>
        {rows.map(({ key, parentId, row }) => {
          const metrics = Object.entries(row).filter(
            ([k, v]) => !SRUM_ROW_HIDDEN.has(k) && v != null && v !== "",
          );
          return (
            <tr key={key} tabIndex={0}>
              <td>
                <Val value={metaFirst(row, ["app", "app_id"])} />
              </td>
              <td className="mono">
                <Val value={metaFirst(row, ["user", "user_id"])} />
              </td>
              <td>{timeCell(row, ["timestamp"])}</td>
              <td>
                {metrics.length ? (
                  <dl className="an-kv">
                    {metrics.slice(0, 8).map(([k, v]) => (
                      <div key={k} style={{ display: "contents" }}>
                        <dt className="mono">{humanizeKey(k)}</dt>
                        <dd className="mono">{String(v)}</dd>
                      </div>
                    ))}
                  </dl>
                ) : (
                  MISSING
                )}
              </td>
              <td>
                <ArtifactLink caseId={caseId} id={parentId}>
                  open
                </ArtifactLink>
              </td>
            </tr>
          );
        })}
      </tbody>
    </table>
  );
}

// ---------------------------------------------------------------------------
// Browser history — table plus a top-domains analytic bar chart
// ---------------------------------------------------------------------------

/** Parse a URL's host, tolerating scheme-less values. */
function urlHost(raw: string): string | null {
  try {
    return new URL(raw).hostname || null;
  } catch {
    const m = raw.match(/^(?:[a-z]+:\/\/)?([^/:?#]+)/i);
    return m ? m[1] : null;
  }
}

function DomainChart({ records }: { records: ParsedRecord[] }): ReactNode {
  const top = useMemo(() => {
    const counts = new Map<string, number>();
    for (const r of records) {
      const url = metaStr(r.metadata, "url");
      if (!url) continue;
      const host = urlHost(url);
      if (!host) continue;
      counts.set(host, (counts.get(host) ?? 0) + 1);
    }
    return [...counts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 10);
  }, [records]);

  if (top.length === 0) return null;
  const max = top[0][1];

  return (
    <div className="an-domains" data-testid="an-domain-chart">
      <div className="an-domains-title">Top domains (this page)</div>
      {top.map(([host, n]) => (
        <div key={host} className="an-domain-row" data-testid="an-domain-row">
          <span className="an-domain-name mono" title={host}>
            {host}
          </span>
          <span className="an-domain-bar-wrap">
            <span
              className="an-domain-bar"
              style={{ width: `${Math.max((n / max) * 100, 4)}%` }}
            />
          </span>
          <span className="an-domain-count mono">{n}</span>
        </div>
      ))}
    </div>
  );
}

const BrowserHistoryTable = makeTableViewer([
  truncCol("URL", ["url"]),
  strCol("Title", ["title"]),
  numCol("Visits", ["visit_count"]),
  timeCol("Visit time", ["visit_time"]),
  strCol("Browser", ["browser"]),
]);

function BrowserHistoryViewer(props: ViewerProps): ReactNode {
  return (
    <div>
      <DomainChart records={props.records} />
      <BrowserHistoryTable {...props} />
    </div>
  );
}

// ---------------------------------------------------------------------------
// Generic key/value fallback
// ---------------------------------------------------------------------------

/** Keys that are noise in the generic table (bulky or internal). */
const GENERIC_HIDDEN = new Set(["type", "subtype", "short_desc"]);

/**
 * What a record is ABOUT, ranked ahead of what it merely records.
 *
 * The generic table took the first eight keys in the order the parser wrote
 * them, which is the order they appear in the JSON — so a DNS resolution showed
 * transaction id, opcode, rcode and three booleans, and neither the name that
 * was looked up nor the host that looked it up nor the time (UI-028). Whoever,
 * whatever and when come first now; protocol trivia keeps its place behind
 * them.
 *
 * Deliberately a rank, not an allow-list: an unranked key is still shown, after
 * the ranked ones. A generic viewer that dropped what it did not recognise
 * would hide the one field that mattered on exactly the record types nobody has
 * written a viewer for yet.
 */
const GENERIC_PRIORITY: RegExp[] = [
  /^name$/,
  /(^|_)(path|url|host|domain|address|email|phone|number|account|user|owner|sender|recipient|client|server|source|destination|peer)(_|$)/,
  /(^|_)(time|date|timestamp|created|modified|accessed|started|ended)(_|$)|_at$/,
];

/** Rank of a metadata key for the generic table; lower is shown first. */
export function genericKeyRank(key: string): number {
  const i = GENERIC_PRIORITY.findIndex((re) => re.test(key));
  return i === -1 ? GENERIC_PRIORITY.length : i;
}

/** Columns the generic table shows. Past this the record's own fields are not
 * on the screen, and the count of them is stated rather than left to be
 * discovered — a record whose distinguishing field is the ninth key would
 * otherwise read as one of a kind it is not. */
const GENERIC_COLUMN_LIMIT = 8;

export function GenericViewer({ records, caseId }: ViewerProps): ReactNode {
  const allKeys = useMemo(() => {
    const seen: string[] = [];
    const set = new Set<string>();
    for (const r of records) {
      for (const k of Object.keys(r.metadata)) {
        if (!set.has(k) && !GENERIC_HIDDEN.has(k)) {
          const v = r.metadata[k];
          // Skip huge nested arrays/objects in the flat table.
          if (Array.isArray(v) && v.length > 0 && typeof v[0] === "object")
            continue;
          set.add(k);
          seen.push(k);
        }
      }
    }
    // A stable sort by rank: within a tier the parser's own order is kept, so
    // a record type whose keys are all equally ranked reads exactly as before.
    return seen
      .map((key, index) => ({ key, index, rank: genericKeyRank(key) }))
      .sort((a, b) => a.rank - b.rank || a.index - b.index)
      .map((entry) => entry.key);
  }, [records]);
  const keys = useMemo(
    () => allKeys.slice(0, GENERIC_COLUMN_LIMIT),
    [allKeys],
  );
  const hidden = allKeys.length - keys.length;

  // The discovered keys become ordinary columns, so the generic fallback gets
  // the same windowing and keyboard contract as every tailored viewer rather
  // than its own second-best table.
  const columns = useMemo(
    () =>
      keys.map((k) => ({
        key: k,
        header: humanizeKey(k),
        render: (m: RecordMetadata) => <MonoTrunc value={metaStr(m, k)} />,
      })),
    [keys],
  );

  return (
    <>
      {hidden > 0 ? (
        // Silence here is the defect: on the wireless profiles it meant a
        // cleartext passphrase, a DPAPI-protected key and no key at all
        // rendered as three identical rows, because `key_state` was the
        // ninth field.
        <p className="an-muted an-small">
          This record type has no tailored view, so the table shows the{" "}
          {keys.length} fields ranked highest and <strong>{hidden} more are
          on each record and not shown here</strong>. Open a record to read
          all of them.
        </p>
      ) : null}
      <RecordTable records={records} caseId={caseId} columns={columns} />
    </>
  );
}

// ---------------------------------------------------------------------------
// Registry: type string -> tailored viewer
// ---------------------------------------------------------------------------

const srumViewer: ViewerDef = { Component: SrumViewer };

// ---------------------------------------------------------------------------
// Shared helpers for the rich (analytics) viewers
// ---------------------------------------------------------------------------

/** Lower-cased extension of a path, "(none)" when there is none. */
function extOf(path: string | null): string | null {
  if (!path) return null;
  const base = path.split(/[\\/]/).pop() ?? "";
  const dot = base.lastIndexOf(".");
  return dot > 0 ? base.slice(dot + 1).toLowerCase() : "(none)";
}

/** Windows drive ("C:") or leading POSIX segment ("/usr") of a path. */
function driveOf(path: string | null): string | null {
  if (!path) return null;
  const win = path.match(/^([A-Za-z]):[\\/]/);
  if (win) return `${win[1].toUpperCase()}:`;
  const seg = path.split(/[\\/]/).filter(Boolean)[0];
  return seg ? `/${seg}` : null;
}

/** Host of a URL, tolerant of malformed input. */
function domainOf(url: string | null): string | null {
  if (!url) return null;
  try {
    return new URL(url).hostname || null;
  } catch {
    return url.split("/")[2] ?? url;
  }
}

const EVTX_TONE: Record<string, StatTone> = {
  Critical: "critical",
  Error: "error",
  Warning: "warning",
  Information: "ok",
  Verbose: "neutral",
};
const EVTX_LEVEL_ORDER = [
  "Critical",
  "Error",
  "Warning",
  "Information",
  "Verbose",
];

/** Security-relevant Windows event IDs worth flagging in a triage view. */
const NOTABLE_EVENT_IDS: Record<string, string> = {
  "104": "Event log was cleared",
  "1102": "Security audit log was cleared",
  "4624": "Successful account logon",
  "4625": "Failed account logon",
  "4648": "Logon using explicit credentials",
  "4672": "Special privileges assigned to new logon",
  "4688": "New process created",
  "4698": "Scheduled task created",
  "4720": "User account created",
  "4726": "User account deleted",
  "4728": "Member added to a security-enabled global group",
  "4732": "Member added to a security-enabled local group",
  "4740": "User account locked out",
  "4756": "Member added to a security-enabled universal group",
  "7045": "A new service was installed",
};

/** Build severity stat tiles from a level-description key. */
function levelStats(records: { metadata: RecordMetadata }[]): StatTile[] {
  const counts = new Map<string, number>();
  for (const r of records) {
    const lvl = metaStr(r.metadata, "level_description") ?? "Information";
    counts.set(lvl, (counts.get(lvl) ?? 0) + 1);
  }
  const known = EVTX_LEVEL_ORDER.filter((l) => counts.has(l));
  const extras = [...counts.keys()].filter(
    (l) => !EVTX_LEVEL_ORDER.includes(l),
  );
  return [...known, ...extras].map((l) => ({
    key: l,
    label: l,
    count: counts.get(l)!,
    tone: EVTX_TONE[l] ?? "neutral",
  }));
}

/**
 * Human sentence for a signature-mismatch record: what the content actually is
 * versus what its name claims. Null when there is no mismatch. Powers both the
 * per-row notable flag and the Signature column's tooltip.
 */
function fileSigMismatchReason(m: RecordMetadata): string | null {
  if (!metaBool(m, "signature_mismatch")) return null;
  const detected = metaStr(m, "detected_type") ?? "unknown content";
  const ext = metaStr(m, "actual_extension");
  return ext
    ? `Content detected as ${detected}, but the file is named .${ext} — its real type does not match its extension (possible disguised file).`
    : `Content detected as ${detected}, but its extension does not match (possible disguised file).`;
}

/**
 * Human sentence for a trailing-data ("overlay") record: bytes appended after
 * the image's logical end — a file concatenated onto the end to hide it. Null
 * when the file has no overlay.
 */
function fileTrailingReason(m: RecordMetadata): string | null {
  if (!metaBool(m, "trailing_data")) return null;
  const size = metaNum(m, "trailing_size");
  const off = metaNum(m, "trailing_offset");
  const kind = metaStr(m, "trailing_detected_type");
  const bytes = size != null ? `${size} byte(s)` : "extra data";
  const looks = kind ? ` that looks like ${kind}` : "";
  const at = off != null ? ` after the image ends at offset ${off}` : "";
  return `${bytes}${looks} is appended${at} — data hidden past the file's logical end (possible concealed file).`;
}

/**
 * Whether the hidden-data check ran, and what it concluded.
 *
 * `seance_plugin_file_analysis` walks a file to its format's logical end and
 * reports anything appended past it. It has four outcomes, and three of them
 * used to arrive here indistinguishable: a file walked clean wrote
 * `trailing_data: false`, a file whose walk was stopped by a size cap or a
 * short read wrote `trailing_data_undetermined` that nothing read, and a file
 * whose format this build has no walker for (every PDF, every archive, every
 * document) wrote no key at all. All three rendered as the same blank cell in
 * a row tiled "Signature OK".
 *
 * Only `none` is evidence that the file hides nothing. The other three are the
 * check not having produced a result, and an examiner reading "clean" off them
 * is reading a conclusion nobody reached.
 *
 * The words are the ones `pages/memory/normalize.ts` already uses for a value
 * absent for a stated reason, so this is not a third vocabulary.
 */
type TrailingCheck =
  | "found"
  | "none"
  | "undetermined"
  | "not_applicable"
  /** The record carries no outcome at all — it predates the declaration. */
  | "not_stated";

const TRAILING_CHECK_VALUES: readonly TrailingCheck[] = [
  "found",
  "none",
  "undetermined",
  "not_applicable",
];

function isTrailingCheck(value: string): value is TrailingCheck {
  return (TRAILING_CHECK_VALUES as readonly string[]).includes(value);
}

function trailingCheck(m: RecordMetadata): TrailingCheck {
  const declared = metaStr(m, "trailing_data_check");
  if (declared != null) {
    // A token this client does not recognise means the producer and the reader
    // disagree about the vocabulary. That is not a clean result.
    return isTrailingCheck(declared) ? declared : "undetermined";
  }
  // Records written before the outcome was declared. The two older keys still
  // separate the two conclusions the plugin did reach; everything else on such
  // a record is genuinely unstated, and is not promoted to "clean".
  if (metaBool(m, "trailing_data")) return "found";
  if (metaBool(m, "trailing_data_undetermined")) return "undetermined";
  if (m["trailing_data"] === false) return "none";
  return "not_stated";
}

/** The word shown in the cell. Never a blank for a check that did not run. */
const TRAILING_WORD: Record<TrailingCheck, string> = {
  found: "TRAILING",
  none: "none",
  undetermined: "not determined",
  not_applicable: "not applicable",
  not_stated: "not stated",
};

const TRAILING_MEANING: Record<TrailingCheck, string> = {
  found:
    "Bytes were found past this file's format terminator — data hidden past the file's logical end (possible concealed file).",
  none: "This file was walked to its format's logical end and nothing follows it. Nothing is concealed past the end of this file.",
  undetermined:
    "The hidden-data check was attempted on this file and could not reach a conclusion, so the part of the file where an appended payload would sit was never inspected. This is not a finding that the file is clean.",
  not_applicable:
    "This file's format has no logical end that this build knows how to locate, so the hidden-data check never ran. Nothing was inspected and nothing is claimed either way.",
  not_stated:
    "This record carries no hidden-data outcome at all — it was produced before the check declared one. Whether it ran cannot be established from this record.",
};

/**
 * The reason the producer gave, phrased. `incompleteReasonLabel` carries the
 * shared `IncompleteReason` vocabulary (`cap_reached`, `short_read`,
 * `unresolved_structure`), so the two modules stay one vocabulary.
 */
function trailingReasonPhrase(
  m: RecordMetadata,
  check: TrailingCheck,
): string | null {
  if (check === "undetermined") {
    const raw = metaStr(m, "trailing_data_undetermined_reason");
    return raw == null ? null : incompleteReasonLabel(raw);
  }
  if (check === "not_applicable") {
    const raw = metaStr(m, "trailing_data_not_applicable_reason");
    return raw == null ? null : incompleteReasonLabel(raw);
  }
  return null;
}

/** The full hover sentence: what the outcome means, plus why, when stated. */
function trailingSentence(m: RecordMetadata, check: TrailingCheck): string {
  const reason = trailingReasonPhrase(m, check);
  const meaning = TRAILING_MEANING[check];
  return reason ? `${meaning} Reason: ${reason}.` : meaning;
}

/** Combined notability for a file-signature record: a disguised extension or
 * hidden trailing data, whichever applies.
 *
 * Deliberately still only the two findings. A hidden-data check that could not
 * conclude is not a finding about the file, and this column renders a red flag;
 * it is carried instead by its own stat tile and by the Hidden data cell, which
 * name it without asserting anything about the file's contents. */
function fileSigNotable(m: RecordMetadata): string | null {
  return fileSigMismatchReason(m) ?? fileTrailingReason(m);
}

/**
 * Which tile a file-signature record belongs in.
 *
 * `unchecked` exists so that "the hidden-data check could not conclude" and
 * "the hidden-data check found nothing" are not the same number. `not_stated`
 * lands there too: a record that never said whether the check ran cannot be
 * counted as one where it ran and passed. `not_applicable` does not — nothing
 * went wrong on those files, the signature really is OK, and the cell says the
 * check did not apply.
 */
function fileSigStat(m: RecordMetadata): string {
  if (metaBool(m, "signature_mismatch")) return "mismatch";
  const check = trailingCheck(m);
  if (check === "found") return "trailing";
  if (check === "undetermined" || check === "not_stated") return "unchecked";
  return "ok";
}

/**
 * Entropy as it was actually measured, never as if it were the file's.
 *
 * `seance_plugin_file_analysis` computes Shannon entropy over at most the first
 * 192 KiB and declares that on `entropy_sampled` / `entropy_bytes` /
 * `entropy_file_bytes` / `entropy_note`. Nothing read those keys, so a figure
 * derived from a prefix arrived here as the file's entropy — the number an
 * examiner uses to decide whether content is encrypted or packed. An installer
 * with a plaintext manifest ahead of a packed payload measures low over its
 * prefix, and "low entropy: not encrypted" said about bytes nobody measured is
 * a quantitative claim about evidence that was never made. The extent is
 * therefore shown beside the number, in bytes, with the plugin's own sentence.
 */
function entropyCell(m: RecordMetadata): ReactNode {
  const value = metaStr(m, "entropy");
  if (value == null) return <span className="mono">{MISSING}</span>;
  const scope = readScope(m, ENTROPY_SCOPE);
  return (
    <span className="an-sig">
      <span className="mono">
        {value} <ScopeBadgeFor scope={scope} spec={ENTROPY_SCOPE} />
      </span>
      {scope.state === "partial" && (
        <span className="an-sig-detail mono">
          first {scope.measured != null ? formatExtent(scope.measured) : "?"} of{" "}
          {scope.total != null ? formatExtent(scope.total) : "?"} bytes
        </span>
      )}
    </span>
  );
}

/**
 * The entropy classification, carrying the same extent as the figure it was
 * derived from. A class read off a prefix must not render like one read off the
 * whole file: the class is the part an examiner quotes.
 */
function entropyClassCell(m: RecordMetadata): ReactNode {
  const cls = metaStr(m, "entropy_classification");
  if (cls == null) return <span className="mono">{MISSING}</span>;
  const scope = readScope(m, ENTROPY_SCOPE);
  return (
    <span className="an-sig">
      <span>{cls}</span>
      <ScopeBadgeFor scope={scope} spec={ENTROPY_SCOPE} />
    </span>
  );
}

/**
 * Bucket label for the entropy-class frequency bars.
 *
 * A sampled class and a whole-file class are kept in separate bars: the bar is
 * read as "N files are high-entropy", and the sampled ones do not support that
 * about the files, only about their first 192 KiB.
 */
function entropyClassBucket(m: RecordMetadata): string | null {
  const cls = metaStr(m, "entropy_classification");
  if (cls == null) return null;
  return `${cls}${scopeLabelSuffix(readScope(m, ENTROPY_SCOPE), ENTROPY_SCOPE)}`;
}

// ---------------------------------------------------------------------------
// Network flows
// ---------------------------------------------------------------------------

/**
 * One endpoint of a flow as `ip:port`.
 *
 * The port is left off when the flow has none (ICMP has no ports) rather than
 * printed as a zero, because port 0 is a real value on the wire. An IPv6
 * address is bracketed: `2001:db8::1:443` reads as one more hextet, and a
 * port mis-read as part of the address names a different host.
 */
function endpointCell(
  m: RecordMetadata,
  ipKey: string,
  portKey: string,
): ReactNode {
  const ip = metaStr(m, ipKey);
  if (ip == null) return <span className="mono">{MISSING}</span>;
  const port = metaNum(m, portKey);
  const host = ip.includes(":") ? `[${ip}]` : ip;
  // The address is a pivot trigger — one click from a peer to everything in
  // the case that touches it — while the port stays part of the display.
  return (
    <PivotMono pivotOn={ip} display={port == null ? host : `${host}:${port}`} />
  );
}

/**
 * The emission stage's TCP state tokens, spelled. `syn_only` in a table reads
 * as a typo, and an examiner should not have to know the vocabulary to read
 * "a connection attempt that was never answered".
 *
 * The list is `TcpState::as_str` in `seance_plugin_pcap/src/flows.rs`, and
 * every `_no_handshake_seen` token means the same thing: packets flowed but
 * the connection's opening is not in this file, so "closed" or "reset" is a
 * statement about the end of something whose start the capture never saw.
 * `no_transport_seen` is the IP-pair flow whose packets said TCP but ended
 * before a flags byte — no state at all was read, which is different from
 * "no handshake".
 */
const TCP_STATE_LABEL: Record<string, string> = {
  syn_only: "SYN only",
  handshake_seen: "handshake seen",
  handshake_partially_seen: "handshake partially seen",
  established_no_handshake_seen: "established, no handshake seen",
  closed: "closed",
  closed_no_handshake_seen: "closed, no handshake seen",
  reset: "reset",
  reset_no_handshake_seen: "reset, no handshake seen",
  no_transport_seen: "no transport seen",
};

const NETWORK_FLOW_COLUMNS: Column[] = [
  strCol("Protocol", ["protocol"], true),
  // An endpoint is two keys, and addresses order lexically ("10.0.0.10" before
  // "10.0.0.9"), so neither endpoint column offers a sort: a wrong ordering
  // presented as address order is worse than none.
  col("local_ip", "Local", (m) => endpointCell(m, "local_ip", "local_port")),
  col("remote_ip", "Remote", (m) =>
    endpointCell(m, "remote_ip", "remote_port"),
  ),
  {
    // Whether the peer is routable is the column that finds a C2 address, so
    // it is a badge rather than a word in the row. A flow the stage did not
    // classify gets the placeholder: "internal" is the one word that would make
    // an examiner stop looking at it, and a missing verdict is not that word.
    ...col("remote_is_external", "Peer", (m) => {
      const v = m.remote_is_external;
      if (typeof v !== "boolean")
        return <span className="an-muted">{MISSING}</span>;
      return v ? (
        <span className="badge badge-accent">external</span>
      ) : (
        <span className="an-muted">internal</span>
      );
    }),
    sortKey: "remote_is_external",
    sortDefaultOrder: "desc",
  },
  {
    ...col("tcp_state", "State", (m) => {
      const raw = metaStr(m, "tcp_state");
      return <Val value={raw == null ? null : (TCP_STATE_LABEL[raw] ?? raw)} />;
    }),
    sortKey: "tcp_state",
  },
  numCol("Packets", ["packets"]),
  {
    // A packet the snaplen cut is counted at its captured length, so a flow
    // with cut packets carries a byte figure smaller than what crossed the
    // wire. The figure is still shown — it is what the evidence holds — but
    // never on its own.
    ...col("bytes", "Bytes", (m) => {
      const n = metaNum(m, "bytes");
      const cut = metaNum(m, "truncated_packets") ?? 0;
      const incomplete = metaBool(m, "content_incomplete");
      return (
        <>
          <span className="mono">{n != null ? formatBytes(n) : MISSING}</span>
          {cut > 0 ? (
            <>
              {" "}
              <span
                className="badge badge-warn"
                title={`${formatCount(cut)} packet${cut === 1 ? "" : "s"} cut short by the capture snaplen: this byte count excludes what was cut`}
              >
                cut
              </span>
            </>
          ) : incomplete ? (
            <>
              {" "}
              <span
                className="badge badge-warn"
                title={incompleteReasonLabel(
                  metaStr(m, "content_incomplete_reason"),
                )}
              >
                incomplete
              </span>
            </>
          ) : null}
        </>
      );
    }),
    sortKey: "bytes",
    sortDefaultOrder: "desc",
  },
  timeCol("First seen", ["first_seen"]),
  {
    // The stage sends null for a flow with fewer than two timestamped packets,
    // so a zero here is two real timestamps that coincide: a fact, not an
    // unknown. Only null gets the placeholder.
    ...col("duration_seconds", "Duration", (m) => {
      const n = metaNum(m, "duration_seconds");
      return (
        <span className="mono">
          {n == null ? MISSING : `${formatDecimal(n)} s`}
        </span>
      );
    }),
    sortKey: "duration_seconds",
    sortDefaultOrder: "desc",
  },
];

// ---------------------------------------------------------------------------
// HTTP, TLS and ARP out of a packet capture
// ---------------------------------------------------------------------------

/**
 * A nested object on a record's metadata, or null.
 *
 * The HTTP stage writes the request and the response as objects on the
 * transaction (`request.method`, `response.status`), because a transaction is
 * two messages and flattening them would collide every header name they
 * share. `metaStr` reads one level, so these viewers reach in through here
 * rather than rendering a JSON blob — which is what the generic table did.
 */
function sub(m: RecordMetadata, key: string): RecordMetadata | null {
  const v = m[key];
  if (v == null || typeof v !== "object" || Array.isArray(v)) return null;
  return v as RecordMetadata;
}

/** One key off a transaction's request, then its response, first present. */
function msgStr(m: RecordMetadata, key: string): string | null {
  for (const role of ["request", "response"]) {
    const message = sub(m, role);
    if (message == null) continue;
    const v = metaStr(message, key);
    if (v != null) return v;
  }
  return null;
}

/**
 * How a response was matched to its request, spelled.
 *
 * `Pairing` in `seance_plugin_pcap/src/http.rs`. Pairing is an INFERENCE:
 * HTTP/1.1 answers requests on one connection in order, so the nth response is
 * taken to answer the nth request — and over a stream with a hole in it the
 * missing bytes may have held a whole message. The stage's own `pairing_basis`
 * for that case ends "THIS PAIRING MAY BE WRONG", and a row printing a request
 * beside a response with no qualification renders that inference as a fact.
 */
const HTTP_PAIRING_LABEL: Record<string, string> = {
  in_order: "in order",
  in_order_over_a_gap: "in order, over a gap",
  request_unanswered: "no response captured",
  response_unmatched: "no request captured",
};

/** The pairings whose basis this build cannot stand behind. */
const HTTP_PAIRING_UNSAFE = new Set(["in_order_over_a_gap"]);

/**
 * The status classes the tiles split a transaction list by, in the order they
 * are shown.
 *
 * `unanswered` is its own bucket and not folded into an error: a request with
 * no response in the capture is an absence of evidence, and counting it beside
 * the 5xx would turn "the answer was not captured" into "the server failed".
 */
const HTTP_STATUS_CLASSES: [string, string, StatTone][] = [
  ["success", "2xx succeeded", "ok"],
  ["redirect", "3xx redirected", "accent"],
  ["client_error", "4xx client error", "warning"],
  ["server_error", "5xx server error", "error"],
  ["other", "Other status", "neutral"],
  ["unanswered", "No response captured", "neutral"],
];

/** Which status class a transaction falls in. */
function httpStatusClass(m: RecordMetadata): string {
  const response = sub(m, "response");
  const status = response == null ? null : metaNum(response, "status");
  if (status == null) return "unanswered";
  if (status >= 200 && status < 300) return "success";
  if (status >= 300 && status < 400) return "redirect";
  if (status >= 400 && status < 500) return "client_error";
  if (status >= 500 && status < 600) return "server_error";
  return "other";
}

/**
 * What the client actually sent: a posted form's fields and the query
 * string's, as `name = value`.
 *
 * This is the column a fraud or an exfiltration case turns on — a login, a
 * search, a transfer amount — and the generic table left it as a nested blob
 * two levels down. Both sources are shown because a GET form puts its answers
 * in the query and a POST form in the body, and an examiner asking "what did
 * they send" does not know which in advance. The stage bounds both
 * (`MAX_FORM_FIELDS`, `MAX_FORM_VALUE_BYTES`) and counts what it dropped, so
 * a bounded set is never presented here as the whole one.
 */
function httpSentCell(m: RecordMetadata): ReactNode {
  const request = sub(m, "request");
  if (request == null) return <span className="an-muted">{MISSING}</span>;
  const parts: string[] = [];
  let capped = 0;
  let truncated = 0;
  let malformed = 0;
  for (const source of ["form_fields", "query_fields"]) {
    const form = sub(request, source);
    if (form == null) continue;
    const fields = sub(form, "fields");
    if (fields != null) {
      for (const [name, value] of Object.entries(fields)) {
        parts.push(`${name} = ${String(value)}`);
      }
    }
    capped += metaNum(form, "fields_beyond_cap") ?? 0;
    truncated += metaNum(form, "values_truncated") ?? 0;
    malformed += metaNum(form, "malformed_pairs") ?? 0;
  }
  if (parts.length === 0 && capped === 0 && malformed === 0) {
    return <span className="an-muted">{MISSING}</span>;
  }
  // Every way this cell is short of what was sent, named. The whole value is
  // in the body artifact, which is the sentence the badge carries.
  const shortfalls: string[] = [];
  if (capped > 0) {
    shortfalls.push(
      `${formatCount(capped)} further field(s) were past this build's ceiling and are not listed`,
    );
  }
  if (truncated > 0) {
    shortfalls.push(
      `${formatCount(truncated)} value(s) are cut here; the whole value is in the body artifact`,
    );
  }
  if (malformed > 0) {
    shortfalls.push(
      `${formatCount(malformed)} pair(s) carried no "=" and were not invented into fields`,
    );
  }
  return (
    <>
      <span className="an-trunc" title={parts.join("\n")}>
        {parts.length > 0 ? parts.join(" · ") : MISSING}
      </span>
      {shortfalls.length > 0 && (
        <>
          {" "}
          <span className="badge badge-warn" title={shortfalls.join("; ")}>
            part
          </span>
        </>
      )}
    </>
  );
}

/**
 * Why a transaction's messages are a prefix of the real ones, or null.
 *
 * "The response carried no Set-Cookie" is false where the header block ran
 * out first, so this is the one thing on the row an examiner must not read
 * past.
 */
function httpMessagePartial(m: RecordMetadata): string | null {
  for (const role of ["request", "response"]) {
    const message = sub(m, role);
    if (message == null) continue;
    if (!metaBool(message, "headers_complete")) {
      return `the ${role}'s headers are a prefix: its stream ended inside the header block, so headers after the ones read here were never seen`;
    }
    const dropped = metaNum(message, "headers_dropped") ?? 0;
    if (dropped > 0) {
      return `${formatCount(dropped)} header line(s) of the ${role} were past this build's ceiling and were not parsed`;
    }
    const bodyBytes = metaNum(message, "body_bytes") ?? 0;
    if (bodyBytes > 0 && !metaBool(message, "body_is_whole")) {
      return `the ${role}'s body is a prefix of what it declared (${metaStr(message, "body_end") ?? "short"}); the bytes held are the body artifact`;
    }
    if (metaBool(message, "body_capped")) {
      return `the ${role}'s body was cut at this build's ceiling; the whole body is the body artifact`;
    }
  }
  return null;
}

const HTTP_TRANSACTION_COLUMNS: Column[] = [
  col("method", "Method", (m) => {
    const request = sub(m, "request");
    return <Val value={request == null ? null : metaStr(request, "method")} />;
  }),
  // The URL is what an examiner follows, so it is a pivot trigger: one click
  // from this transaction to everything else in the case that touches it. The
  // stage builds it from the request line and the Host header; where the
  // request carried no Host there is no URL to build, and the target — all
  // the request line held — stands in rather than leaving the cell empty.
  col("url", "URL", (m) => (
    <PivotMono pivotOn={metaStr(m, "url") ?? msgStr(m, "target")} />
  )),
  col("host", "Host", (m) => <PivotMono pivotOn={metaStr(m, "host")} />),
  {
    // Status and reason together: "404" is the code and "Not Found" is what
    // this server called it, and a server answering 200 with a phrase of its
    // own is worth seeing. A transaction with no response has neither, and
    // the Paired column says which of the two absences that is.
    ...col("status", "Status", (m) => {
      const response = sub(m, "response");
      const status = response == null ? null : metaNum(response, "status");
      if (status == null) return <span className="an-muted">{MISSING}</span>;
      const reason = response == null ? null : metaStr(response, "reason");
      return (
        <span className="mono">
          {status}
          {reason != null ? ` ${reason}` : ""}
        </span>
      );
    }),
  },
  {
    // What the response CLAIMED its body is, never what the body is: the body
    // is handed on as its own artifact and the ordinary signature analysis
    // reads it, so a declared type disagreeing with the bytes is a finding
    // there and is not quietly corrected here.
    ...col("content_type", "Declared type", (m) => {
      const response = sub(m, "response");
      return (
        <Val
          value={response == null ? null : metaStr(response, "content_type")}
        />
      );
    }),
  },
  col("what_was_sent", "What was sent", httpSentCell),
  col("body_artifact_id", "Body", (m) => {
    const held: string[] = [];
    for (const role of ["request", "response"]) {
      const message = sub(m, role);
      if (message == null) continue;
      if (metaStr(message, "body_artifact_id") != null) held.push(role);
    }
    if (held.length === 0) return <span className="an-muted">none</span>;
    return (
      <span
        className="badge badge-accent"
        title={`The ${held.join(" and ")} body is its own artifact, so the carver, the signature analysis, YARA and the search index all reach it`}
      >
        {held.join(" + ")}
      </span>
    );
  }),
  {
    // A pairing is an inference, and this is where it is qualified. One made
    // across a hole in the stream reads "may be wrong" on the row itself and
    // not only in a tooltip: an examiner quoting a request beside a response
    // has to meet that without hovering.
    ...col("pairing", "Paired", (m) => {
      const raw = metaStr(m, "pairing");
      if (raw == null) return <span className="an-muted">{MISSING}</span>;
      const basis = metaStr(m, "pairing_basis") ?? undefined;
      return (
        <>
          <span title={basis}>
            {HTTP_PAIRING_LABEL[raw] ?? raw.replace(/_/g, " ")}
          </span>
          {HTTP_PAIRING_UNSAFE.has(raw) && (
            <>
              {" "}
              <span className="badge badge-danger" title={basis}>
                may be wrong
              </span>
            </>
          )}
        </>
      );
    }),
    sortKey: "pairing",
  },
  {
    // Whether what is on this row is the whole exchange. A message that is a
    // prefix is named as one, because "incomplete" alone does not tell an
    // examiner that the absence of a header is not evidence of its absence.
    ...col("content_incomplete", "Whole?", (m) => {
      const partial = httpMessagePartial(m);
      const incomplete = metaBool(m, "content_incomplete");
      if (partial == null && !incomplete) {
        return <span className="an-muted">whole</span>;
      }
      const detail =
        metaStr(m, "content_incomplete_detail") ??
        incompleteReasonLabel(metaStr(m, "content_incomplete_reason"));
      return (
        <span
          className="badge badge-warn"
          title={partial != null ? `${partial}; ${detail}` : detail}
        >
          {partial != null ? "a prefix" : "incomplete"}
        </span>
      );
    }),
    sortKey: "content_incomplete",
    sortDefaultOrder: "desc",
  },
];

const TLS_SESSION_COLUMNS: Column[] = [
  // Headed "asked for" on purpose. SNI is what the CLIENT sent; nothing here
  // resolved it, verified it, or compared it against the certificate, and a
  // column headed "Server" would read as this build's own answer to "what
  // host is this". `server_name_source` says the same in the record.
  col("server_name", "Name asked for (SNI)", (m) => {
    const name = metaStr(m, "server_name");
    if (name == null) {
      return (
        <span
          className="an-muted"
          title="This client sent no server_name extension, so the capture holds no name for this session — which is not a statement that the server has none"
        >
          none sent
        </span>
      );
    }
    return (
      <span title={metaStr(m, "server_name_source") ?? undefined}>
        <PivotMono pivotOn={name} />
      </span>
    );
  }),
  col("server_ip", "Server", (m) =>
    endpointCell(m, "server_ip", "server_port"),
  ),
  strCol("Version", ["negotiated_version"]),
  {
    // A known-weak suite is the finding a TLS list exists to surface, so it is
    // a badge beside the suite and not a flag somewhere else. "Known weak" is
    // this build's own list (`cipher_is_known_weak`) and a statement about the
    // suite — not a demonstration that this conversation was broken — and the
    // title says so rather than leaving the badge to imply it.
    ...col("negotiated_cipher", "Cipher", (m) => {
      const cipher = metaStr(m, "negotiated_cipher");
      if (cipher == null) return <span className="an-muted">{MISSING}</span>;
      return (
        <>
          <span className="mono">{cipher}</span>
          {metaBool(m, "cipher_is_known_weak") && (
            <>
              {" "}
              <span
                className="badge badge-danger"
                title="This suite is on this build's known-weak list. That is a statement about the suite, not a demonstration that this conversation was broken."
              >
                known weak
              </span>
            </>
          )}
        </>
      );
    }),
    sortKey: "negotiated_cipher",
  },
  // The client's fingerprint, and the one field here that follows a TOOL
  // rather than a host: the same JA3 on two addresses is the same software.
  // A pivot trigger for exactly that reason.
  pivotCol("JA3", ["ja3_md5"]),
  {
    // The leaf certificate's subject, or the reason there is none. These two
    // must not render alike: an empty cell on a TLS 1.3 session would read as
    // "this server presented no certificate", which no capture of TLS 1.3 can
    // establish — the certificate is inside the encrypted extensions and was
    // never in the bytes.
    ...col("certificate_subject", "Certificate subject", (m) => {
      const subject = metaStr(m, "certificate_subject");
      if (subject != null) return <MonoTrunc value={subject} />;
      const unavailable = metaStr(m, "certificates_unavailable");
      if (unavailable == null) {
        return <span className="an-muted">{MISSING}</span>;
      }
      return (
        <span
          className="badge badge-warn"
          title={
            metaStr(m, "certificates_unavailable_statement") ??
            incompleteReasonLabel(unavailable)
          }
        >
          {unavailable === "encrypted_by_tls13"
            ? "encrypted by TLS 1.3"
            : "not in the cleartext"}
        </span>
      );
    }),
  },
  {
    // How many certificates reached a record of their own, and how many were
    // presented and could not be parsed. The second number is the one that
    // matters: a chain shown as two where three were sent is a false account
    // of what the server presented.
    ...col("certificates", "Certificates", (m) => {
      const n = metaNum(m, "certificates") ?? 0;
      const unparsable = metaNum(m, "unparsable_certificates") ?? 0;
      return (
        <>
          <span className="mono">{formatCount(n)}</span>
          {unparsable > 0 && (
            <>
              {" "}
              <span
                className="badge badge-warn"
                title={`${formatCount(unparsable)} certificate(s) this server presented could not be parsed by this build; they were sent and have no record below`}
              >
                +{formatCount(unparsable)} unparsable
              </span>
            </>
          )}
        </>
      );
    }),
    sortKey: "certificates",
    sortDefaultOrder: "desc",
  },
];

const TLS_CERTIFICATE_COLUMNS: Column[] = [
  pivotCol("Subject", ["subject_common_name", "subject"]),
  strCol("Issuer", ["issuer_common_name", "issuer"]),
  {
    // Whether one of this certificate's own names covers the name the client
    // asked for. The stage is explicit that this is a comparison of two
    // strings and NOT a verification, so the words here are "matches the name
    // asked for" and never "valid for".
    ...col("covers_the_name_requested", "Name matches?", (m) => {
      const covers = m.covers_the_name_requested;
      if (typeof covers !== "boolean") {
        return (
          <span
            className="an-muted"
            title="No server_name was asked for in this session, so there are no two names to compare"
          >
            not compared
          </span>
        );
      }
      const meaning =
        metaStr(m, "covers_the_name_requested_meaning") ?? undefined;
      return covers ? (
        <span className="an-muted" title={meaning}>
          matches the name asked for
        </span>
      ) : (
        <span className="badge badge-warn" title={meaning}>
          no name matches
        </span>
      );
    }),
    sortKey: "covers_the_name_requested",
  },
  timeCol("Valid from", ["not_before"]),
  timeCol("Valid until", ["not_after"]),
  {
    // `self_signed` is subject and issuer being the same string and nothing
    // more — no signature was checked — so the badge says what was compared
    // rather than reaching the verdict "a self-signed certificate".
    ...col("self_signed", "Self-issued?", (m) => {
      if (!metaBool(m, "self_signed")) {
        return <span className="an-muted">issuer differs</span>;
      }
      return (
        <span
          className="badge badge-warn"
          title="Subject and issuer are the same name. That comparison is all this is: no signature was verified, so it is not a demonstration that the certificate signed itself."
        >
          subject = issuer
        </span>
      );
    }),
    sortKey: "self_signed",
    sortDefaultOrder: "desc",
  },
  // Every name the certificate carries — DNS names, addresses, e-mail, URIs —
  // because the one that matters is rarely the common name. Each is its own
  // pivot trigger.
  pivotListCol("Names", "names"),
  pivotCol("SHA-256", ["sha256"]),
  {
    // The qualification, in words, on every certificate row. Without it a row
    // showing a subject, an issuer and a validity window reads as a
    // certificate this build checked — and nothing here checks one. The three
    // flags are written `false` by the stage on every record rather than
    // omitted, so a record missing them is a shape this viewer does not
    // recognise and says so instead of claiming the checks were made.
    ...col("signature_verified", "Checked?", (m) => {
      const flags: [string, string][] = [
        ["signature_verified", "signature not verified"],
        ["chain_built", "no chain built"],
        ["revocation_checked", "no revocation check"],
      ];
      if (flags.some(([key]) => typeof m[key] !== "boolean")) {
        return (
          <span
            className="badge badge-warn"
            title="This record does not carry the three verification flags, so what was checked cannot be stated from it"
          >
            not stated
          </span>
        );
      }
      const notDone = flags
        .filter(([key]) => m[key] === false)
        .map(([, phrase]) => phrase);
      if (notDone.length === 0) return <span className="an-muted">—</span>;
      return (
        <span
          className="badge badge-warn"
          title={metaStr(m, "statement") ?? notDone.join("; ")}
        >
          {notDone.join(" · ")}
        </span>
      );
    }),
  },
];

/**
 * A wireless network the machine was configured for — the macOS
 * known-networks list and the Windows WLAN profiles, which are one record
 * type on purpose so "where has this machine been" is one screen.
 *
 * The column this viewer exists for is **the key**. A profile whose
 * passphrase is in the file in plain text, one whose key is a DPAPI blob this
 * build will not decrypt, one whose document never said which, and one with
 * no key at all are four different findings, and on the generic table they
 * were four identical rows — the eight columns it showed were the network's
 * name in four forms and a truncated paragraph. The passphrase is what an
 * examiner opens the file for, and the DPAPI case is the one they must not
 * mistake for it.
 */
const WIFI_NETWORK_COLUMNS: Column[] = [
  pivotCol("Network (SSID)", ["ssid", "ssid_name", "profile_name"]),
  {
    ...col("key_state", "Key", (m) => {
      const state = metaStr(m, "key_state");
      const statement = metaStr(m, "key_statement") ?? undefined;
      if (state === "in_the_clear") {
        const key = metaStr(m, "key");
        return (
          <span title={statement}>
            <span className="badge badge-danger">in the clear</span>{" "}
            {key ? <span className="an-mono">{key}</span> : null}
          </span>
        );
      }
      if (state === "dpapi_protected") {
        const dpapi = sub(m, "key_dpapi");
        const guid = dpapi ? metaStr(dpapi, "master_key_guid") : null;
        return (
          <span title={statement}>
            <span className="badge">DPAPI, not decrypted</span>
            {guid ? <span className="an-muted"> master key {guid}</span> : null}
          </span>
        );
      }
      if (state === "protection_not_stated") {
        // The document did not say. Rendering this as either of the two
        // states above is the defect this column exists to prevent.
        return (
          <span title={statement}>
            <span className="badge badge-warn">protection not stated</span>
          </span>
        );
      }
      if (state === "protected_unreadable") {
        return (
          <span title={statement}>
            <span className="badge badge-warn">protected, unreadable</span>
          </span>
        );
      }
      if (state === "none") {
        return (
          <span className="an-muted" title={statement}>
            no key in this profile
          </span>
        );
      }
      // The macOS record carries no key field at all, which is a different
      // thing again from a profile that carries none.
      return <span className="an-muted">not recorded here</span>;
    }),
    sortKey: "key_state",
  },
  {
    ...col("security", "Security", (m) => {
      const types = Array.isArray(m.security_types)
        ? (m.security_types as unknown[]).filter((t) => typeof t === "string")
        : [];
      if (metaBool(m, "open_network")) {
        return <span className="badge badge-danger">open — no key needed</span>;
      }
      if (types.length === 0)
        return <span className="an-muted">not stated</span>;
      return <span>{types.join(" / ")}</span>;
    }),
    sortKey: "authentication",
  },
  {
    ...col("hidden_network", "Hidden?", (m) =>
      metaBool(m, "hidden_network") ? (
        <span
          className="badge"
          title="The network does not announce itself, so a machine configured for it actively looks for it"
        >
          hidden
        </span>
      ) : (
        <span className="an-muted">broadcast or not stated</span>
      ),
    ),
    sortKey: "hidden_network",
  },
  {
    ...col("connects_automatically", "Joins by itself?", (m) =>
      metaBool(m, "connects_automatically") ? (
        <span
          className="badge"
          title="connectionMode is auto: the machine joined this network whenever it was in range"
        >
          automatic
        </span>
      ) : (
        <span className="an-muted">manual or not stated</span>
      ),
    ),
    sortKey: "connects_automatically",
  },
  // The macOS record carries a join time; the Windows profile carries no
  // timestamp at all, and the cell says which rather than rendering an empty
  // date.
  {
    ...col("last_joined", "Last joined", (m) => {
      const joined =
        metaStr(m, "last_joined_rfc3339") ?? metaStr(m, "last_joined");
      if (joined) return timeCell(m, ["last_joined_rfc3339", "last_joined"]);
      const note = metaStr(m, "join_times_note") ?? undefined;
      return (
        <span className="an-muted" title={note}>
          no join time in this record
        </span>
      );
    }),
    sortKey: "last_joined_rfc3339",
    sortDefaultOrder: "desc",
  },
  strCol("Platform", ["platform"]),
  truncCol("Read from", ["source_file", "path"]),
];
/**
 * A NetworkList profile: a network this machine has been ON, which is a
 * different claim from the wireless profiles that say it was configured for
 * one.
 *
 * The two time columns are the reason this viewer exists. `DateCreated` and
 * `DateLastConnected` are written in the machine's LOCAL time with no zone in
 * them, and the record carries an instant only where the parser could measure
 * the offset against the profile key's own last-written timestamp. So a row
 * shows the instant where there is one, and the local time with a badge where
 * there is not — never a local time formatted as though it were UTC, which is
 * how four to six hours get onto a report.
 */
const NETWORK_PROFILE_COLUMNS: Column[] = [
  pivotCol("Network", ["network_name", "profile_name"]),
  strCol("Kind", ["network_kind"]),
  {
    ...col("category", "Category", (m) => {
      const category = metaStr(m, "category");
      const managed = metaBool(m, "managed_by_a_domain");
      if (!category) return <span className="an-muted">not stated</span>;
      return (
        <span>
          {category}
          {managed ? (
            <span className="badge" title="A domain managed this network">
              domain-managed
            </span>
          ) : null}
        </span>
      );
    }),
    sortKey: "category",
  },
  networkProfileTimeCol("Last connected", "date_last_connected"),
  networkProfileTimeCol("First connected", "date_created"),
  pivotCol("Gateway MAC", ["default_gateway_mac"]),
  strCol("DNS suffix", ["dns_suffix"]),
];

/**
 * One of the two NetworkList times. `field` is the UTC instant's key; the
 * local time as written is at `<field>_local`.
 */
function networkProfileTimeCol(header: string, field: string): Column {
  return {
    ...col(field, header, (m) => {
      const instant = metaStr(m, field);
      if (instant) return timeCell(m, [field]);
      const local = metaStr(m, `${field}_local`);
      if (!local) return <span className="an-muted">not recorded</span>;
      return (
        <span
          title={
            metaStr(m, "time_zone_note") ??
            "This value is the machine's local time and no zone was recorded, so no instant is claimed"
          }
        >
          <span className="an-mono">{local}</span>{" "}
          <span className="badge badge-warn">local, zone unknown</span>
        </span>
      );
    }),
    sortKey: field,
    sortDefaultOrder: "desc",
  };
}

const ARP_BINDING_COLUMNS: Column[] = [
  // "Address claimed", not "Address": ARP does not authenticate, so every row
  // here is an announcement that was believed because it arrived.
  pivotCol("Address claimed", ["ip"]),
  pivotListCol("Claimed by", "macs"),
  {
    // The column this record type exists for. A contested address is the
    // signature of ARP cache poisoning — and equally of a failover pair, a
    // DHCP lease handed on, a replaced network card or a virtual machine moved
    // between hosts — so the badge counts the claimants and the record's own
    // statement, which reaches no verdict, is what it carries.
    ...col("contested", "Contested?", (m) => {
      const statement = metaStr(m, "statement") ?? undefined;
      const beyond = metaNum(m, "macs_beyond_cap") ?? 0;
      if (!metaBool(m, "contested")) {
        return (
          <span className="an-muted" title={statement}>
            one claimant
          </span>
        );
      }
      const listed = Array.isArray(m.macs) ? m.macs.length : 0;
      const claimants = listed + beyond;
      return (
        <span className="badge badge-danger" title={statement}>
          {claimants > 0 ? `${formatCount(claimants)} claimants` : "contested"}
          {beyond > 0 ? ` (${formatCount(beyond)} not listed)` : ""}
        </span>
      );
    }),
    sortKey: "contested",
    sortDefaultOrder: "desc",
  },
  // When the segment's caches started to be wrong: the first time a SECOND
  // hardware address was seen claiming the address. Absent on an uncontested
  // one, and absent where no frame carried a time.
  timeCol("Contested from", ["contested_from"]),
  numCol("Frames", ["packets"]),
];

/**
 * File type of a deleted file, from its recorded original path.
 *
 * A `$I` record that ran out before the path terminator loses the tail of the
 * path — which is exactly where the file name and extension are. Bucketing that
 * fragment as a file type would report an extension nobody read, so a truncated
 * path is kept out of the type bars and named as such.
 */
function deletedFileType(m: RecordMetadata): string | null {
  if (readScope(m, RECYCLE_ORIGINAL_PATH_SCOPE).state !== "whole") {
    return "(path truncated — type unknown)";
  }
  return extOf(metaStr(m, "original_path"));
}

// ---------------------------------------------------------------------------
// Installed programs (Windows Uninstall keys)
// ---------------------------------------------------------------------------

/**
 * The name cell for an Uninstall entry.
 *
 * A key with no DisplayName is the shape a quietly installed MSI leaves: the
 * key is a GUID and nothing under it says what it is. The row still exists and
 * is still a program, so the key name stands in — but shown as the key name in
 * mono with a marker, never as though it were the product's name. Sorting on
 * this column is refused for the same reason: no one key orders it the way its
 * heading reads.
 */
const installedProgramName = (m: RecordMetadata): ReactNode => {
  const name = metaStr(m, "display_name");
  if (name != null) return <Val value={name} />;
  const key = metaStr(m, "key_name");
  if (key == null) return MISSING;
  return (
    <>
      <span
        className="mono"
        title="No DisplayName value under this Uninstall key; this is the registry key name"
      >
        {key}
      </span>{" "}
      <span className="badge">key name</span>
    </>
  );
};

/**
 * Which registry view the key was read under. `wow64` absent is "the parser
 * did not say", and that is not the same as native, so it buckets as nothing.
 */
const installedProgramArch = (m: RecordMetadata): string | null => {
  const v = m["wow64"];
  if (typeof v !== "boolean") return null;
  return v ? "32-bit (Wow6432Node)" : "native";
};

/**
 * The scope tile a record belongs to. The producer writes "machine" for
 * SOFTWARE and "user" for NTUSER; any other value is counted as unstated
 * rather than folded into either.
 */
const installedProgramScope = (
  m: RecordMetadata,
): "machine" | "user" | "unstated" => {
  const s = metaStr(m, "scope");
  return s === "machine" || s === "user" ? s : "unstated";
};

const INSTALLED_PROGRAM_COLUMNS: Column[] = [
  col("display_name", "Name", installedProgramName),
  // Version strings order lexically on the server ("10.0" before "9.0"), which
  // is not the order a "Version ▲" heading promises, so no sort is offered.
  { ...strCol("Version", ["display_version"], true), sortKey: undefined },
  strCol("Publisher", ["publisher"]),
  {
    // The registry holds a day (InstallDate is "YYYYMMDD"), and the producer
    // hands it on as "YYYY-MM-DD". It is shown as the day it is: running it
    // through a time cell would print a midnight the source never recorded.
    ...col("install_date", "Installed", (m) => {
      const d = metaStr(m, "install_date");
      const src = metaStr(m, "install_date_source");
      return (
        <span
          className="mono"
          title={d != null && src != null ? `From ${src}` : undefined}
        >
          {d ?? MISSING}
        </span>
      );
    }),
    sortKey: "install_date",
    sortDefaultOrder: "desc",
  },
  {
    // EstimatedSize is stored in KiB. It is what the installer claimed, not a
    // measurement of anything on disk, and absent is absent.
    ...col("estimated_size_kb", "Size", (m) => {
      const kb = metaNum(m, "estimated_size_kb");
      return (
        <span className="mono">
          {kb != null ? formatBytes(kb * 1024) : MISSING}
        </span>
      );
    }),
    sortKey: "estimated_size_kb",
    sortDefaultOrder: "desc",
  },
  truncCol("Location", ["install_location"]),
  strCol("Scope", ["scope"]),
  strCol("Hive", ["hive_type"], true),
];

export const VIEWERS: Record<string, ViewerDef> = {
  BrowserHistory: {
    Component: BrowserHistoryViewer,
  },
  BrowserDownload: {
    Component: makeRichViewer({
      noun: "browser downloads",
      timeKeys: ["start_time"],
      searchKeys: ["target_path", "source_url", "browser"],
      dimensions: [
        { title: "Browser", value: (m) => metaStr(m, "browser") },
        {
          title: "Source domain",
          value: (m) => domainOf(metaStr(m, "source_url")),
        },
        { title: "File type", value: (m) => extOf(metaStr(m, "target_path")) },
      ],
      columns: [
        truncCol("Target path", ["target_path"]),
        truncCol("Source URL", ["source_url"]),
        bytesCol("Size", ["total_bytes"]),
        timeCol("Started", ["start_time"]),
        strCol("Browser", ["browser"]),
      ],
    }),
    aggregate: true,
  },
  BrowserBookmark: {
    Component: makeRichViewer({
      noun: "bookmarks",
      timeKeys: ["date_added"],
      searchKeys: ["title", "url", "browser"],
      dimensions: [
        { title: "Browser", value: (m) => metaStr(m, "browser") },
        { title: "Domain", value: (m) => domainOf(metaStr(m, "url")) },
      ],
      columns: [
        strCol("Title", ["title"]),
        truncCol("URL", ["url"]),
        timeCol("Added", ["date_added"]),
        strCol("Browser", ["browser"]),
      ],
    }),
    aggregate: true,
  },
  PrefetchEntry: {
    Component: makeRichViewer({
      noun: "prefetch entries",
      timeKeys: ["last_execution_time"],
      searchKeys: ["executable_name"],
      dimensions: [
        {
          title: "Most-run executables",
          value: (m) => metaStr(m, "executable_name"),
          weight: (m) => metaNum(m, "run_count") ?? 0,
        },
      ],
      columns: [
        pivotCol("Executable", ["executable_name"]),
        numCol("Runs", ["run_count"]),
        timeCol("Last run", ["last_execution_time"]),
        numCol("Referenced files", ["loaded_files_count"]),
        strCol("Version", ["version"], true),
      ],
    }),
    aggregate: true,
  },
  LnkFile: {
    Component: makeRichViewer({
      noun: "shortcut (.lnk) files",
      timeKeys: ["target_modified", "target_created", "target_accessed"],
      searchKeys: [
        "target_local_path",
        "relative_path",
        "arguments",
        "volume_label",
        "volume_serial",
        "shell_item_name",
      ],
      dimensions: [
        {
          title: "Target drive",
          value: (m) =>
            driveOf(metaFirst(m, ["target_local_path", "relative_path"])),
        },
        // The question this record class is most often asked: was the file on
        // removable media. The shortcut records the answer and it was being
        // discarded.
        { title: "Drive type", value: (m) => metaStr(m, "drive_type_name") },
        { title: "Volume", value: (m) => metaStr(m, "volume_label") },
        {
          title: "Target type",
          value: (m) =>
            extOf(metaFirst(m, ["target_local_path", "relative_path"])),
        },
      ],
      // A shortcut to removable media is worth seeing without opening the
      // row — and the caution has to travel with it, because "removable" is
      // what Windows thought when the shortcut was written.
      notable: (m) =>
        metaStr(m, "drive_type_name") === "removable"
          ? "the shortcut recorded this volume as removable when it was written — a lead towards external media, not proof"
          : null,
      columns: [
        truncCol("Target path", ["target_local_path", "relative_path"]),
        strCol("Drive type", ["drive_type_name"]),
        strCol("Volume", ["volume_label"]),
        strCol("Volume serial", ["volume_serial"]),
        numCol("Target size", ["target_size_recorded"]),
        truncCol("Arguments", ["arguments"]),
        truncCol("Working dir", ["working_dir"]),
        timeCol("Created", ["target_created"]),
        timeCol("Modified", ["target_modified"]),
        timeCol("Accessed", ["target_accessed"]),
        // The LinkTargetIDList's own shell item, read through the format
        // (`ROADMAP` §5.16) — one name per level, the same field names and
        // shapes ShellMruEntry publishes, so this column reads either.
        pivotListCol("Path (from the shell item)", "shell_item_path"),
        timeCol("Shell item modified", ["shell_item_modified"]),
        timeCol("Shell item created", ["shell_item_created"]),
        timeCol("Shell item accessed", ["shell_item_accessed"]),
      ],
    }),
    aggregate: true,
  },
  RegistryHive: {
    Component: makeRichViewer({
      noun: "registry hives",
      searchKeys: ["hive_type", "root_key_name"],
      dimensions: [
        // `hive_type` is the ingested file name upper-cased (`AMCACHE.HVE`),
        // not a classification of the hive (HUNT-167), so it is labelled as
        // what it is.
        { title: "Hive file", value: (m) => metaStr(m, "hive_type") },
        {
          title: "Keys by hive",
          value: (m) => metaStr(m, "hive_type"),
          weight: (m) => metaNum(m, "total_keys") ?? 0,
        },
      ],
      columns: [
        strCol("Hive", ["hive_type"], true),
        truncCol("Root key", ["root_key_name"]),
        numCol("Keys", ["total_keys"]),
        numCol("Values", ["total_values"]),
      ],
    }),
    aggregate: true,
  },
  EvtxLogEntry: {
    Component: makeRichViewer({
      noun: "event log entries",
      timeKeys: ["timestamp"],
      searchKeys: ["provider_name", "short_desc", "channel", "event_id"],
      stats: levelStats,
      statOf: (m) => metaStr(m, "level_description") ?? "Information",
      dimensions: [
        { title: "Top event IDs", value: (m) => metaStr(m, "event_id") },
        { title: "Providers", value: (m) => metaStr(m, "provider_name") },
        { title: "Channels", value: (m) => metaStr(m, "channel") },
      ],
      notable: (m) => {
        const id = metaStr(m, "event_id");
        return id ? (NOTABLE_EVENT_IDS[id] ?? null) : null;
      },
      columns: [
        strCol("Event ID", ["event_id"], true),
        strCol("Provider", ["provider_name"]),
        strCol("Level", ["level_description"]),
        strCol("Channel", ["channel"], true),
        timeCol("Time", ["timestamp"]),
        truncCol("Summary", ["short_desc"]),
      ],
    }),
    aggregate: true,
  },
  RecycleBinEntry: {
    Component: makeRichViewer({
      noun: "recycle bin entries",
      timeKeys: ["deleted_time"],
      searchKeys: ["original_path", "recycle_bin_path"],
      dimensions: [
        { title: "Deleted file types", value: deletedFileType },
        {
          title: "Largest types",
          value: deletedFileType,
          weight: (m) => metaNum(m, "file_size") ?? 0,
        },
        // The drive letter is at the head of the path, and `$I` truncation cuts
        // the tail, so this bucket survives a short record intact.
        { title: "Drive", value: (m) => driveOf(metaStr(m, "original_path")) },
      ],
      columns: [
        col("original_path", "Original path", (m) => (
          <span className="an-sig">
            <MonoTrunc value={metaStr(m, "original_path")} />
            <ScopeBadgeFor
              scope={readScope(m, RECYCLE_ORIGINAL_PATH_SCOPE)}
              spec={RECYCLE_ORIGINAL_PATH_SCOPE}
            />
          </span>
        )),
        timeCol("Deleted", ["deleted_time"]),
        bytesCol("Size", ["file_size"]),
        truncCol("Recycle path", ["recycle_bin_path"]),
      ],
    }),
    aggregate: true,
  },
  ShellBagEntry: {
    Component: makeRichViewer({
      noun: "shellbag entries",
      // The times are FAT date/time pairs: local wall-clock with no zone. They
      // are sortable here because ordering them against each other is valid;
      // what is not valid is reading one as an instant, which the row says.
      timeKeys: ["folder_modified", "folder_accessed", "folder_created"],
      searchKeys: ["path", "folder_name"],
      dimensions: [
        { title: "Drive", value: (m) => driveOf(metaStr(m, "path")) },
        { title: "Folders", value: (m) => metaStr(m, "folder_name") },
      ],
      // A shellbag's whole value is "this folder was browsed, and here is
      // when". The when is a local wall-clock with no recorded zone, and a
      // column of RFC 3339 strings reads as UTC unless the row says otherwise.
      notable: (m) =>
        metaStr(m, "timezone") === "local"
          ? "these times are local wall-clock as Explorer wrote them, with no recorded zone — not UTC"
          : null,
      columns: [
        truncCol("Path", ["path"]),
        strCol("Folder", ["folder_name"]),
        timeCol("Modified", ["folder_modified"]),
        timeCol("Created", ["folder_created"]),
        timeCol("Accessed", ["folder_accessed"]),
        strCol("Zone", ["timezone"]),
        strCol("Slot", ["slot"], true),
      ],
    }),
    aggregate: true,
  },
  AmcacheEntry: {
    Component: makeRichViewer({
      noun: "amcache entries",
      timeKeys: ["link_date"],
      searchKeys: ["file_path", "publisher", "sha1_hash"],
      dimensions: [
        { title: "Publishers", value: (m) => metaStr(m, "publisher") },
        { title: "File types", value: (m) => extOf(metaStr(m, "file_path")) },
        { title: "Drive", value: (m) => driveOf(metaStr(m, "file_path")) },
      ],
      columns: [
        truncCol("File path", ["file_path"]),
        pivotCol("SHA1", ["sha1_hash"]),
        bytesCol("Size", ["file_size"]),
        timeCol("Link date", ["link_date"]),
        strCol("Publisher", ["publisher"]),
        strCol("Version", ["version"], true),
      ],
    }),
    aggregate: true,
  },
  ShimcacheEntry: {
    Component: makeRichViewer({
      noun: "shimcache entries",
      timeKeys: ["last_modified"],
      searchKeys: ["path", "control_set"],
      stats: (recs) => {
        let exec = 0;
        let no = 0;
        for (const r of recs) {
          if (metaBool(r.metadata, "exec_flag")) exec++;
          else no++;
        }
        return [
          { key: "exec", label: "Executed", count: exec, tone: "accent" },
          { key: "noexec", label: "No exec flag", count: no, tone: "neutral" },
        ];
      },
      statOf: (m) => (metaBool(m, "exec_flag") ? "exec" : "noexec"),
      dimensions: [
        { title: "Drive", value: (m) => driveOf(metaStr(m, "path")) },
        { title: "Control set", value: (m) => metaStr(m, "control_set") },
      ],
      columns: [
        truncCol("Path", ["path"]),
        timeCol("Last modified", ["last_modified"]),
        boolCol("Executed", "exec_flag", "executed", "no exec"),
        numCol("Position", ["position"]),
        strCol("Control set", ["control_set"], true),
      ],
    }),
    aggregate: true,
  },
  StickyNoteRecovered: {
    // HUNT-128 / PLUM-1. A note the app hard-deleted (it sets no tombstone),
    // decoded from an older WAL frame. Every row is recovered, not live, and
    // its deletion is an inference, so the marker on every row says which
    // frame it came from and why it is called deleted.
    Component: makeRichViewer({
      noun: "recovered sticky notes",
      searchKeys: ["text", "note_id", "source_file"],
      dimensions: [{ title: "Source", value: (m) => metaStr(m, "source_file") }],
      notable: (m) => {
        if (metaBool(m, "validated_against_real_notes") === false) {
          return (
            metaStr(m, "validation_notice") ??
            "This record has never been validated against a real Sticky Notes file"
          );
        }
        return (
          metaStr(m, "deletion_basis") ??
          "Recovered from an older write-ahead-log frame; deletion is inferred"
        );
      },
      columns: [
        strCol("Note", ["text", "name"]),
        pivotCol("Identifier", ["note_id"]),
        timeCol("Created", ["created"]),
        timeCol("Modified", ["modified"]),
        numCol("WAL frame", ["wal_frame"]),
        strCol("Source", ["source_file"]),
      ],
    }),
    aggregate: true,
  },
  StickyNote: {
    // ROADMAP §2.6. A `plum.sqlite` record from a store at `user_version` 13
    // was graded on one lab-made 6.1.4.0 database (PLUM-1) and carries
    // `validated_against_real_notes: true`; any other schema version keeps the
    // never-validated stamp (`false`), and the row marker is how an examiner
    // sees it without opening the row. A `.snt` record was graded on one real
    // Windows 7 file (SNT-1) and carries `true`, so it gets no marker.
    Component: makeRichViewer({
      noun: "sticky notes",
      searchKeys: ["text", "note_id", "storage_name", "source_file"],
      dimensions: [
        { title: "Source", value: (m) => metaStr(m, "source_file") },
        { title: "Format", value: (m) => metaStr(m, "source_format") },
      ],
      notable: (m) => {
        // The stamp first: it qualifies every other field on the row.
        if (metaBool(m, "validated_against_real_notes") === false) {
          return (
            metaStr(m, "validation_notice") ??
            "This record has never been validated against a real Sticky Notes file"
          );
        }
        if (metaBool(m, "unrecognised_structure")) {
          return (
            metaStr(m, "unrecognised_reason") ??
            "No stream in this storage was recognised, so no text was extracted"
          );
        }
        if (metaBool(m, "content_incomplete")) {
          return `Record incomplete: ${incompleteReasonLabel(
            metaStr(m, "content_incomplete_reason"),
          )}`;
        }
        return null;
      },
      columns: [
        // `name` is the fallback because a storage whose streams this build
        // could not read has no text, and a row with nothing in it reads as a
        // note that was empty rather than as one that would not parse.
        strCol("Note", ["text", "name"]),
        pivotCol("Identifier", ["storage_name", "note_id"]),
        timeCol("Created", ["created"]),
        timeCol("Modified", ["modified"]),
        timeCol("Deleted", ["deleted"]),
        strCol("Source", ["source_file"]),
      ],
    }),
    aggregate: true,
  },
  DeviceInstallEvent: {
    // ROADMAP §2.6. One row per section of a setupapi log that concerns a
    // device. The times are LOCAL with no recorded offset, so they are shown
    // exactly as the log wrote them — a column headed with a UTC time here
    // would be a conversion nobody can justify.
    Component: makeRichViewer({
      noun: "device installs",
      searchKeys: [
        "device_instance_id",
        "subject",
        "section_kind",
        "driven_by_command",
      ],
      dimensions: [
        { title: "Action", value: (m) => metaStr(m, "device_action") },
        { title: "Log", value: (m) => metaStr(m, "log_file") },
        { title: "Exit status", value: (m) => metaStr(m, "exit_status") },
      ],
      // What earns a marker: a device that failed to start (the `!!!` lines,
      // which are the only such record in any real log measured here), a
      // section the log never closed, or a log describing a different
      // installation from this machine.
      notable: (m) => {
        const warnings = m.warnings;
        if (Array.isArray(warnings) && warnings.length > 0) {
          return warnings.filter((w) => typeof w === "string").join(" ");
        }
        if (metaBool(m, "section_closed") === false) {
          return "The log never closed this section: it has no end time and no exit status, which is what a machine losing power mid-install leaves behind";
        }
        return null;
      },
      columns: [
        strCol("Device", ["device_instance_id", "subject"]),
        strCol("Action", ["device_action"]),
        // Deliberately `strCol` and not `timeCol`: these are local times with
        // no offset recorded anywhere in the file, and a time column would
        // format and sort them as though their zone were known.
        strCol("Section start (local)", ["start_local"], true),
        strCol("Section end (local)", ["end_local"], true),
        strCol("Exit status", ["exit_status"]),
        strCol("Log", ["log_file"]),
      ],
    }),
    aggregate: true,
  },
  LocalAccount: {
    // ROADMAP §2.6. The RID, the times and the account-control state come out
    // of the SAM `F` and `V` binary values. The columns are chosen so that the
    // two things an examiner asks — who could log on here, and when did they —
    // are answerable without opening a row.
    Component: makeRichViewer({
      noun: "local accounts",
      searchKeys: ["username", "key_name", "comment", "full_name"],
      dimensions: [
        {
          title: "Enabled",
          value: (m) => {
            const e = metaBool(m, "account_enabled");
            return e == null ? null : e ? "enabled" : "disabled";
          },
        },
        {
          title: "Password stored",
          value: (m) => {
            const h = metaBool(m, "stored_password_hash_present");
            return h == null ? null : h ? "a hash is stored" : "no hash stored";
          },
        },
      ],
      // What earns a marker: the account's own key disagreeing with itself
      // about its RID, a descriptor this build refused to resolve, or an
      // account named in the index whose key was never read — which is this
      // build's reach and not an absence in the account.
      notable: (m) => {
        const conflict = metaStr(m, "rid_conflict");
        if (conflict != null) return conflict;
        const missing = metaStr(m, "account_key_note");
        if (missing != null) return missing;
        if (metaBool(m, "content_incomplete")) {
          return `Record incomplete: ${incompleteReasonLabel(
            metaStr(m, "content_incomplete_reason"),
          )}`;
        }
        return null;
      },
      columns: [
        strCol("Account", ["username"]),
        pivotCol("RID", ["rid"]),
        timeCol("Last logon", ["last_logon"]),
        timeCol("Password set", ["last_password_set"]),
        numCol("Logons", ["login_count"]),
        strCol("Comment", ["comment"]),
      ],
    }),
    aggregate: true,
  },
  UsbDevice: {
    // ROADMAP §2.6 asks, of both USB serials, WHEN each was first and last
    // connected. The parser decodes those times from the device-property keys
    // and this view showed the name, vendor, product, revision and serial and
    // no date at all — so the answer was on the record and on no screen.
    Component: makeRichViewer({
      noun: "USB devices",
      searchKeys: [
        "friendly_name",
        "vendor",
        "product",
        "serial",
        "device_class",
      ],
      dimensions: [
        { title: "Vendors", value: (m) => metaStr(m, "vendor") },
        { title: "Products", value: (m) => metaStr(m, "product") },
      ],
      // What earns a marker, in order: the device's own property times
      // disagreeing — read correctly, and not something this build can vouch
      // for as one account — then a hive whose pending transactions were never
      // applied, then a record the parser could not finish.
      notable: (m) => {
        const clash = m.time_contradictions;
        if (Array.isArray(clash) && clash.length > 0) {
          return clash.filter((c) => typeof c === "string").join(" ");
        }
        const replay = m.replay;
        const stamp =
          replay != null && typeof replay === "object"
            ? (replay as Record<string, unknown>)
            : null;
        if (
          stamp != null &&
          metaBool(stamp, "hive_dirty") &&
          !metaBool(stamp, "recovered")
        ) {
          const why = metaStr(stamp, "reason");
          return `Hive was dirty at acquisition and its transaction logs were not applied${
            why != null ? ` (${why})` : ""
          }; this entry is the on-disk state and may be stale`;
        }
        if (metaBool(m, "content_incomplete")) {
          return `Record incomplete: ${incompleteReasonLabel(
            metaStr(m, "content_incomplete_reason"),
          )}`;
        }
        return null;
      },
      columns: [
        strCol("Friendly name", ["friendly_name"]),
        strCol("Vendor", ["vendor"]),
        strCol("Product", ["product"]),
        strCol("Revision", ["revision"], true),
        pivotCol("Serial", ["serial"]),
        // `install_date` is when THIS device instance was installed, which is
        // the first connection of this device to this machine;
        // `first_install_date` is when a device of its KIND first was. They
        // are separate properties and are not conflated into one column.
        timeCol("First installed", ["install_date"]),
        timeCol("Last connected", ["last_arrival_date"]),
        timeCol("Last removed", ["last_removal_date"]),
      ],
    }),
    aggregate: true,
  },
  InstalledProgram: {
    // The Uninstall-key inventory. The tiles split machine-wide (SOFTWARE)
    // from per-user (NTUSER) installs; the bars rank publishers and install
    // months and split native from Wow6432Node and system components from
    // applications; the filter box takes a name, a publisher or a path.
    Component: makeRichViewer({
      noun: "installed programs",
      searchKeys: ["display_name", "publisher", "key_name", "install_location"],
      stats: (recs) => {
        let machine = 0;
        let user = 0;
        let unstated = 0;
        for (const r of recs) {
          const s = installedProgramScope(r.metadata);
          if (s === "machine") machine++;
          else if (s === "user") user++;
          else unstated++;
        }
        const tiles: StatTile[] = [
          {
            key: "machine",
            label: "Machine-wide",
            count: machine,
            tone: "accent",
          },
          { key: "user", label: "Per-user", count: user, tone: "neutral" },
        ];
        if (unstated > 0) {
          tiles.push({
            key: "unstated",
            label: "Scope unstated",
            count: unstated,
            tone: "neutral",
          });
        }
        return tiles;
      },
      statOf: (m) => installedProgramScope(m),
      dimensions: [
        // System components against applications is a bar list rather than a
        // second pair of tiles: the shell's tile filter is one partition per
        // viewer, and a tile that highlighted but did not filter would be a
        // control that lies. Bars filter, and compose with the tiles.
        {
          title: "Kind",
          value: (m) => {
            const v = m["system_component"];
            if (typeof v !== "boolean") return null;
            return v ? "System components" : "Applications";
          },
        },
        { title: "Publisher", value: (m) => metaStr(m, "publisher") },
        {
          title: "Install month",
          value: (m) => {
            const d = metaStr(m, "install_date");
            return d != null && /^\d{4}-\d{2}/.test(d) ? d.slice(0, 7) : null;
          },
        },
        { title: "Architecture", value: (m) => installedProgramArch(m) },
      ],
      // A system component is ordinary, not suspicious. What earns a marker is
      // a hive whose pending transactions were never applied — this row is the
      // on-disk state and may not be the last one — or a record the parser
      // could not finish.
      notable: (m) => {
        // The replay stamp is nested under `replay`, as the registry parser
        // writes it on every derived record (UsbDevice carries the same
        // shape). Reading it flat at the top level meant this marker never
        // fired on a real record.
        const replay = m.replay;
        const stamp =
          replay != null && typeof replay === "object"
            ? (replay as Record<string, unknown>)
            : null;
        if (
          stamp != null &&
          metaBool(stamp, "hive_dirty") &&
          !metaBool(stamp, "recovered")
        ) {
          const why = metaStr(stamp, "reason");
          return `Hive was dirty at acquisition and its transaction logs were not applied${
            why != null ? ` (${why})` : ""
          }; this entry is the on-disk state and may be stale`;
        }
        if (metaBool(m, "content_incomplete")) {
          return `Record incomplete: ${incompleteReasonLabel(
            metaStr(m, "content_incomplete_reason"),
          )}`;
        }
        return null;
      },
      columns: INSTALLED_PROGRAM_COLUMNS,
    }),
    aggregate: true,
    columns: INSTALLED_PROGRAM_COLUMNS,
  },
  SrumAppResourceUsage: srumViewer,
  SrumNetworkDataUsage: srumViewer,
  SrumNetworkConnectivity: srumViewer,
  SrumEnergyUsage: srumViewer,
  exif: { Component: ExifViewer },
  SqliteRow: { Component: SqliteViewer, aggregate: true },
  // Chat media as a picture wall; the conversation shows message-linked items
  // inline, so these views default to the ones with no link.
  iMessageAttachment: {
    Component: makeChatMediaViewer("iMessage"),
    aggregate: true,
  },
  WhatsAppAttachment: {
    Component: makeChatMediaViewer("WhatsApp"),
    aggregate: true,
  },
  iMessage: { Component: IMessageViewer, aggregate: true },
  WhatsApp: { Component: WhatsAppViewer, aggregate: true },
  Signal: { Component: SignalViewer, aggregate: true },
  Instagram: { Component: InstagramViewer, aggregate: true },
  Snapchat: { Component: SnapchatViewer, aggregate: true },
  TwitterDM: { Component: TwitterDmViewer, aggregate: true },
  AndroidSms: { Component: AndroidSmsViewer, aggregate: true },
  Viber: { Component: ViberViewer, aggregate: true },
  Kik: { Component: KikViewer, aggregate: true },
  Skype: { Component: SkypeViewer, aggregate: true },
  LINE: { Component: LineViewer, aggregate: true },
  TelegramMessage: { Component: TelegramViewer, aggregate: true },
  FacebookMessenger: { Component: MessengerViewer, aggregate: true },
  WeChat: { Component: WeChatViewer, aggregate: true },
  CalendarEvent: { Component: CalendarViewer, aggregate: true },
  EmailMessage: { Component: EmailViewer, aggregate: true },
  CallLog: { Component: CallLogViewer, aggregate: true },
  Contact: { Component: ContactViewer, aggregate: true },
  PlistFile: { Component: PlistViewer },
  FileSignatureAnalysis: {
    Component: makeRichViewer({
      noun: "file signature analyses",
      searchKeys: ["filename", "detected_type"],
      stats: (recs) => {
        let mism = 0;
        let trailing = 0;
        let unchecked = 0;
        let ok = 0;
        for (const r of recs) {
          const bucket = fileSigStat(r.metadata);
          if (bucket === "mismatch") mism++;
          else if (bucket === "trailing") trailing++;
          else if (bucket === "unchecked") unchecked++;
          else ok++;
        }
        return [
          {
            key: "mismatch",
            label: "Extension mismatch",
            count: mism,
            tone: "error",
          },
          {
            key: "trailing",
            label: "Hidden trailing data",
            count: trailing,
            tone: "error",
          },
          // Its own tile, not folded into "Signature OK". These files were not
          // cleared; the check on them did not produce a result, and a count
          // that mixes the two is a count an examiner cannot act on.
          {
            key: "unchecked",
            label: "Hidden-data check inconclusive",
            count: unchecked,
            tone: "warning",
          },
          { key: "ok", label: "Signature OK", count: ok, tone: "ok" },
        ];
      },
      statOf: (m) => fileSigStat(m),
      dimensions: [
        { title: "Detected types", value: (m) => metaStr(m, "detected_type") },
        { title: "Entropy class", value: entropyClassBucket },
      ],
      notable: (m) => fileSigNotable(m),
      columns: [
        truncCol("File", ["filename"]),
        strCol("Detected type", ["detected_type"]),
        strCol("Claimed ext", ["actual_extension"]),
        col("signature_mismatch", "Signature", (m) => {
          const reason = fileSigMismatchReason(m);
          if (!reason) return <span className="an-muted">ok</span>;
          const detected = metaStr(m, "detected_type") ?? "?";
          const ext = metaStr(m, "actual_extension");
          return (
            <span className="an-sig" title={reason}>
              <span className="badge badge-danger">MISMATCH</span>
              <span className="an-sig-detail mono">
                {detected} ≠ .{ext ?? "?"}
              </span>
            </span>
          );
        }),
        col("trailing_data", "Hidden data", (m) => {
          const check = trailingCheck(m);
          if (check === "found") {
            const reason = fileTrailingReason(m) ?? TRAILING_MEANING.found;
            const kind = metaStr(m, "trailing_detected_type") ?? "data";
            const size = metaNum(m, "trailing_size");
            return (
              <span className="an-sig" title={reason}>
                <span className="badge badge-danger">TRAILING</span>
                <span className="an-sig-detail mono">
                  +{size ?? "?"}B {kind}
                </span>
              </span>
            );
          }
          const sentence = trailingSentence(m, check);
          if (check === "none") {
            // The one outcome that clears the file. Quiet, but it says the
            // word rather than leaving a blank an examiner has to guess at.
            return (
              <span className="an-muted" title={sentence}>
                {TRAILING_WORD.none}
              </span>
            );
          }
          if (check === "not_applicable") {
            // Not a warning: nothing failed. But not a blank either — a blank
            // in this column reads as "checked, nothing found".
            return (
              <span className="an-muted" title={sentence}>
                {TRAILING_WORD.not_applicable}
              </span>
            );
          }
          const detail = trailingReasonPhrase(m, check);
          return (
            <span className="an-sig" title={sentence}>
              <span
                className="badge badge-warn"
                role="note"
                aria-label={`${TRAILING_WORD[check]} — ${sentence}`}
              >
                {TRAILING_WORD[check]}
              </span>
              {detail && <span className="an-sig-detail mono">{detail}</span>}
            </span>
          );
        }),
        col("entropy", "Entropy", entropyCell),
        col("entropy_classification", "Entropy class", entropyClassCell),
      ],
    }),
    aggregate: true,
  },
  VssSnapshot: {
    Component: makeRichViewer({
      noun: "volume shadow copies",
      timeKeys: ["creation_time"],
      searchKeys: ["name", "snapshot_id", "store_id"],
      stats: (recs) => {
        let recon = 0;
        let unavailable = 0;
        for (const r of recs) {
          if (metaStr(r.metadata, "content_reconstruction") === "reconstructed")
            recon++;
          else unavailable++;
        }
        return [
          {
            key: "reconstructed",
            label: "Content reconstructable",
            count: recon,
            tone: "ok",
          },
          {
            key: "unavailable",
            label: "Needs store chain",
            count: unavailable,
            tone: "warning",
          },
        ];
      },
      statOf: (m) =>
        metaStr(m, "content_reconstruction") === "reconstructed"
          ? "reconstructed"
          : "unavailable",
      dimensions: [
        { title: "Store version", value: (m) => metaStr(m, "store_version") },
      ],
      columns: [
        strCol("Snapshot", ["name"]),
        timeCol("Created", ["creation_time"]),
        bytesCol("Volume size", ["volume_size"]),
        numCol("Modified blocks", ["modified_blocks"]),
        col("content_reconstruction", "Content", (m) =>
          metaStr(m, "content_reconstruction") === "reconstructed" ? (
            <span className="badge badge-accent">reconstructable</span>
          ) : (
            <span className="badge">needs store chain</span>
          ),
        ),
      ],
    }),
    aggregate: true,
  },
  // HUNT-154: a shadow copy's $MFT record that differs from the live
  // volume's. Never a file of the live volume: every row says which snapshot
  // it was read from, and its content is served from that snapshot.
  VssPriorVersion: {
    Component: makeRichViewer({
      noun: "prior versions from shadow copies",
      timeKeys: ["vss_creation_time"],
      searchKeys: [
        "file_name",
        "snapshot_path",
        "live_path",
        "vss_snapshot_id",
      ],
      stats: (recs) => {
        let gone = 0;
        let changed = 0;
        for (const r of recs) {
          if (
            r.metadata.absent_from_live === true ||
            (r.metadata.in_use_in_snapshot === true &&
              metaStr(r.metadata, "live_sequence_number") !==
                metaStr(r.metadata, "sequence_number"))
          )
            gone++;
          else changed++;
        }
        return [
          {
            key: "replaced",
            label: "Record reused or gone live",
            count: gone,
            tone: "warning",
          },
          {
            key: "changed",
            label: "Same record, other values",
            count: changed,
            tone: "ok",
          },
        ];
      },
      statOf: (m) =>
        m.absent_from_live === true ||
        (m.in_use_in_snapshot === true &&
          metaStr(m, "live_sequence_number") !== metaStr(m, "sequence_number"))
          ? "replaced"
          : "changed",
      dimensions: [
        { title: "Snapshot", value: (m) => metaStr(m, "vss_creation_time") },
      ],
      columns: [
        col("snapshot_label", "Version", () => (
          <span
            className="badge badge-warn"
            title="Read from a shadow copy, not the live volume"
          >
            shadow copy
          </span>
        )),
        strCol("File (in snapshot)", ["snapshot_path", "file_name"]),
        timeCol("Snapshot created", ["vss_creation_time"]),
        numCol("Record", ["record_number"]),
        col("changed_fields", "Differs in", (m) => {
          const raw = m.changed_fields;
          const list = Array.isArray(raw)
            ? raw.filter((x): x is string => typeof x === "string")
            : [];
          return (
            <span className="mono">
              {list.length ? list.join(", ") : MISSING}
            </span>
          );
        }),
        strCol("Live path", ["live_path"]),
      ],
    }),
    aggregate: true,
  },
  PeSignature: {
    Component: makeRichViewer({
      noun: "PE executables",
      timeKeys: ["compile_timestamp"],
      searchKeys: ["publisher", "cert_issuer", "imphash", "name"],
      stats: (recs) => {
        let valid = 0;
        let mismatch = 0;
        let unsigned = 0;
        for (const r of recs) {
          if (!metaBool(r.metadata, "signed")) unsigned++;
          else if (metaStr(r.metadata, "signature_integrity") === "valid")
            valid++;
          else mismatch++;
        }
        return [
          { key: "valid", label: "Signature valid", count: valid, tone: "ok" },
          {
            key: "mismatch",
            label: "Signature invalid",
            count: mismatch,
            tone: "error",
          },
          {
            key: "unsigned",
            label: "Unsigned",
            count: unsigned,
            tone: "warning",
          },
        ];
      },
      statOf: (m) =>
        !metaBool(m, "signed")
          ? "unsigned"
          : metaStr(m, "signature_integrity") === "valid"
            ? "valid"
            : "mismatch",
      dimensions: [
        { title: "Publishers", value: (m) => metaStr(m, "publisher") },
        { title: "Machine", value: (m) => metaStr(m, "machine") },
        { title: "Subsystem", value: (m) => metaStr(m, "subsystem") },
      ],
      notable: (m) =>
        metaBool(m, "signed") && metaStr(m, "signature_integrity") !== "valid"
          ? "Authenticode signature does not match the file (tampered or corrupt)."
          : metaBool(m, "likely_packed")
            ? "High-entropy section: the executable is likely packed or encrypted."
            : null,
      columns: [
        strCol("File", ["name"]),
        strCol("Publisher", ["publisher"]),
        col("signed", "Signature", (m) => {
          if (!metaBool(m, "signed"))
            return <span className="badge">unsigned</span>;
          const ok = metaStr(m, "signature_integrity") === "valid";
          return ok ? (
            <span className="badge badge-accent">valid</span>
          ) : (
            <span className="badge badge-danger">MISMATCH</span>
          );
        }),
        boolCol("Packed", "likely_packed", "packed", "no"),
        pivotCol("imphash", ["imphash"]),
        strCol("Machine", ["machine"], true),
        timeCol("Compiled", ["compile_timestamp"]),
      ],
    }),
    aggregate: true,
  },
  Voicemail: {
    Component: makeTableViewer([
      strCol("Sender", ["sender"], true),
      strCol("Callback", ["callback_number"], true),
      numCol("Duration (s)", ["duration_seconds"]),
      timeCol("Received", ["date"]),
      delCol("Status", "deleted"),
    ]),
  },
  Reminder: {
    Component: makeTableViewer([
      strCol("Title", ["title"]),
      timeCol("Due", ["due"]),
      boolCol("Done", "completed", "completed", "open"),
      timeCol("Completed", ["completed_date"]),
      numCol("Priority", ["priority"]),
      strCol("List", ["calendar_name"]),
    ]),
  },
  Note: {
    Component: makeTableViewer([
      strCol("Title", ["title"]),
      truncCol("Snippet", ["snippet"]),
      timeCol("Created", ["created"]),
      timeCol("Modified", ["modified"]),
    ]),
  },
  PhotoAsset: {
    Component: makeRichViewer({
      noun: "photo assets",
      timeKeys: ["date"],
      searchKeys: ["filename", "original_filename"],
      dimensions: [
        { title: "Media kind", value: (m) => metaStr(m, "media_kind") },
      ],
      columns: [
        pivotCol("Filename", ["filename", "original_filename"]),
        strCol("Kind", ["media_kind"]),
        boolCol("GPS", "has_gps", "has GPS", "no"),
        boolCol("Favorite", "favorite", "favorite", "no"),
        timeCol("Created", ["date"]),
        delCol("Status", "deleted"),
      ],
    }),
    aggregate: true,
  },
  PowerLogEvent: {
    Component: makeTableViewer([
      strCol("Event", ["event"]),
      strCol("Category", ["category"]),
      timeCol("Time", ["date"]),
    ]),
  },
  ShellHistoryEntry: {
    Component: makeRichViewer({
      noun: "shell history commands",
      timeKeys: ["date"],
      searchKeys: ["command", "shell"],
      dimensions: [{ title: "Shell", value: (m) => metaStr(m, "shell") }],
      columns: [
        strCol("Shell", ["shell"], true),
        truncCol("Command", ["command"]),
        numCol("Line", ["line_number"]),
        timeCol("Time", ["date"]),
      ],
    }),
    aggregate: true,
  },
  // What the phone has been near: a car, a watch, a speaker, a skimmer. The
  // file's order is a column because Android appends a device when it is first
  // remembered, so the top row is the earliest pairing — the only answer for a
  // device that carries no timestamp at all.
  // Where the phone was, newest first: "where was this device last" is the
  // question, and the accuracy is part of the answer — a fix good to 1.4 km is
  // a different statement from one good to 5 m.
  CachedLocation: {
    Component: makeTableViewer([
      strCol("Latitude", ["gps_lat"], true),
      strCol("Longitude", ["gps_lon"], true),
      timeCol("When", ["timestamp"]),
      numCol("Accuracy (m)", ["horizontal_accuracy_m"]),
      numCol("Speed (m/s)", ["speed_mps"]),
      numCol("Altitude (m)", ["altitude_m"]),
    ]),
  },
  BluetoothPairing: {
    Component: makeTableViewer([
      strCol("#", ["order"]),
      truncCol("Device", ["device_name"]),
      pivotCol("Address", ["address"]),
      timeCol("Last seen", ["last_seen"]),
      strCol("Link key", ["link_key_present"]),
      strCol("Type", ["device_type"]),
    ]),
  },
  // What the exhibit says it is. One record per identity file, so two files
  // disagreeing are two rows: the device-facts panel on System Info folds them
  // and shows the disagreement; this is the evidence underneath it.
  HostDeviceInfo: {
    Component: makeTableViewer([
      strCol("Platform", ["platform"]),
      truncCol("Read from", ["source_file"]),
      factsCol("What it states"),
      strCol("Record", ["name"]),
    ]),
  },
  MobileDeviceInfo: {
    Component: makeTableViewer([
      strCol("Platform", ["platform"]),
      truncCol("Read from", ["source_file"]),
      factsCol("What it states"),
      strCol("Record", ["name"]),
    ]),
  },
  // A phone backed up to this exhibit. The IMEI and serial are what identify
  // the handset itself; whether the backup is encrypted decides what else can
  // be read out of it.
  IosBackupInfo: {
    Component: makeTableViewer([
      strCol("Device", ["device_name"]),
      strCol("Model", ["product_type"]),
      strCol("iOS", ["product_version", "build_version"]),
      pivotCol("IMEI", ["imei"]),
      pivotCol("Serial", ["serial_number"]),
      timeCol("Backed up", ["date"]),
      boolCol("Encryption", "encrypted", "encrypted", "not encrypted"),
      truncCol("Backup", ["backup_path", "source_file"]),
    ]),
  },
  // What is installed, and where it was installed from: an application in
  // /Applications is a different statement from one running out of a user's
  // Downloads folder, and the version is what a vulnerability question turns on.
  // The screen an examiner comes to this record class for is not the list of
  // apps — it is "which of these did not come from the store". Android's
  // package manager records the installing package, and on the graded device
  // exactly one of the 63 packages with its code in user data has none: a
  // rooting tool. A flat table cannot be grouped on that, so this is a rich
  // viewer with install provenance as a dimension.
  InstalledApp: {
    Component: makeRichViewer({
      noun: "installed applications",
      timeKeys: ["first_install_rfc3339", "install_time_rfc3339", "update_time_rfc3339"],
      searchKeys: ["package", "name", "installer_package", "code_path"],
      dimensions: [
        { title: "How it was installed", value: (m) => metaStr(m, "install_source") },
        { title: "Installer", value: (m) => metaStr(m, "installer_package") },
        { title: "Code partition", value: (m) => metaStr(m, "code_partition") },
        { title: "Platform", value: (m) => metaStr(m, "platform") },
      ],
      // The caution rides on the row, because this is the row somebody
      // screenshots. "No installer recorded" is a signal and not a proof, and
      // a package shipped with the OS has no installer for a reason that is
      // not suspicious at all.
      notable: (m) => {
        switch (metaStr(m, "install_source")) {
          case "no_installer_recorded":
            return "no installer recorded, and the code is in user data: the signal a sideload leaves — a signal, not a proof";
          case "not_recorded":
            return "the file recorded neither an installer nor a code path for this package";
          default:
            return null;
        }
      },
      columns: [
        strCol("Application", ["name", "display_name", "bundle_name"]),
        strCol("Identifier", ["package"], true),
        strCol("How installed", ["install_source"]),
        strCol("Installer", ["installer_package"]),
        strCol("Version", ["version", "version_name"]),
        strCol("Build", ["build_version"]),
        strCol("Installed in", ["installed_in"]),
        timeCol("First installed", [
          "first_install_rfc3339",
          "install_time_rfc3339",
        ]),
        timeCol("Updated", ["update_time_rfc3339"]),
        truncCol("Bundle", ["bundle_path", "code_path", "source_file"]),
        strCol("Platform", ["platform"]),
      ],
    }),
    aggregate: true,
  },
  MediaProperties: {
    Component: makeTableViewer([
      truncCol("File", ["source_file"]),
      strCol("Duration", ["duration_hms"], true),
      timeCol("Recorded", ["created"]),
      timeCol("Modified", ["modified"]),
      strCol("Brand", ["major_brand"]),
    ]),
  },
  // The question a network case turns on is "who looked up what, and when" —
  // and the generic table answered it with transaction ids and protocol flags
  // (UI-028). The answer set is an array of objects, so it is rendered here
  // rather than left to the flat table, which skips nested values.
  DnsResolution: {
    Component: makeTableViewer([
      pivotCol("Name looked up", ["name"]),
      pivotCol("Client", ["client_ip"]),
      // The answers are a list: a query with two A records answered twice, and
      // showing one of them would be a smaller truth than the record holds.
      // Each is its own pivot trigger, so either address is one click from
      // everything else in the case that touches it (§1.0).
      pivotListCol("Resolved to", "answer_data"),
      pivotCol("Server", ["server_ip"]),
      strCol("Result", ["rcode_name"]),
      // The product writes a time one way; an examiner comparing two screens
      // should not have to notice that two spellings are the same instant.
      timeCol("Time", ["timestamp"]),
    ]),
  },
  NetworkCapture: {
    Component: makeTableViewer([
      truncCol("Capture", ["source_name"]),
      strCol("Format", ["format"]),
      numCol("Packets", ["packets"]),
      numCol("Flows", ["flow_count"]),
      timeCol("First seen", ["first_seen"]),
      timeCol("Last seen", ["last_seen"]),
    ]),
  },
  // A whole exhibit that no parser in this build claimed. Rare and important:
  // it is the difference between "the capture held nothing" and "nothing here
  // reads captures" (HUNT-060).
  SourceUnparsed: {
    Component: makeTableViewer([
      truncCol("Source", ["source_name"]),
      strCol("Taken to be", ["detected_type"]),
      strCol("Modules run", ["modules_run"]),
      truncCol("What this means", ["message"]),
    ]),
  },
  TrashEntry: {
    Component: makeTableViewer([
      truncCol("Original path", ["original_path"]),
      strCol("Deleted", ["deletion_date"], true),
    ]),
  },
  RecentFileEntry: {
    Component: makeTableViewer([
      truncCol("File", ["uri"]),
      strCol("Application", ["application"]),
      strCol("Added", ["added"], true),
      strCol("Last visited", ["visited"], true),
    ]),
  },
  ThumbcacheEntry: {
    Component: makeTableViewer([
      pivotCol("Entry hash", ["entry_hash"]),
      truncCol("Identifier", ["identifier"]),
      strCol("Format", ["image_format"]),
      bytesCol("Data size", ["data_size"]),
    ]),
  },
  FreedesktopThumbnail: {
    Component: makeTableViewer([
      truncCol("Original file", ["original_path"]),
      timeCol("Source modified", ["source_mtime"]),
      strCol("MIME type", ["mime_type"]),
      strCol("Generator", ["software"]),
    ]),
  },
  FSEventsRecord: {
    Component: makeTableViewer([
      truncCol("Path", ["path"]),
      strCol("Change", ["flag_names"]),
      numCol("Event ID", ["event_id"]),
    ]),
  },
  DSStoreEntry: {
    Component: makeTableViewer([
      pivotCol("Filename", ["filename"]),
      strCol("Records", ["structures"]),
    ]),
  },
  NetworkFlow: {
    // A rich viewer, not the plain table: the plain shell renders no sort
    // control, and "which flow moved the most bytes" and "which peers are
    // outside the network" are the two questions a flow list exists to
    // answer. The tiles split routable from private peers; the bars rank
    // peers by bytes; the filter box takes an address or a port.
    Component: makeRichViewer({
      noun: "network flows",
      timeKeys: ["first_seen"],
      searchKeys: [
        "remote_ip",
        "local_ip",
        "remote_port",
        "local_port",
        "protocol",
        "tcp_state",
      ],
      stats: (recs) => {
        let external = 0;
        let internal = 0;
        let unclassified = 0;
        for (const r of recs) {
          const ext = metaBool(r.metadata, "remote_is_external");
          if (ext === true) external++;
          else if (ext === false) internal++;
          else unclassified++;
        }
        const tiles: StatTile[] = [
          {
            key: "external",
            label: "External peers",
            count: external,
            tone: "accent",
          },
          {
            key: "internal",
            label: "Internal peers",
            count: internal,
            tone: "neutral",
          },
        ];
        if (unclassified > 0) {
          tiles.push({
            key: "unclassified",
            label: "Unclassified",
            count: unclassified,
            tone: "neutral",
          });
        }
        return tiles;
      },
      statOf: (m) => {
        const ext = metaBool(m, "remote_is_external");
        return ext === true
          ? "external"
          : ext === false
            ? "internal"
            : "unclassified";
      },
      dimensions: [
        {
          title: "Remote peers by bytes",
          value: (m) => metaStr(m, "remote_ip"),
          weight: (m) => metaNum(m, "bytes") ?? 0,
        },
        {
          title: "Remote ports",
          value: (m) => {
            const p = metaNum(m, "remote_port");
            return p == null ? null : String(p);
          },
        },
        { title: "Protocol", value: (m) => metaStr(m, "protocol") },
        { title: "TCP state", value: (m) => metaStr(m, "tcp_state") },
      ],
      // A flow the capture cut short is worth a second look: its byte count is
      // of the bytes held, and a refused other half means one direction of the
      // conversation is on a different row.
      notable: (m) => {
        const cut = metaNum(m, "truncated_packets") ?? 0;
        const refused = metaNum(m, "refused_packets_between_hosts") ?? 0;
        if (cut > 0) return `${cut} packets cut by the snaplen`;
        if (refused > 0)
          return `${refused} packets between these hosts refused before a port was read`;
        return null;
      },
      columns: NETWORK_FLOW_COLUMNS,
    }),
    aggregate: true,
    columns: NETWORK_FLOW_COLUMNS,
  },
  // What was asked for and what came back, out of the reassembled TCP
  // streams. The question is "what did this host fetch, what did it send, and
  // what came back" — and the generic table answered it with a nested request
  // object and a nested response object, so the method, the status and the
  // posted form fields were all one unreadable JSON cell (§5 of
  // UI_TESTING.md). The tiles split the status classes, because "what failed"
  // and "what was redirected" are two different follow-ups; the bars rank the
  // hosts, the methods and the declared types.
  HttpTransaction: {
    Component: makeRichViewer({
      noun: "HTTP transactions",
      searchKeys: [
        "url",
        "host",
        "client_ip",
        "server_ip",
        "pairing",
        "short_desc",
      ],
      stats: (recs) => {
        const counts = new Map<string, number>();
        for (const r of recs) counts.set(
          httpStatusClass(r.metadata),
          (counts.get(httpStatusClass(r.metadata)) ?? 0) + 1,
        );
        const tiles: StatTile[] = [];
        for (const [key, label, tone] of HTTP_STATUS_CLASSES) {
          const count = counts.get(key) ?? 0;
          if (count === 0) continue;
          tiles.push({ key, label, count, tone });
        }
        return tiles;
      },
      statOf: httpStatusClass,
      dimensions: [
        { title: "Hosts", value: (m) => metaStr(m, "host") },
        {
          title: "Methods",
          value: (m) => {
            const request = sub(m, "request");
            return request == null ? null : metaStr(request, "method");
          },
        },
        {
          title: "Declared types",
          value: (m) => {
            const response = sub(m, "response");
            return response == null
              ? null
              : (metaStr(response, "content_type")?.split(";")[0]?.trim() ??
                  null);
          },
        },
        { title: "Server", value: (m) => metaStr(m, "server_ip") },
      ],
      // The pairing first: it qualifies everything else on the row, because a
      // response shown beside the wrong request makes every other cell a
      // statement about a different exchange.
      notable: (m) => {
        const pairing = metaStr(m, "pairing");
        if (pairing != null && HTTP_PAIRING_UNSAFE.has(pairing)) {
          return (
            metaStr(m, "pairing_basis") ??
            "this pairing was made across a gap in the stream and may be wrong"
          );
        }
        const partial = httpMessagePartial(m);
        if (partial != null) return `A prefix, not the whole message: ${partial}`;
        if (metaBool(m, "content_incomplete")) {
          return (
            metaStr(m, "content_incomplete_detail") ??
            `Record incomplete: ${incompleteReasonLabel(
              metaStr(m, "content_incomplete_reason"),
            )}`
          );
        }
        return null;
      },
      columns: HTTP_TRANSACTION_COLUMNS,
    }),
    aggregate: true,
    columns: HTTP_TRANSACTION_COLUMNS,
  },
  // Who a host spoke to in cipher, read from the only part of a TLS
  // conversation that is in the clear. The question is "what did this host
  // connect to, with what, and what did the far end claim to be" — none of
  // which the generic table answered, because the handshakes, the hellos and
  // the chain are four nested objects. The tile that matters is the
  // known-weak-suite count; the bars rank the names asked for and the
  // versions, which is how an examiner finds the one session that negotiated
  // TLS 1.0.
  TlsSession: {
    Component: makeRichViewer({
      noun: "TLS sessions",
      searchKeys: [
        "server_name",
        "ja3_md5",
        "negotiated_cipher",
        "negotiated_version",
        "certificate_subject",
        "certificate_issuer",
        "server_ip",
      ],
      stats: (recs) => {
        let weak = 0;
        let noCertificate = 0;
        for (const r of recs) {
          if (metaBool(r.metadata, "cipher_is_known_weak")) weak++;
          else if (metaStr(r.metadata, "certificates_unavailable") != null) {
            noCertificate++;
          }
        }
        const tiles: StatTile[] = [];
        if (weak > 0) {
          tiles.push({
            key: "weak",
            label: "Known-weak cipher",
            count: weak,
            tone: "error",
          });
        }
        if (noCertificate > 0) {
          // Labelled "no certificate in the capture", never "no certificate":
          // a TLS 1.3 session's certificate is inside the encrypted
          // extensions and was never in the bytes to be read.
          tiles.push({
            key: "no_certificate",
            label: "No certificate in the capture",
            count: noCertificate,
            tone: "neutral",
          });
        }
        return tiles;
      },
      statOf: (m) =>
        metaBool(m, "cipher_is_known_weak")
          ? "weak"
          : metaStr(m, "certificates_unavailable") != null
            ? "no_certificate"
            : null,
      dimensions: [
        {
          title: "Names asked for (SNI)",
          value: (m) => metaStr(m, "server_name"),
        },
        { title: "Version", value: (m) => metaStr(m, "negotiated_version") },
        { title: "Cipher", value: (m) => metaStr(m, "negotiated_cipher") },
        { title: "JA3", value: (m) => metaStr(m, "ja3_md5") },
      ],
      notable: (m) => {
        if (metaBool(m, "cipher_is_known_weak")) {
          return `This session negotiated ${metaStr(m, "negotiated_cipher") ?? "a suite"}, which is on this build's known-weak list. That is a statement about the suite and not a demonstration that this conversation was broken.`;
        }
        const unavailable = metaStr(m, "certificates_unavailable");
        if (unavailable != null) {
          return (
            metaStr(m, "certificates_unavailable_statement") ??
            incompleteReasonLabel(unavailable)
          );
        }
        if (metaBool(m, "content_incomplete")) {
          return (
            metaStr(m, "content_incomplete_detail") ??
            `Record incomplete: ${incompleteReasonLabel(
              metaStr(m, "content_incomplete_reason"),
            )}`
          );
        }
        return null;
      },
      columns: TLS_SESSION_COLUMNS,
    }),
    aggregate: true,
    columns: TLS_SESSION_COLUMNS,
  },
  // What a host CLAIMED to be. One row per certificate a server presented, and
  // the two questions it answers are "who issued this" and "when was it good
  // for" — a validity window the generic table rendered as two ISO strings
  // among forty other keys, with the subject alternative names, which are
  // where the name that matters usually is, in a nested array below them.
  // Every row carries what was not checked, in words: nothing here verifies a
  // signature, builds a chain, or consults a trust store or a revocation list.
  TlsCertificate: {
    Component: makeRichViewer({
      noun: "TLS certificates",
      // The validity window is the only time axis a certificate has, and
      // `not_before` is the end of it that says when the thing was minted.
      timeKeys: ["not_before"],
      searchKeys: [
        "subject",
        "issuer",
        "subject_common_name",
        "issuer_common_name",
        "sha256",
        "serial",
        "server_name_requested",
      ],
      stats: (recs) => {
        let selfIssued = 0;
        let nameMismatch = 0;
        for (const r of recs) {
          if (metaBool(r.metadata, "self_signed")) selfIssued++;
          else if (r.metadata.covers_the_name_requested === false) {
            nameMismatch++;
          }
        }
        const tiles: StatTile[] = [];
        if (selfIssued > 0) {
          tiles.push({
            key: "self_issued",
            label: "Subject = issuer",
            count: selfIssued,
            tone: "accent",
          });
        }
        if (nameMismatch > 0) {
          tiles.push({
            key: "name_mismatch",
            label: "No name matches the one asked for",
            count: nameMismatch,
            tone: "accent",
          });
        }
        return tiles;
      },
      statOf: (m) =>
        metaBool(m, "self_signed")
          ? "self_issued"
          : m.covers_the_name_requested === false
            ? "name_mismatch"
            : null,
      dimensions: [
        {
          title: "Issuer",
          value: (m) => metaFirst(m, ["issuer_common_name", "issuer"]),
        },
        {
          title: "Key algorithm",
          value: (m) => metaStr(m, "key_algorithm"),
        },
        {
          title: "Signature algorithm",
          value: (m) => metaStr(m, "signature_algorithm"),
        },
        {
          title: "Position in chain",
          value: (m) => {
            const n = metaNum(m, "position_in_chain");
            return n == null ? null : n === 0 ? "leaf" : `intermediate ${n}`;
          },
        },
      ],
      // Two markers, and neither is a verdict: a certificate that issued
      // itself and one whose own names do not cover the name the client asked
      // for are both leads, and the sentence says on what basis.
      notable: (m) => {
        if (metaBool(m, "self_signed")) {
          return (
            metaStr(m, "statement") ??
            "Subject and issuer are the same name; no signature was verified, so that comparison is all this is"
          );
        }
        if (m.covers_the_name_requested === false) {
          return (
            metaStr(m, "covers_the_name_requested_meaning") ??
            "None of this certificate's own names matches the name the client asked for. It is a comparison of two strings, NOT a verification."
          );
        }
        if (metaBool(m, "content_incomplete")) {
          return (
            metaStr(m, "content_incomplete_detail") ??
            `Record incomplete: ${incompleteReasonLabel(
              metaStr(m, "content_incomplete_reason"),
            )}`
          );
        }
        return null;
      },
      columns: TLS_CERTIFICATE_COLUMNS,
    }),
    aggregate: true,
    columns: TLS_CERTIFICATE_COLUMNS,
  },
  // Who claimed which address on the segment. The question is "was anything on
  // this wire lying about who it was", and the answer is arithmetic over two
  // lists: an address claimed by more than one hardware address. ARP does not
  // authenticate — a reply is believed because it arrived — so the contested
  // tile is a lead and every row, contested or not, carries the sentence
  // saying a binding is an announcement rather than a proven fact.
  ArpBinding: {
    Component: makeRichViewer({
      noun: "address claims",
      timeKeys: ["contested_from"],
      searchKeys: ["ip", "macs", "short_desc", "source_name"],
      stats: (recs) => {
        let contested = 0;
        let single = 0;
        for (const r of recs) {
          if (metaBool(r.metadata, "contested")) contested++;
          else single++;
        }
        const tiles: StatTile[] = [
          {
            key: "contested",
            label: "Contested addresses",
            count: contested,
            tone: "error",
          },
          {
            key: "single",
            label: "One claimant",
            count: single,
            tone: "neutral",
          },
        ];
        return tiles;
      },
      statOf: (m) => (metaBool(m, "contested") ? "contested" : "single"),
      dimensions: [
        // Bucketed by how many hardware addresses claimed it, which is the
        // one grouping this record type has: an address claimed three times
        // is a different question from one claimed twice.
        {
          title: "Claimants",
          value: (m) => {
            const listed = Array.isArray(m.macs) ? m.macs.length : 0;
            const beyond = metaNum(m, "macs_beyond_cap") ?? 0;
            const n = listed + beyond;
            if (n === 0) return null;
            return n === 1 ? "1 hardware address" : `${n} hardware addresses`;
          },
        },
        { title: "Capture", value: (m) => metaStr(m, "source_name") },
      ],
      notable: (m) => {
        if (metaBool(m, "contested")) {
          return (
            metaStr(m, "statement") ??
            "More than one hardware address claimed this address; ARP does not authenticate and no verdict is reached here"
          );
        }
        if (metaBool(m, "content_incomplete")) {
          return (
            metaStr(m, "content_incomplete_detail") ??
            `Record incomplete: ${incompleteReasonLabel(
              metaStr(m, "content_incomplete_reason"),
            )}`
          );
        }
        return null;
      },
      columns: ARP_BINDING_COLUMNS,
    }),
    aggregate: true,
    columns: ARP_BINDING_COLUMNS,
  },
  // A wireless network the machine was configured FOR: the macOS
  // known-networks list and the Windows WLAN profiles, one type on purpose.
  // See WIFI_NETWORK_COLUMNS for why the key column exists.
  WifiNetwork: {
    Component: makeRichViewer({
      noun: "wireless networks",
      timeKeys: ["last_joined_rfc3339", "added_at_rfc3339"],
      searchKeys: [
        "ssid",
        "profile_name",
        "source_file",
        "path",
        "interface_guid",
      ],
      stats: (recs) => {
        let clear = 0;
        let held = 0;
        let notStated = 0;
        let none = 0;
        for (const r of recs) {
          switch (metaStr(r.metadata, "key_state")) {
            case "in_the_clear":
              clear++;
              break;
            case "dpapi_protected":
            case "protected_unreadable":
              held++;
              break;
            case "protection_not_stated":
              notStated++;
              break;
            default:
              none++;
          }
        }
        const tiles: StatTile[] = [];
        if (clear > 0) {
          tiles.push({
            key: "clear",
            label: "Key in the clear",
            count: clear,
            tone: "error",
          });
        }
        if (held > 0) {
          tiles.push({
            key: "protected",
            label: "Key protected, not decrypted",
            count: held,
            tone: "warning",
          });
        }
        if (notStated > 0) {
          tiles.push({
            key: "not-stated",
            label: "Protection not stated",
            count: notStated,
            tone: "warning",
          });
        }
        tiles.push({
          key: "none",
          label: "No key on the record",
          count: none,
          tone: "neutral",
        });
        return tiles;
      },
      statOf: (m) => {
        switch (metaStr(m, "key_state")) {
          case "in_the_clear":
            return "clear";
          case "dpapi_protected":
          case "protected_unreadable":
            return "protected";
          case "protection_not_stated":
            return "not-stated";
          default:
            return "none";
        }
      },
      dimensions: [
        { title: "Security", value: (m) => metaStr(m, "authentication") },
        { title: "Platform", value: (m) => metaStr(m, "platform") },
        { title: "Adapter", value: (m) => metaStr(m, "interface_guid") },
      ],
      notable: (m) => {
        if (metaBool(m, "ssid_forms_disagree")) {
          return (
            metaStr(m, "content_incomplete_detail") ??
            "This profile's SSID is written two ways and they do not agree"
          );
        }
        if (metaBool(m, "content_incomplete")) {
          return (
            metaStr(m, "content_incomplete_detail") ??
            `Record incomplete: ${incompleteReasonLabel(
              metaStr(m, "content_incomplete_reason"),
            )}`
          );
        }
        return null;
      },
      columns: WIFI_NETWORK_COLUMNS,
    }),
    aggregate: true,
    columns: WIFI_NETWORK_COLUMNS,
  },
  // A network this machine has BEEN ON, from the NetworkList keys, as against
  // the WifiNetwork records that say it was configured for one. The times are
  // the point of the record and the zone is the point of the viewer: see
  // NETWORK_PROFILE_COLUMNS.
  NetworkProfile: {
    Component: makeRichViewer({
      noun: "networks the machine has been on",
      timeKeys: ["date_last_connected", "date_created"],
      searchKeys: [
        "network_name",
        "profile_name",
        "description",
        "default_gateway_mac",
        "dns_suffix",
      ],
      stats: (recs) => {
        let wireless = 0;
        let wired = 0;
        let other = 0;
        let noInstant = 0;
        for (const r of recs) {
          const kind = metaStr(r.metadata, "network_kind");
          if (kind === "wireless") wireless++;
          else if (kind === "wired") wired++;
          else other++;
          if (!metaStr(r.metadata, "date_last_connected")) noInstant++;
        }
        const tiles: StatTile[] = [
          {
            key: "wireless",
            label: "Wireless",
            count: wireless,
            tone: "neutral",
          },
          { key: "wired", label: "Wired", count: wired, tone: "neutral" },
          { key: "other", label: "VPN or unknown", count: other, tone: "neutral" },
        ];
        if (noInstant > 0) {
          // Not folded into the others: a row with no instant is a row whose
          // local time cannot be placed, and that is a different state from a
          // network of an unknown kind.
          tiles.push({
            key: "no-instant",
            label: "No instant (zone unknown)",
            count: noInstant,
            tone: "warning",
          });
        }
        return tiles;
      },
      statOf: (m) => {
        if (!metaStr(m, "date_last_connected")) return "no-instant";
        const kind = metaStr(m, "network_kind");
        return kind === "wireless" ? "wireless" : kind === "wired" ? "wired" : "other";
      },
      dimensions: [
        { title: "Kind", value: (m) => metaStr(m, "network_kind") },
        { title: "Category", value: (m) => metaStr(m, "category") },
        { title: "Gateway MAC", value: (m) => metaStr(m, "default_gateway_mac") },
        { title: "DNS suffix", value: (m) => metaStr(m, "dns_suffix") },
      ],
      notable: (m) => {
        if (metaBool(m, "content_incomplete")) {
          return (
            metaStr(m, "content_incomplete_detail") ??
            metaStr(m, "time_zone_note") ??
            `Record incomplete: ${incompleteReasonLabel(
              metaStr(m, "content_incomplete_reason"),
            )}`
          );
        }
        return null;
      },
      columns: NETWORK_PROFILE_COLUMNS,
    }),
    aggregate: true,
    columns: NETWORK_PROFILE_COLUMNS,
  },
  WindowsTimelineActivity: {
    Component: WindowsTimelineViewer,
    aggregate: true,
  },

  // ---- NTFS change journals -------------------------------------------------
  //
  // The two NTFS journals are among the largest record classes any Windows case
  // produces and both fell through to a generic key/value table, where a
  // reason-flag bitmask and an LSN are unreadable and the file activity they
  // describe cannot be grouped or sorted at all.
  UsnJournalEntry: {
    Component: makeRichViewer({
      noun: "USN journal entries",
      timeKeys: ["timestamp"],
      searchKeys: ["file_name", "primary_operation", "reason_names"],
      dimensions: [
        { title: "Operation", value: (m) => metaStr(m, "primary_operation") },
        { title: "Most-changed files", value: (m) => metaStr(m, "file_name") },
        { title: "File type", value: (m) => extOf(metaStr(m, "file_name")) },
      ],
      // Deletion is what an examiner comes to the USN journal for: it is often
      // the only surviving record that a file existed at all.
      notable: (m) =>
        (metaStr(m, "reason_names") ?? "").includes("FILE_DELETE")
          ? "file deleted"
          : null,
      columns: [
        timeCol("Time", ["timestamp"]),
        pivotCol("File", ["file_name"]),
        strCol("Operation", ["primary_operation"]),
        truncCol("Reasons", ["reason_names"]),
        strCol("USN", ["usn"], true),
        strCol("File ref", ["file_reference"], true),
        strCol("Parent ref", ["parent_reference"], true),
      ],
    }),
    aggregate: true,
  },
  NtfsLogFileRecord: {
    Component: makeRichViewer({
      noun: "$LogFile transaction records",
      searchKeys: ["operation", "undo_operation_name"],
      dimensions: [
        { title: "Redo operation", value: (m) => metaStr(m, "operation") },
        {
          title: "Undo operation",
          value: (m) => metaStr(m, "undo_operation_name"),
        },
      ],
      // A record whose client data spilled past its page was decoded from the
      // first fragment only; the parser stamps that, and it must stay visible
      // in the listing rather than only on the individual record.
      notable: (m) =>
        metaBool(m, "multi_page")
          ? "payload spans pages — partially decoded"
          : null,
      columns: [
        numCol("Record", ["record_number"]),
        strCol("LSN", ["lsn"], true),
        strCol("Redo", ["operation"]),
        strCol("Undo", ["undo_operation_name"]),
        numCol("Page", ["page_number"]),
        numCol("Transaction", ["transaction_id"]),
        numCol("Target attr", ["target_attribute"]),
      ],
    }),
    aggregate: true,
  },

  // ---- Browser artefacts beyond history/downloads/bookmarks ----------------
  BrowserCookie: {
    Component: makeRichViewer({
      noun: "browser cookies",
      timeKeys: ["creation_time"],
      searchKeys: ["host", "cookie_name", "browser"],
      dimensions: [
        { title: "Host", value: (m) => metaStr(m, "host") },
        { title: "Browser", value: (m) => metaStr(m, "browser") },
      ],
      columns: [
        pivotCol("Host", ["host"]),
        strCol("Cookie", ["cookie_name"]),
        timeCol("Created", ["creation_time"]),
        timeCol("Last access", ["last_access"]),
        timeCol("Expires", ["expiry_time"]),
        boolCol("Secure", "is_secure", "secure", "plain"),
        boolCol("HttpOnly", "is_httponly", "httpOnly", "script-readable"),
        strCol("Browser", ["browser"]),
      ],
    }),
    aggregate: true,
  },
  BrowserLogin: {
    Component: makeRichViewer({
      noun: "saved logins",
      timeKeys: ["last_used"],
      searchKeys: ["origin_url", "username", "browser"],
      dimensions: [
        { title: "Site", value: (m) => domainOf(metaStr(m, "origin_url")) },
        { title: "Username", value: (m) => metaStr(m, "username") },
      ],
      columns: [
        truncCol("Site", ["origin_url"]),
        pivotCol("Username", ["username"]),
        // The password itself is never decrypted here; whether one was STORED
        // is the fact, and saying so is not the same as revealing it.
        boolCol(
          "Password stored",
          "has_saved_password",
          "stored (encrypted)",
          "none",
        ),
        numCol("Times used", ["times_used"]),
        timeCol("Last used", ["last_used"]),
        timeCol("Created", ["date_created"]),
        strCol("Browser", ["browser"]),
      ],
    }),
    aggregate: true,
  },
  BrowserAutofill: {
    Component: makeRichViewer({
      noun: "autofill entries",
      timeKeys: ["last_used"],
      searchKeys: ["field_name", "value", "browser"],
      dimensions: [
        { title: "Field", value: (m) => metaStr(m, "field_name") },
        { title: "Browser", value: (m) => metaStr(m, "browser") },
      ],
      columns: [
        strCol("Field", ["field_name"]),
        truncCol("Value", ["value"]),
        numCol("Used", ["use_count"]),
        timeCol("First used", ["first_used"]),
        timeCol("Last used", ["last_used"]),
        strCol("Browser", ["browser"]),
      ],
    }),
    aggregate: true,
  },
  BrowserSession: {
    Component: makeRichViewer({
      noun: "restored tabs",
      searchKeys: ["url", "title", "browser"],
      dimensions: [
        { title: "Domain", value: (m) => domainOf(metaStr(m, "url")) },
        { title: "Window", value: (m) => metaStr(m, "window") },
      ],
      columns: [
        strCol("Title", ["title"]),
        truncCol("URL", ["url"]),
        numCol("Window", ["window"]),
        strCol("Browser", ["browser"]),
      ],
    }),
    aggregate: true,
  },

  // ---- Detections -----------------------------------------------------------
  YaraMatch: {
    Component: makeRichViewer({
      noun: "YARA matches",
      searchKeys: ["rule", "namespace", "surface", "path", "stream_name"],
      dimensions: [
        { title: "Rule", value: (m) => metaStr(m, "rule") },
        // Which surface the hit is on (ROADMAP §2.3): a file's own content,
        // an alternate data stream, a registry value, free space. The
        // parser stamps every record with it so a hit in free space can
        // never be read as a hit in a live file; the bars make the split
        // the first thing on the screen.
        { title: "Surface", value: (m) => metaStr(m, "surface") },
        { title: "Namespace", value: (m) => metaStr(m, "namespace") },
      ],
      notable: (m) => {
        // Two independent facts, both stated when both hold: where the
        // bytes were, and whether they were the stored bytes at all.
        const parts: string[] = [];
        const surface = metaStr(m, "surface");
        if (surface === "unallocated")
          parts.push("in free space: not a hit in a live file");
        if (surface === "ads")
          parts.push(
            "in an alternate data stream: content beside the named file, not the file's own",
          );
        if (surface === "slack")
          parts.push(
            `in the slack of ${metaStr(m, "base_file") ?? "a live file"}: past the file's logical end, not its content, and possibly an earlier file's`,
          );
        if (metaBool(m, "bytes_are_decoded"))
          parts.push(
            `matched in decoded bytes (${metaStr(m, "decoded_via") ?? "decoded"}): the pattern was never stored in this form`,
          );
        return parts.length ? parts.join("; ") : null;
      },
      columns: [
        strCol("Rule", ["rule"]),
        wordCol("Surface", "surface"),
        truncCol("Path", ["path"]),
        strCol("Stream", ["stream_name"]),
        // Pattern hits versus a rule that was true with no string found
        // (`condition: true`, a filesize test): 0 here is a real answer.
        numCol("Pattern hits", ["pattern_match_count"]),
        entropyCol(),
        col("bytes_are_decoded", "Bytes", (m) =>
          metaBool(m, "bytes_are_decoded") ? (
            <span className="badge badge-accent">
              decoded ({metaStr(m, "decoded_via") ?? "decoded"})
            </span>
          ) : (
            <span className="badge">stored bytes</span>
          ),
        ),
        strCol("Namespace", ["namespace"]),
        strCol("Tags", ["tags"]),
        // The denominator for "N matched": without it, N matches out of an
        // unknown rule set is a number with no scale.
        numCol("Rules in set", ["rules_in_set"]),
      ],
    }),
    aggregate: true,
  },
  // One record per region the scanner read (ROADMAP §2.3): its entropy over
  // the bytes read, whether the read reached the declared size, and the
  // decoded spans lifted out of it.
  YaraRegionScanned: {
    Component: makeRichViewer({
      noun: "regions scanned by YARA",
      timeKeys: [],
      searchKeys: ["surface", "path", "stream_name", "region_source"],
      dimensions: [
        { title: "Surface", value: (m) => metaStr(m, "surface") },
        { title: "Region source", value: (m) => metaStr(m, "region_source") },
      ],
      notable: (m) =>
        metaBool(m, "content_incomplete")
          ? (metaStr(m, "content_incomplete_detail") ??
            "the scan did not reach the whole region")
          : null,
      columns: [
        wordCol("Surface", "surface"),
        truncCol("Path", ["path"]),
        strCol("Stream", ["stream_name"]),
        numCol("Offset", ["offset_bytes"]),
        bytesCol("Bytes scanned", ["bytes_scanned"]),
        bytesCol("Declared size", ["declared_size"]),
        col("scan_complete", "Read", (m) =>
          metaBool(m, "scan_complete") ? (
            <span className="badge badge-accent">whole</span>
          ) : (
            <span className="badge badge-warn">part</span>
          ),
        ),
        entropyCol(),
        numCol("Matches", ["matches"]),
        numCol("Decoded spans found", ["decoded_spans_found"]),
        numCol("Decoded spans scanned", ["decoded_spans_scanned"]),
      ],
    }),
    aggregate: true,
  },
  // One record per hive whose value inventory was scanned: how many values
  // were scanned on each basis — the stored bytes the registry parser
  // published (exact), bytes rebuilt here from a lossless rendering (a record
  // from a build before HUNT-159, HUNT-207), or text re-encoded as UTF-16LE
  // (a string, or a capped multi-string's element list, HUNT-217) — and how
  // many could not be. Scanned is the sum of the three basis columns.
  YaraRegistryCoverage: {
    Component: makeTableViewer([
      strCol("Hive", ["hive_type", "hive", "name"]),
      numCol("Values", ["values_total"]),
      numCol("Scanned", ["values_scanned"]),
      numCol("Exact bytes", ["values_scanned_exact"]),
      numCol("Rebuilt from rendering", ["values_scanned_rebuilt"]),
      numCol("Re-encoded (UTF-16LE)", ["values_scanned_reencoded"]),
      numCol("Not scanned", ["values_not_scanned"]),
      numCol("Engine errors", ["values_engine_error"]),
      bytesCol("Bytes scanned", ["bytes_scanned"]),
      bytesCol("Byte budget", ["byte_budget"]),
      boolCol("Budget", "byte_budget_reached", "reached", "not reached"),
      numCol("Matches", ["matches"]),
    ]),
  },
  // One record per file whose decoded spans were not all scanned: emitted
  // only when a ceiling was hit, so a listed file is a file a rule written
  // for a decoded payload may have had no chance to fire on.
  YaraDecodeCoverage: {
    Component: makeTableViewer([
      wordCol("Surface", "surface"),
      truncCol("Path", ["path"]),
      col("decoded_spans_scanned", "Decoded spans scanned", (m) => {
        const scanned = metaNum(m, "decoded_spans_scanned");
        const found = metaNum(m, "decoded_spans_found");
        if (scanned == null) return <span className="an-muted">{MISSING}</span>;
        return (
          <span className="mono">
            {formatCount(scanned)}
            {found != null ? ` of ${formatCount(found)}` : ""}
          </span>
        );
      }),
      bytesCol("Decoded bytes scanned", ["decoded_bytes_scanned"]),
      boolCol("Cap", "decoded_cap_reached", "reached", "not reached"),
      strCol("Shortfall", ["content_incomplete_detail", "message"]),
    ]),
  },

  // ---- Login accounting: Linux utmp/btmp/wtmp/lastlog, macOS utmpx ---------
  LoginSession: {
    Component: makeRichViewer({
      noun: "login sessions",
      timeKeys: ["login_time"],
      searchKeys: ["user", "host", "tty"],
      dimensions: [
        { title: "User", value: (m) => metaStr(m, "user") },
        { title: "Source host", value: (m) => metaStr(m, "host") },
        { title: "Terminal", value: (m) => metaStr(m, "tty") },
      ],
      columns: [
        strCol("User", ["user"]),
        timeCol("Login", ["login_time"]),
        timeCol("Logout", ["logout_time"]),
        numCol("Duration (s)", ["duration_seconds"]),
        strCol("Terminal", ["tty"]),
        strCol("From", ["host", "ip"]),
        numCol("PID", ["pid"]),
      ],
    }),
    aggregate: true,
  },
  FailedLogin: {
    Component: makeRichViewer({
      noun: "failed logins",
      // The btmp producer writes `time`, not `timestamp` (seance_plugin_utmp,
      // pinned by its tests). This read `timestamp`, so the Time column and the
      // events-over-time chart were empty for every failed login on screen.
      timeKeys: ["time"],
      searchKeys: ["user", "host", "tty"],
      dimensions: [
        { title: "Attempted user", value: (m) => metaStr(m, "user") },
        { title: "Source host", value: (m) => metaStr(m, "host") },
      ],
      columns: [
        // The macOS audit trail names the account by number, not by name, so
        // `user_id` stands in — an empty User column on a refused SSH login
        // would read as no attacker rather than as a numeric identity.
        strCol("User", ["user", "user_id"]),
        timeCol("Time", ["time"]),
        strCol("From", ["host", "ip"]),
        strCol("Terminal", ["tty"]),
        strCol("Record type", ["ut_type"]),
        numCol("PID", ["pid"]),
        strCol("Source", ["source_file"]),
      ],
    }),
    aggregate: true,
  },

  // ---- Apple System Log (/var/log/asl) -------------------------------------
  //
  // macOS keeps no on-disk wtmpx, so the login history is in this store under
  // the com.apple.system.utmpx and com.apple.system.lastlog facilities. The
  // facility dimension is therefore the first thing an examiner filters on.
  AslMessage: {
    Component: makeRichViewer({
      noun: "Apple System Log entries",
      timeKeys: ["timestamp"],
      searchKeys: ["sender", "message", "facility", "host"],
      dimensions: [
        { title: "Facility", value: (m) => metaStr(m, "facility") },
        { title: "Sender", value: (m) => metaStr(m, "sender") },
        { title: "Level", value: (m) => metaStr(m, "level_name") },
      ],
      // A login-history record is why this store is read at all, so it must
      // be visible in a list that is mostly launchd noise.
      notable: (m) => {
        const facility = metaStr(m, "facility");
        if (
          facility === "com.apple.system.utmpx" ||
          facility === "com.apple.system.lastlog"
        )
          return "login history: macOS keeps this nowhere else";
        return null;
      },
      columns: [
        timeCol("Time", ["timestamp"]),
        strCol("Level", ["level_name"]),
        strCol("Sender", ["sender"]),
        strCol("Facility", ["facility"]),
        numCol("PID", ["pid"]),
        strCol("Message", ["message"]),
        strCol("Host", ["host"]),
      ],
    }),
    aggregate: true,
  },

  // ---- macOS keychains -----------------------------------------------------
  //
  // An encrypted store with a cleartext index. The secret is never here, so
  // the screen's job is to make that visible on every row while showing what
  // IS here: the service, the account, and when the credential was stored.
  KeychainItem: {
    Component: makeRichViewer({
      noun: "keychain items",
      // The keychain's dates are ISO-like strings (`20210212003531Z`), not
      // epoch integers, so there is no time column to sort on. Naming a
      // timeKey that holds a string would render every row undated.
      timeKeys: [],
      searchKeys: ["service", "account", "PrintName", "server", "comment"],
      dimensions: [
        { title: "Kind", value: (m) => metaStr(m, "item_kind") },
        { title: "Service", value: (m) => metaStr(m, "service") },
        { title: "Secret", value: (m) => metaStr(m, "secret_state") },
      ],
      // A locked secret is the normal case and must be legible as such: an
      // examiner must never read a keychain item as a credential that was
      // recovered.
      notable: (m) => {
        const state = metaStr(m, "secret_state");
        if (state === "locked") return "the secret is encrypted and was not recovered";
        if (state === "not_wrapped_as_expected")
          return "the payload is not wrapped as this format expects";
        return null;
      },
      columns: [
        strCol("Label", ["PrintName", "Label"]),
        strCol("Service", ["service", "server"]),
        strCol("Account", ["account"]),
        strCol("Kind", ["item_kind"]),
        strCol("Stored", ["created"]),
        strCol("Modified", ["modified"]),
        strCol("Secret", ["secret_state"]),
        strCol("Description", ["kind_description"]),
      ],
    }),
    aggregate: true,
  },

  // ---- the iOS keychain inside an encrypted backup (HUNT-111) ---------------
  //
  // Attributes are decrypted and shown; the secret never is. A read item's
  // secret is withheld (released only through an audited reveal), and a
  // ThisDeviceOnly item could not be opened at all. Both must be legible on
  // the row, so nobody reads an item as a recovered credential. The columns
  // are named, so a stray field (`v_Data`) is never rendered.
  IosKeychainItem: {
    Component: makeRichViewer({
      noun: "iOS keychain items",
      // `created`/`modified` are RFC 3339 strings, not epoch integers.
      timeKeys: [],
      searchKeys: ["service", "account", "server", "label", "access_group"],
      dimensions: [
        { title: "Kind", value: (m) => metaStr(m, "item_kind") },
        { title: "State", value: (m) => metaStr(m, "state") },
        { title: "Class", value: (m) => metaStr(m, "keychain_class_name") },
        { title: "Access group", value: (m) => metaStr(m, "access_group") },
      ],
      notable: (m) => {
        const state = metaStr(m, "state");
        if (state === "device_bound")
          return "bound to the device: its key is wrapped under a hardware key a backup does not carry, so nothing in it was read";
        if (state === "authentication_failed")
          return "the item did not authenticate, so its decrypted bytes are not shown";
        if (state && state !== "read") return "this item was not read";
        if (metaStr(m, "secret_state") === "withheld")
          return "the secret decrypted but is withheld: it is not shown, exported or searchable";
        return null;
      },
      columns: [
        strCol("Service", ["service", "server", "label"]),
        strCol("Account", ["account", "account_hex"]),
        strCol("Access group", ["access_group"]),
        strCol("Kind", ["item_kind"]),
        strCol("Class", ["keychain_class_name"]),
        strCol("State", ["state"]),
        strCol("Secret", ["secret_state"]),
        strCol("Created", ["created"]),
        strCol("Modified", ["modified"]),
      ],
    }),
    aggregate: true,
  },

  // ---- the iCloud keychain circle (keychain-2.db ckdevicestate) ------------
  //
  // A device named here need not be in the evidence: this is the inventory of
  // what the Apple ID trusted, which is why the screen leads with the OS and
  // build rather than with the zone.
  ICloudKeychainDevice: {
    Component: makeRichViewer({
      noun: "iCloud keychain devices",
      timeKeys: [],
      searchKeys: ["os_version", "device_id", "octagon_peer_id", "cloudkit_zone"],
      dimensions: [
        { title: "Device", value: (m) => metaStr(m, "os_version") },
        { title: "Circle status", value: (m) => metaStr(m, "sos_circle_status") },
        { title: "Zone", value: (m) => metaStr(m, "cloudkit_zone") },
      ],
      // The circle status is per zone, so a device can be syncing in one and
      // failing in another; a zone in error is worth seeing on the row.
      notable: (m) =>
        metaStr(m, "sos_circle_status") === "kSOSCCError"
          ? "this zone was not syncing"
          : null,
      columns: [
        strCol("Device", ["os_version"]),
        strCol("Zone", ["cloudkit_zone"]),
        strCol("Circle", ["sos_circle_status"]),
        strCol("Octagon peer", ["octagon_peer_id"]),
        strCol("Octagon status", ["octagon_status"]),
        strCol("Key state", ["key_state"]),
        strCol("Device id", ["device_id"]),
        strCol("Last unlock", ["last_unlock"]),
      ],
    }),
    aggregate: true,
  },

  // ---- macOS audit trails (OpenBSM, /var/audit) ----------------------------
  //
  // macOS keeps no `btmp` and, since 10.5, no on-disk `wtmpx`: this is where
  // the login history is. Every record carries whether the attempt succeeded,
  // so a failure must be visible without opening the row.
  AuditEvent: {
    Component: makeRichViewer({
      noun: "audit events",
      timeKeys: ["timestamp"],
      searchKeys: ["event_name", "message", "signing_id", "source_address"],
      dimensions: [
        { title: "Event", value: (m) => metaStr(m, "event_name") },
        { title: "Class", value: (m) => metaStr(m, "event_class_description") },
        { title: "Outcome", value: (m) => metaStr(m, "outcome") },
        { title: "Source address", value: (m) => metaStr(m, "source_address") },
      ],
      notable: (m) => {
        const outcome = metaStr(m, "outcome");
        if (outcome === "failed") return "the system refused this";
        if (outcome === "not_recorded") return "outcome not recorded";
        return null;
      },
      columns: [
        timeCol("Time", ["timestamp"]),
        strCol("Event", ["event_name"]),
        strCol("Outcome", ["outcome"]),
        numCol("Audit uid", ["audit_user_id"]),
        strCol("From", ["source_address"]),
        numCol("PID", ["pid"]),
        strCol("Asked by", ["signing_id"]),
        strCol("Message", ["message"]),
      ],
    }),
    aggregate: true,
  },
  BootEvent: {
    Component: makeRichViewer({
      noun: "boot and shutdown events",
      timeKeys: ["timestamp", "time"],
      searchKeys: ["kind", "ut_type"],
      dimensions: [{ title: "Kind", value: (m) => metaStr(m, "kind") }],
      // A record whose clock could not be trusted must say so where it is read,
      // not only on the record's own page.
      notable: (m) =>
        metaBool(m, "time_unusable") ? "timestamp not usable" : null,
      columns: [
        strCol("Kind", ["kind"]),
        timeCol("Time", ["timestamp", "time"]),
        strCol("Record type", ["ut_type"]),
        numCol("Index", ["record_index"]),
      ],
    }),
    aggregate: true,
  },
  // ---- Spotlight's metadata index (.Spotlight-V100/Store-V2) --------------
  //
  // One screen for the indexed items and two for the store's vocabularies.
  // Spotlight indexes files that have since been DELETED, which is much of
  // why the store is read at all, so none of the three may render as a
  // statement that a file is on the volume now.
  // ---- the registry MRUs: what the shell recorded as opened ---------------
  //
  // The path is an ARRAY — one name per level of the shell item ID list — and
  // the generic flat table skips nested values, so without this viewer the
  // one field read out of the format is invisible. The other thing this screen
  // has to keep straight is whose date is whose: an MRU entry has no time of
  // its own, only the key does.
  ShellMruEntry: {
    Component: makeRichViewer({
      noun: "recently-opened items",
      // The shell item's own FAT times, where the deepest item carries any.
      // The key's last-write time belongs to the key, not the entry, so it is
      // not a sort key here.
      timeKeys: ["shell_item_modified", "shell_item_accessed", "shell_item_created"],
      searchKeys: ["display_name", "shell_item_name", "command", "link_name", "key_path"],
      dimensions: [
        { title: "MRU key", value: (m) => metaStr(m, "mru_kind") },
        { title: "Extension", value: (m) => metaStr(m, "extension") },
      ],
      notable: (m) => {
        if (metaStr(m, "order_source") === "not_listed")
          return "on the key but absent from the order list: a stale entry with no position";
        // k of n items unread (HUNT-147): the detail names the number.
        if ((metaNum(m, "shell_items_unread") ?? 0) > 0)
          return (
            metaStr(m, "content_incomplete_detail") ??
            "part of the shell item ID list could not be read"
          );
        if (m["shell_item_parsed"] === false)
          return "part of the shell item is unread — the names shown come from the format, the rest of each item does not";
        // CIDSizeMRU / FirstFolder: a name, then bytes this build does not
        // interpret (HUNT-167). The detail names the byte count.
        if (m["content_incomplete"] === true)
          return (
            metaStr(m, "content_incomplete_detail") ??
            "part of this value was not decoded"
          );
        // A zeroed file reference would name $MFT if published as entry 0;
        // the parser withholds it and says so, and so does the row.
        if (metaStr(m, "shell_item_mft_reference_note") != null)
          return (
            metaStr(m, "shell_item_mft_reference_note") ??
            "the shell item's file reference is all zero and is not reported as an MFT entry"
          );
        return null;
      },
      columns: [
        strCol("Item", ["display_name", "shell_item_name"]),
        // One name per level, out of the item's own structure. This is the
        // field HUNT-127 asked for: before it, the name came from a scan for
        // delimited printable runs.
        pivotListCol("Path (from the format)", "shell_item_path"),
        numCol("Position", ["mru_position"]),
        // The deepest item's NTFS file reference (HUNT-147), the same field
        // names seance_plugin_lnk publishes, so an MRU entry and a shortcut
        // to the same file can be put side by side.
        numCol("MFT entry", ["shell_item_mft_entry"]),
        numCol("MFT sequence", ["shell_item_mft_sequence"]),
        col("shell_items_unread", "Items unread", (m) => {
          const unread = metaNum(m, "shell_items_unread");
          const total = metaNum(m, "shell_items_total");
          if (unread == null) return <span className="an-muted">{MISSING}</span>;
          return (
            <span className={unread > 0 ? "mono badge badge-warn" : "mono"}>
              {formatCount(unread)}
              {total != null ? ` of ${formatCount(total)}` : ""}
            </span>
          );
        }),
        strCol("Shortcut file", ["link_name"]),
        timeCol("Item modified", ["shell_item_modified"]),
        timeCol("Item accessed", ["shell_item_accessed"]),
        strCol("Zone", ["timezone"]),
        truncCol("Key", ["key_path"]),
        timeCol("Key last written", ["key_last_written"]),
      ],
    }),
    aggregate: true,
  },
  // ---- the unified log's format-string catalogue (/var/db/uuidtext) -------
  //
  // An inventory of the code on the machine that logs. The screen's whole job
  // is to keep one thing legible: a catalogue entry is NOT a record that the
  // binary ran, and it is not a log message — it is the sentences the OS would
  // have substituted arguments into.
  UnifiedLogImage: {
    Component: makeRichViewer({
      noun: "binaries with a logging catalogue",
      // A catalogue states no time at all. Naming a timeKey would render
      // every row undated on a screen where no row has a date to give.
      timeKeys: [],
      searchKeys: ["image_path", "image_uuid", "source_file"],
      dimensions: [
        { title: "Catalogue", value: (m) => metaStr(m, "source_file") },
      ],
      // The row-level caution. It is on every row because this is the
      // inference the record type most invites, and a note at the top of a
      // screen does not survive a screenshot of one line.
      notable: (m) =>
        m["image_uuid_recorded"] === false
          ? "no UUID: this file's name was not preserved, so it cannot be matched to a log reference"
          : "the machine held a logging catalogue for this binary — not a record that it ran",
      columns: [
        strCol("Binary", ["image_path"]),
        numCol("Format strings", ["format_strings"]),
        strCol("UUID", ["image_uuid"]),
        numCol("Load address", ["load_address"]),
        numCol("Image size", ["image_size"]),
        strCol("Catalogue", ["source_file"]),
      ],
    }),
    aggregate: true,
  },
  // ---- the unified log itself (.tracev3) ------------------------------------
  //
  // One row per decoded message. Two things must be legible on the row: a
  // message that was NOT resolved has no text (never an empty one), and a
  // message is only as dated as its clock source — `timesync` is the machine's
  // own database, `tracev3_header` is the file's single anchor.
  UnifiedLogMessage: {
    Component: makeRichViewer({
      noun: "unified log messages",
      timeKeys: ["timestamp"],
      searchKeys: ["message", "format_string", "process", "image", "subsystem", "category"],
      dimensions: [
        { title: "Type", value: (m) => metaStr(m, "activity_type") },
        { title: "Level", value: (m) => metaStr(m, "level") },
        { title: "Subsystem", value: (m) => metaStr(m, "subsystem") },
        { title: "Time source", value: (m) => metaStr(m, "time_source") },
      ],
      notable: (m) => {
        if (m["resolved"] === false)
          return "not resolved: " + (metaStr(m, "unresolved_reason") || "no format string") + " - no text is shown";
        if (m["dated"] === false) return "could not be dated: no clock anchor for its boot";
        if (m["data_decoded"] === false)
          return "statedump data not decoded; its bytes are kept, not rendered";
        if (m["lost_entries"] != null) return "loss record: the log says entries were dropped here";
        return null;
      },
      columns: [
        timeCol("Time", ["timestamp"]),
        strCol("Type", ["activity_type"]),
        strCol("Level", ["level"]),
        strCol("Process", ["process"]),
        numCol("PID", ["pid"]),
        strCol("Subsystem", ["subsystem"]),
        strCol("Category", ["category"]),
        strCol("Message", ["message"]),
        strCol("Clock", ["time_source"]),
      ],
    }),
  },
  // The per-file record: how much of the file was read, and whether its tree
  // (the catalogue a format string resolves against) was reachable.
  UnifiedLog: {
    Component: makeRichViewer({
      noun: "unified log files",
      timeKeys: [],
      searchKeys: ["file_name"],
      dimensions: [
        { title: "Decoded", value: (m) => (m["messages_decoded"] === true ? "messages decoded" : "counted only") },
      ],
      notable: (m) =>
        m["messages_decoded"] === true
          ? null
          : "counted, not decoded: " + (metaStr(m, "note") || "the file's tree was not reachable"),
      columns: [
        strCol("File", ["file_name"]),
        numCol("Chunks", ["chunk_count"]),
        numCol("Tracepoints", ["tracepoints"]),
        numCol("Statedumps", ["statedump_entries"]),
        numCol("Simpledumps", ["simpledump_entries"]),
        numCol("Processes", ["distinct_processes"]),
        numCol("Bytes", ["bytes"]),
      ],
    }),
    aggregate: true,
  },
  SpotlightItem: {
    Component: makeRichViewer({
      noun: "Spotlight indexed items",
      // The index's own write time is on every record; the file's own dates
      // are attributes and are the ones an examiner sorts on.
      timeKeys: ["modified", "created", "added", "last_used", "indexed_at"],
      searchKeys: ["path", "file_name", "display_name", "content_type", "where_from"],
      dimensions: [
        { title: "Kind", value: (m) => metaStr(m, "content_type") },
        { title: "Owner uid", value: (m) => metaStr(m, "uid") },
        { title: "Store", value: (m) => metaStr(m, "source_file") },
      ],
      // Two things a flat table would bury. A path that does not reach a root
      // is not a path, and an item whose attribute stream stopped is missing
      // part of what the store holds about it — both have to be legible on
      // the row, because that is where the value gets read off.
      // Read off the raw field rather than through `metaBool`, which returns
      // false for a key that is absent: both of these are emitted ONLY when
      // they are false, so "absent" means complete and testing the value
      // through a coercion would flag every row.
      notable: (m) => {
        if (m["attributes_complete"] === false)
          return "part of this item's metadata was not decoded";
        if (m["path_complete"] === false)
          return "the parent chain leaves this store: not an absolute path";
        return null;
      },
      columns: [
        strCol("Path", ["path", "file_name"]),
        strCol("Content type", ["content_type"]),
        numCol("Size", ["logical_size"]),
        timeCol("Modified", ["modified"]),
        timeCol("Created", ["created"]),
        timeCol("Last used", ["last_used"]),
        numCol("Uses", ["use_count"]),
        strCol("Downloaded from", ["where_from"]),
        numCol("UID", ["uid"]),
        timeCol("Indexed", ["indexed_at"]),
      ],
    }),
    aggregate: true,
  },
  SpotlightProperty: {
    Component: makeRichViewer({
      noun: "Spotlight indexed attributes",
      // A property table entry carries no time; naming a timeKey that no
      // record holds would render every row undated.
      timeKeys: [],
      searchKeys: ["attribute", "source_file"],
      dimensions: [
        { title: "Store", value: (m) => metaStr(m, "source_file") },
        { title: "Value type", value: (m) => metaStr(m, "value_type") },
      ],
      columns: [
        strCol("Attribute", ["attribute"]),
        numCol("Property id", ["property_id"]),
        numCol("Property type", ["property_type"]),
        numCol("Value type", ["value_type"]),
        strCol("Store", ["source_file"]),
      ],
    }),
    aggregate: true,
  },
  SpotlightContentType: {
    Component: makeRichViewer({
      noun: "Spotlight content types",
      timeKeys: [],
      searchKeys: ["content_type", "source_file"],
      dimensions: [{ title: "Store", value: (m) => metaStr(m, "source_file") }],
      // The inference this record must not invite. An id is meaningful only
      // inside its own store, and the type's presence is not presence of a
      // file — so the caution rides on every row rather than sitting once at
      // the top of the screen where a screenshot loses it.
      notable: () => "the index knew this type; a matching file need not exist now",
      columns: [
        strCol("Content type", ["content_type"]),
        numCol("Category id", ["category_id"]),
        strCol("Store", ["source_file"]),
      ],
    }),
    aggregate: true,
  },
  LastLogin: {
    Component: makeRichViewer({
      noun: "last-login records",
      // lastlog writes `last_login_time`; same defect as FailedLogin above.
      timeKeys: ["last_login_time"],
      searchKeys: ["user", "host", "tty"],
      dimensions: [
        { title: "Source host", value: (m) => metaStr(m, "host") },
        { title: "Terminal", value: (m) => metaStr(m, "tty") },
      ],
      columns: [
        // `lastlog` is indexed BY uid and carries no name; the parser writes
        // null rather than inventing one, and the column shows that as absent.
        numCol("UID", ["uid"]),
        strCol("User", ["user"]),
        timeCol("Last login", ["last_login_time"]),
        strCol("Terminal", ["tty"]),
        strCol("From", ["host", "ip"]),
      ],
    }),
    aggregate: true,
  },

  // ---- Recovered Windows event log entries (ROADMAP §2.4) ----------------
  //
  // A DIFFERENT TYPE from `EvtxLogEntry`, on purpose: an event carved from a
  // chunk the intact parser rejected, read out of chunk slack, or found loose
  // is not the same class of evidence as a record the log serves. The screen
  // shows the live columns and then, on every row, where the record came
  // from, what state the chunk header was in, whether its checksums held,
  // whether the template used to render it was its own, and which
  // substitutions could not be bound.
  EvtxRecoveredLogEntry: {
    Component: makeRichViewer({
      noun: "recovered event log entries",
      timeKeys: ["timestamp"],
      searchKeys: [
        "provider_name",
        "short_desc",
        "channel",
        "event_id",
        "recovery_source",
      ],
      stats: levelStats,
      statOf: (m) => metaStr(m, "level_description") ?? "Information",
      dimensions: [
        {
          title: "Recovered from",
          value: (m) => {
            const v = metaStr(m, "recovery_source");
            return v ? (EVTX_RECOVERY_SOURCE[v] ?? v) : null;
          },
        },
        { title: "Top event IDs", value: (m) => metaStr(m, "event_id") },
        { title: "Providers", value: (m) => metaStr(m, "provider_name") },
        { title: "Channels", value: (m) => metaStr(m, "channel") },
      ],
      notable: (m) => {
        if (metaBool(m, "partial"))
          return (
            metaStr(m, "content_incomplete_detail") ??
            "partial: not every substitution could be bound"
          );
        if (metaBool(m, "rendered_with_borrowed_template"))
          return "rendered with a template borrowed from another chunk: the text is the template's and the values are this record's";
        if (metaBool(m, "record_id_also_read_live"))
          return "a live record with this id was also read: this may be an earlier copy of it";
        const id = metaStr(m, "event_id");
        return id ? (NOTABLE_EVENT_IDS[id] ?? null) : null;
      },
      columns: [
        strCol("Event ID", ["event_id"], true),
        strCol("Provider", ["provider_name"]),
        strCol("Level", ["level_description"]),
        strCol("Channel", ["channel"], true),
        timeCol("Time", ["timestamp"]),
        truncCol("Summary", ["short_desc"]),
        wordCol("Recovered from", "recovery_source", EVTX_RECOVERY_SOURCE),
        wordCol("Chunk header", "chunk_header"),
        wordCol("Header checksum", "chunk_header_checksum", EVTX_CHECKSUM_STATE),
        wordCol("Data checksum", "chunk_data_checksum", EVTX_CHECKSUM_STATE),
        col("rendered_with_borrowed_template", "Template", (m) =>
          metaBool(m, "rendered_with_borrowed_template") ? (
            <span className="badge badge-warn">borrowed</span>
          ) : (
            <span className="badge">own</span>
          ),
        ),
        col("partial", "Content", (m) =>
          metaBool(m, "partial") ? (
            <span className="badge badge-warn">partial</span>
          ) : (
            <span className="badge">rendered</span>
          ),
        ),
        col("incomplete_substitutions", "Unbound substitutions", (m) => {
          const v = unboundSubstitutions(m);
          return v ? (
            <span className="mono">{v}</span>
          ) : (
            <span className="an-muted">{MISSING}</span>
          );
        }),
        numCol("Chunk offset", ["chunk_offset"]),
        numCol("Record offset", ["record_offset"]),
      ],
    }),
    aggregate: true,
  },
  // The carve's own account of itself, one record per file: what it scanned,
  // what it found, and every bound it hit. A bound that was hit makes every
  // count a floor, and the row says so.
  EvtxRecoveryStatus: {
    Component: makeTableViewer([
      strCol("Recovery", ["name"]),
      col("bytes_scanned", "Bytes scanned", (m) => {
        const scanned = metaNum(m, "bytes_scanned");
        const declared = metaNum(m, "bytes_declared");
        if (scanned == null) return <span className="an-muted">{MISSING}</span>;
        return (
          <span className="mono">
            {formatBytes(scanned)}
            {declared != null ? ` of ${formatBytes(declared)}` : ""}
          </span>
        );
      }),
      numCol("Chunks found", ["chunks_found"]),
      numCol("Checksums valid", ["chunks_checksum_valid"]),
      numCol("Checksums failed", ["chunks_checksum_failed"]),
      numCol("Checksums absent", ["chunks_checksum_absent"]),
      numCol("Checksums unverifiable", ["chunks_checksum_unverifiable"]),
      numCol("Chunks truncated", ["chunks_truncated"]),
      numCol("Chunks unopenable", ["chunks_unopenable"]),
      numCol("Records recovered", ["records_recovered"]),
      numCol("Partial", ["records_partial"]),
      numCol("Header only", ["records_header_only"]),
      numCol("Borrowed template", ["records_borrowed_template"]),
      numCol("Also read live", ["records_already_live"]),
      // A source that returned fewer bytes than it declared was not scanned
      // whole, whatever the bounds say: the count of bytes scanned is only
      // meaningful against the declared size, so the shortfall is its own
      // badge rather than a number a reader has to subtract.
      col("short_read", "Input", (m) =>
        metaBool(m, "short_read") ? (
          <span className="badge badge-warn">
            short read — not the whole input was scanned
          </span>
        ) : (
          <span className="badge">read whole</span>
        ),
      ),
      col("counts_are_floor", "Bounds", (m) => {
        const hit = [
          ["scan_bound_hit", "scan bound hit"],
          ["chunks_bound_hit", "chunks bound hit"],
          ["records_bound_hit", "records bound hit"],
          ["template_pool_bound_hit", "template pool bound hit"],
        ]
          .filter(([key]) => metaBool(m, key))
          .map(([, label]) => label);
        if (hit.length === 0) return <span className="badge">none hit</span>;
        return (
          <span className="badge badge-warn">
            {hit.join(", ")} — counts are a floor
          </span>
        );
      }),
      strCol("Message", ["message"]),
    ]),
  },

  // ---- Registry cells recovered from unallocated space (ROADMAP §5.9) ------
  //
  // Never merged with the live tree. A recovered key's path is an INFERENCE
  // from a parent offset that may have been reused since; the column header
  // says so, and a path that does not reach the root is flagged on the row.
  RecoveredRegistryKey: {
    Component: makeRichViewer({
      noun: "recovered registry keys",
      timeKeys: ["last_written"],
      searchKeys: ["key_path", "key_name", "hive"],
      dimensions: [
        { title: "Hive", value: (m) => metaStr(m, "hive") },
        {
          title: "Path",
          value: (m) =>
            m.key_path_complete === false
              ? "does not reach the root"
              : "reaches the root",
        },
        {
          title: "Live namesake",
          value: (m) =>
            metaBool(m, "live_key_with_same_name_under_parent")
              ? "a live key of this name under the same parent"
              : "no live key of this name under the parent",
        },
      ],
      notable: (m) => {
        if (m.key_path_complete === false)
          return `the path does not reach the root: the parent chain stops at an offset (${metaStr(m, "key_path_parent_offset_unresolved") ?? "?"}) that resolves to no cell`;
        if (metaBool(m, "live_key_with_same_name_under_parent"))
          return "a live key of this name exists under the same parent: a previous version of it, or a removed namesake — the cell does not say which, and this is not evidence that the key was deleted";
        return null;
      },
      columns: [
        pivotCol("Key path (inferred from offsets)", ["key_path"]),
        strCol("Hive", ["hive"], true),
        timeCol("Last written", ["last_written"]),
        numCol("Subkeys declared", ["subkey_count_declared"]),
        numCol("Values declared", ["value_count_declared"]),
        boolCol(
          "Live namesake",
          "live_key_with_same_name_under_parent",
          "yes",
          "no",
        ),
        numCol("Cell offset", ["bin_offset"]),
        wordCol("Evidence", "evidence_state"),
      ],
    }),
    aggregate: true,
  },
  // A freed vk cell records no key, and the value list that once named it
  // was freed with it: the Key column says "not inferred" on every row rather
  // than showing a dash that reads as the hive root.
  RecoveredRegistryValue: {
    Component: makeRichViewer({
      noun: "recovered registry values",
      timeKeys: [],
      searchKeys: ["value_name", "value_data", "hive", "value_type"],
      dimensions: [
        { title: "Hive", value: (m) => metaStr(m, "hive") },
        { title: "Type", value: (m) => metaStr(m, "value_type") },
        { title: "Data basis", value: recoveredValueBasis },
      ],
      notable: (m) => {
        if (m.data_read === false)
          return `data not read: ${metaStr(m, "data_unread_reason") ?? "no reason recorded"}`;
        const basis = metaStr(m, "data_basis") ?? "";
        if (basis.startsWith("an allocated"))
          return "data read from an allocated cell the freed value points at: the cell may have been reused since, so these bytes are what it holds today";
        return null;
      },
      columns: [
        pivotCol("Value", ["value_name"]),
        strCol("Type", ["value_type"], true),
        col("value_data", "Data", (m) =>
          m.data_read === false ? (
            <span className="badge badge-warn">not read</span>
          ) : (
            <MonoTrunc value={metaStr(m, "value_data") ?? ""} />
          ),
        ),
        col("data_basis", "Data basis", (m) => (
          <span title={metaStr(m, "data_basis") ?? undefined}>
            {recoveredValueBasis(m)}
          </span>
        )),
        col("key_path", "Key", () => (
          <span className="an-muted">not inferred</span>
        )),
        strCol("Hive", ["hive"], true),
        boolCol("Tombstoned", "tombstoned", "yes", "no"),
        numCol("Declared size", ["raw_data_size_declared"]),
        numCol("Cell offset", ["bin_offset"]),
        wordCol("Evidence", "evidence_state"),
      ],
    }),
    aggregate: true,
  },

  // ---- Feature histograms (ROADMAP §2.1) -----------------------------------
  FeatureHistogramSummary: {
    Component: FeatureHistogramViewer,
  },

  // ---- Jump list DestList entries (ROADMAP §2.5) ---------------------------
  //
  // The field at offset 116 of a version 2+ entry is one the sources this
  // module follows do not establish (libyal: "Unknown (access count?)";
  // plaso: unknown5). It is shown as read, under a header that says exactly
  // that, and is never called an access count.
  JumpListDestListEntry: {
    Component: makeRichViewer({
      noun: "jump list entries",
      timeKeys: ["last_recorded_time"],
      searchKeys: ["path", "application", "hostname", "jump_list", "app_id"],
      dimensions: [
        {
          title: "Application",
          value: (m) => metaStr(m, "application") ?? "not established",
        },
        { title: "Jump list", value: (m) => metaStr(m, "jump_list") },
        { title: "Host", value: (m) => metaStr(m, "hostname") },
      ],
      notable: (m) => {
        if (m.application == null && metaStr(m, "application_unknown") != null)
          return metaStr(m, "application_unknown");
        if (metaStr(m, "last_recorded_time_unavailable") != null)
          return metaStr(m, "last_recorded_time_unavailable");
        if (metaStr(m, "pin_status_note") != null)
          return metaStr(m, "pin_status_note");
        return null;
      },
      columns: [
        pivotCol("Path", ["path"]),
        col("application", "Application", (m) => {
          const app = metaStr(m, "application");
          return app ? (
            <Val value={app} />
          ) : (
            <span className="an-muted">not established</span>
          );
        }),
        numCol("MRU position", ["mru_position"]),
        timeCol("Last recorded", ["last_recorded_time"]),
        col("pinned", "Pinned", (m) => {
          if (m.pinned === true)
            return <span className="badge badge-accent">pinned</span>;
          if (m.pinned === false) return <span className="badge">not pinned</span>;
          return <span className="an-muted">not established</span>;
        }),
        numCol("Offset 116 (undocumented; possibly an access count)", [
          "offset_116_unknown_possibly_access_count",
        ]),
        strCol("Host", ["hostname"]),
        numCol("Entry #", ["entry_number"]),
        strCol("Stream", ["stream_name"], true),
        strCol("Jump list", ["jump_list"], true),
        strCol("AppID", ["app_id"], true),
        numCol("DestList version", ["dest_list_format_version"]),
      ],
    }),
    aggregate: true,
  },

  // ---- BITS queue, Search index, RDP cache (ROADMAP §2.5) ------------------
  //
  // A BITS job is a queued transfer, not a completed one: no transfer-
  // completion time is claimed, and the third and fourth trailer times are
  // shown unnamed. A `qmgr.db` job carries `files_read: false` and says so.
  BitsJob: {
    Component: makeRichViewer({
      noun: "BITS jobs",
      timeKeys: ["creation_time"],
      searchKeys: ["job_name", "description", "owner_sid", "notify_command", "remote_urls"],
      dimensions: [
        { title: "State", value: (m) => metaStr(m, "state_name") ?? "unnamed" },
        { title: "Source", value: (m) => metaStr(m, "source_format") },
        { title: "Owner", value: (m) => metaStr(m, "owner_sid") },
      ],
      notable: (m) =>
        m.files_read === false
          ? "header only: this job's file list and times were not read"
          : metaStr(m, "notify_command"),
      columns: [
        strCol("Job", ["job_name"]),
        strCol("State", ["state_name"]),
        strCol("Type", ["job_type_name"]),
        strCol("Owner SID", ["owner_sid"], true),
        timeCol("Created", ["creation_time"]),
        numCol("Files", ["file_count"]),
        strCol("Notify command", ["notify_command"], true),
        strCol("Source", ["source_file"], true),
        strCol("Format", ["source_format"], true),
      ],
    }),
    aggregate: true,
  },
  BitsFileTransfer: {
    Component: makeRichViewer({
      noun: "BITS file records (not linked to a job)",
      timeKeys: [],
      searchKeys: ["local_path", "remote_url"],
      dimensions: [{ title: "Source", value: (m) => metaStr(m, "source_file") }],
      columns: [
        strCol("URL", ["remote_url"]),
        strCol("Local path", ["local_path"]),
        numCol("Bytes transferred", ["bytes_transferred"]),
        strCol("Source", ["source_file"], true),
      ],
    }),
    aggregate: true,
  },
  BitsCarvedFileTransfer: {
    Component: makeRichViewer({
      noun: "BITS file records (carved from stale bytes; the owning job is unknown)",
      timeKeys: [],
      searchKeys: ["local_path", "remote_url"],
      dimensions: [{ title: "Recovery", value: (m) => metaStr(m, "recovery_method") }],
      notable: () => "recovered from bytes no live job owns",
      columns: [
        strCol("URL", ["remote_url"]),
        strCol("Local path", ["local_path"]),
        numCol("Offset", ["offset"]),
        strCol("Recovery", ["recovery_method"], true),
        strCol("Source", ["source_file"], true),
      ],
    }),
    aggregate: true,
  },
  WindowsSearchItem: {
    Component: makeRichViewer({
      noun: "Search index rows (the item may no longer exist)",
      timeKeys: [],
      searchKeys: ["path"],
      dimensions: [{ title: "Schema", value: (m) => metaStr(m, "schema_variant") }],
      notable: (m) =>
        Array.isArray(m.properties_not_decoded) && m.properties_not_decoded.length > 0
          ? "some properties were not decoded"
          : null,
      columns: [
        pivotCol("Path", ["path"]),
        numCol("Item ID", ["item_id"]),
        strCol("Schema", ["schema_variant"], true),
        strCol("Source", ["source_file"], true),
      ],
    }),
    aggregate: true,
  },
  RdpBitmapCache: {
    Component: makeRichViewer({
      noun: "RDP bitmap cache files",
      timeKeys: [],
      searchKeys: ["source_file"],
      dimensions: [{ title: "Status", value: (m) => metaStr(m, "status") }],
      notable: (m) => metaStr(m, "collage_note"),
      columns: [
        strCol("File", ["source_file"]),
        strCol("Format", ["source_format"], true),
        numCol("Tiles", ["tiles"]),
        numCol("Collages", ["collages"]),
        strCol("Status", ["status"]),
      ],
    }),
    aggregate: true,
  },

  // ---- iOS Safari and HealthKit (ROADMAP §1.5) -----------------------------
  SafariBookmark: {
    Component: makeRichViewer({
      noun: "Safari bookmarks",
      timeKeys: ["last_modified"],
      searchKeys: ["title", "url", "folder_path"],
      dimensions: [
        { title: "Domain", value: (m) => domainOf(metaStr(m, "url")) },
        { title: "Folder", value: (m) => metaStr(m, "folder_path") },
      ],
      notable: (m) =>
        metaBool(m, "deleted") ? "flagged deleted in the store" : null,
      columns: [
        strCol("Title", ["title"]),
        truncCol("URL", ["url"]),
        strCol("Folder", ["folder_path"]),
        boolCol("Reading list", "reading_list", "reading list", "bookmark"),
        // `read` is a tri-state in the store: NULL means Safari never
        // recorded it, and the parser leaves the field absent rather than
        // defaulting it to unread.
        col("read", "Read", (m) => {
          if (m.read === true) return <span className="badge">read</span>;
          if (m.read === false) return <span className="badge">unread</span>;
          return <span className="an-muted">not recorded</span>;
        }),
        timeCol("Last modified", ["last_modified"]),
        delCol("Deleted", "deleted"),
      ],
    }),
    aggregate: true,
  },
  SafariOpenTab: {
    Component: makeRichViewer({
      noun: "Safari open tabs",
      timeKeys: ["last_visit", "last_modified"],
      searchKeys: ["title", "url", "tab_group"],
      dimensions: [
        { title: "Domain", value: (m) => domainOf(metaStr(m, "url")) },
        { title: "Tab group", value: (m) => metaStr(m, "tab_group") },
        {
          title: "Browsing",
          value: (m) => (metaBool(m, "private_browsing") ? "private" : "normal"),
        },
      ],
      notable: (m) => {
        if (m.session_history_decoded === false)
          return (
            metaStr(m, "content_incomplete_detail") ??
            "the tab's back/forward history is present and unread"
          );
        if (metaBool(m, "session_history_truncated"))
          return `back/forward list capped at ${metaStr(m, "session_history_cap") ?? "?"} entries`;
        if (metaBool(m, "private_browsing")) return "a private browsing tab";
        return null;
      },
      columns: [
        strCol("Title", ["title"]),
        truncCol("URL", ["url"]),
        strCol("Tab group", ["tab_group"]),
        boolCol("Browsing", "private_browsing", "private", "normal"),
        numCol("Window", ["window_id"]),
        col("is_active_tab", "Active", (m) =>
          m.is_active_tab === undefined || m.is_active_tab === null ? (
            <span className="an-muted">not recorded</span>
          ) : metaBool(m, "is_active_tab") ? (
            <span className="badge badge-accent">active</span>
          ) : (
            <span className="badge">background</span>
          ),
        ),
        timeCol("Last visit", ["last_visit"]),
        numCol("Back/forward entries", ["session_history_entries"]),
        delCol("Deleted", "deleted"),
      ],
    }),
    aggregate: true,
  },
  WebSearchQuery: {
    Component: makeRichViewer({
      noun: "web searches",
      timeKeys: ["timestamp"],
      searchKeys: ["query", "browser"],
      dimensions: [{ title: "Browser", value: (m) => metaStr(m, "browser") }],
      columns: [
        pivotCol("Query", ["query"]),
        timeCol("Time", ["timestamp"]),
        strCol("Browser", ["browser"]),
        // The plist records the query and when, not which engine served it.
        col("search_engine", "Search engine", (m) =>
          metaBool(m, "search_engine_not_recorded") ? (
            <span className="an-muted">not recorded</span>
          ) : (
            <Val value={metaStr(m, "search_engine")} />
          ),
        ),
        strCol("Source", ["source"], true),
      ],
    }),
    aggregate: true,
  },
  HealthSample: {
    Component: makeRichViewer({
      noun: "HealthKit samples",
      timeKeys: ["start"],
      searchKeys: ["data_type_name", "source_name", "unit", "recording_timezone"],
      dimensions: [
        {
          title: "Sample type",
          value: (m) =>
            metaStr(m, "data_type_name") ??
            (metaStr(m, "data_type") != null
              ? `type ${metaStr(m, "data_type")} (not named by this build)`
              : null),
        },
        { title: "Source", value: (m) => metaStr(m, "source_name") },
        { title: "Recording zone", value: (m) => metaStr(m, "recording_timezone") },
      ],
      notable: (m) => {
        if (metaBool(m, "data_type_name_unknown"))
          return `sample type ${metaStr(m, "data_type") ?? "?"} is not one this build names`;
        if (metaBool(m, "deleted")) return "flagged deleted in the store";
        return null;
      },
      columns: [
        col("data_type_name", "Type", (m) => {
          const name = metaStr(m, "data_type_name");
          if (name) return <span className="mono">{name}</span>;
          const code = metaStr(m, "data_type");
          return code != null ? (
            <span className="an-muted">type {code} (not named by this build)</span>
          ) : (
            <span className="an-muted">not recorded</span>
          );
        }),
        numCol("Quantity", ["quantity"]),
        col("unit", "Unit", (m) =>
          metaBool(m, "unit_not_recorded") ? (
            <span className="an-muted">not recorded</span>
          ) : (
            <Val value={metaStr(m, "unit")} />
          ),
        ),
        timeCol("Start", ["start"]),
        timeCol("End", ["end"]),
        numCol("Duration (s)", ["duration_seconds"]),
        strCol("Source", ["source_name"]),
        strCol("Device", ["source_product_type", "origin_product_type"]),
        strCol("Recording zone", ["recording_timezone"]),
        delCol("Deleted", "deleted"),
      ],
    }),
    aggregate: true,
  },

  // ---- Parser schema warnings (ROADMAP §1.4a) ------------------------------
  //
  // One record per parser that met a store outside the schema range it was
  // validated on, could not read the version, or could not resolve a column.
  // The records it qualifies still parsed; this row says on what basis.
  ParserStaleWarning: {
    Component: makeRichViewer({
      noun: "parser schema warnings",
      timeKeys: [],
      searchKeys: ["app", "status", "store", "source_table"],
      dimensions: [
        { title: "Parser", value: (m) => metaStr(m, "app") },
        { title: "Status", value: (m) => metaStr(m, "status") },
      ],
      // Two spellings of the same facts reach this screen: the shared
      // marker (`seen_schema_version`, `supported_range`,
      // `unresolved_fields`) and the per-app schema notes
      // (`schema_version_seen`, `schema_version_supported`,
      // `schema_unresolved_fields`). Both are read; neither is guessed.
      columns: [
        strCol("Parser", ["app"]),
        strCol("Status", ["status"], true),
        strCol("Store", ["store", "source_table"], true),
        strCol("Table", ["source_table", "table"], true),
        strCol(
          "Schema version seen",
          ["seen_schema_version", "schema_version_seen"],
          true,
        ),
        strCol(
          "Validated range",
          ["supported_range", "schema_version_supported"],
          true,
        ),
        // The real file(s) the range's endpoints were read from, or why no
        // range is declared: a range with no evidence behind it is a guess.
        strCol("Validated on", [
          "validated_against",
          "schema_version_evidence",
          "schema_unranged_reason",
        ]),
        col("unresolved_fields", "Unresolved fields", (m, ctx) => {
          const key = Array.isArray(m.unresolved_fields)
            ? "unresolved_fields"
            : "schema_unresolved_fields";
          return pivotListCol("Unresolved fields", key).render(m, ctx);
        }),
        numCol("Records recovered", ["records_recovered"]),
        strCol("Detail", ["content_incomplete_detail", "detail", "message"]),
      ],
    }),
    aggregate: true,
  },

  // ---- Linux memory stages that publish paths (ROADMAP §4.2) ---------------
  LinuxMemoryOpenFiles: {
    Component: LinuxOpenFilesViewer,
  },
  LinuxMemoryMounts: {
    Component: LinuxMountsViewer,
  },

  // ---- The eight Windows memory stages of ROADMAP §5.3 ---------------------
  //
  // One record per stage; each viewer flattens the stage's array into rows
  // under the stage's own statement, and shows a check the build could not
  // make as not made rather than passed.
  MemoryProcessorBlocks: { Component: MemoryProcessorBlocksViewer },
  MemoryBigPool: { Component: MemoryBigPoolViewer },
  MemoryVirtualMap: { Component: MemoryVirtualMapViewer },
  MemoryHiveCellRoutines: { Component: MemoryHiveCellRoutinesViewer },
  MemoryVersionInfo: { Component: MemoryVersionInfoViewer },
  MemoryMbrScan: { Component: MemoryMbrScanViewer },
  MemoryScheduledTasks: { Component: MemoryScheduledTasksViewer },
  MemoryTrueCrypt: { Component: MemoryTrueCryptViewer },
  MemoryConsoleHistory: { Component: MemoryConsoleHistoryViewer },
};
