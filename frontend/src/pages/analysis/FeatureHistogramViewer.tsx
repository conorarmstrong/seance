import type { ReactNode } from "react";
import { formatBytes, formatCount } from "../../lib/format";
import type { ParsedRecord, RecordMetadata } from "./api";
import { ArtifactLink } from "./cells";
import { MISSING, metaBool, metaNum, metaStr } from "./lib";
import type { ViewerProps } from "./viewers";

/**
 * The bulk feature scanner's histogram (ROADMAP §2.1): one record per scan
 * that found anything, holding the most-common values per selector with
 * exact counts, and every ceiling the scan ran into.
 *
 * The generic table cannot show this record: its substance is two nested
 * tables (`top`, `by_kind`), which the flat view skips. What this screen has
 * to keep straight is that a capped histogram is not an exhaustive one — the
 * record's own `note` says so with the numbers, and it is printed verbatim
 * rather than paraphrased, because "counts are exact for the tracked values
 * and the distinct total is a floor" is a sentence an examiner quotes.
 */

interface TopEntry {
  kind: string;
  value: string;
  count: number;
}

interface KindTotals {
  hits: number;
  distinct_values: number;
}

function topEntries(m: RecordMetadata): TopEntry[] {
  const raw = m.top;
  if (!Array.isArray(raw)) return [];
  const out: TopEntry[] = [];
  for (const entry of raw) {
    if (!entry || typeof entry !== "object") continue;
    const e = entry as Record<string, unknown>;
    out.push({
      kind: typeof e.kind === "string" ? e.kind : MISSING,
      value: typeof e.value === "string" ? e.value : String(e.value ?? MISSING),
      count: typeof e.count === "number" ? e.count : 0,
    });
  }
  return out;
}

function kindTotals(m: RecordMetadata): [string, KindTotals][] {
  const raw = m.by_kind;
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return [];
  const out: [string, KindTotals][] = [];
  for (const [kind, totals] of Object.entries(raw as Record<string, unknown>)) {
    if (!totals || typeof totals !== "object") continue;
    const t = totals as Record<string, unknown>;
    out.push([
      kind,
      {
        hits: typeof t.hits === "number" ? t.hits : 0,
        distinct_values:
          typeof t.distinct_values === "number" ? t.distinct_values : 0,
      },
    ]);
  }
  // Biggest population first, as the top table is.
  out.sort((a, b) => b[1].hits - a[1].hits || a[0].localeCompare(b[0]));
  return out;
}

function HistogramRecord({
  record,
  caseId,
}: {
  record: ParsedRecord;
  caseId: string;
}): ReactNode {
  const m = record.metadata;
  const totalHits = metaNum(m, "total_hits");
  const distinct = metaNum(m, "distinct_values");
  const capped = metaBool(m, "capped");
  const scanCapped = metaBool(m, "scan_capped");
  const bytesScanned = metaNum(m, "bytes_scanned");
  const top = topEntries(m);
  const omitted = metaNum(m, "top_omitted") ?? 0;
  const note = metaStr(m, "note");

  return (
    <section className="an-card" data-testid="feature-histogram">
      <h2 className="an-card-head">
        {formatCount(totalHits)} hits over {formatCount(distinct)} distinct
        values
        {capped ? <span className="badge badge-warn"> capped</span> : null}
        {" · "}
        <ArtifactLink caseId={caseId} id={record.id}>
          record
        </ArtifactLink>
      </h2>
      {/* The record's own statement of its ceiling, in its own words. A capped
          histogram must never be rendered as exhaustive, and the sentence
          that says so names the cap and the hits it dropped. */}
      {note ? <p className="an-small">{note}</p> : null}
      {bytesScanned != null ? (
        <p className="an-muted an-small">
          {formatBytes(bytesScanned)} scanned
          {scanCapped
            ? " — the scan stopped at its byte ceiling; this histogram covers the bytes read, not the whole object"
            : ""}
          .
        </p>
      ) : null}

      <h3 className="an-small">By selector</h3>
      <table className="an-table">
        <thead>
          <tr>
            <th>Kind</th>
            <th>Hits</th>
            <th>Distinct values</th>
          </tr>
        </thead>
        <tbody>
          {kindTotals(m).map(([kind, t]) => (
            <tr key={kind}>
              <td className="mono">{kind}</td>
              <td className="mono">{formatCount(t.hits)}</td>
              <td className="mono">{formatCount(t.distinct_values)}</td>
            </tr>
          ))}
        </tbody>
      </table>

      <h3 className="an-small">
        Most-common values
        {omitted > 0 ? (
          <span className="an-muted">
            {" "}
            — showing {formatCount(top.length)} of {formatCount(distinct)}{" "}
            distinct values; {formatCount(omitted)} are not listed here
          </span>
        ) : null}
      </h3>
      <table className="an-table">
        <thead>
          <tr>
            <th>Kind</th>
            <th>Value</th>
            <th>Count</th>
          </tr>
        </thead>
        <tbody>
          {top.map((e, i) => (
            <tr key={`${e.kind}:${e.value}:${i}`}>
              <td className="mono">{e.kind}</td>
              <td className="mono">{e.value}</td>
              <td className="mono">{formatCount(e.count)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  );
}

export function FeatureHistogramViewer({
  records,
  caseId,
}: ViewerProps): ReactNode {
  if (records.length === 0) {
    return <p className="an-muted">No feature histograms.</p>;
  }
  return (
    <div className="an-grid">
      {records.map((r) => (
        <HistogramRecord key={r.id} record={r} caseId={caseId} />
      ))}
    </div>
  );
}
