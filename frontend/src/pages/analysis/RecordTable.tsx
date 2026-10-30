import { useEffect, useRef, useState } from "react";
import type { KeyboardEvent, ReactNode } from "react";
import { useNavigate } from "react-router-dom";
import { VirtualRows } from "../../components/VirtualRows";
import { useRovingRows } from "../../hooks/useRovingRows";
import type { ParsedRecord, RecordMetadata, SortOrder } from "./api";
import { ArtifactLink, type CellCtx, type Column } from "./cells";

/**
 * Starting estimate for a row's height in px. `VirtualRows` measures the real
 * one as soon as the table has been laid out; this only has to be close enough
 * for the first paint.
 */
const ROW_HEIGHT_ESTIMATE = 30;

/** How long a row's copy button reads "copied" before going back to "copy". */
const COPIED_FEEDBACK_MS = 1500;

/** Which metadata key the rows are ordered by, and in which direction. */
export interface RecordTableSort {
  /** Bare metadata key, or null for the server's ingest order. */
  key: string | null;
  order: SortOrder;
}

/**
 * A per-row copy affordance.
 *
 * Two of this app's tables were hand-rolled rather than built on this
 * component, and the one capability they had that this component did not was a
 * button in each row that put a value on the clipboard — coordinates an
 * examiner is about to paste into a mapping tool, most often. Keeping a
 * bespoke table for it would have cost those tables windowing, a single tab
 * stop and honest `aria-rowindex`, so the capability moved here instead.
 *
 * It is deliberately NOT a tabbable button. A control in every row is a tab
 * stop in every row, which is exactly what the roving tab stop below exists to
 * remove; the button is `tabIndex={-1}` and stays clickable, and the keyboard
 * reaches the same value by pressing `c` on the focused row.
 */
export interface RecordTableCopy {
  /** Column header for the copy column. */
  header: string;
  /** Accessible name for the button, e.g. "Copy coordinates". */
  label: string;
  /** The text this row copies, or null when the row has nothing to copy. */
  value: (metadata: RecordMetadata, ctx: CellCtx) => string | null;
}

/**
 * The parsed-record table every record viewer renders its rows through.
 *
 * It exists to make two properties true everywhere at once rather than in each
 * of the twenty-odd viewers:
 *
 *  * The DOM is windowed. Records stream in a page at a time as the table is
 *    scrolled and are never evicted, so before this an examiner hunting a
 *    needle through an event log built up tens of thousands of live rows —
 *    stutter on every render, then a dead tab, taking their filter state and
 *    their place in the list with it.
 *  * The keyboard reaches the whole table, and the table is one tab stop —
 *    which means the row AND everything inside it, because a tabbable link in
 *    every row is a tab stop in every row whatever the row element does. Rows
 *    used to carry `tabIndex=0` each, which on an infinite-scroll table is an
 *    unbounded number of stops between the filter box and whatever follows the
 *    table; arrow keys did nothing at all. The "open" link is therefore
 *    `tabIndex={-1}` and Enter on the row goes to the same place.
 *
 * Windowing is not allowed to change either what the examiner can reach or
 * what the screen claims: the movement keys address the record set rather than
 * the rendered slice (`VirtualRows` keeps the row the keyboard is on rendered
 * wherever the scroll is), and `aria-rowcount` / `aria-rowindex` number rows
 * against the set so no assistive technology reads the window out as the
 * population. The counts a viewer prints above the table are its own business
 * and pass through here untouched.
 *
 * Selection, sortable headers and the copy affordance live here rather than in
 * a viewer for the same reason the windowing does: every table that wanted one
 * of them used to be a hand-written `<table>`, and a hand-written table is a
 * table without any of the properties above.
 */
export function RecordTable({
  records,
  caseId,
  columns,
  notable,
  className,
  rowClassName,
  rowTestId,
  selectedId,
  onSelect,
  copy,
  sort,
  onSort,
}: {
  /** The rows this table holds — after any filtering the viewer applied. */
  records: ParsedRecord[];
  caseId: string;
  columns: Column[];
  /** A returned reason marks the row notable and adds a leading flag column. */
  notable?: (metadata: RecordMetadata) => string | null;
  className?: string;
  /** Class added to every record row, for a viewer's own row styling. */
  rowClassName?: string;
  /** `data-testid` stamped on every record row. */
  rowTestId?: string;
  /** Id of the row the viewer considers selected (a detail panel, a map pin). */
  selectedId?: string | null;
  /**
   * Called when a row is chosen. Fires on click AND on keyboard movement, so a
   * keyboard-only examiner can drive a detail panel; Enter still opens the
   * artifact, which is what Enter does in every table here.
   */
  onSelect?: (record: ParsedRecord) => void;
  copy?: RecordTableCopy;
  /**
   * The ordering currently applied. A column with a `sortKey` renders a sort
   * button when this and `onSort` are both given.
   */
  sort?: RecordTableSort;
  /** A sort header was clicked, with the column's bare metadata key. */
  onSort?: (key: string) => void;
}): ReactNode {
  const navigate = useNavigate();
  // Read by the activation callback, which outlives the render that built it.
  const recordsRef = useRef(records);
  recordsRef.current = records;
  const onSelectRef = useRef(onSelect);
  onSelectRef.current = onSelect;

  const roving = useRovingRows({
    count: records.length,
    // Enter opens the focused record's artifact: the same destination as the
    // row's own "open" link, so a keyboard walk of the table ends where a
    // mouse one does.
    onActivate: (index) => {
      const record = recordsRef.current[index];
      if (record) navigate(`/cases/${caseId}/artifacts/${record.id}`);
    },
    // Deliberate keyboard moves only — never the focus a click also causes, so
    // a click-built selection is not immediately overwritten by its own focus.
    onMove: (index) => {
      const record = recordsRef.current[index];
      if (record) onSelectRef.current?.(record);
    },
  });

  // Which row last had something copied out of it, so its button can say so.
  const [copiedId, setCopiedId] = useState<string | null>(null);
  // A keyboard copy has no button press to look at, so the fact that it
  // happened is announced instead. Politely: it must not interrupt whatever a
  // screen reader is in the middle of reading out of the row.
  const [announcement, setAnnouncement] = useState("");
  const timer = useRef<number | undefined>(undefined);
  useEffect(() => () => window.clearTimeout(timer.current), []);

  const doCopy = (record: ParsedRecord, text: string) => {
    setCopiedId(record.id);
    setAnnouncement(`Copied ${text}`);
    void navigator.clipboard?.writeText(text).catch(() => {});
    window.clearTimeout(timer.current);
    timer.current = window.setTimeout(() => {
      setCopiedId((current) => (current === record.id ? null : current));
    }, COPIED_FEEDBACK_MS);
  };

  // A record an examiner's later run answered stays in the case — that the
  // first run said what it said is part of the history — so it is still in this
  // table, and must not read as a second, competing answer. The column appears
  // only when the rows on screen actually hold one (HUNT-107).
  const hasSuperseded = records.some((r) => r.metadata.superseded === true);
  const effectiveColumns: Column[] = hasSuperseded
    ? [
        {
          key: "__superseded",
          header: "Status",
          render: (meta: RecordMetadata) =>
            meta.superseded === true ? (
              <span
                className="badge badge-warn"
                title={
                  typeof meta.superseded_reason === "string"
                    ? meta.superseded_reason
                    : "a later run answered this record"
                }
              >
                superseded
              </span>
            ) : null,
        },
        ...columns,
      ]
    : columns;

  const colSpan =
    effectiveColumns.length + (notable ? 1 : 0) + (copy ? 1 : 0) + 1;
  const sortable = !!(sort && onSort);

  return (
    <>
      <table
        className={
          className ? `data-table an-table ${className}` : "data-table an-table"
        }
        aria-rowcount={records.length + 1}
      >
        <thead>
          <tr aria-rowindex={1}>
            {notable && <th aria-label="Notable" />}
            {effectiveColumns.map((c) => {
              const active =
                sortable && c.sortKey != null && sort!.key === c.sortKey;
              return (
                <th
                  key={c.key}
                  aria-sort={
                    !sortable || c.sortKey == null
                      ? undefined
                      : active
                        ? sort!.order === "asc"
                          ? "ascending"
                          : "descending"
                        : "none"
                  }
                >
                  {sortable && c.sortKey != null ? (
                    <button
                      type="button"
                      className="an-sort"
                      /* Which metadata key the server orders on, named rather
                         than implied. A column's heading is a label for what it
                         SHOWS, and a cell that falls back to a second key when
                         the first is absent does not sort the way its heading
                         reads — so the key is on the control that applies it. */
                      title={`Sort every record of this type by ${c.sortKey}`}
                      onClick={() => onSort!(c.sortKey!)}
                    >
                      {c.header}
                      {active ? (sort!.order === "asc" ? " ▲" : " ▼") : ""}
                    </button>
                  ) : (
                    c.header
                  )}
                </th>
              );
            })}
            {copy && <th>{copy.header}</th>}
            <th>Artifact</th>
          </tr>
        </thead>
        <tbody>
          <VirtualRows
            count={records.length}
            rowHeight={ROW_HEIGHT_ESTIMATE}
            colSpan={colSpan}
            pinnedIndex={roving.activeIndex}
          >
            {(index, rowProps) => {
              const record = records[index];
              const reason = notable?.(record.metadata) ?? null;
              const ctx: CellCtx = { caseId, record };
              const copyText = copy ? copy.value(record.metadata, ctx) : null;
              const selected = selectedId != null && selectedId === record.id;
              const rowClass = [
                rowClassName ?? null,
                reason ? "rv-notable" : null,
                selected ? "selected" : null,
              ]
                .filter(Boolean)
                .join(" ");
              const rovingProps = roving.getRowProps(index);
              return (
                <tr
                  key={record.id}
                  {...rowProps}
                  {...rovingProps}
                  data-testid={rowTestId}
                  aria-selected={onSelect ? selected : undefined}
                  className={rowClass || undefined}
                  onClick={onSelect ? () => onSelect(record) : undefined}
                  onKeyDown={(e: KeyboardEvent<HTMLElement>) => {
                    // `c` copies the focused row, which is how the keyboard
                    // reaches a button that is deliberately not a tab stop.
                    // Modified presses are left alone: Ctrl/Cmd-C is the
                    // browser's own copy and must keep working.
                    if (
                      copyText &&
                      (e.key === "c" || e.key === "C") &&
                      !e.ctrlKey &&
                      !e.metaKey &&
                      !e.altKey
                    ) {
                      e.preventDefault();
                      doCopy(record, copyText);
                    }
                    rovingProps.onKeyDown(e);
                  }}
                >
                  {notable && (
                    <td className="rv-flag">
                      {reason && (
                        <span className="badge badge-danger" title={reason}>
                          !
                        </span>
                      )}
                    </td>
                  )}
                  {effectiveColumns.map((c) => (
                    <td key={c.key}>{c.render(record.metadata, ctx)}</td>
                  ))}
                  {copy && (
                    <td className="an-copy-cell">
                      {copyText && (
                        <button
                          type="button"
                          className="an-copy-btn"
                          /* Out of the tab order for the same reason the
                             "open" link is: a control per row is a tab stop
                             per row. `c` on the focused row does the same
                             thing, and the title says so. */
                          tabIndex={-1}
                          aria-label={copy.label}
                          aria-keyshortcuts="c"
                          title={`${copy.label} (press c on the focused row)`}
                          onClick={(e) => {
                            e.stopPropagation();
                            doCopy(record, copyText);
                          }}
                        >
                          {copiedId === record.id ? "copied" : "copy"}
                        </button>
                      )}
                    </td>
                  )}
                  <td>
                    {/* Out of the tab order, in it with Enter. A link per row is
                        a tab stop per row, which would undo the roving stop
                        above it — see ArtifactLink. */}
                    <ArtifactLink caseId={caseId} id={record.id} tabIndex={-1}>
                      open
                    </ArtifactLink>
                  </td>
                </tr>
              );
            }}
          </VirtualRows>
        </tbody>
      </table>
      {copy && (
        <div className="sr-only" role="status" aria-live="polite">
          {announcement}
        </div>
      )}
    </>
  );
}
