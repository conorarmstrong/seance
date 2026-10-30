import type { ReactNode } from "react";
import { formatBytes, formatCount } from "../../lib/format";
import type { ParsedRecord } from "./api";
import { ArtifactLink } from "./cells";
import { MISSING, metaBool, metaNum, metaStr } from "./lib";
import type { ViewerProps } from "./viewers";

/**
 * The eight Windows memory stages of ROADMAP §5.3 (`kpcrs`, `bigpools`,
 * `virtmap`, `getcellroutine`, `verinfo`, `mbrscan`, `scheduled_tasks`, the
 * TrueCrypt family). Each stage is ONE record whose substance is a nested
 * array the generic key/value table skips, so before these viewers the
 * records screen showed the stage's counters and none of its findings.
 *
 * Three rules every table here keeps, because they are what the stages were
 * written to assert:
 *
 * - a check the build's symbols could not make is shown as **not made**,
 *   never as passed — `null` is not a pass;
 * - a ceiling is shown with its number, in the stage's own sentence where it
 *   has one (`entries_publication_cap_note`), and a stage that did not
 *   complete says so above its rows;
 * - an inference is labelled as one (a POSSIBLE XTS pair is two adjacent
 *   schedules, not a decoded key container).
 *
 * The stage's `statement` — the sentence the plugin wrote for an examiner —
 * is printed verbatim at the top of every stage.
 */

type Obj = Record<string, unknown>;

function objectArray(raw: unknown): Obj[] {
  if (!Array.isArray(raw)) return [];
  return raw.filter((x): x is Obj => !!x && typeof x === "object");
}

function obj(raw: unknown): Obj | null {
  return raw && typeof raw === "object" && !Array.isArray(raw)
    ? (raw as Obj)
    : null;
}

function str(o: Obj | null, key: string): string | null {
  if (!o) return null;
  const v = o[key];
  if (typeof v === "string") return v.length ? v : null;
  if (typeof v === "number" || typeof v === "boolean") return String(v);
  return null;
}

function num(o: Obj | null, key: string): number | null {
  if (!o) return null;
  const v = o[key];
  return typeof v === "number" && Number.isFinite(v) ? v : null;
}

/** A tri-state check: `true` agree, `false` disagree, `null` not made. */
function Check({ value }: { value: unknown }): ReactNode {
  if (value === true) return <span className="badge">agree</span>;
  if (value === false)
    return <span className="badge badge-warn">disagree</span>;
  return <span className="an-muted">not made</span>;
}

function Mono({ value }: { value: string | null }): ReactNode {
  return value ? (
    <span className="mono">{value}</span>
  ) : (
    <span className="an-muted">{MISSING}</span>
  );
}

/**
 * The header every stage shares: the stage's own statement, whether it
 * completed, and each reason it did not.
 */
function StageHead({
  record,
  caseId,
  summary,
}: {
  record: ParsedRecord;
  caseId: string;
  summary?: ReactNode;
}): ReactNode {
  const m = record.metadata;
  const statement = metaStr(m, "statement");
  const complete = m.content_complete !== false;
  const incomplete = objectArray(m.incomplete);
  return (
    <div className="an-card-head-block">
      <p className="an-small">
        <ArtifactLink caseId={caseId} id={record.id}>
          stage record
        </ArtifactLink>
        {summary ? <> — {summary}</> : null}
      </p>
      {statement ? <p>{statement}</p> : null}
      {!complete ? (
        <p className="an-small">
          <span className="badge badge-warn">
            the stage did not complete — every count here is a floor
          </span>
          {incomplete.length > 0 ? (
            <ul>
              {incomplete.map((i, n) => (
                <li key={n}>
                  <span className="mono">{str(i, "reason") ?? "?"}</span>:{" "}
                  {str(i, "detail") ?? "no detail recorded"}
                </li>
              ))}
            </ul>
          ) : null}
        </p>
      ) : null}
    </div>
  );
}

function Table({
  headers,
  children,
}: {
  headers: string[];
  children: ReactNode;
}): ReactNode {
  return (
    <div className="an-wt-table-wrap">
      <table className="data-table an-table">
        <thead>
          <tr>
            {headers.map((h) => (
              <th key={h}>{h}</th>
            ))}
          </tr>
        </thead>
        <tbody>{children}</tbody>
      </table>
    </div>
  );
}

type StageBody = (record: ParsedRecord, caseId: string) => ReactNode;

function StageList({
  records,
  caseId,
  noun,
  body,
}: ViewerProps & { noun: string; body: StageBody }): ReactNode {
  if (records.length === 0) {
    return <p className="an-muted">No {noun} stage record.</p>;
  }
  return (
    <div>
      {records.map((record) => (
        <section key={record.id} className="an-card">
          {body(record, caseId)}
        </section>
      ))}
    </div>
  );
}

// ---------------------------------------------------------------------------
// processor_blocks: processors[]
// ---------------------------------------------------------------------------

const memoryProcessorBlocksViewerBody: StageBody = (record, caseId) => {
  const m = record.metadata;
  const rows = objectArray(m.processors);
  const claimed = metaNum(m, "processors_claimed");
  return (
    <>
      <StageHead
        record={record}
        caseId={caseId}
        summary={
          <>
            {formatCount(metaNum(m, "processors_walked") ?? rows.length)}{" "}
            processors walked
            {claimed != null
              ? `, ${formatCount(claimed)} claimed by KeNumberProcessors`
              : ""}
            {metaStr(m, "processor_count_note")
              ? ` (${metaStr(m, "processor_count_note")})`
              : ""}
            ; {formatCount(metaNum(m, "incoherent") ?? 0)} incoherent
          </>
        }
      />
      <Table
        headers={[
          "Slot",
          "KPCR",
          "PRCB",
          "Self",
          "PRCB pointer",
          "Number",
          "At capture",
          "Current process",
          "Current thread",
          "Version",
        ]}
      >
        {rows.map((p, i) => {
          const proc = obj(p.current_process);
          const procText =
            proc && (str(proc, "name") || str(proc, "pid"))
              ? `${str(proc, "name") ?? "?"}${str(proc, "pid") != null ? ` (${str(proc, "pid")})` : ""}`
              : null;
          const major = str(p, "major_version");
          const minor = str(p, "minor_version");
          return (
            <tr key={`${record.id}:${i}`}>
              <td className="mono">{str(p, "index") ?? MISSING}</td>
              <td>
                <Mono value={str(p, "kpcr")} />
              </td>
              <td>
                <Mono value={str(p, "prcb")} />
              </td>
              <td>
                <Check value={p.self_agrees} />
              </td>
              <td>
                <Check value={p.current_prcb_agrees} />
              </td>
              <td>
                <Check value={p.number_agrees} />
              </td>
              <td>
                {p.idle === true ? (
                  <span className="badge">idle</span>
                ) : p.idle === false ? (
                  <span className="badge badge-accent">running</span>
                ) : (
                  <span className="an-muted">not established</span>
                )}
              </td>
              <td>
                {procText ? (
                  <span className="mono">{procText}</span>
                ) : (
                  <span className="an-muted">not followed</span>
                )}
              </td>
              <td>
                <Mono value={str(p, "current_thread")} />
              </td>
              <td className="mono">
                {major != null || minor != null
                  ? `${major ?? "?"}.${minor ?? "?"}`
                  : MISSING}
              </td>
            </tr>
          );
        })}
      </Table>
    </>
  );
};

// ---------------------------------------------------------------------------
// big_pool: tags{} and entries[]
// ---------------------------------------------------------------------------

const memoryBigPoolViewerBody: StageBody = (record, caseId) => {
  const m = record.metadata;
  const tags = obj(m.tags) ?? {};
  const tagRows = Object.entries(tags)
    .map(([tag, totals]) => [tag, obj(totals)] as const)
    .sort(
      (a, b) =>
        (num(b[1], "bytes_in_use") ?? 0) - (num(a[1], "bytes_in_use") ?? 0) ||
        a[0].localeCompare(b[0]),
    );
  const entries = objectArray(m.entries);
  const claimed = metaNum(m, "in_use_counter_claimed");
  const counterAgrees = m.in_use_counter_agrees;
  const capNote = metaStr(m, "entries_publication_cap_note");
  return (
    <>
      <StageHead
        record={record}
        caseId={caseId}
        summary={
          <>
            {formatCount(metaNum(m, "entries_read"))} of{" "}
            {formatCount(metaNum(m, "entries_declared"))} table entries read:{" "}
            {formatCount(metaNum(m, "entries_in_use"))} in use,{" "}
            {formatCount(metaNum(m, "entries_free"))} freed,{" "}
            {formatCount(metaNum(m, "entries_empty"))} empty
            {claimed != null ? (
              <>
                ; the kernel's in-use counter says {formatCount(claimed)} and{" "}
                {counterAgrees === true
                  ? "agrees with the walk"
                  : counterAgrees === false
                    ? "disagrees with the walk"
                    : "was not compared"}
              </>
            ) : null}
          </>
        }
      />
      <h3 className="an-small">
        By tag ({formatCount(metaNum(m, "tags_total") ?? tagRows.length)};
        totals are exact even where the entries below are capped)
      </h3>
      <Table
        headers={["Tag", "In use", "Freed", "Bytes in use", "Bytes freed"]}
      >
        {tagRows.map(([tag, t]) => (
          <tr key={tag}>
            <td className="mono">{tag}</td>
            <td className="mono">{formatCount(num(t, "in_use"))}</td>
            <td className="mono">{formatCount(num(t, "free"))}</td>
            <td className="mono">{formatBytes(num(t, "bytes_in_use") ?? 0)}</td>
            <td className="mono">{formatBytes(num(t, "bytes_free") ?? 0)}</td>
          </tr>
        ))}
      </Table>
      <h3 className="an-small">
        Entries (
        {formatCount(metaNum(m, "entries_published") ?? entries.length)}{" "}
        published)
        {metaBool(m, "entries_truncated") ? (
          <span className="badge badge-warn"> capped</span>
        ) : null}
      </h3>
      {capNote ? <p className="an-small">{capNote}</p> : null}
      <Table
        headers={["Address", "Tag", "State", "Bytes", "Pool type", "Billed to"]}
      >
        {entries.map((e, i) => {
          const poolType = obj(e.pool_type);
          return (
            <tr key={`${record.id}:${i}`}>
              <td>
                <Mono value={str(e, "va")} />
              </td>
              <td className="mono">{str(e, "tag") ?? MISSING}</td>
              <td>
                {e.free === true ? (
                  <span className="badge badge-warn">freed</span>
                ) : e.free === false ? (
                  <span className="badge">in use</span>
                ) : (
                  <span className="an-muted">not established</span>
                )}
              </td>
              <td className="mono">
                {num(e, "number_of_bytes") != null
                  ? formatBytes(num(e, "number_of_bytes")!)
                  : MISSING}
              </td>
              <td className="mono">
                {str(poolType, "name") ?? str(poolType, "raw") ?? MISSING}
              </td>
              <td>
                <Mono value={str(e, "process_billed")} />
              </td>
            </tr>
          );
        })}
      </Table>
    </>
  );
};

// ---------------------------------------------------------------------------
// virtual_map: regions[] and checks[]
// ---------------------------------------------------------------------------

const memoryVirtualMapViewerBody: StageBody = (record, caseId) => {
  const m = record.metadata;
  const regions = objectArray(m.regions);
  const checks = objectArray(m.checks);
  const kernelRegion = obj(m.kernel_base_region);
  const namingUnavailable = metaStr(m, "naming_unavailable");
  return (
    <>
      <StageHead
        record={record}
        caseId={caseId}
        summary={
          <>
            {formatCount(metaNum(m, "regions_in_use"))} of{" "}
            {formatCount(metaNum(m, "regions_declared"))} declared regions in
            use
            {kernelRegion
              ? `; the kernel's load address lies in slot ${str(kernelRegion, "index") ?? "?"} (${str(kernelRegion, "type_name") ?? "unnamed"})`
              : m.kernel_base_in_a_region === false
                ? "; the kernel's load address lies in no region"
                : ""}
            {namingUnavailable
              ? `; region names unavailable: ${namingUnavailable}`
              : ""}
          </>
        }
      />
      {checks.length > 0 ? (
        <Table headers={["Check", "Result", "Detail"]}>
          {checks.map((c, i) => (
            <tr key={`${record.id}:check:${i}`}>
              <td>{str(c, "name") ?? MISSING}</td>
              <td>
                {c.passed === true ? (
                  <span className="badge">passed</span>
                ) : c.passed === false ? (
                  <span className="badge badge-warn">failed</span>
                ) : (
                  <span className="an-muted">not made</span>
                )}
              </td>
              <td>{str(c, "detail") ?? MISSING}</td>
            </tr>
          ))}
        </Table>
      ) : null}
      <Table headers={["Slot", "Type", "Base", "End", "Size", "State"]}>
        {regions.map((r, i) => (
          <tr key={`${record.id}:${i}`}>
            <td className="mono">{str(r, "index") ?? MISSING}</td>
            <td>
              {str(r, "type_name") ? (
                <span className="mono">{str(r, "type_name")}</span>
              ) : (
                <span className="an-muted">not named by the type map</span>
              )}
              {str(r, "type_value") != null ? (
                <span className="an-muted an-small">
                  {" "}
                  (type {str(r, "type_value")})
                </span>
              ) : null}
            </td>
            <td>
              <Mono value={str(r, "base")} />
            </td>
            <td>
              <Mono value={str(r, "end")} />
            </td>
            <td className="mono">
              {num(r, "bytes") != null
                ? formatBytes(num(r, "bytes")!)
                : MISSING}
            </td>
            <td>
              {r.empty === true ? (
                <span className="an-muted">empty</span>
              ) : (
                <span className="badge">in use</span>
              )}
            </td>
          </tr>
        ))}
      </Table>
    </>
  );
};

// ---------------------------------------------------------------------------
// hive_cell_routines: hives[]
// ---------------------------------------------------------------------------

function RoutineCell({ raw }: { raw: unknown }): ReactNode {
  const r = obj(raw);
  if (!r) return <span className="an-muted">not declared by this build</span>;
  const ownership = obj(r.ownership);
  const symbol = str(r, "symbol");
  const offset = num(r, "symbol_offset");
  const placed =
    symbol != null
      ? offset != null && offset !== 0
        ? `${symbol}+${offset}`
        : symbol
      : null;
  const module = str(ownership, "module");
  const kind = str(ownership, "kind");
  return (
    <span className="an-sig">
      <Mono value={str(r, "address")} />
      {placed ? (
        <>
          {" "}
          <span className="mono">{placed}</span>
        </>
      ) : null}
      {module ? (
        <>
          {" "}
          <span className="an-small">in {module}</span>
        </>
      ) : kind === "outside_any_module" ? (
        <>
          {" "}
          <span className="badge badge-warn">in no loaded module</span>
        </>
      ) : kind === "undetermined" ? (
        <>
          {" "}
          <span className="an-muted an-small">
            owner undetermined: {str(ownership, "detail") ?? "no detail"}
          </span>
        </>
      ) : null}
      {r.outside_the_kernel === true ? (
        <>
          {" "}
          <span className="badge badge-warn">outside the kernel</span>
        </>
      ) : null}
    </span>
  );
}

const memoryHiveCellRoutinesViewerBody: StageBody = (record, caseId) => {
  const m = record.metadata;
  const hives = objectArray(m.hives);
  return (
    <>
      <StageHead
        record={record}
        caseId={caseId}
        summary={
          <>
            {formatCount(metaNum(m, "hives_examined") ?? hives.length)} hives
            examined;{" "}
            {formatCount(
              metaNum(m, "hives_with_a_routine_outside_the_kernel") ?? 0,
            )}{" "}
            with a routine outside the kernel
            {m.hive_list_complete === false
              ? "; the hive list was not walked whole"
              : ""}
            {m.module_map_authoritative === false
              ? "; the module map cannot support 'in no module' claims"
              : ""}
          </>
        }
      />
      <Table
        headers={[
          "Hive",
          "CMHIVE",
          "GetCellRoutine",
          "ReleaseCellRoutine",
          "Read",
        ]}
      >
        {hives.map((h, i) => (
          <tr key={`${record.id}:${i}`}>
            <td className="mono">{str(h, "hive_name") ?? "(unnamed)"}</td>
            <td>
              <Mono value={str(h, "cmhive")} />
            </td>
            <td>
              <RoutineCell raw={h.get_cell_routine} />
            </td>
            <td>
              <RoutineCell raw={h.release_cell_routine} />
            </td>
            <td>
              {str(h, "unreadable") ? (
                <span className="badge badge-warn">{str(h, "unreadable")}</span>
              ) : (
                <span className="badge">read</span>
              )}
            </td>
          </tr>
        ))}
      </Table>
    </>
  );
};

// ---------------------------------------------------------------------------
// version_info: kernel_modules[] and processes[].images[]
// ---------------------------------------------------------------------------

interface ImageRow {
  key: string;
  owner: string;
  name: string | null;
  path: string | null;
  base: string | null;
  fileVersion: string | null;
  productVersion: string | null;
  company: string | null;
  originalFilename: string | null;
  outcome: string | null;
  outcomeDetail: string | null;
}

function imageRow(owner: string, key: string, img: Obj): ImageRow {
  const fixed = obj(img.fixed);
  return {
    key,
    owner,
    name: str(img, "name"),
    path: str(img, "path"),
    base: str(img, "base"),
    fileVersion: str(fixed, "file_version"),
    productVersion: str(fixed, "product_version"),
    company: str(img, "company"),
    originalFilename: str(img, "original_filename"),
    outcome: str(img, "outcome"),
    outcomeDetail: str(img, "outcome_detail"),
  };
}

const memoryVersionInfoViewerBody: StageBody = (record, caseId) => {
  const m = record.metadata;
  const rows: ImageRow[] = [];
  for (const [i, img] of objectArray(m.kernel_modules).entries()) {
    rows.push(imageRow("kernel", `${record.id}:k:${i}`, img));
  }
  for (const [pi, p] of objectArray(m.processes).entries()) {
    const owner = `${str(p, "name") ?? "?"} (${str(p, "pid") ?? "?"})`;
    for (const [ii, img] of objectArray(p.images).entries()) {
      rows.push(imageRow(owner, `${record.id}:p:${pi}:${ii}`, img));
    }
  }
  return (
    <>
      <StageHead
        record={record}
        caseId={caseId}
        summary={
          <>
            {formatCount(metaNum(m, "images_examined") ?? rows.length)} images
            examined: {formatCount(metaNum(m, "images_with_a_version") ?? 0)}{" "}
            with a version resource,{" "}
            {formatCount(metaNum(m, "images_without_a_version") ?? 0)} without,{" "}
            {formatCount(metaNum(m, "images_resource_discarded") ?? 0)} with the
            resource section discarded,{" "}
            {formatCount(metaNum(m, "images_unreadable") ?? 0)} unreadable
            {metaBool(m, "images_capped") ? "; the image list was capped" : ""}
            {m.kernel_list_complete === false
              ? "; the kernel module list was not walked whole"
              : ""}
            {m.process_list_complete === false
              ? "; the process list was not walked whole"
              : ""}
          </>
        }
      />
      <Table
        headers={[
          "Loaded in",
          "Image",
          "Base",
          "File version",
          "Product version",
          "Company",
          "Original file name",
          "Resource",
        ]}
      >
        {rows.map((r) => (
          <tr key={r.key}>
            <td className="mono">{r.owner}</td>
            <td>
              <span className="mono" title={r.path ?? undefined}>
                {r.name ?? r.path ?? MISSING}
              </span>
            </td>
            <td>
              <Mono value={r.base} />
            </td>
            <td>
              <Mono value={r.fileVersion} />
            </td>
            <td>
              <Mono value={r.productVersion} />
            </td>
            <td>{r.company ?? <span className="an-muted">{MISSING}</span>}</td>
            <td>
              <Mono value={r.originalFilename} />
            </td>
            <td>
              {r.outcome === "read" ? (
                <span className="badge">read</span>
              ) : (
                <span
                  className="badge badge-warn"
                  title={r.outcome ?? undefined}
                >
                  {(r.outcome ?? "not read").replace(/_/g, " ")}
                  {r.outcomeDetail ? `: ${r.outcomeDetail}` : ""}
                </span>
              )}
            </td>
          </tr>
        ))}
      </Table>
    </>
  );
};

// ---------------------------------------------------------------------------
// mbr_scan: candidates[]
// ---------------------------------------------------------------------------

const memoryMbrScanViewerBody: StageBody = (record, caseId) => {
  const m = record.metadata;
  const candidates = objectArray(m.candidates);
  return (
    <>
      <StageHead
        record={record}
        caseId={caseId}
        summary={
          <>
            {formatBytes(metaNum(m, "bytes_scanned") ?? 0)} scanned
            {(metaNum(m, "unread_bytes") ?? 0) > 0
              ? `, ${formatBytes(metaNum(m, "unread_bytes")!)} unread`
              : ""}
            {(metaNum(m, "unmapped_bytes") ?? 0) > 0
              ? `, ${formatBytes(metaNum(m, "unmapped_bytes")!)} unmapped`
              : ""}
            ; {formatCount(metaNum(m, "sectors_with_signature") ?? 0)} sectors
            end in 55 AA;{" "}
            {formatCount(
              metaNum(m, "candidates_published") ?? candidates.length,
            )}{" "}
            published
            {metaBool(m, "candidates_truncated") ? " (capped)" : ""}
            {(metaNum(m, "candidates_unreadable") ?? 0) > 0
              ? `, ${formatCount(metaNum(m, "candidates_unreadable")!)} unreadable`
              : ""}
          </>
        }
      />
      <Table
        headers={[
          "Physical offset",
          "Kind",
          "Checks",
          "Disk signature",
          "Partitions in use",
          "Partition table",
          "Boot code",
        ]}
      >
        {candidates.map((c, i) => {
          const failed = num(c, "checks_failed") ?? 0;
          const checks = objectArray(c.checks).filter(
            (k) => k.passed === false,
          );
          const partitions = objectArray(c.partitions).filter(
            (p) => p.empty !== true,
          );
          return (
            <tr key={`${record.id}:${i}`}>
              <td>
                <Mono value={str(c, "offset_hex")} />
              </td>
              <td>
                <span className="badge" title={str(c, "kind") ?? undefined}>
                  {(str(c, "kind") ?? "?").replace(/_/g, " ")}
                </span>
              </td>
              <td>
                {c.well_formed === true ? (
                  <span className="badge">well formed</span>
                ) : (
                  <span
                    className="badge badge-warn"
                    title={checks
                      .map(
                        (k) =>
                          `${str(k, "name") ?? "?"}: ${str(k, "detail") ?? ""}`,
                      )
                      .join("; ")}
                  >
                    {formatCount(failed)} checks failed
                  </span>
                )}
              </td>
              <td>
                <Mono value={str(c, "disk_signature")} />
              </td>
              <td className="mono">
                {formatCount(num(c, "partitions_in_use") ?? 0)}
              </td>
              <td className="mono an-small">
                {partitions.length
                  ? partitions
                      .map(
                        (p) =>
                          `#${str(p, "index") ?? "?"} ${str(p, "type_name") ?? `type ${str(p, "type") ?? "?"}`} @${str(p, "first_lba") ?? "?"} ×${str(p, "sectors") ?? "?"}`,
                      )
                      .join("; ")
                  : MISSING}
              </td>
              <td>
                {c.boot_code_empty === true ? (
                  <span className="an-muted">empty</span>
                ) : (
                  <Mono value={str(c, "boot_code_sha256")} />
                )}
              </td>
            </tr>
          );
        })}
      </Table>
    </>
  );
};

// ---------------------------------------------------------------------------
// scheduled_tasks: tasks[]
// ---------------------------------------------------------------------------

/** A registry value as the stage renders it: text, dword, binary (length
 * only), unavailable (with why) or absent. */
function regValue(raw: unknown): { text: string; known: boolean } {
  const v = obj(raw);
  if (!v) return { text: MISSING, known: false };
  switch (v.kind) {
    case "text":
      return { text: str(v, "text") ?? "", known: true };
    case "dword":
      return { text: str(v, "value") ?? MISSING, known: true };
    case "binary":
      return {
        text: `${formatCount(num(v, "length") ?? 0)} bytes (not decoded)`,
        known: false,
      };
    case "unavailable":
      return {
        text: `unavailable: ${str(v, "detail") ?? "no detail"}`,
        known: false,
      };
    case "absent":
      return { text: "absent", known: false };
    default:
      return { text: MISSING, known: false };
  }
}

function actionText(a: Obj): string {
  switch (a.kind) {
    case "exec": {
      const cmd = str(a, "command") ?? "";
      const args = str(a, "arguments");
      return args ? `${cmd} ${args}` : cmd;
    }
    case "com_handler":
      return `COM handler ${str(a, "class_id") ?? "?"}`;
    case "email":
      return `mail from ${str(a, "from") ?? "?"} to ${str(a, "to") ?? "?"}: ${str(a, "subject") ?? ""}`;
    case "message_box":
      return `message box: ${str(a, "title") ?? ""}`;
    default:
      return `${str(a, "kind") ?? "?"} action`;
  }
}

/** One decoded trigger as a line: kind, schedule, start, repetition. A
 * localized start is wall-clock time in the machine's zone, never UTC. */
function triggerText(t: Obj): string {
  const kind = str(t, "kind") ?? "?";
  const schedule = str(t, "schedule");
  const start = obj(t.start);
  const at = str(start, "time");
  const every = str(t, "repetition_interval");
  let text = schedule ? `${kind} (${schedule})` : kind;
  if (at) text += ` from ${at}${start?.localized === true ? " local" : ""}`;
  if (every) text += `, every ${every}`;
  if (t.enabled === false) text += " (disabled)";
  return text;
}

const memoryScheduledTasksViewerBody: StageBody = (record, caseId) => {
  const m = record.metadata;
  const tasks = objectArray(m.tasks);
  return (
    <>
      <StageHead
        record={record}
        caseId={caseId}
        summary={
          <>
            {formatCount(metaNum(m, "tasks_total") ?? tasks.length)} tasks read
            {metaNum(m, "tasks_declared") != null
              ? ` of ${formatCount(metaNum(m, "tasks_declared")!)} the index declares`
              : ""}
            {m.tasks_index_complete === false
              ? " (the index was not read whole)"
              : ""}
            {metaBool(m, "capped") ? " (capped)" : ""}
            {metaStr(m, "unavailable") ? `; ${metaStr(m, "unavailable")}` : ""}.
          </>
        }
      />
      <Table
        headers={[
          "Task",
          "Author",
          "Actions",
          "Triggers",
          "Created",
          "Last run",
          "Last result",
          "Decode",
        ]}
      >
        {tasks.map((t, i) => {
          const path = regValue(t.path);
          const author = regValue(t.author);
          const actions = obj(t.actions);
          const actionList = objectArray(actions?.actions);
          const dyn = obj(t.dynamic_info);
          const problems = [
            str(t, "actions_error"),
            str(t, "dynamic_info_error"),
            str(actions, "unknown_kind")
              ? `unknown action kind ${str(actions, "unknown_kind")}`
              : null,
            str(actions, "malformed"),
            str(t, "triggers_error"),
            str(obj(t.triggers), "stopped")
              ? `triggers stopped: ${str(obj(t.triggers), "stopped")}`
              : null,
          ].filter((p): p is string => !!p);
          const triggerList = objectArray(obj(t.triggers)?.triggers);
          return (
            <tr key={`${record.id}:${i}`}>
              <td className={path.known ? "mono" : "an-muted"}>
                {path.known
                  ? path.text
                  : `${str(t, "id") ?? "?"} (path ${path.text})`}
              </td>
              <td className={author.known ? "" : "an-muted"}>{author.text}</td>
              <td className="mono an-small">
                {actionList.length ? (
                  actionList.map((a, n) => <div key={n}>{actionText(a)}</div>)
                ) : (
                  <span className="an-muted">
                    {t.actions == null ? "no Actions value" : "none decoded"}
                  </span>
                )}
              </td>
              <td className="mono an-small">
                {triggerList.length ? (
                  triggerList.map((tr, n) => (
                    <div key={n}>{triggerText(tr)}</div>
                  ))
                ) : (
                  <span className="an-muted">
                    {t.triggers == null ? "not decoded" : "none decoded"}
                  </span>
                )}
              </td>
              <td>
                <Mono value={str(obj(dyn?.creation), "utc")} />
              </td>
              <td>
                <Mono value={str(obj(dyn?.last_run), "utc")} />
              </td>
              <td>
                <Mono value={str(dyn, "last_result")} />
              </td>
              <td>
                {problems.length ? (
                  <span className="badge badge-warn">
                    {problems.join("; ")}
                  </span>
                ) : (
                  <span className="badge">decoded</span>
                )}
              </td>
            </tr>
          );
        })}
      </Table>
    </>
  );
};

// ---------------------------------------------------------------------------
// truecrypt: driver{}, sweep{}
// ---------------------------------------------------------------------------

const memoryTrueCryptViewerBody: StageBody = (record, caseId) => {
  const m = record.metadata;
  const driver = obj(m.driver);
  const sweep = obj(m.sweep);
  const schedules = objectArray(sweep?.schedules);
  const unhashed = objectArray(sweep?.schedules_unhashed);
  const pairs = Array.isArray(sweep?.possible_xts_pairs)
    ? (sweep!.possible_xts_pairs as unknown[]).filter(Array.isArray)
    : [];
  const pairedAddresses = new Set(
    pairs.flatMap((p) => (p as unknown[]).map((a) => String(a))),
  );
  const names = Array.isArray(driver?.names_looked_for)
    ? (driver!.names_looked_for as unknown[]).map(String).join(", ")
    : null;
  return (
    <>
      <StageHead
        record={record}
        caseId={caseId}
        summary={
          driver?.present === true ? (
            <>
              driver <span className="mono">{str(driver, "name") ?? "?"}</span>{" "}
              on the loaded-module list at <Mono value={str(driver, "base")} />
              {num(driver, "size") != null
                ? ` (${formatBytes(num(driver, "size")!)})`
                : ""}
            </>
          ) : (
            <>
              no driver on the loaded-module list
              {num(driver, "modules_walked") != null
                ? ` (${formatCount(num(driver, "modules_walked")!)} modules walked${driver?.list_complete === false ? ", list not walked whole" : ""})`
                : ""}
              {names ? `; looked for ${names}` : ""}
            </>
          )
        }
      />
      {metaStr(m, "sweep_did_not_run_because") ? (
        <p className="an-small">
          <span className="badge">sweep did not run</span>{" "}
          {metaStr(m, "sweep_did_not_run_because")}
        </p>
      ) : null}
      {metaStr(m, "validation_note") ? (
        <p className="an-muted an-small">{metaStr(m, "validation_note")}</p>
      ) : null}
      {sweep ? (
        <>
          <p className="an-small">
            Swept {str(sweep, "region") ?? "the region"}:{" "}
            {formatBytes(num(sweep, "bytes_scanned") ?? 0)} scanned
            {(num(sweep, "unread_bytes") ?? 0) > 0
              ? `, ${formatBytes(num(sweep, "unread_bytes")!)} unread`
              : ""}
            {(num(sweep, "unmapped_bytes") ?? 0) > 0
              ? `, ${formatBytes(num(sweep, "unmapped_bytes")!)} unmapped`
              : ""}
            ; {formatCount(num(sweep, "schedules_total") ?? schedules.length)}{" "}
            verified AES key schedules
            {sweep.schedules_truncated === true ? " (capped)" : ""}
            {(num(sweep, "schedules_unhashed_total") ?? unhashed.length) > 0
              ? `, ${formatCount(num(sweep, "schedules_unhashed_total") ?? unhashed.length)} found and not hashed`
              : ""}
            . {formatCount(pairs.length)} adjacent AES-256 pairs are reported as
            a POSSIBLE XTS pair — an inference from adjacency, not a decoded key
            container; the driver's own container is not decoded.
          </p>
          <Table headers={["Address", "Key bits", "Key SHA-256", "Pair"]}>
            {schedules.map((s, i) => (
              <tr key={`${record.id}:${i}`}>
                <td>
                  <Mono value={str(s, "address")} />
                </td>
                <td className="mono">{str(s, "bits") ?? MISSING}</td>
                <td>
                  <Mono value={str(s, "key_sha256")} />
                </td>
                <td>
                  {pairedAddresses.has(str(s, "address") ?? "") ? (
                    <span className="badge badge-warn">
                      POSSIBLE XTS pair (inference)
                    </span>
                  ) : (
                    <span className="an-muted">{MISSING}</span>
                  )}
                </td>
              </tr>
            ))}
            {unhashed.map((s, i) => (
              <tr key={`${record.id}:u:${i}`}>
                <td>
                  <Mono value={str(s, "address")} />
                </td>
                <td className="mono">{str(s, "bits") ?? MISSING}</td>
                <td className="an-muted">
                  not hashed: {str(s, "detail") ?? "no detail"}
                </td>
                <td>
                  <span className="an-muted">{MISSING}</span>
                </td>
              </tr>
            ))}
          </Table>
        </>
      ) : null}
    </>
  );
};

// ---------------------------------------------------------------------------
// console_history: hosts[], console_clients_listed[], summary
// ---------------------------------------------------------------------------

const memoryConsoleHistoryViewerBody: StageBody = (record, caseId) => {
  const m = record.metadata;
  const hosts = objectArray(m.hosts);
  const clients = objectArray(m.console_clients_listed);
  const rows = hosts.flatMap((h) =>
    objectArray(h.histories).map((hist) => ({ host: h, hist })),
  );
  return (
    <>
      <StageHead
        record={record}
        caseId={caseId}
        summary={
          <>
            {formatCount(hosts.length)} console host(s) swept,{" "}
            {formatCount(num(m, "histories_total") ?? rows.length)} command
            history/histories recognised
          </>
        }
      />
      {metaStr(m, "summary") ? (
        <p className="an-small">{metaStr(m, "summary")}</p>
      ) : null}
      {hosts.length ? (
        <Table
          headers={[
            "Host",
            "PID",
            "Histories",
            "Heap swept",
            "Not resident",
            "Paged out / unreadable",
          ]}
        >
          {hosts.map((h, i) => (
            <tr key={`${record.id}:h:${i}`}>
              <td className="mono">{str(h, "host") ?? MISSING}</td>
              <td className="mono">{str(h, "pid") ?? MISSING}</td>
              <td className="mono">
                {h.swept === true
                  ? formatCount(num(h, "histories_found") ?? 0)
                  : "not swept"}
              </td>
              <td>{formatBytes(num(h, "bytes_swept") ?? 0)}</td>
              <td>{formatBytes(num(h, "bytes_not_resident") ?? 0)}</td>
              <td>
                {formatBytes(
                  (num(h, "bytes_paged_out") ?? 0) +
                    (num(h, "bytes_unreadable") ?? 0),
                )}
                {str(h, "not_swept_because")
                  ? ` — ${str(h, "not_swept_because")}`
                  : ""}
              </td>
            </tr>
          ))}
        </Table>
      ) : null}
      {rows.map(({ host, hist }, i) => (
        <div key={`${record.id}:c:${i}`}>
          <p className="an-small">
            Host <span className="mono">{str(host, "pid") ?? MISSING}</span>,
            history for <span className="mono">{str(hist, "application")}</span>{" "}
            at <Mono value={str(hist, "address")} />, limit{" "}
            {str(hist, "command_limit") ?? MISSING}; commands in stored order.
          </p>
          <Table headers={["#", "Command", "Status"]}>
            {objectArray(hist.commands).map((c, j) => (
              <tr key={`${record.id}:c:${i}:${j}`}>
                <td className="mono">{str(c, "index") ?? MISSING}</td>
                <td className="mono">{str(c, "text") ?? MISSING}</td>
                <td>
                  {str(c, "unreadable") ? (
                    <span className="badge badge-warn">
                      unreadable: {str(c, "unreadable")}
                    </span>
                  ) : (
                    <span className="badge">read</span>
                  )}
                </td>
              </tr>
            ))}
          </Table>
        </div>
      ))}
      {clients.length ? (
        <p className="an-muted an-small">
          Console clients on the process list:{" "}
          {clients
            .map((c) => `${str(c, "name") ?? "?"} (${str(c, "pid") ?? "?"})`)
            .join(", ")}
          .
        </p>
      ) : null}
      {metaStr(m, "layout_basis") ? (
        <p className="an-muted an-small">{metaStr(m, "layout_basis")}</p>
      ) : null}
    </>
  );
};

export function MemoryProcessorBlocksViewer(props: ViewerProps): ReactNode {
  return (
    <StageList
      {...props}
      noun="processor blocks"
      body={memoryProcessorBlocksViewerBody}
    />
  );
}

export function MemoryBigPoolViewer(props: ViewerProps): ReactNode {
  return (
    <StageList {...props} noun="big pool" body={memoryBigPoolViewerBody} />
  );
}

export function MemoryVirtualMapViewer(props: ViewerProps): ReactNode {
  return (
    <StageList
      {...props}
      noun="virtual map"
      body={memoryVirtualMapViewerBody}
    />
  );
}

export function MemoryHiveCellRoutinesViewer(props: ViewerProps): ReactNode {
  return (
    <StageList
      {...props}
      noun="hive cell routines"
      body={memoryHiveCellRoutinesViewerBody}
    />
  );
}

export function MemoryVersionInfoViewer(props: ViewerProps): ReactNode {
  return (
    <StageList
      {...props}
      noun="version info"
      body={memoryVersionInfoViewerBody}
    />
  );
}

export function MemoryMbrScanViewer(props: ViewerProps): ReactNode {
  return (
    <StageList {...props} noun="MBR scan" body={memoryMbrScanViewerBody} />
  );
}

export function MemoryScheduledTasksViewer(props: ViewerProps): ReactNode {
  return (
    <StageList
      {...props}
      noun="scheduled tasks"
      body={memoryScheduledTasksViewerBody}
    />
  );
}

export function MemoryTrueCryptViewer(props: ViewerProps): ReactNode {
  return (
    <StageList {...props} noun="TrueCrypt" body={memoryTrueCryptViewerBody} />
  );
}

export function MemoryConsoleHistoryViewer(props: ViewerProps): ReactNode {
  return (
    <StageList
      {...props}
      noun="console history"
      body={memoryConsoleHistoryViewerBody}
    />
  );
}
