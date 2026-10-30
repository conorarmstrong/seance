import type { ReactNode } from "react";
import { formatCount } from "../../lib/format";
import type { ParsedRecord, RecordMetadata } from "./api";
import { ArtifactLink } from "./cells";
import { MISSING, metaStr } from "./lib";
import type { ViewerProps } from "./viewers";

/**
 * The Linux memory stages that publish paths (ROADMAP §4.2): open files and
 * mounts. Each stage is ONE record holding every process's descriptors (or
 * every namespace's mounts) as nested arrays, which the generic table skips —
 * so before these viewers the one thing the stage was rewritten to produce,
 * a mount-crossing path with its own scope, was invisible from the records
 * screen.
 *
 * Every path here is qualified by the walk that produced it. `path_scope` is
 * one of three words the stage writes: `mount_crossing` (walked across mount
 * points towards the process's root), `dentry_tree_relative` (reconstructed
 * within one mount only, the reduced walk), and `pseudo` (a socket, pipe or
 * anonymous inode rendered the way the kernel renders it — not a path in
 * any mount). The word is shown beside every path with the stage's own
 * sentence for it, because a relative path read as an absolute one names the
 * wrong file.
 */

/**
 * A field the stage sends as an envelope: `{kind:"known", value}`,
 * `{kind:"not_applicable"}`, `{kind:"not_declared", member}` or
 * `{kind:"unavailable", detail}`. "There is no file behind this descriptor"
 * and "the pointer to it would not read" are different facts, so each kind
 * is rendered as what it is rather than collapsed to a dash.
 */
function envelope(raw: unknown): { text: string; known: boolean } {
  if (raw == null) return { text: MISSING, known: false };
  if (typeof raw === "string" || typeof raw === "number") {
    return { text: String(raw), known: true };
  }
  if (typeof raw !== "object") return { text: MISSING, known: false };
  const e = raw as Record<string, unknown>;
  switch (e.kind) {
    case "known":
      return { text: String(e.value ?? MISSING), known: true };
    case "not_applicable":
      return { text: "not applicable", known: false };
    case "not_declared":
      return {
        text: `not declared by this build (${String(e.member ?? "?")})`,
        known: false,
      };
    case "unavailable":
      return {
        text: `unavailable: ${String(e.detail ?? "no detail")}`,
        known: false,
      };
    default:
      return { text: MISSING, known: false };
  }
}

/** The stage's scope word, spaced for reading; the raw word stays in the title. */
function scopeLabel(scope: string | null): string {
  if (!scope) return MISSING;
  return scope.replace(/_/g, " ");
}

function ScopeCell({
  scope,
  detail,
}: {
  scope: string | null;
  detail: string | null;
}): ReactNode {
  return (
    <span className="an-sig" title={scope ?? undefined}>
      <span className="badge">{scopeLabel(scope)}</span>
      {detail ? <span className="an-sig-detail an-small"> {detail}</span> : null}
    </span>
  );
}

function objectArray(raw: unknown): Record<string, unknown>[] {
  if (!Array.isArray(raw)) return [];
  return raw.filter(
    (x): x is Record<string, unknown> => !!x && typeof x === "object",
  );
}

function str(o: Record<string, unknown>, key: string): string | null {
  const v = o[key];
  if (typeof v === "string") return v.length ? v : null;
  if (typeof v === "number" || typeof v === "boolean") return String(v);
  return null;
}

/** The survey-level statement every stage record carries: which walk the
 * build allowed, and that each row says which walk it got. */
function SurveyNote({
  record,
  caseId,
  counts,
}: {
  record: ParsedRecord;
  caseId: string;
  counts: string;
}): ReactNode {
  const m = record.metadata;
  const scope = metaStr(m, "path_scope");
  const note = metaStr(m, "path_scope_note");
  const complete = m.complete === true;
  return (
    <p className="an-small">
      <ArtifactLink caseId={caseId} id={record.id}>
        stage record
      </ArtifactLink>
      {" — "}
      {counts}
      {complete ? "" : " (the walk did not complete; this is a floor)"}.
      {scope ? (
        <>
          {" "}
          Path walk attempted: <span className="badge">{scopeLabel(scope)}</span>
          {note ? <> — {note}</> : null}
        </>
      ) : null}
    </p>
  );
}

// ---------------------------------------------------------------------------
// Open files: processes[].files[]
// ---------------------------------------------------------------------------

interface FileRow {
  key: string;
  pid: string;
  comm: string;
  fd: string;
  path: { text: string; known: boolean };
  kind: string | null;
  scope: string | null;
  scopeDetail: string | null;
}

function fileRows(m: RecordMetadata, recordId: string): FileRow[] {
  const out: FileRow[] = [];
  for (const [pi, process] of objectArray(m.processes).entries()) {
    const pid = envelope(process.pid).text;
    const comm = envelope(process.comm).text;
    for (const [fi, file] of objectArray(process.files).entries()) {
      out.push({
        key: `${recordId}:${pi}:${fi}`,
        pid,
        comm,
        fd: str(file, "fd") ?? MISSING,
        path: envelope(file.path),
        kind: str(file, "path_kind"),
        scope: str(file, "path_scope"),
        scopeDetail: str(file, "path_scope_detail"),
      });
    }
  }
  return out;
}

export function LinuxOpenFilesViewer({
  records,
  caseId,
}: ViewerProps): ReactNode {
  if (records.length === 0) {
    return <p className="an-muted">No open-files stage record.</p>;
  }
  return (
    <div>
      {records.map((record) => {
        const rows = fileRows(record.metadata, record.id);
        const m = record.metadata;
        return (
          <section key={record.id} className="an-card">
            <SurveyNote
              record={record}
              caseId={caseId}
              counts={`${formatCount(Number(m.process_count ?? 0))} processes, ${formatCount(Number(m.open_file_count ?? rows.length))} open files`}
            />
            <div className="an-wt-table-wrap">
              <table className="data-table an-table">
                <thead>
                  <tr>
                    <th>PID</th>
                    <th>Process</th>
                    <th>FD</th>
                    <th>Path</th>
                    <th>Kind</th>
                    <th>Path scope</th>
                  </tr>
                </thead>
                <tbody>
                  {rows.map((r) => (
                    <tr key={r.key}>
                      <td className="mono">{r.pid}</td>
                      <td className="mono">{r.comm}</td>
                      <td className="mono">{r.fd}</td>
                      <td className={r.path.known ? "mono" : "an-muted"}>
                        {r.path.text}
                      </td>
                      <td>{r.kind ?? MISSING}</td>
                      <td>
                        <ScopeCell scope={r.scope} detail={r.scopeDetail} />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>
        );
      })}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Mounts: namespaces[].mounts[]
// ---------------------------------------------------------------------------

interface MountRow {
  key: string;
  namespace: string;
  devname: { text: string; known: boolean };
  mountPoint: { text: string; known: boolean };
  scope: string | null;
  scopeDetail: string | null;
  fsRoot: { text: string; known: boolean };
  flags: string;
}

/**
 * `mnt_flags` as the stage renders it: `{access:"ro"|"rw", options:[...],
 * shared, unbindable}` when read, or `{not_declared: member}`,
 * `{not_applicable: true}` or `{unavailable: detail}` when not. The three
 * "not read" forms are kept apart from "rw with no options", which is what a
 * blank would have read as.
 */
function mountFlags(raw: unknown): string {
  if (!raw || typeof raw !== "object") return MISSING;
  const f = raw as Record<string, unknown>;
  if (typeof f.not_declared === "string") {
    return `not declared by this build (${f.not_declared})`;
  }
  if (f.not_applicable === true) return "not applicable";
  if (typeof f.unavailable === "string") return `unavailable: ${f.unavailable}`;
  const parts: string[] = [];
  if (typeof f.access === "string") parts.push(f.access);
  if (Array.isArray(f.options)) {
    parts.push(...f.options.filter((o): o is string => typeof o === "string"));
  }
  if (f.shared === true) parts.push("shared");
  if (f.unbindable === true) parts.push("unbindable");
  return parts.length ? parts.join(" ") : MISSING;
}

function mountRows(m: RecordMetadata, recordId: string): MountRow[] {
  const out: MountRow[] = [];
  for (const [ni, ns] of objectArray(m.namespaces).entries()) {
    const namespace = str(ns, "mnt_ns_address_hex") ?? String(ni);
    for (const [mi, mount] of objectArray(ns.mounts).entries()) {
      const flags = mountFlags(mount.flags);
      out.push({
        key: `${recordId}:${ni}:${mi}`,
        namespace,
        devname: envelope(mount.devname),
        mountPoint: envelope(mount.mount_point),
        scope: str(mount, "mount_point_scope"),
        scopeDetail: str(mount, "mount_point_scope_detail"),
        fsRoot: envelope(mount.fs_root),
        flags,
      });
    }
  }
  return out;
}

export function LinuxMountsViewer({ records, caseId }: ViewerProps): ReactNode {
  if (records.length === 0) {
    return <p className="an-muted">No mounts stage record.</p>;
  }
  return (
    <div>
      {records.map((record) => {
        const rows = mountRows(record.metadata, record.id);
        const m = record.metadata;
        return (
          <section key={record.id} className="an-card">
            <SurveyNote
              record={record}
              caseId={caseId}
              counts={`${formatCount(Number(m.namespace_count ?? 0))} mount namespaces, ${formatCount(Number(m.mount_count ?? rows.length))} mounts`}
            />
            <div className="an-wt-table-wrap">
              <table className="data-table an-table">
                <thead>
                  <tr>
                    <th>Namespace</th>
                    <th>Device</th>
                    <th>Mount point</th>
                    <th>Mount point scope</th>
                    <th>Filesystem root (within the mount)</th>
                    <th>Flags</th>
                  </tr>
                </thead>
                <tbody>
                  {rows.map((r) => (
                    <tr key={r.key}>
                      <td className="mono">{r.namespace}</td>
                      <td className={r.devname.known ? "mono" : "an-muted"}>
                        {r.devname.text}
                      </td>
                      <td className={r.mountPoint.known ? "mono" : "an-muted"}>
                        {r.mountPoint.text}
                      </td>
                      <td>
                        <ScopeCell scope={r.scope} detail={r.scopeDetail} />
                      </td>
                      <td className={r.fsRoot.known ? "mono" : "an-muted"}>
                        {r.fsRoot.text}
                      </td>
                      <td className="mono">{r.flags || MISSING}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>
        );
      })}
    </div>
  );
}
