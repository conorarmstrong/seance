import { useMutation } from "@tanstack/react-query";
import { useState } from "react";
import { formatCount } from "../../lib/format";
import {
  runSweep,
  SWEEP_REGIONS,
  type SweepRegion,
  type SweepRequest,
  type SweepResponse,
} from "./api";

/** Hits listed before the list is cut; the rest are counted, not hidden. */
const HITS_SHOWN = 200;

const commaList = (s: string) =>
  s
    .split(",")
    .map((v) => v.trim())
    .filter((v) => v !== "");

/**
 * The case-wide byte sweep (ROADMAP §1.2), on the Search screen.
 *
 * The index search above answers from what was indexed; this reads the
 * evidence bytes themselves, region by region, for text (UTF-8, UTF-16LE/BE
 * and any named single-byte code page) and hex byte patterns. The panel adds
 * no claim of its own. It forwards what the route answers, and it is built so
 * that an answer a ceiling cut can never be read as a finished one: the status
 * line is the route's `complete`, every ceiling that bit is named with its
 * number, and the slack sentence stands beside the region counts on every
 * answer, because `slack: 0` alone reads as "no slack held the term".
 */
export function ByteSweepPanel({ caseId }: { caseId: string }) {
  const [text, setText] = useState("");
  const [bytes, setBytes] = useState("");
  const [codepages, setCodepages] = useState("");
  const [extensions, setExtensions] = useState("");
  const [regions, setRegions] = useState<SweepRegion[]>(SWEEP_REGIONS);
  const [maxHits, setMaxHits] = useState("");
  // The request the answer on screen belongs to, so Resume continues that
  // sweep and not whatever the form holds by the time it is pressed.
  const [lastRequest, setLastRequest] = useState<SweepRequest | null>(null);

  const sweep = useMutation({
    mutationFn: (body: SweepRequest) => runSweep(caseId, body),
    onSuccess: (_answer, body) => setLastRequest(body),
  });

  const buildRequest = (): SweepRequest | null => {
    const patterns: SweepRequest["patterns"] = [];
    if (text !== "") patterns.push({ kind: "text", value: text });
    if (bytes.trim() !== "")
      patterns.push({ kind: "bytes", value: bytes.trim() });
    if (patterns.length === 0) return null;
    const body: SweepRequest = { patterns };
    const cps = commaList(codepages);
    if (cps.length > 0) body.codepages = cps;
    const scope: NonNullable<SweepRequest["scope"]> = {};
    const exts = commaList(extensions);
    if (exts.length > 0) scope.extensions = exts;
    // Every region is the server's default; only a narrowed set is sent, so a
    // request that admits everything reads as one.
    if (regions.length !== SWEEP_REGIONS.length) scope.regions = regions;
    if (Object.keys(scope).length > 0) body.scope = scope;
    const n = Number.parseInt(maxHits, 10);
    if (maxHits.trim() !== "" && Number.isFinite(n) && n > 0) {
      body.bounds = { max_hits: n };
    }
    return body;
  };

  const request = buildRequest();
  const toggleRegion = (r: SweepRegion) =>
    setRegions((prev) =>
      prev.includes(r)
        ? prev.filter((x) => x !== r)
        : SWEEP_REGIONS.filter((x) => x === r || prev.includes(x)),
    );

  const answer = sweep.data;
  return (
    <details className="srch-sweep">
      <summary>Byte sweep of the evidence bytes</summary>
      <div className="srch-sweep-body">
        <p>
          Reads the bytes of every object the scope admits — live files, file
          slack, unallocated space, recovered (carved or deleted) content and
          raw images — rather than the search index. Text is searched as UTF-8,
          UTF-16LE and UTF-16BE, and under any code page named here.
        </p>
        <form
          className="srch-sweep-form"
          onSubmit={(e) => {
            e.preventDefault();
            if (request) sweep.mutate(request);
          }}
        >
          <label>
            Sweep text
            <input value={text} onChange={(e) => setText(e.target.value)} />
          </label>
          <label>
            Sweep bytes (hex)
            <input value={bytes} onChange={(e) => setBytes(e.target.value)} />
          </label>
          <label>
            Sweep code pages
            <input
              value={codepages}
              placeholder="windows-1252, koi8-r"
              onChange={(e) => setCodepages(e.target.value)}
            />
          </label>
          <label>
            Sweep extensions
            <input
              value={extensions}
              placeholder=".txt,.doc"
              onChange={(e) => setExtensions(e.target.value)}
            />
          </label>
          <label>
            Sweep max hits
            <input
              value={maxHits}
              inputMode="numeric"
              onChange={(e) => setMaxHits(e.target.value)}
            />
          </label>
          <fieldset>
            <legend>Regions</legend>
            {SWEEP_REGIONS.map((r) => (
              <label key={r} className="srch-sweep-region">
                <input
                  type="checkbox"
                  checked={regions.includes(r)}
                  onChange={() => toggleRegion(r)}
                />
                {r}
              </label>
            ))}
          </fieldset>
          <button
            type="submit"
            disabled={
              request == null || regions.length === 0 || sweep.isPending
            }
          >
            Sweep
          </button>
        </form>

        {sweep.isError && (
          <p role="alert" className="srch-sweep-error">
            {sweep.error instanceof Error
              ? sweep.error.message
              : String(sweep.error)}
          </p>
        )}
        {answer && (
          <SweepAnswer
            answer={answer}
            onResume={
              answer.next_cursor && lastRequest
                ? () =>
                    sweep.mutate({
                      ...lastRequest,
                      resume: answer.next_cursor!,
                    })
                : undefined
            }
            pending={sweep.isPending}
          />
        )}
      </div>
    </details>
  );
}

function SweepAnswer({
  answer,
  onResume,
  pending,
}: {
  answer: SweepResponse;
  onResume?: () => void;
  pending: boolean;
}) {
  return (
    <div className="srch-sweep-answer">
      <p data-testid="sweep-status" className={answer.complete ? "ok" : "warn"}>
        {answer.complete
          ? "Complete"
          : "Incomplete — this answer does not speak for the objects it did not reach"}
        {` · ${formatCount(answer.hits.length)} hits in ${formatCount(
          answer.objects_searched,
        )} objects, ${formatCount(answer.bytes_scanned)} bytes read`}
      </p>
      <p>{answer.coverage_statement}</p>
      <ul className="srch-sweep-ceilings">
        {answer.hit_cap_reached && (
          <li>
            The hit ceiling of {formatCount(answer.max_hits)} was reached (the
            server&rsquo;s most is {formatCount(answer.max_hits_ceiling)}).
          </li>
        )}
        {answer.byte_cap_reached && (
          <li>
            The byte ceiling of {formatCount(answer.max_bytes)} was reached (the
            server&rsquo;s most is {formatCount(answer.max_bytes_ceiling)}).
          </li>
        )}
        {answer.object_stream_cut && (
          <li>
            The case holds more objects than the{" "}
            {formatCount(answer.objects_ceiling)} one call pulls; the rest were
            not offered.
          </li>
        )}
        {!answer.complete && !answer.next_cursor && (
          <li>
            No resume cursor was returned, so this sweep cannot be continued
            from here.
          </li>
        )}
      </ul>
      {onResume && (
        <button type="button" onClick={onResume} disabled={pending}>
          Resume from where this sweep stopped
        </button>
      )}

      <p>{answer.scope_statement}</p>
      <table className="srch-sweep-regions" aria-label="Objects by region">
        <thead>
          <tr>
            <th>Region</th>
            <th>Offered</th>
            <th>Searched</th>
          </tr>
        </thead>
        <tbody>
          {SWEEP_REGIONS.map((r) => (
            <tr key={r}>
              <th scope="row">{r}</th>
              <td>{formatCount(answer.objects_offered_by_region[r] ?? 0)}</td>
              <td>{formatCount(answer.objects_searched_by_region[r] ?? 0)}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <p className="srch-sweep-slack">{answer.slack_statement}</p>
      {answer.regions_not_searched.length > 0 && (
        <p>Regions not searched: {answer.regions_not_searched.join(", ")}</p>
      )}
      <p>Encodings searched: {answer.encodings_searched.join(", ")}</p>
      {answer.codepages_absent.length > 0 && (
        <p>
          Code pages not recognised, not searched:{" "}
          {answer.codepages_absent.join(", ")}
        </p>
      )}
      {answer.encodings_skipped.map((s) => (
        <p key={`${s.pattern_index}-${s.encoding}`}>
          Pattern {s.pattern_index} not searched under {s.encoding}: {s.reason}
        </p>
      ))}
      {answer.objects_without_bytes > 0 && (
        <p>
          {formatCount(answer.objects_without_bytes)} objects carry no bytes of
          their own (records, events, directories) and were not searched.
        </p>
      )}
      {answer.raw_objects_not_offered > 0 && (
        <p>
          {formatCount(answer.raw_objects_not_offered)} raw image, partition,
          file-system or container objects were not offered: the scope does not
          admit raw.
        </p>
      )}

      {(answer.short_reads.length > 0 ||
        answer.read_failures.length > 0 ||
        answer.beyond_declared_size.length > 0) && (
        <ul className="srch-sweep-problems">
          {answer.short_reads.map((s) => (
            <li key={`sr-${s.artifact_id}`}>
              Short read: {s.artifact_id} ended at {s.bytes_read} of a declared{" "}
              {s.declared_size} bytes.
            </li>
          ))}
          {answer.read_failures.map((f) => (
            <li key={`rf-${f.artifact_id}`}>
              Read failure: {f.artifact_id} failed at offset {f.offset}:{" "}
              {f.error}. Nothing past it was searched.
            </li>
          ))}
          {answer.beyond_declared_size.map((b) => (
            <li key={`bd-${b.artifact_id}`}>
              {b.artifact_id} holds {b.bytes_beyond} bytes past its declared{" "}
              {b.declared_size}; they were not searched.
            </li>
          ))}
        </ul>
      )}

      {answer.hits_endian_ambiguous > 0 && (
        <p>
          {formatCount(answer.hits_endian_ambiguous)} hits read as the pattern
          in both UTF-16 byte orders; each names both readings, and neither
          should be quoted alone.
        </p>
      )}
      <ol className="srch-sweep-hits">
        {answer.hits.slice(0, HITS_SHOWN).map((h, i) => (
          <li
            key={`${h.artifact_id}-${h.offset}-${h.pattern_index}`}
            data-testid={`sweep-hit-${i}`}
          >
            [{h.region}] {h.path ?? "(no path)"} ({h.artifact_type}{" "}
            {h.artifact_id}) — offset {h.offset}, length {h.length}: &ldquo;
            {h.pattern_value}&rdquo; as {h.encodings.join(", ")}
            {(h.endian_aliases ?? []).map((a) => (
              <span
                key={`${a.encoding}-${a.offset}`}
                className="srch-sweep-alias"
              >
                {" "}
                — also reads as {a.encoding} at offset {a.offset}
                {a.folded
                  ? " (folded into this hit)"
                  : " (listed as its own hit)"}
                ; the bytes do not say which byte order was written
              </span>
            ))}
          </li>
        ))}
      </ol>
      {answer.hits.length > HITS_SHOWN && (
        <p>
          {formatCount(answer.hits.length - HITS_SHOWN)} more hits in this
          answer are not listed here.
        </p>
      )}
    </div>
  );
}
