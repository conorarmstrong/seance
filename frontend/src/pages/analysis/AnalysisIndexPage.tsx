import { useQuery } from "@tanstack/react-query";
import { Link, useParams } from "react-router-dom";
import { getRecordTypes } from "./api";
import { AppsPanel } from "./AppsPanel";
import { humanizeType } from "./lib";
import { VIEWERS } from "./viewers";
import { formatCount } from "../../lib/format";
import { groupRecordTypes } from "./recordCategories";
import { QuickFilterBar, useQuickFilter } from "../../components/QuickFilter";
import "./analysis.css";

/**
 * Analysis landing surface. Lists every ParsedRecord `type` present in the
 * case as a card; each card opens a type-specific viewer.
 */
export function AnalysisIndexPage() {
  const { caseId } = useParams<{ caseId: string }>();

  const typesQuery = useQuery({
    queryKey: ["analysis-types", caseId],
    queryFn: () => getRecordTypes(caseId!),
    enabled: !!caseId,
  });

  // Internal/derived record types are not analyst-facing artifacts.
  const INTERNAL = new Set(["file_hash", "allocation_map", "CarvingSummary"]);
  const types = (typesQuery.data?.record_types ?? []).filter(
    (t) => !INTERNAL.has(t.type),
  );
  // Grouped by what the records are ABOUT, not by how many there are. Counting
  // is not importance: ranking by population opened a real macOS case with
  // 78,093 recovered SQLite rows and 37,738 signature analyses, while the five
  // iMessages and the device the case was about sat below the fold (UI-033).
  // A quick type-ahead over the record types (§1.1). A case can hold sixty of
  // them, and an examiner who knows they want "prefetch" should not have to
  // find which of seven groups it sits in. The whole list is loaded, so the
  // bar makes no claim about a subset.
  const search = useQuickFilter(caseId ?? "", types, (t) => [
    t.type,
    humanizeType(t.type),
  ]);
  const groups = groupRecordTypes(search.rows);
  const anyTypes = types.length > 0;

  return (
    <div>
      <h1 className="page-title">Analysis</h1>
      <p className="an-intro">
        Every parsed record in this case, grouped by what it is about rather
        than by how many there are. Open a type for a viewer tailored to its
        fields.
      </p>

      {typesQuery.isPending && (
        <div className="loading">Loading record types…</div>
      )}
      {typesQuery.isError && (
        <div className="error-note">{typesQuery.error.message}</div>
      )}
      {typesQuery.data && !anyTypes && (
        <div className="empty-state">
          <h3>No parsed records</h3>
          <p>No plugins have emitted structured records for this case yet.</p>
        </div>
      )}
      {/* Before the record-type groups: "which programs was this person using"
          is the first triage question, and the type list answers the second
          (§2.12). */}
      {caseId && <AppsPanel caseId={caseId} />}

      {typesQuery.data && anyTypes && (
        <QuickFilterBar
          filter={search}
          noun="record type"
          placeholder="Filter record types…"
        />
      )}
      {/* The groups are rebuilt from what matched, so a needle matching
          nothing leaves no group behind — and the count above says it matched
          nothing rather than the page reading as a case with no records. */}

      {typesQuery.data &&
        anyTypes &&
        groups.map((group) => (
          <section key={group.category} className="an-group">
            <div className="an-group-head">
              <h2 className="an-group-name">{group.category}</h2>
              <span className="an-group-count mono">
                {formatCount(group.total)} records
              </span>
            </div>
            <p className="an-group-blurb">{group.blurb}</p>
            <div className="an-grid">
              {group.types.map(({ type, count }) => {
                const tailored = type in VIEWERS;
                return (
                  <Link
                    key={type}
                    to={`/cases/${caseId}/analysis/${encodeURIComponent(type)}`}
                    className="an-card"
                  >
                    <div className="an-card-head">
                      <div className="an-card-name" title={humanizeType(type)}>
                        {humanizeType(type)}
                      </div>
                      {!tailored && (
                        <span className="badge an-card-generic">
                          generic view
                        </span>
                      )}
                    </div>
                    <div className="an-card-count mono">
                      {formatCount(count)}
                      <span className="an-card-count-unit"> records</span>
                    </div>
                    <div className="an-card-type mono" title={type}>
                      {type}
                    </div>
                  </Link>
                );
              })}
            </div>
          </section>
        ))}
    </div>
  );
}
