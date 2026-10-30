import type { ArtifactListItem } from "../api/types";
import type { SourceFilter } from "../lib/useSourceFilter";

/**
 * The "scope to one acquisition" dropdown, driven by {@link useSourceFilter}.
 * Renders nothing for a single-source case. Presentation (wrapper/label/select
 * classes, the "all sources" wording) is passed in so the Logical navigator and
 * System Info can keep their own styling while sharing one implementation of the
 * control and its selection logic (CR-008).
 */
export function SourceSelect({
  filter,
  id,
  wrapperClassName,
  labelClassName,
  selectClassName,
  label = "Source",
  allLabel = "All sources",
}: {
  filter: SourceFilter;
  id: string;
  wrapperClassName?: string;
  labelClassName?: string;
  selectClassName?: string;
  label?: string;
  allLabel?: string;
}) {
  if (!filter.multiSource) return null;
  return (
    <div className={wrapperClassName}>
      <label className={labelClassName} htmlFor={id}>
        {label}
      </label>
      <select
        id={id}
        className={selectClassName}
        value={filter.activeSource ?? ""}
        onChange={(e) => filter.setSourceId(e.target.value || undefined)}
      >
        <option value="">{allLabel}</option>
        {filter.sourceItems.map((s) => (
          <option key={s.id} value={s.id}>
            {sourceLabel(s, filter.sourceItems)}
          </option>
        ))}
      </select>
    </div>
  );
}

/**
 * What to call a source in the picker.
 *
 * The name alone is enough until two sources share it — which happens as soon
 * as an image is ingested a subtree at a time (a macOS tree gives three sources
 * called "Applications") or a folder is ingested twice after an interrupted
 * run. Scoping to one of those by name is picking blind, so a shared name is
 * qualified by the path it came from, and a shared path by the head of the
 * artifact's id, which is the only thing left that tells them apart.
 */
export function sourceLabel(
  source: ArtifactListItem,
  all: ArtifactListItem[],
): string {
  const sameName = all.filter((s) => s.name === source.name);
  if (sameName.length < 2) return source.name;
  const path =
    typeof source.metadata?.path === "string" ? source.metadata.path : null;
  if (path) {
    const samePath = sameName.filter(
      (s) =>
        (typeof s.metadata?.path === "string" ? s.metadata.path : null) ===
        path,
    );
    if (samePath.length < 2) return `${source.name} — ${path}`;
    return `${source.name} — ${path} (${source.id.slice(0, 8)})`;
  }
  return `${source.name} (${source.id.slice(0, 8)})`;
}
