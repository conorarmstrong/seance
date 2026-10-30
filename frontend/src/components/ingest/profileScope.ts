/**
 * What an ingestion profile will and will not run, computed from the record.
 *
 * A profile is a scoping decision with no trace: the orchestrator's gate
 * (`should_run_module_static`) simply never dispatches an excluded module, so
 * there is no job row, no processing-log entry and no incompleteness stamp
 * anywhere in the case to say the analysis did not happen. A case ingested
 * under the triage profile is therefore output-identical to a machine that
 * genuinely had no browser history, no messages and no email — and that
 * absence is what gets written into a statement.
 *
 * Nothing here is a hardcoded description of any profile. The module list comes
 * from the profile record the server holds (`enabled_modules` /
 * `disabled_modules`), the population it is measured against comes from the
 * running build's module registry (`GET /modules`), and this file only applies
 * the same rule the server applies. The only editorial content is the
 * namespace-to-heading table below, which names the id prefixes; every module
 * id itself is shown verbatim.
 */

import type { IngestionProfile } from '../../api/types'

/** The two lists a profile record carries. */
export interface ProfileModuleLists {
  enabled_modules: string[]
  disabled_modules: string[]
}

/** What a profile does to the running build's module registry. */
export interface ProfileScope {
  /** Registered modules this profile lets run, in registry order. */
  runs: string[]
  /** Registered modules this profile excludes, in registry order. */
  skips: string[]
  /**
   * Modules the profile names that this build does not register. They cannot
   * run, and counting them under `runs` would overstate the ingest: the server
   * warns about them into a log no examiner reads.
   */
  unregistered: string[]
  /** How many modules the running build registers — the stated population. */
  registered: number
  /** True when at least one registered module will not run under this profile. */
  restricts: boolean
}

/**
 * Apply the profile's rule to the registry.
 *
 * Mirrors `IngestionProfile::should_run_module` in `seance_core/src/profile.rs`
 * exactly, including the part that surprises people: an EMPTY enabled list
 * means "run everything", not "run nothing".
 */
export function profileScope(
  profile: ProfileModuleLists,
  registry: string[],
): ProfileScope {
  const disabled = new Set(profile.disabled_modules)
  const enabled = new Set(profile.enabled_modules)
  const runsAll = profile.enabled_modules.length === 0
  const runs: string[] = []
  const skips: string[] = []
  for (const id of registry) {
    const willRun = !disabled.has(id) && (runsAll || enabled.has(id))
    ;(willRun ? runs : skips).push(id)
  }
  const registered = new Set(registry)
  const unregistered = profile.enabled_modules.filter(
    (id) => !registered.has(id),
  )
  return {
    runs,
    skips,
    unregistered,
    registered: registry.length,
    restricts: skips.length > 0,
  }
}

/**
 * The id prefix a module belongs to: everything but the last dotted segment for
 * a three-part id (`plugin.ntfs.mft_parser` → `plugin.ntfs`), the first segment
 * for a two-part one (`macos.tcc` → `macos`).
 */
export function moduleNamespace(id: string): string {
  const parts = id.split('.')
  if (parts.length <= 2) return parts[0]
  return parts.slice(0, -1).join('.')
}

/**
 * Examiner-facing heading for a module namespace.
 *
 * Category names only, never an enumeration of what is in the category: a
 * parenthetical list would be a second copy of the registry that drifts out of
 * date silently, which is the class of claim this file exists to avoid. Two
 * namespaces may share a heading (the filesystem parsers live under both
 * `plugin.fs` and `plugin.filesystem`), and `groupModules` merges them.
 */
const NAMESPACE_LABEL: Record<string, string> = {
  container: 'Evidence containers',
  macos: 'macOS system artifacts',
  'plugin.analysis': 'File analysis',
  'plugin.apple': 'Apple messaging',
  'plugin.browsers': 'Browser history and cache',
  'plugin.bulk': 'Bulk feature extraction',
  'plugin.calendar': 'Calendars',
  'plugin.crypto': 'Encrypted volume decryption',
  'plugin.disk': 'Partitions and filesystem detection',
  'plugin.documents': 'Office documents',
  'plugin.email': 'Email',
  'plugin.executable': 'Executables',
  'plugin.filesystem': 'Filesystems',
  'plugin.fs': 'Filesystems',
  'plugin.generic': 'SQLite databases',
  'plugin.hash': 'Hashing',
  'plugin.ios': 'iOS artifacts',
  'plugin.linux': 'Linux system artifacts',
  'plugin.macos': 'macOS system artifacts',
  'plugin.media': 'Images and media',
  'plugin.memory': 'Memory analysis',
  'plugin.messaging': 'Chat and messaging',
  'plugin.mobile': 'Mobile backups and devices',
  'plugin.ntfs': 'NTFS',
  'plugin.os': 'Cross-platform OS artifacts',
  'plugin.recovery': 'Carving and recovery',
  'plugin.search': 'Search index',
  'plugin.windows': 'Windows artifacts',
}

/**
 * The heading for a namespace, or the namespace itself when this build has one
 * the table does not know. Shown verbatim rather than prettified, so a new
 * module family is never mistaken for a curated category name.
 */
export function namespaceLabel(namespace: string): string {
  return NAMESPACE_LABEL[namespace] ?? namespace
}

/** A set of module ids under one heading. */
export interface ModuleGroup {
  label: string
  ids: string[]
}

/**
 * Group module ids by heading, largest group first, so the first line an
 * examiner reads is the biggest thing the profile is doing.
 *
 * Ordering is by code unit, never `localeCompare`: this list is quoted, and two
 * examiners on different locales must be shown the same order.
 */
export function groupModules(ids: string[]): ModuleGroup[] {
  const byLabel = new Map<string, string[]>()
  for (const id of ids) {
    const label = namespaceLabel(moduleNamespace(id))
    const group = byLabel.get(label)
    if (group) group.push(id)
    else byLabel.set(label, [id])
  }
  return [...byLabel.entries()]
    .map(([label, group]) => ({
      label,
      ids: [...group].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0)),
    }))
    .sort(
      (a, b) =>
        b.ids.length - a.ids.length ||
        (a.label < b.label ? -1 : a.label > b.label ? 1 : 0),
    )
}

/**
 * Which profile governs an ingest, and what that profile does.
 *
 * `none` — no profile is in force; every registered module runs.
 * `profile` — this record governs the run. `scope` is null when the module
 *   registry could not be read, which means the exclusions cannot be listed;
 *   the record's own lists still say whether it restricts anything.
 * `unrecorded` — a built-in profile name (`triage`, `deep`) that this case has
 *   never had applied, so no record of it exists to read. What it contains is
 *   knowable only to the server, and a screen that guessed would be describing
 *   a scoping decision it cannot see.
 * `unreadable` — a list this answer depends on did not load. Never collapsed
 *   into "no profile": "we could not find out" and "nothing is in force" are
 *   different facts, and only one of them is safe to act on.
 */
export type ProfileGovernance =
  | { kind: 'none' }
  | {
      kind: 'profile'
      profile: IngestionProfile
      scope: ProfileScope | null
      /**
       * True when this profile governs because it is already active on the
       * case, rather than because the examiner picked it in this modal. It is
       * the whole of the sticky-state problem: the choice outlives the ingest
       * that made it.
       */
      inherited: boolean
    }
  | { kind: 'unrecorded'; name: string }
  | { kind: 'unreadable'; what: 'profile list' | 'active profile' }

/** The profile names the server materialises on demand from its own templates. */
export const BUILT_IN_PROFILE_NAMES = ['triage', 'deep']

export function resolveProfileGovernance({
  selection,
  profiles,
  active,
  registry,
}: {
  /** The select's value: '' for the empty option, a built-in name, or an id. */
  selection: string
  /** `listProfiles` data; undefined while it has not loaded or has failed. */
  profiles: IngestionProfile[] | undefined
  /** `getActiveProfile` data; undefined while it has not loaded or has failed. */
  active: IngestionProfile | null | undefined
  /** Module ids from `GET /modules`; undefined when that could not be read. */
  registry: string[] | undefined
}): ProfileGovernance {
  const withScope = (
    profile: IngestionProfile,
    inherited: boolean,
  ): ProfileGovernance => ({
    kind: 'profile',
    profile,
    scope: registry ? profileScope(profile, registry) : null,
    inherited,
  })

  if (selection === '') {
    // Naming no profile does not clear one: the server only touches the case's
    // active profile when the request names one, so this ingest runs under
    // whatever a previous ingest left active.
    if (active === undefined) return { kind: 'unreadable', what: 'active profile' }
    if (active === null) return { kind: 'none' }
    return withScope(active, true)
  }

  if (profiles === undefined) return { kind: 'unreadable', what: 'profile list' }

  const byName = BUILT_IN_PROFILE_NAMES.includes(selection)
    ? profiles.find((p) => p.name === selection)
    : undefined
  const record = byName ?? profiles.find((p) => p.id === selection)
  if (record) return withScope(record, false)
  return { kind: 'unrecorded', name: selection }
}
