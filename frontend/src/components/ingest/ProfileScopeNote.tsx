import { useState } from 'react'
import { formatCount } from '../../lib/format'
import {
  groupModules,
  type ProfileGovernance,
  type ProfileScope,
} from './profileScope'

/**
 * What the profile in force does to a run, in the one place it can still be
 * acted on (the ingest modal) and the one place its consequences are read (the
 * dashboard).
 *
 * Everything here is derived from two server answers — the profile record and
 * the module registry — never from a description of a profile held in this
 * file. When either is missing the note says so instead of falling back to a
 * reassuring sentence: "we could not find out which modules will run" and
 * "every module will run" are different facts, and only one of them is safe to
 * quote.
 *
 * The tone follows the incompleteness vocabulary (`warn-note`, `error-note`):
 * a restricted profile is not an error and not a pass, it is a gap the
 * examiner chose and must be able to describe under oath.
 */

/** Where the note is shown, which decides what the reader can still do. */
export type ProfileNoteContext = 'ingest' | 'case'

/**
 * "13 of 119 modules registered in this build" — always with its population.
 *
 * The verb around this phrase is deliberately "lets run", never "runs": the
 * profile decides which modules are ELIGIBLE, and an eligible module still only
 * runs if an artifact it subscribes to turns up. The exclusions are the exact
 * half — an excluded module cannot run at all.
 */
function population(scope: ProfileScope): string {
  return `${formatCount(scope.runs.length)} of ${formatCount(scope.registered)} modules registered in this build`
}

/** The categories a set of excluded modules falls into, largest first. */
function SkippedCategories({ skips }: { skips: string[] }) {
  const [expanded, setExpanded] = useState(false)
  const groups = groupModules(skips)
  return (
    <>
      <ul className="ingest-profile-groups">
        {groups.map((group) => (
          <li key={group.label}>
            {group.label}{' '}
            <span className="mono">({formatCount(group.ids.length)})</span>
          </li>
        ))}
      </ul>
      <button
        type="button"
        className="link-button"
        aria-expanded={expanded}
        onClick={() => setExpanded((v) => !v)}
      >
        {expanded ? 'Hide' : 'Show'} the {formatCount(skips.length)} modules
        that will not run
      </button>
      {expanded && (
        <ul className="ingest-profile-modules mono">
          {skips.map((id) => (
            <li key={id}>{id}</li>
          ))}
        </ul>
      )}
    </>
  )
}

/**
 * The sentence an examiner needs most, and the one the product never said: a
 * module excluded by profile is not recorded anywhere as having been skipped.
 */
function AbsenceSentence() {
  return (
    <p className="ingest-profile-absence">
      A module a profile excludes leaves no job, no processing-log row and no
      incompleteness stamp. Its results are simply absent from this case, and
      nothing on any screen tells that apart from evidence that had none.
    </p>
  )
}

export function ProfileScopeNote({
  governance,
  context,
  registered,
}: {
  governance: ProfileGovernance
  context: ProfileNoteContext
  /**
   * Size of the module registry, for the case where no profile is in force and
   * so there is no scope to carry it. Null when the registry could not be read;
   * the count is then left unstated rather than guessed.
   */
  registered: number | null
}) {
  const label = 'Analysis profile scope'
  // The stickiness clause. It is the second half of the defect this note
  // exists for: the profile is case state, so a choice made for one exhibit
  // silently governs the phone backup ingested three days later.
  const forever =
    context === 'ingest'
      ? 'this ingest and every later ingest'
      : 'every ingest in this case'
  // What a profile does NOT record. The orchestrator reads whichever profile is
  // active when a run starts and stamps nothing on what it produced, so an
  // examiner reading this case later cannot learn which profile governed the
  // artifacts already in it — only which one governs the next run.
  const onlyCurrent =
    context === 'case' ? (
      <p>
        Séance holds the profile as current case state only: nothing records
        which profile governed any earlier ingest, so this says what governs
        processing now, not what governed the artifacts already in this case.
      </p>
    ) : null

  if (governance.kind === 'unreadable') {
    return (
      <div
        className="error-note ingest-profile-note"
        role="note"
        aria-label={label}
      >
        The {governance.what} could not be read, so this screen cannot say
        which modules{' '}
        {context === 'ingest' ? 'this ingest will run' : 'ran in this case'}.
        That is a failed request, not a case with no profile in force.
      </div>
    )
  }

  if (governance.kind === 'unrecorded') {
    return (
      <div
        className="warn-note ingest-profile-note"
        role="note"
        aria-label={label}
      >
        <p>
          Séance holds no record of <strong>{governance.name}</strong> on this
          case, so what it runs cannot be listed here — and this screen will not
          guess at a module list it cannot read. Applying it saves it as the
          case&rsquo;s profile: it then governs {forever} until it is changed,
          and its module list appears here and in Case settings.
        </p>
        <p>
          If it excludes modules, their results will be absent from this case
          with nothing on any screen to say they never ran.
        </p>
      </div>
    )
  }

  if (governance.kind === 'none') {
    return (
      <div className="ingest-profile-note" role="note" aria-label={label}>
        No analysis profile is in force on this case: nothing is excluded, so{' '}
        {registered == null
          ? 'any module registered in this build may run (the registry could not be read, so the number is not stated here)'
          : `any of the ${formatCount(registered)} modules registered in this build may run`}
        .
      </div>
    )
  }

  const { profile, scope, inherited } = governance
  const held =
    context === 'case'
      ? `It is active on this case: ${forever} runs under it until it is changed in Case settings or in the ingest dialog.`
      : inherited
        ? `It is active on this case now. Naming no profile here does not clear it — ${forever} run under it until it is changed here or in Case settings.`
        : `Choosing it saves it on the case: it governs ${forever} until it is changed here or in Case settings.`

  // The registry did not load. The record still says whether the profile
  // restricts anything — an enabled or disabled list with anything in it does —
  // so that much is stated and the rest is declared unknown.
  if (scope == null) {
    const namesLists =
      profile.enabled_modules.length > 0 || profile.disabled_modules.length > 0
    return (
      <div
        className="warn-note ingest-profile-note"
        role="note"
        aria-label={label}
      >
        <p>
          Profile <strong>{profile.name}</strong> governs this run. The module
          registry could not be read, so which modules it runs and which it
          excludes cannot be listed here.
        </p>
        <p>
          {namesLists
            ? `Its record names ${formatCount(profile.enabled_modules.length)} enabled and ${formatCount(profile.disabled_modules.length)} disabled modules, so it does scope the run.`
            : 'Its record names no enabled and no disabled modules, which in this product means every module runs.'}{' '}
          {held}
        </p>
        {namesLists && <AbsenceSentence />}
        {onlyCurrent}
      </div>
    )
  }

  if (!scope.restricts) {
    return (
      <div className="ingest-profile-note" role="note" aria-label={label}>
        <p>
          Profile <strong>{profile.name}</strong> excludes nothing: any of the{' '}
          {formatCount(scope.registered)} modules registered in this build may
          run. {held}
        </p>
        {scope.unregistered.length > 0 && (
          <p>
            It also names {formatCount(scope.unregistered.length)} module
            {scope.unregistered.length === 1 ? '' : 's'} this build does not
            register (
            <span className="mono">{scope.unregistered.join(', ')}</span>), which
            therefore cannot run.
          </p>
        )}
        {onlyCurrent}
      </div>
    )
  }

  return (
    <div
      className="warn-note ingest-profile-note"
      role="note"
      aria-label={label}
    >
      <p>
        Profile <strong>{profile.name}</strong> lets {population(scope)} run;{' '}
        {formatCount(scope.skips.length)} registered modules are excluded and
        will not run. {held}
      </p>
      <AbsenceSentence />
      {onlyCurrent}
      <p className="ingest-profile-groups-lede">Not run, by category:</p>
      <SkippedCategories skips={scope.skips} />
      {scope.unregistered.length > 0 && (
        <p>
          The profile also names {formatCount(scope.unregistered.length)} module
          {scope.unregistered.length === 1 ? '' : 's'} this build does not
          register (
          <span className="mono">{scope.unregistered.join(', ')}</span>), which
          cannot run either.
        </p>
      )}
    </div>
  )
}
