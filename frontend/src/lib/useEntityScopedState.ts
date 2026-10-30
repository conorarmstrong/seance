import { useCallback, useState } from 'react'

/**
 * Local component state that can only be read back while the entity it was set
 * under is still the one on screen.
 *
 * The recurring defect this exists to eliminate: a page holds a selection, an
 * open modal, a target id or a filter string in a plain `useState`, and the
 * route param that identifies the entity (`:caseId`, `:artifactId`) changes
 * WITHOUT the page unmounting. `useEntityScopedQuery` covers the fetched rows;
 * it does not cover this. The stale local value then drives real work under the
 * new entity: a delete confirmed against case A's hash set id while the chrome
 * reads case B, a hits panel querying case B with case A's set id, a client
 * filter from case A silently emptying case B's table so the examiner concludes
 * the case has no records. Artifact and hash-set UUIDs are per-case, so a
 * carried id is not reliably rejected by the server either — it can hit a real
 * row in the wrong case.
 *
 * Resetting in a `useEffect` keyed on the entity does not close the hole: the
 * render in which the id has already changed happens BEFORE the effect runs, so
 * queries and mutations fired from that render still carry the previous
 * entity's value. Storing the value together with the entity it was set under
 * and resolving it during render removes the window entirely — a stale value is
 * never observable, so there is nothing to reset.
 *
 * `scopeKey` identifies the entity the value belongs to, usually `caseId` or
 * `` `${caseId}/${artifactId}` ``. `initial` is what the value reads as under
 * any other entity; pass a stable reference (a module-level constant, not a
 * fresh object literal) when it is an object or array, since it is returned
 * directly after a scope change and the setter's identity is memoized on it.
 */
export function useEntityScopedState<T>(
  scopeKey: string,
  initial: T,
): [T, (next: T | ((previous: T) => T)) => void] {
  const [held, setHeld] = useState<{ scope: string; value: T }>({
    scope: scopeKey,
    value: initial,
  })

  // Discard the held value the moment the entity changes, rather than merely
  // declining to read it. Keeping it would resurrect the previous entity's
  // value if the examiner navigated back — case A, then case B, then case A
  // again would silently reopen a dialog on an id that may no longer exist.
  //
  // Setting state during render is React's documented way to adjust state when
  // an input changes: the component re-renders immediately, before anything is
  // committed or any child sees the intermediate value, so no effect timing
  // window opens. The guard makes it terminate.
  if (held.scope !== scopeKey) {
    setHeld({ scope: scopeKey, value: initial })
  }

  const value = held.scope === scopeKey ? held.value : initial

  // Memoized on the scope it writes to, which is the only thing it closes over.
  // The identity has to be stable while the entity is unchanged: these setters
  // are handed to `memo`-wrapped rows (the timeline's selection checkboxes, for
  // one), and a fresh function every render would defeat that memoization on
  // tables of hundreds of rows.
  //
  // Memoizing on `scopeKey` — rather than making the setter always read the
  // CURRENT scope through a ref — is deliberate. A callback captured under case
  // A must keep writing to case A: an async handler that settles after the
  // examiner has switched cases then lands its value where nothing reads it,
  // instead of depositing case A's selection into case B.
  const set = useCallback(
    (next: T | ((previous: T) => T)) => {
      setHeld((previous) => {
        // The updater form must see the value for the CURRENT scope, not
        // whatever the previous entity left behind, or a toggle would flip the
        // old value.
        const base = previous.scope === scopeKey ? previous.value : initial
        return {
          scope: scopeKey,
          value:
            typeof next === 'function'
              ? (next as (p: T) => T)(base)
              : next,
        }
      })
    },
    [scopeKey, initial],
  )

  return [value, set]
}
