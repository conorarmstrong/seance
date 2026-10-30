import { createContext, useCallback, useContext, useMemo, useState, type ReactNode } from 'react'
import { PivotDrawer } from '../components/PivotDrawer'

/**
 * App-wide access to the universal pivot. Any surface that shows a value —
 * the Entities list, a search result, a record viewer cell, the artifact
 * inspector, the timeline — calls `openPivot(value)` to open one shared
 * drawer showing every artifact that references it, grouped by record kind.
 *
 * One drawer instance lives at the case-shell level so opening a pivot never
 * depends on where in the tree the value was rendered, and closing one
 * pivot before opening the next is automatic.
 */
export interface PivotApi {
  openPivot: (value: string) => void
}

/**
 * The pivot context itself.
 *
 * Exported so a test can provide an `openPivot` it can observe, and assert
 * that a surface really triggers the pivot, without mounting the drawer and
 * the search request behind it. Production code uses [`PivotProvider`] and
 * [`usePivot`] and has no reason to touch this.
 */
export const PivotCtx = createContext<PivotApi | null>(null)

export function PivotProvider({
  caseId,
  children,
}: {
  caseId: string
  children: ReactNode
}) {
  const [value, setValue] = useState<string | null>(null)
  const openPivot = useCallback((v: string) => {
    const trimmed = v.trim()
    if (trimmed !== '') setValue(trimmed)
  }, [])
  const api = useMemo(() => ({ openPivot }), [openPivot])

  return (
    <PivotCtx.Provider value={api}>
      {children}
      {value !== null && (
        <PivotDrawer
          caseId={caseId}
          value={value}
          onClose={() => setValue(null)}
        />
      )}
    </PivotCtx.Provider>
  )
}

/**
 * Open the universal pivot on a value. Returns `openPivot`; safe to call from
 * any component under a case route. Outside a `PivotProvider` it is a no-op
 * with a console warning rather than a crash, so a viewer rendered in
 * isolation (a test, a storybook) still mounts.
 */
export function usePivot(): PivotApi {
  const ctx = useContext(PivotCtx)
  if (ctx) return ctx
  return {
    openPivot: () =>
      console.warn('usePivot() called outside a PivotProvider; ignoring'),
  }
}
