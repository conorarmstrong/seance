import { createContext, useContext, type ReactNode } from 'react'
import { useProcessingEvents } from '../hooks/useProcessingEvents'

type ProcessingState = ReturnType<typeof useProcessingEvents>

const ProcessingContext = createContext<ProcessingState | null>(null)

/**
 * Just "is this case being processed right now".
 *
 * Kept separate from the full state on purpose: the full value changes on every
 * SSE event (several times a second during ingest), so a page that reads it
 * re-renders at that rate. A boolean only notifies its consumers when it
 * actually flips, which lets a routed page decide whether to poll without
 * paying for the event stream (LIVE-021). Defaults to false so a component
 * rendered outside a provider — as in unit tests — reads "idle" rather than
 * throwing.
 */
const ProcessingActiveContext = createContext<boolean>(false)

// Subscribes to the case's SSE stream once and exposes the processing state via
// context. It is rendered with `children` passed straight through, so when an
// SSE event updates the state, React re-renders only the components that call
// useProcessing (the processing panel and custody strip) -- never the routed
// page in the <Outlet/>, which previously re-rendered on every event (twice a
// second or more during ingest).
export function ProcessingProvider({
  caseId,
  children,
}: {
  caseId: string
  children: ReactNode
}) {
  const processing = useProcessingEvents(caseId)
  return (
    <ProcessingContext.Provider value={processing}>
      <ProcessingActiveContext.Provider value={processing.active}>
        {children}
      </ProcessingActiveContext.Provider>
    </ProcessingContext.Provider>
  )
}

// Read the live processing state. Must be used within a ProcessingProvider.
export function useProcessing(): ProcessingState {
  const ctx = useContext(ProcessingContext)
  if (!ctx) {
    throw new Error('useProcessing must be used within a ProcessingProvider')
  }
  return ctx
}

/**
 * True while this case has work in flight. Safe to call from a routed page:
 * unlike [`useProcessing`], it re-renders the caller only when the flag flips.
 */
export function useProcessingActive(): boolean {
  return useContext(ProcessingActiveContext)
}
