import { useOutletContext } from 'react-router-dom'
import type { MemoryImageSummary } from './api'

/**
 * The selected memory capture, shared from the section shell to every lens.
 *
 * This lives apart from `MemoryLayout` for a mechanical reason worth stating:
 * the router lazy-loads route modules through a helper that requires every
 * export of a route module to be a component. A hook exported alongside the
 * shell would break that contract at the type level, so the seam stays in its
 * own module and the shell exports only the component the router mounts.
 */

/** Everything a lens needs about the capture currently being examined. */
export interface MemoryContext {
  caseId: string
  /** Artifact id of the capture; part of every query key beneath the shell. */
  imageId: string
  image: MemoryImageSummary
  /** Scope key for `useEntityScopedQuery`: case *and* capture. */
  scopeKey: string
}

/**
 * Read the selected capture inside a lens.
 *
 * Throws rather than returning a partial context. A lens that rendered without
 * a capture would query an undefined image id, and an undefined id in a URL is
 * the kind of thing a server can answer with somebody else's rows — an
 * exception here is far cheaper than misattributed evidence on screen.
 */
export function useMemoryContext(): MemoryContext {
  const context = useOutletContext<MemoryContext | null>()
  if (context == null) {
    throw new Error(
      'useMemoryContext must be used inside the memory section shell',
    )
  }
  return context
}
