import { isValidElement, type ReactElement, type ReactNode } from 'react'
import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { describe, expect, it } from 'vitest'

import { AppRoutes, canonicalWorkbenchPath, suggestedCaseRoute } from './routes'
import { CASE_DESTINATIONS } from './commands'

/**
 * Every path declared under `/cases/:caseId`, relative to it.
 *
 * Read out of the route table itself rather than restated here, so that a rail
 * item or a palette command pointing at an address nobody routed fails this
 * suite instead of failing an examiner with "Page not found".
 */
function caseRoutePaths(): string[] {
  const found: string[] = []

  const walk = (node: ReactNode, prefix: string | null) => {
    if (Array.isArray(node)) {
      for (const child of node) walk(child, prefix)
      return
    }
    if (!isValidElement(node)) return
    const props = (node as ReactElement).props as {
      path?: string
      index?: boolean
      children?: ReactNode
    }

    // Outside the case subtree still: descend looking for its root.
    if (prefix === null) {
      if (props.path === '/cases/:caseId') {
        found.push('')
        walk(props.children, '')
        return
      }
      walk(props.children, null)
      return
    }

    if (props.index) {
      found.push(prefix)
      return
    }
    if (typeof props.path === 'string') {
      const here = prefix === '' ? props.path : `${prefix}/${props.path}`
      found.push(here)
      walk(props.children, here)
      return
    }
    walk(props.children, prefix)
  }

  walk(AppRoutes(), null)
  return found
}

describe('AppRoutes', () => {
  it('renders a not-found view for unknown routes', () => {
    render(
      <MemoryRouter initialEntries={['/no/such/page']}>
        <AppRoutes />
      </MemoryRouter>,
    )
    expect(screen.getByText('Page not found')).toBeInTheDocument()
    expect(
      screen.getByRole('link', { name: 'Back to cases' }),
    ).toHaveAttribute('href', '/')
  })

  it('routes every address the rail and the palette offer', () => {
    const routed = new Set(caseRoutePaths())
    for (const dest of CASE_DESTINATIONS) {
      // The query string is view state, not address: `gallery?kind=videos` is
      // routed by `gallery`.
      const path = dest.to.split('?')[0]
      expect(routed.has(path), `'${dest.label}' points at unrouted '${path}'`).toBe(
        true,
      )
    }
  })

  it('keeps a case-scoped catch-all so a stale link does not eject the examiner', () => {
    // Without it, `/cases/<id>/anything-else` falls through to the app-level
    // `*` and the examiner loses the rail, the palette and the navigator -- the
    // three things they need to recover from a link that has moved.
    expect(caseRoutePaths()).toContain('*')
  })
})

describe('canonicalWorkbenchPath', () => {
  const at = (query: string) =>
    canonicalWorkbenchPath('c1', new URLSearchParams(query))

  it('sends every category view to the address that names it', () => {
    expect(at('view=comms')).toBe('/cases/c1/communications')
    expect(at('view=gallery')).toBe('/cases/c1/gallery')
    expect(at('view=geo')).toBe('/cases/c1/geo')
    expect(at('view=execution')).toBe('/cases/c1/execution')
  })

  it('keeps the media kind, which is the only thing separating three views', () => {
    expect(at('view=videos')).toBe('/cases/c1/gallery?kind=videos')
    expect(at('view=audio')).toBe('/cases/c1/gallery?kind=audio')
  })

  it('sends an embedded artifact to the artifact address search results already use', () => {
    expect(at('artifact=a-1')).toBe('/cases/c1/artifacts/a-1')
  })

  it('carries a record type’s provenance scope across, never dropping it', () => {
    // `?source=` is what stops rows recovered from one database being read
    // under the heading of another. A redirect that quietly dropped it would
    // manufacture exactly the misattribution the parameter exists to prevent.
    expect(at('type=SqliteRow&source=s-9')).toBe(
      '/cases/c1/analysis/SqliteRow?source=s-9',
    )
    expect(at('type=SqliteRow')).toBe('/cases/c1/analysis/SqliteRow')
  })

  it('percent-encodes ids so a slash in one cannot invent a path segment', () => {
    expect(at('artifact=a/b')).toBe('/cases/c1/artifacts/a%2Fb')
  })

  it('carries any other parameter through untouched', () => {
    expect(at('view=geo&sel=p-3')).toBe('/cases/c1/geo?sel=p-3')
  })

  it('resolves in the order the workbench itself resolved them', () => {
    // The workbench read view, then artifact, then type. A redirect that chose
    // differently would change what an existing URL shows.
    expect(at('view=geo&artifact=a-1&type=Note')).toBe('/cases/c1/geo')
    expect(at('artifact=a-1&type=Note')).toBe('/cases/c1/artifacts/a-1')
  })

  it('leaves an unselected or unrecognised workbench alone', () => {
    expect(at('')).toBeNull()
    expect(at('view=not-a-view')).toBeNull()
  })

  it('treats an empty parameter as no selection, not as a selection of nothing', () => {
    // `/artifacts/` matches no route; a URL that selected nothing must land on
    // the workbench's own "nothing selected", not on a dead address.
    expect(at('artifact=')).toBeNull()
    expect(at('type=')).toBeNull()
    expect(at('view=&artifact=a-1')).toBe('/cases/c1/artifacts/a-1')
  })
})

describe('suggestedCaseRoute', () => {
  it('names the real address of a memory lens reached without its section', () => {
    // `/cases/<id>/image` was observed live. It is not a broken link and not a
    // missing page: the page is built and routed at `memory/image`.
    expect(suggestedCaseRoute('image')).toEqual({
      to: 'memory/image',
      label: 'Memory → Image',
    })
    expect(suggestedCaseRoute('processes')).toEqual({
      to: 'memory/processes',
      label: 'Memory → Processes',
    })
  })

  it('suggests nothing where the guess would be a coin flip', () => {
    // `system` could mean the memory lens or System Info, and a product whose
    // screens get quoted does not guess between two evidence sources.
    expect(suggestedCaseRoute('system')).toBeNull()
    expect(suggestedCaseRoute('zzz')).toBeNull()
  })
})
