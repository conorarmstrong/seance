import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { http, HttpResponse } from 'msw'
import { MemoryRouter } from 'react-router-dom'
import { describe, expect, it } from 'vitest'
import { server } from '../../test/server'
import { FrameSpy, inputValue } from '../../test/frames'
import { ExecutionPage } from './ExecutionPage'

/** One prefetch row per case; every other execution type answers empty. */
function mockRecords(programByCase: Record<string, string>) {
  server.use(
    http.get('/api/v1/cases/:caseId/records', ({ params, request }) => {
      const type = new URL(request.url).searchParams.get('type')
      const program = programByCase[params.caseId as string]
      const records =
        type === 'PrefetchEntry' && program
          ? [
              {
                id: `art-${program}`,
                parent_id: null,
                artifact_type: 'ParsedRecord',
                metadata: { executable_name: program, run_count: 3 },
              },
            ]
          : []
      return HttpResponse.json({
        records,
        total: records.length,
        page: 1,
        page_size: 100,
        type,
      })
    }),
  )
}

/** What the page showed in one committed frame. */
type Frame = { search: string | null; sourcePressed: string | null }

function snapshot(): Frame {
  const tile = [...document.querySelectorAll('button')].find((b) =>
    /Prefetch/.test(b.textContent ?? ''),
  )
  return {
    search: inputValue('Filter execution events'),
    sourcePressed: tile?.getAttribute('aria-pressed') ?? null,
  }
}

function renderPage(caseId: string) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  })
  const frames: Frame[] = []
  const ui = (id: string) => (
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <ExecutionPage caseId={id} />
        <FrameSpy capture={snapshot} frames={frames} />
      </MemoryRouter>
    </QueryClientProvider>
  )
  const utils = render(ui(caseId))
  return { switchCase: (id: string) => utils.rerender(ui(id)), frames }
}

describe('ExecutionPage case switching (BUG-282)', () => {
  it('clears the source, program and search filters when the case changes', async () => {
    // Same defect class as the comms view: the queries are case-keyed, the
    // cross-filters are not. Case 2 under case 1's program filter is an empty
    // table presented as the full execution picture.
    mockRecords({ 'case-1': 'EVIL.EXE', 'case-2': 'OTHER.EXE' })
    const { switchCase } = renderPage('case-1')
    expect((await screen.findAllByText('EVIL.EXE')).length).toBeGreaterThan(0)

    await userEvent.click(screen.getByRole('button', { name: /Prefetch/ }))
    const search = screen.getByLabelText('Filter execution events')
    await userEvent.type(search, 'EVIL')
    await waitFor(() => expect(search).toHaveValue('EVIL'))
    expect(screen.getByRole('button', { name: /Prefetch/ })).toHaveAttribute(
      'aria-pressed',
      'true',
    )

    switchCase('case-2')

    expect((await screen.findAllByText('OTHER.EXE')).length).toBeGreaterThan(0)
    expect(screen.getByLabelText('Filter execution events')).toHaveValue('')
    expect(screen.getByRole('button', { name: /Prefetch/ })).toHaveAttribute(
      'aria-pressed',
      'false',
    )
  })

  it('never paints a single frame of case 2 through case 1 filters (B2-146)', async () => {
    // A `useEffect` reset runs after the commit it is meant to correct. With
    // case 2's records cached, that commit is a painted frame of case 2's
    // execution evidence filtered by a program from case 1 — the page reads as
    // "this machine ran almost nothing". Only a layout-effect snapshot can
    // observe it, since `rerender` flushes passive effects before returning.
    mockRecords({ 'case-1': 'EVIL.EXE', 'case-2': 'OTHER.EXE' })
    const { switchCase, frames } = renderPage('case-1')
    await screen.findAllByText('EVIL.EXE')

    switchCase('case-2')
    await screen.findAllByText('OTHER.EXE')
    switchCase('case-1')
    await screen.findAllByText('EVIL.EXE')

    await userEvent.click(screen.getByRole('button', { name: /Prefetch/ }))
    const search = screen.getByLabelText('Filter execution events')
    await userEvent.type(search, 'EVIL')
    await waitFor(() => expect(search).toHaveValue('EVIL'))

    frames.length = 0
    switchCase('case-2')

    // A frame that has not drawn the toolbar yet reads as null; what must never
    // appear is case 1's filter over case 2's records.
    //
    // `FrameSpy` observes the DOM, and a `MutationObserver` delivers its records
    // as a microtask, so the sink is still empty on the synchronous line after
    // the switch. Wait for the frames to arrive and then assert on all of them:
    // the sink keeps every frame it saw, so a corrected one landing afterwards
    // cannot hide the offending one. Asserting non-empty first is what stops a
    // harness that recorded nothing from reading as a pass.
    await waitFor(() => expect(frames.length).toBeGreaterThan(0))
    for (const frame of frames) {
      expect(frame.search ?? '').toBe('')
      expect(frame.sourcePressed ?? 'false').toBe('false')
    }
  })
})

/**
 * The standard incompleteness pair on the correlated execution view.
 *
 * A shimcache or amcache entry comes out of a registry hive, and a hive read
 * that hit its cap stamps the pair on what it did produce. `normalizeExecution`
 * keeps only a program name and a time, which is exactly where the difference
 * between "this machine ran these" and "these are the ones we got to" is lost.
 */
describe('ExecutionPage incompleteness', () => {
  function mockOnePrefetch(extra: Record<string, unknown>) {
    server.use(
      http.get('/api/v1/cases/:caseId/records', ({ request }) => {
        const type = new URL(request.url).searchParams.get('type')
        const records =
          type === 'PrefetchEntry'
            ? [
                {
                  id: 'art-1',
                  parent_id: null,
                  artifact_type: 'ParsedRecord',
                  metadata: { executable_name: 'NOTEPAD.EXE', run_count: 3, ...extra },
                },
              ]
            : []
        return HttpResponse.json({
          records,
          total: records.length,
          page: 1,
          page_size: 100,
          type,
        })
      }),
    )
  }

  it('announces a short listing, with its reason, over the correlated table', async () => {
    mockOnePrefetch({
      inventory_incomplete: true,
      inventory_incomplete_reason: 'hive_not_read_in_full',
    })
    renderPage('case-1')

    await screen.findAllByText('NOTEPAD.EXE')
    const notes = await screen.findAllByRole('note')
    const banner = notes.find((n) => /incomplete:/.test(n.textContent ?? ''))
    expect(banner).toBeDefined()
    expect(banner).toHaveTextContent('listing incomplete')
    expect(banner).toHaveTextContent('hive not read in full')
  })

  it('says nothing when every correlated record is whole', async () => {
    mockOnePrefetch({})
    renderPage('case-1')

    await screen.findAllByText('NOTEPAD.EXE')
    expect(
      screen.queryByText(/declares itself incomplete/),
    ).not.toBeInTheDocument()
  })
})
