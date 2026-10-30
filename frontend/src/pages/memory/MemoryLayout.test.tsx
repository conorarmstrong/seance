import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { http, HttpResponse } from 'msw'
import { Route, useSearchParams } from 'react-router-dom'
import { describe, expect, it } from 'vitest'
import { server } from '../../test/server'
import { CASE_ID, IMAGE_ID, image, mockImages, renderMemory } from './testing'
import { paramsForImage } from './MemoryLayout'

function Probe() {
  const [params] = useSearchParams()
  return (
    <div>
      lens content
      {/* What a lens beneath the shell actually reads. `pid` names a process
          inside ONE capture, so it must not be here after a capture change. */}
      <span data-testid="lens-pid">{params.get('pid') ?? 'none'}</span>
      {/* A filter over whatever capture is on screen, not a capture-scoped
          selection: it must survive the switch. */}
      <span data-testid="lens-state">{params.get('state') ?? 'none'}</span>
    </div>
  )
}

const ROUTES = <Route index element={<Probe />} />

describe('MemoryLayout', () => {
  it('says the case holds no capture rather than rendering empty lenses', async () => {
    server.use(
      http.get(`/api/v1/cases/${CASE_ID}/memory/images`, () =>
        HttpResponse.json({
          case_id: CASE_ID,
          images: [],
          image_count: 0,
          images_truncated: false,
          summaries_complete: true,
        }),
      ),
    )
    renderMemory(`/cases/${CASE_ID}/memory`, ROUTES)
    expect(
      await screen.findByText('No memory capture in this case'),
    ).toBeInTheDocument()
    expect(screen.queryByText('lens content')).not.toBeInTheDocument()
  })

  it('names the credential lens for what it holds: stores, not credentials (B3-M01)', async () => {
    // The tab label is the product's first claim about what is behind it. The
    // lens lists which credential stores were resident and what is named in
    // them; it decrypts nothing, so nothing behind it is a credential an
    // examiner could quote.
    mockImages()
    renderMemory(`/cases/${CASE_ID}/memory?image=${IMAGE_ID}`, ROUTES)

    expect(
      await screen.findByRole('link', { name: 'Credential stores' }),
    ).toBeInTheDocument()
    expect(
      screen.queryByRole('link', { name: 'Credentials' }),
    ).not.toBeInTheDocument()
  })

  it('distinguishes a failure to list captures from a case with none', async () => {
    server.use(
      http.get(`/api/v1/cases/${CASE_ID}/memory/images`, () =>
        HttpResponse.json(
          { error: { code: 'BOOM', message: 'no' } },
          { status: 500 },
        ),
      ),
    )
    renderMemory(`/cases/${CASE_ID}/memory`, ROUTES)
    expect(await screen.findByText(/could not be listed/i)).toBeInTheDocument()
    expect(
      screen.queryByText('No memory capture in this case'),
    ).not.toBeInTheDocument()
  })

  it('selects the only capture and renders the lens beneath it', async () => {
    mockImages()
    renderMemory(`/cases/${CASE_ID}/memory`, ROUTES)
    expect(await screen.findByText('lens content')).toBeInTheDocument()
    expect(screen.getByText('WIN10-DESK.mem')).toBeInTheDocument()
  })

  it('refuses a capture id this case does not contain instead of falling back to another capture', async () => {
    mockImages()
    renderMemory(`/cases/${CASE_ID}/memory?image=from-another-case`, ROUTES)
    expect(
      await screen.findByText(/That capture is not in this case/i),
    ).toBeInTheDocument()
    expect(screen.queryByText('lens content')).not.toBeInTheDocument()
  })

  it('offers a picker for a second capture and threads it into every lens link', async () => {
    mockImages([image(), image({ image_id: 'image-2', name: 'SERVER.raw' })])
    renderMemory(`/cases/${CASE_ID}/memory`, ROUTES)
    await screen.findByText('lens content')

    expect(screen.getByRole('link', { name: 'Processes' })).toHaveAttribute(
      'href',
      `/cases/${CASE_ID}/memory/processes?image=${IMAGE_ID}`,
    )

    await userEvent.selectOptions(
      screen.getByRole('combobox', { name: /capture/i }),
      'image-2',
    )
    await waitFor(() =>
      expect(screen.getByRole('link', { name: 'Processes' })).toHaveAttribute(
        'href',
        `/cases/${CASE_ID}/memory/processes?image=image-2`,
      ),
    )
  })

  it('drops a selected pid when the capture changes, so one machine s process is not shown under another', async () => {
    mockImages([image(), image({ image_id: 'image-2', name: 'SERVER.raw' })])
    renderMemory(
      `/cases/${CASE_ID}/memory?image=${IMAGE_ID}&pid=123&state=LISTENING`,
      ROUTES,
    )
    await screen.findByText('lens content')
    expect(screen.getByTestId('lens-pid')).toHaveTextContent('123')

    await userEvent.selectOptions(
      screen.getByRole('combobox', { name: /capture/i }),
      'image-2',
    )

    // PIDs recycle: capture 2 very likely also has a process 123, so carrying
    // the parameter over would show a DIFFERENT machine's process under an
    // address that reads as a deliberate selection.
    await waitFor(() =>
      expect(screen.getByTestId('lens-pid')).toHaveTextContent('none'),
    )
    // A filter over "whatever capture is on screen" is not capture-scoped and
    // must survive, or every switch would silently widen the view.
    expect(screen.getByTestId('lens-state')).toHaveTextContent('LISTENING')
  })

  it('drops a carried pid when recovering from a capture id this case does not hold', async () => {
    mockImages([image()])
    renderMemory(
      `/cases/${CASE_ID}/memory?image=from-another-case&pid=4242`,
      ROUTES,
    )
    await screen.findByText(/That capture is not in this case/i)

    await userEvent.click(
      screen.getByRole('button', { name: /Open WIN10-DESK\.mem/ }),
    )

    await screen.findByText('lens content')
    expect(screen.getByTestId('lens-pid')).toHaveTextContent('none')
  })

  it('states whether the capture has been analysed at all', async () => {
    mockImages([
      image({
        analysis_state: 'not_analysed',
        analysis_state_meaning:
          'No memory analysis has run against this image.',
        profile: null,
      }),
    ])
    renderMemory(`/cases/${CASE_ID}/memory`, ROUTES)
    await screen.findByText('lens content')
    expect(screen.getByText(/not analysed/)).toBeInTheDocument()
  })
})

/**
 * The capture-scoped param list, pinned directly.
 *
 * `paramsForImage` was exported "for the test that pins this behaviour" and no
 * such test existed. The list also named `focus` and `at`, which no memory lens
 * reads or writes — the params actually in use are image, pid, severity and
 * state — so it claimed to protect deep links that do not exist and could not
 * be checked against the pages it named.
 */
describe('paramsForImage', () => {
  const forImage = (query: string, imageId = 'capture-b') =>
    Object.fromEntries(paramsForImage(new URLSearchParams(query), imageId))

  it('names the new capture', () => {
    expect(forImage('image=capture-a').image).toBe('capture-b')
  })

  it('drops the process selection, which names a process inside one capture', () => {
    // Process ids are small integers every machine reuses, so ?image=B&pid=123
    // resolves to a different machine's process under an address that reads as
    // a deliberate selection.
    expect(forImage('image=capture-a&pid=123')).not.toHaveProperty('pid')
  })

  it('keeps every param that is not capture-scoped', () => {
    // `pid` is the whole list. Anything else is a filter over whatever capture
    // is on screen, and stripping params no lens reads is a claim the code
    // cannot keep.
    expect(forImage('image=capture-a&severity=high&state=LISTENING&at=0x10')).toEqual({
      image: 'capture-b',
      severity: 'high',
      state: 'LISTENING',
      at: '0x10',
    })
  })
})

describe('choosing between captures of the same file (LIVE-016)', () => {
  // Re-running analysis on one capture leaves the case holding two MemoryImage
  // records for it. They are built from the format, so both read
  // "Memory image (windows_hibernation)" — and the shell opened the FIRST,
  // which is the failed attempt. An examiner who supplies the missing symbols,
  // re-runs, and comes back is shown the failure screen and concludes the
  // re-run did nothing.
  const FAILED = image({
    image_id: 'cap-failed',
    name: 'Memory image (windows_hibernation)',
    analysis_state: 'discovery_failed',
    architecture: null,
    profile: null,
  })
  const ANALYSED = image({
    image_id: 'cap-analysed',
    name: 'Memory image (windows_hibernation)',
    analysis_state: 'analysed',
  })

  it('opens the analysed capture, not the first one listed', async () => {
    mockImages([FAILED, ANALYSED])
    renderMemory(`/cases/${CASE_ID}/memory`, ROUTES)

    await screen.findByText('lens content')
    const select = screen.getByRole('combobox') as HTMLSelectElement
    expect(select.value).toBe('cap-analysed')
  })

  it('distinguishes captures that share a name', async () => {
    mockImages([FAILED, ANALYSED])
    renderMemory(`/cases/${CASE_ID}/memory`, ROUTES)

    await screen.findByText('lens content')
    const labels = Array.from(
      screen.getByRole('combobox').querySelectorAll('option'),
    ).map((o) => o.textContent?.trim())

    expect(new Set(labels).size).toBe(labels.length)
    expect(labels.some((l) => /analysed/i.test(l ?? ''))).toBe(true)
    expect(
      labels.some((l) => /profile not established/i.test(l ?? '')),
    ).toBe(true)
  })

  // An explicit choice in the URL still wins over the preference.
  it('honours a capture named in the address', async () => {
    mockImages([FAILED, ANALYSED])
    renderMemory(`/cases/${CASE_ID}/memory?image=cap-failed`, ROUTES)

    await screen.findByText('lens content')
    expect((screen.getByRole('combobox') as HTMLSelectElement).value).toBe(
      'cap-failed',
    )
  })
})


describe('capture labels are unique whatever the server sends (review)', () => {
  // Disambiguating by analysis state alone is not enough: two runs that BOTH
  // succeed share a name and a state, so both options read identically and the
  // picker is as ambiguous as before the fix.
  it('tells two captures apart when name and state both match', async () => {
    mockImages([
      image({ image_id: 'run-1', name: 'Memory image (windows_hibernation)' }),
      image({ image_id: 'run-2', name: 'Memory image (windows_hibernation)' }),
    ])
    renderMemory(`/cases/${CASE_ID}/memory`, ROUTES)

    await screen.findByText('lens content')
    const labels = Array.from(
      screen.getByRole('combobox').querySelectorAll('option'),
    ).map((o) => o.textContent?.trim())
    expect(new Set(labels).size).toBe(labels.length)
  })

  // An unrecognised state must not render the literal word "undefined" into a
  // label an examiner reads as a fact about the capture.
  it('never renders "undefined" for a state it does not recognise', async () => {
    mockImages([
      image({
        image_id: 'a',
        name: 'Memory image (windows_hibernation)',
        analysis_state: 'something_new' as never,
      }),
      image({ image_id: 'b', name: 'Memory image (windows_hibernation)' }),
    ])
    renderMemory(`/cases/${CASE_ID}/memory`, ROUTES)

    await screen.findByText('lens content')
    const labels = Array.from(
      screen.getByRole('combobox').querySelectorAll('option'),
    ).map((o) => o.textContent ?? '')
    expect(labels.join(' | ')).not.toMatch(/undefined/)
  })
})
