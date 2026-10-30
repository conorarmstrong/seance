import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { delay, http, HttpResponse } from 'msw'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import type { FileBrowserResponse, IngestionProfile } from '../../api/types'
import {
  clearIngestTracking,
  isTrackedArtifact,
  isTrackedSource,
} from '../../hooks/processing'
import { ToastProvider } from '../toast/ToastProvider'
import { server } from '../../test/server'
import {
  activeRoot,
  IngestModal,
  isUnderRoot,
  memoryDeclaration,
  undeclaredMemoryCaptures,
} from './IngestModal'

const BROWSE: FileBrowserResponse = {
  current_path: '/evidence',
  parent_path: '/',
  entries: [
    {
      name: 'disk.dd',
      path: '/evidence/disk.dd',
      is_dir: false,
      size: 4096,
      modified: null,
    },
  ],
}

function mockApi() {
  server.use(
    http.get('/api/v1/filesystem/browse', () => HttpResponse.json(BROWSE)),
    http.get('/api/v1/cases/case-1/profiles', () => HttpResponse.json([])),
    // The modal reads the case's ACTIVE profile and the build's module registry
    // so it can say what this ingest will and will not run.
    http.get('/api/v1/cases/case-1/profiles/active', () =>
      HttpResponse.json(null),
    ),
    http.get('/api/v1/modules', () => HttpResponse.json([])),
  )
}

function renderModal(onClose = vi.fn()) {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  })
  render(
    <QueryClientProvider client={queryClient}>
      <ToastProvider>
        <IngestModal caseId="case-1" onClose={onClose} />
      </ToastProvider>
    </QueryClientProvider>,
  )
  return onClose
}

beforeEach(() => {
  sessionStorage.clear()
  mockApi()
})

afterEach(() => {
  clearIngestTracking('case-1')
})

describe('IngestModal case attribution (B5-031)', () => {
  it('refreshes the case the evidence went to, not the one on screen', async () => {
    // `onSuccess` runs in the latest render's closure. If the modal survives a
    // case change mid-submit, reading `caseId` there refreshed the wrong case's
    // tree and stats, leaving the case that received the evidence showing a
    // tree without it.
    let release: (() => void) | null = null
    const inFlight = new Promise<void>((resolve) => {
      release = resolve
    })
    server.use(
      http.post('/api/v1/cases/case-1/ingest', async () => {
        await inFlight
        return HttpResponse.json({ artifact_id: 'art-1', status: 'hashing' })
      }),
      http.get('/api/v1/cases/case-2/profiles', () => HttpResponse.json([])),
      http.get('/api/v1/cases/case-2/profiles/active', () =>
        HttpResponse.json(null),
      ),
    )

    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    })
    const invalidated: unknown[][] = []
    const realInvalidate = queryClient.invalidateQueries.bind(queryClient)
    queryClient.invalidateQueries = ((filters?: { queryKey?: unknown[] }) => {
      if (filters?.queryKey) invalidated.push(filters.queryKey)
      return realInvalidate(filters as never)
    }) as typeof queryClient.invalidateQueries

    const ui = (caseId: string) => (
      <QueryClientProvider client={queryClient}>
        <ToastProvider>
          <IngestModal caseId={caseId} onClose={vi.fn()} />
        </ToastProvider>
      </QueryClientProvider>
    )
    const { rerender } = render(ui('case-1'))

    const user = userEvent.setup()
    await user.click(await screen.findByText('disk.dd'))
    await user.click(screen.getByRole('button', { name: /Ingest 1 source/ }))

    rerender(ui('case-2'))
    release!()

    await waitFor(() => expect(invalidated).toContainEqual(['tree', 'case-1']))
    expect(invalidated).toContainEqual(['case', 'case-1'])
    expect(invalidated).not.toContainEqual(['tree', 'case-2'])
    expect(invalidated).not.toContainEqual(['case', 'case-2'])
  })
})

describe('IngestModal', () => {
  it('submits, closes immediately, and registers the ingest for SSE matching', async () => {
    server.use(
      http.post('/api/v1/cases/case-1/ingest', () =>
        HttpResponse.json({ artifact_id: 'art-1', status: 'hashing' }),
      ),
    )
    const user = userEvent.setup()
    const onClose = renderModal()

    await user.click(await screen.findByText('disk.dd'))
    await user.click(screen.getByRole('button', { name: /Ingest 1 source/ }))

    expect(
      await screen.findByText('Evidence queued — hashing started'),
    ).toBeInTheDocument()
    expect(onClose).toHaveBeenCalled()
    expect(isTrackedArtifact('case-1', 'art-1')).toBe(true)
    expect(isTrackedSource('case-1', '/evidence/disk.dd')).toBe(true)
  })

  it('does not show the previous directory while a new path loads (BUG-202)', async () => {
    server.use(
      http.get('/api/v1/filesystem/browse', async ({ request }) => {
        const p = new URL(request.url).searchParams.get('path')
        if (p === '/evidence/sub') {
          // Freeze the new path's listing so we can observe the load window.
          await delay('infinite')
        }
        return HttpResponse.json({
          current_path: '/evidence',
          parent_path: '/',
          entries: [
            {
              name: 'sub',
              path: '/evidence/sub',
              is_dir: true,
              size: 0,
              modified: null,
            },
            {
              name: 'old-file.dd',
              path: '/evidence/old-file.dd',
              is_dir: false,
              size: 4096,
              modified: null,
            },
          ],
        })
      }),
    )
    const user = userEvent.setup()
    renderModal()

    // Initial directory is shown.
    expect(await screen.findByText('old-file.dd')).toBeInTheDocument()

    // Descend into a subdirectory whose listing never resolves.
    await user.click(screen.getByText('sub'))

    // The previous directory's file must not linger as a selectable entry
    // (clicking it would queue a file from the wrong path).
    await waitFor(() =>
      expect(screen.queryByText('old-file.dd')).not.toBeInTheDocument(),
    )
    expect(screen.getByText('Reading directory…')).toBeInTheDocument()
  })

  it('keeps the modal open and toasts on submit failure', async () => {
    server.use(
      http.post('/api/v1/cases/case-1/ingest', () =>
        HttpResponse.json(
          { error: { code: 'INTERNAL', message: 'boom' } },
          { status: 500 },
        ),
      ),
    )
    const user = userEvent.setup()
    const onClose = renderModal()

    await user.click(await screen.findByText('disk.dd'))
    await user.click(screen.getByRole('button', { name: /Ingest 1 source/ }))

    // The toast now surfaces the server's reason (e.g. the unsupported-format gate).
    expect(await screen.findByText('disk.dd: boom')).toBeInTheDocument()
    expect(onClose).not.toHaveBeenCalled()
    expect(isTrackedSource('case-1', '/evidence/disk.dd')).toBe(false)
  })
})

describe('memory-capture declaration (LIVE-002)', () => {
  /** Capture the JSON body of every ingest POST the modal sends. */
  function captureIngests(): Record<string, unknown>[] {
    const bodies: Record<string, unknown>[] = []
    server.use(
      http.post('/api/v1/cases/case-1/ingest', async ({ request }) => {
        bodies.push((await request.json()) as Record<string, unknown>)
        return HttpResponse.json({ artifact_id: 'art-1', status: 'hashing' })
      }),
    )
    return bodies
  }

  const toggle = () =>
    screen.getByRole('checkbox', {
      name: /declare this source to be a capture of physical memory/i,
    })

  it('sends nothing about memory unless the examiner declares it', async () => {
    // The default must stay silent: a declaration the examiner did not make is
    // an assertion put in their name.
    const bodies = captureIngests()
    const user = userEvent.setup()
    renderModal()

    await user.click(await screen.findByText('disk.dd'))
    await user.click(screen.getByRole('button', { name: /Ingest 1 source/ }))

    await waitFor(() => expect(bodies).toHaveLength(1))
    expect(bodies[0]).not.toHaveProperty('memory_image')
    expect(bodies[0]).not.toHaveProperty('memory_image_format')
  })

  it('declares a raw capture with the flag, not with a format name', async () => {
    // Without this key the memory pipeline never claims a headerless dump and
    // every memory stage reports did_not_run. `memory_image: true` says "this
    // is memory"; it deliberately does NOT claim a format, because a raw dump
    // has no header that could confirm or contradict one.
    const bodies = captureIngests()
    const user = userEvent.setup()
    renderModal()

    await user.click(await screen.findByText('disk.dd'))
    await user.click(toggle())
    await user.click(screen.getByRole('button', { name: /Ingest 1 source/ }))

    await waitFor(() => expect(bodies).toHaveLength(1))
    expect(bodies[0].memory_image).toBe(true)
    expect(bodies[0]).not.toHaveProperty('memory_image_format')
    // A declared capture must be ingested as raw evidence, or the memory module
    // never subscribes to it and the declaration does nothing.
    expect(bodies[0].artifact_type).toBe('RawEvidence')
  })

  it('sends a named format as a format claim, without the raw flag', async () => {
    const bodies = captureIngests()
    const user = userEvent.setup()
    renderModal()

    await user.click(await screen.findByText('disk.dd'))
    await user.click(toggle())
    await user.selectOptions(
      screen.getByRole('combobox', { name: /Declared format/i }),
      'lime',
    )
    await user.click(screen.getByRole('button', { name: /Ingest 1 source/ }))

    await waitFor(() => expect(bodies).toHaveLength(1))
    expect(bodies[0].memory_image_format).toBe('lime')
    expect(bodies[0]).not.toHaveProperty('memory_image')
  })

  it('offers only declarations the analysis can actually read', async () => {
    // Every name the memory analysis's parse_format_name() accepts
    // (DECLARABLE_FORMAT_NAMES in seance_memory/src/format.rs, mirrored by
    // MEMORY_FORMAT_NAMES in seance_api/src/lib.rs). A name outside this set is
    // dropped in silence: the ingest succeeds, no memory record is emitted, and
    // every memory stage reports did_not_run with nothing on the record.
    // Offering one in the picker is a control that does nothing and says
    // nothing — "hibernation" was exactly that until the analysis learned the
    // name.
    const PARSEABLE = new Set([
      'raw',
      'dd',
      'lime-raw',
      'padded',
      'windows_crashdump_32',
      'windows_crash_dump32',
      'crash32',
      'pagedump',
      'windows_crashdump_64',
      'windows_crash_dump64',
      'crash64',
      'crash',
      'pagedu64',
      'dmp',
      'lime',
      'avml',
      'elf_core',
      'elf',
      'elfcore',
      'core',
      'qemu_savevm',
      'qemu',
      'savevm',
      'vmware_snapshot',
      'vmware',
      'vmss',
      'vmsn',
      'vmem',
      'windows_hibernation',
      'hibernation',
      'hiberfil',
      'hiberfil.sys',
      'hiber',
    ])
    const user = userEvent.setup()
    renderModal()
    await user.click(await screen.findByText('disk.dd'))
    await user.click(toggle())

    const select = screen.getByRole('combobox', { name: /Declared format/i })
    const options = within(select).getAllByRole('option') as HTMLOptionElement[]
    expect(options.length).toBeGreaterThan(1)
    for (const option of options) {
      expect(PARSEABLE, `offered format "${option.value}"`).toContain(option.value)
    }
  })

  it('maps the two declarations to the two different assertions', () => {
    expect(memoryDeclaration(false, 'raw')).toEqual({})
    expect(memoryDeclaration(false, 'lime')).toEqual({})
    expect(memoryDeclaration(true, 'raw')).toEqual({ memory_image: true })
    expect(memoryDeclaration(true, 'crash64')).toEqual({
      memory_image_format: 'crash64',
    })
  })

  it('offers hibernation, and says what declaring it gets you', async () => {
    // The name is parsed (DECLARABLE_FORMAT_NAMES), honoured, and its pages are
    // reconstructed into a memory image. The form says so, and names the honest
    // limits (Xpress-Huffman blocks and older layouts become stated gaps).
    const bodies = captureIngests()
    const user = userEvent.setup()
    renderModal()

    await user.click(await screen.findByText('disk.dd'))
    await user.click(toggle())
    await user.selectOptions(
      screen.getByRole('combobox', { name: /Declared format/i }),
      'hibernation',
    )

    const caveat = screen.getByText(/A hibernation file is identified/i)
    expect(caveat).toHaveTextContent(/reconstructed/i)
    expect(caveat).toHaveTextContent(/Xpress-Huffman/i)

    await user.click(screen.getByRole('button', { name: /Ingest 1 source/ }))
    await waitFor(() => expect(bodies).toHaveLength(1))
    expect(bodies[0].memory_image_format).toBe('hibernation')
    expect(bodies[0]).not.toHaveProperty('memory_image')
  })

  it('warns that the declaration is an assertion the evidence cannot check', async () => {
    const user = userEvent.setup()
    renderModal()
    await user.click(await screen.findByText('disk.dd'))
    await user.click(toggle())

    const warning = screen.getByText(/This is your assertion about the evidence/i)
    expect(warning).toHaveTextContent(/no header/i)
    expect(warning).toHaveTextContent(/the analysis will fail or be wrong/i)
    expect(warning).toHaveTextContent(/identified automatically and need no declaration/i)
  })

  it('does not apply one file’s declaration to a whole batch', async () => {
    // The declaration names a file. Silently spreading it across a multi-select
    // would assert that every source is memory.
    const bodies = captureIngests()
    server.use(
      http.get('/api/v1/filesystem/browse', () =>
        HttpResponse.json({
          ...BROWSE,
          entries: [
            ...BROWSE.entries,
            {
              name: 'ram.raw',
              path: '/evidence/ram.raw',
              is_dir: false,
              size: 8192,
              modified: null,
            },
          ],
        }),
      ),
    )
    const user = userEvent.setup()
    renderModal()

    await user.click(await screen.findByText('ram.raw'))
    await user.click(toggle())
    await user.click(screen.getByText('disk.dd'))

    // The examiner is told the declaration is not being sent, rather than it
    // quietly applying to both files or quietly vanishing.
    expect(
      screen.getByText(/2 sources are\s+selected, so it will not be sent/i),
    ).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: /Ingest 2 sources/ }))
    await waitFor(() => expect(bodies).toHaveLength(2))
    for (const body of bodies) {
      expect(body).not.toHaveProperty('memory_image')
      expect(body).not.toHaveProperty('memory_image_format')
    }
  })
})

describe('undeclared memory capture (MEM-014)', () => {
  /** A directory holding a headerless capture beside an ordinary disk image. */
  function browseWithCapture() {
    server.use(
      http.get('/api/v1/filesystem/browse', () =>
        HttpResponse.json({
          ...BROWSE,
          entries: [
            ...BROWSE.entries,
            {
              name: 'physmem.mem',
              path: '/evidence/physmem.mem',
              is_dir: false,
              size: 8192,
              modified: null,
            },
          ],
        }),
      ),
    )
  }

  const hint = () =>
    screen.queryByRole('note', { name: /undeclared memory capture/i })

  it('asks about a source named like a headerless capture', async () => {
    // The pipeline refuses to guess, and it is right to: a name is not
    // evidence. But the refusal was silent — no memory record, no warning, no
    // processing-log row — so the capture read as a machine that was running
    // nothing. seance_memory's own hint goes to the run log, which an examiner
    // never sees; the moment of ingest is where the question gets answered.
    browseWithCapture()
    const user = userEvent.setup()
    renderModal()

    await user.click(await screen.findByText('physmem.mem'))
    const note = hint()
    expect(note).not.toBeNull()
    expect(note).toHaveTextContent('physmem.mem')
    expect(note).toHaveTextContent(/produces no memory record at all/i)
    expect(note).toHaveTextContent(/tick the box above/i)
  })

  it('stays quiet for an ordinary disk image, and once the declaration is made', async () => {
    // A prompt that fires on every case is a prompt nobody reads, and one that
    // survives the declaration it asked for is worse: it says the examiner did
    // not do the thing they just did.
    browseWithCapture()
    const user = userEvent.setup()
    renderModal()

    await user.click(await screen.findByText('disk.dd'))
    expect(hint()).toBeNull()

    await user.click(screen.getByText('physmem.mem'))
    expect(hint()).not.toBeNull()

    await user.click(
      screen.getByRole('checkbox', {
        name: /declare this source to be a capture of physical memory/i,
      }),
    )
    expect(hint()).toBeNull()
  })

  it('recognises only the headerless memory suffixes, whatever their case', () => {
    // Mirrors HEADERLESS_MEMORY_SUFFIXES in seance_memory/src/module.rs.
    // `.raw`, `.dd`, `.bin` and `.img` are ordinary disk-image extensions and
    // must not trigger it, or the prompt appears in every case and is ignored
    // in the one case it matters.
    expect(
      undeclaredMemoryCaptures([
        '/evidence/physmem.mem',
        '/evidence/vm/Windows 10.vmem',
        'C:\\Evidence\\CAPTURE.RAM',
        '/evidence/disk.dd',
        '/evidence/ram.raw',
        '/evidence/card.img',
        '/evidence/dump.bin',
        '/evidence/notes.txt',
      ]),
    ).toEqual([
      '/evidence/physmem.mem',
      '/evidence/vm/Windows 10.vmem',
      'C:\\Evidence\\CAPTURE.RAM',
    ])
  })
})

describe('evidence-root matching (BUG-264)', () => {
  it('requires a path boundary, not a text prefix', () => {
    expect(isUnderRoot('/data2/case', '/data')).toBe(false)
    expect(isUnderRoot('/database', '/data')).toBe(false)
    expect(isUnderRoot('/data/case', '/data')).toBe(true)
    expect(isUnderRoot('/data', '/data')).toBe(true)
    // A trailing separator on the configured root is not a mismatch.
    expect(isUnderRoot('/data/case', '/data/')).toBe(true)
    // Windows-style roots and separators.
    expect(isUnderRoot('C:\\Evidence\\case', 'C:\\Evidence')).toBe(true)
    expect(isUnderRoot('C:\\Evidence2\\case', 'C:\\Evidence')).toBe(false)
  })

  it('picks the most specific root containing the path', () => {
    const roots = ['/data', '/data2', '/data/nested']
    expect(activeRoot(roots, '/data2/img.dd')).toBe('/data2')
    expect(activeRoot(roots, '/data/nested/img.dd')).toBe('/data/nested')
    expect(activeRoot(roots, '/data/img.dd')).toBe('/data')
    expect(activeRoot(roots, '/elsewhere/img.dd')).toBeUndefined()
  })
})

describe('selecting a directory as a source (LIVE-013)', () => {
  const WITH_DIR: FileBrowserResponse = {
    current_path: '/evidence',
    parent_path: '/',
    entries: [
      {
        name: 'iphone_backup',
        path: '/evidence/iphone_backup',
        is_dir: true,
        size: 0,
        modified: null,
      },
      {
        name: 'disk.dd',
        path: '/evidence/disk.dd',
        is_dir: false,
        size: 4096,
        modified: null,
      },
    ],
  }

  beforeEach(() => {
    server.use(
      http.get('/api/v1/filesystem/browse', () => HttpResponse.json(WITH_DIR)),
    )
  })

  // An iOS backup, a logical file-set acquisition and an extracted evidence
  // folder are all directories. The parser that reads them takes the directory
  // (plugin.mobile.ios_backup joins "Manifest.db" onto the path it is given),
  // so a browser that can only tick files cannot reach any of them.
  it('offers a select control on a directory row', async () => {
    const user = userEvent.setup()
    renderModal()

    const select = await screen.findByRole('button', {
      name: /Select iphone_backup/i,
    })
    await user.click(select)

    expect(
      screen.getByRole('button', { name: /Ingest 1 source/ }),
    ).toBeInTheDocument()
  })

  it('sends the directory path as the source', async () => {
    let body: unknown
    server.use(
      http.post('/api/v1/cases/case-1/ingest', async ({ request }) => {
        body = await request.json()
        return HttpResponse.json({ artifact_id: 'a1', status: 'queued' })
      }),
    )
    const user = userEvent.setup()
    renderModal()

    await user.click(
      await screen.findByRole('button', { name: /Select iphone_backup/i }),
    )
    await user.click(screen.getByRole('button', { name: /Ingest 1 source/ }))

    await waitFor(() =>
      expect(body).toMatchObject({ path: '/evidence/iphone_backup' }),
    )
  })

  // Selecting must not cost the examiner the ability to look inside first:
  // clicking the name still descends, and descending selects nothing.
  it('still descends when the directory name is clicked', async () => {
    let asked: string | null = null
    server.use(
      http.get('/api/v1/filesystem/browse', ({ request }) => {
        asked = new URL(request.url).searchParams.get('path')
        return HttpResponse.json(WITH_DIR)
      }),
    )
    const user = userEvent.setup()
    renderModal()

    await user.click(await screen.findByText('iphone_backup'))

    await waitFor(() => expect(asked).toBe('/evidence/iphone_backup'))
    expect(
      screen.queryByRole('button', { name: /Ingest 1 source/ }),
    ).not.toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// Profile disclosure
// ---------------------------------------------------------------------------

const MODULES = [
  'plugin.ntfs.mft_parser',
  'plugin.windows.registry_parser',
  'plugin.browsers.history_parser',
  'plugin.messaging.whatsapp',
  'plugin.email.parser',
  'plugin.mobile.ios_backup',
].map((id) => ({
  id,
  version: '1.0.0',
  subscribes_to: ['FileEntry'],
  execution_mode: 'Automatic',
}))

const TRIAGE_RECORD: IngestionProfile = {
  id: 'prof-triage',
  case_id: 'case-1',
  name: 'triage',
  description: 'Fast triage mode - essential artifacts only',
  enabled_modules: ['plugin.ntfs.mft_parser', 'plugin.windows.registry_parser'],
  disabled_modules: [],
  is_active: true,
  created_at: 1700000000,
}

/** Serve the module registry and the profile state a case would hold. */
function mockProfiles({
  profiles = [] as IngestionProfile[],
  active = null as IngestionProfile | null,
  modules = MODULES,
} = {}) {
  server.use(
    http.get('/api/v1/cases/case-1/profiles', () => HttpResponse.json(profiles)),
    http.get('/api/v1/cases/case-1/profiles/active', () =>
      HttpResponse.json(active),
    ),
    http.get('/api/v1/modules', () => HttpResponse.json(modules)),
  )
}

describe('analysis profile disclosure', () => {
  it('names the profile the case is already running under instead of claiming all modules', async () => {
    // The sticky half of the defect: the server only touches the active profile
    // when the request names one, so an ingest that names none runs under
    // whatever a previous ingest activated. The old empty option read "Default
    // (all modules)", which was then a false statement about this ingest.
    mockProfiles({ profiles: [TRIAGE_RECORD], active: TRIAGE_RECORD })
    renderModal()

    const select = await screen.findByRole('combobox', {
      name: /Analysis profile/i,
    })
    // The empty option is still the one selected — naming a profile would
    // activate it, and this ingest asks for no change — but it now says which
    // profile that leaves in force.
    await waitFor(() =>
      expect(
        within(select).getByRole('option', { selected: true }).textContent,
      ).toMatch(/triage/i),
    )
    expect(screen.queryByText(/Default \(all modules\)/)).not.toBeInTheDocument()
    const note = await screen.findByRole('note', {
      name: /Analysis profile scope/i,
    })
    expect(note).toHaveTextContent(/triage/)
    expect(note).toHaveTextContent(/2 of 6/)
    expect(note).toHaveTextContent(/every later ingest/i)
  })

  it('lists what the chosen profile will not run, from the profile record', async () => {
    mockProfiles({ profiles: [{ ...TRIAGE_RECORD, is_active: false }] })
    const user = userEvent.setup()
    renderModal()

    await user.selectOptions(
      await screen.findByRole('combobox', { name: /Analysis profile/i }),
      'triage',
    )

    const note = await screen.findByRole('note', { name: /Analysis profile scope/i })
    expect(note).toHaveTextContent(/4 .*will not run/i)
    expect(note).toHaveTextContent(/Browser history and cache/)
    expect(note).toHaveTextContent(/Chat and messaging/)
    expect(note).toHaveTextContent(/Email/)
    // The absence a skipped module leaves is the whole reason this note exists.
    expect(note).toHaveTextContent(/no job/i)
    await user.click(screen.getByRole('button', { name: /modules that will not run/i }))
    expect(screen.getByText('plugin.browsers.history_parser')).toBeInTheDocument()
  })

  it('refuses to describe a built-in profile this case has never recorded', async () => {
    // Nothing the frontend can read says what the server's built-in triage
    // profile contains until it exists on the case. Printing a list from
    // memory would be a claim about a scoping decision the UI cannot see.
    mockProfiles({ profiles: [] })
    const user = userEvent.setup()
    renderModal()

    await user.selectOptions(
      await screen.findByRole('combobox', { name: /Analysis profile/i }),
      'triage',
    )

    const note = await screen.findByRole('note', { name: /Analysis profile scope/i })
    expect(note).toHaveTextContent(/no record of ['"]?triage/i)
    expect(note).not.toHaveTextContent(/plugin\./)
  })

  it('offers a materialised built-in once, not twice', async () => {
    // After one triage ingest the server has created a profile named "triage",
    // which listProfiles then returns beside the modal's own built-in option.
    mockProfiles({ profiles: [TRIAGE_RECORD], active: TRIAGE_RECORD })
    renderModal()

    const select = await screen.findByRole('combobox', {
      name: /Analysis profile/i,
    })
    // Wait for the record to arrive — the duplicate only appears once
    // listProfiles has answered.
    const note = await screen.findByRole('note', {
      name: /Analysis profile scope/i,
    })
    await waitFor(() => expect(note).toHaveTextContent(/2 of 6/))
    expect(
      within(select)
        .getAllByRole('option')
        .map((o) => (o as HTMLOptionElement).value),
    ).toEqual(['', 'triage', 'deep'])
  })

  it('does not call a profile lookup that is still in flight unreadable', async () => {
    // "Could not be read" is a claim about a request that finished. Rendering
    // it while one is in flight teaches the examiner to disbelieve the note.
    mockProfiles({ profiles: [TRIAGE_RECORD], active: TRIAGE_RECORD })
    server.use(
      http.get('/api/v1/cases/case-1/profiles/active', async () => {
        await delay(200)
        return HttpResponse.json(TRIAGE_RECORD)
      }),
    )
    renderModal()

    await screen.findByRole('combobox', { name: /Analysis profile/i })
    expect(screen.queryByText(/could not be read/i)).toBeNull()
    const note = await screen.findByRole('note', {
      name: /Analysis profile scope/i,
    })
    await waitFor(() => expect(note).toHaveTextContent(/2 of 6/))
  })

  it('says the scope is unknown when the module registry cannot be read', async () => {
    mockProfiles({ profiles: [TRIAGE_RECORD], active: TRIAGE_RECORD })
    server.use(
      http.get('/api/v1/modules', () =>
        HttpResponse.json(
          { error: { code: 'INTERNAL', message: 'boom' } },
          { status: 500 },
        ),
      ),
    )
    renderModal()

    const note = await screen.findByRole('note', { name: /Analysis profile scope/i })
    await waitFor(() => expect(note).toHaveTextContent(/could not be read/i))
    // The profile is still named: what is unknown is what it excludes.
    expect(note).toHaveTextContent(/triage/)
  })
})

describe('profile activation is case state', () => {
  it('refreshes the case profile after an ingest that named one', async () => {
    // Naming a profile activates it on the CASE, so every screen that reports
    // the case profile — this modal on its next open, the dashboard's scope
    // note — is stale the moment the request is accepted.
    mockProfiles({ profiles: [] })
    server.use(
      http.post('/api/v1/cases/case-1/ingest', () =>
        HttpResponse.json({ artifact_id: 'art-1', status: 'hashing' }),
      ),
    )
    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    })
    const invalidated: unknown[][] = []
    const realInvalidate = queryClient.invalidateQueries.bind(queryClient)
    queryClient.invalidateQueries = ((filters?: { queryKey?: unknown[] }) => {
      if (filters?.queryKey) invalidated.push(filters.queryKey)
      return realInvalidate(filters as never)
    }) as typeof queryClient.invalidateQueries
    render(
      <QueryClientProvider client={queryClient}>
        <ToastProvider>
          <IngestModal caseId="case-1" onClose={vi.fn()} />
        </ToastProvider>
      </QueryClientProvider>,
    )

    const user = userEvent.setup()
    await user.selectOptions(
      await screen.findByRole('combobox', { name: /Analysis profile/i }),
      'triage',
    )
    await user.click(await screen.findByText('disk.dd'))
    await user.click(screen.getByRole('button', { name: /Ingest 1 source/ }))

    await waitFor(() =>
      expect(invalidated).toContainEqual(['profile-active', 'case-1']),
    )
    expect(invalidated).toContainEqual(['profiles', 'case-1'])
  })
})

describe('pasting a known evidence path', () => {
  it('browses the path the examiner typed', async () => {
    const asked: (string | null)[] = []
    server.use(
      http.get('/api/v1/filesystem/browse', ({ request }) => {
        const p = new URL(request.url).searchParams.get('path')
        asked.push(p)
        return HttpResponse.json({
          ...BROWSE,
          current_path: p ?? '/evidence',
        })
      }),
    )
    const user = userEvent.setup()
    renderModal()

    const input = await screen.findByRole('textbox', { name: /path/i })
    await user.clear(input)
    await user.type(input, '/evidence/2026/OP-KESTREL{Enter}')

    await waitFor(() =>
      expect(asked).toContain('/evidence/2026/OP-KESTREL'),
    )
  })

  /**
   * The paste must survive the click that follows it.
   *
   * The whole reason this line is editable is that the path arrives on the
   * clipboard from the acquisition ticket. An examiner who pastes one and then
   * clicks anything at all — a directory row, the Ingest button, the profile
   * select — blurs the input, and reverting it there threw the paste away with
   * nothing on screen saying so: the line went back to reading the directory
   * the browser was already in, which looks exactly like a paste that never
   * happened. That is data loss dressed as a no-op, on the first screen of
   * every case.
   */
  it('keeps a pasted path when focus leaves the input', async () => {
    const user = userEvent.setup()
    renderModal()

    const input = await screen.findByRole('textbox', { name: /path/i })
    await user.clear(input)
    await user.type(input, '/evidence/2026/OP-KESTREL')
    await user.tab()

    expect(input).toHaveValue('/evidence/2026/OP-KESTREL')
  })

  it('says that a pasted path has not been opened yet', async () => {
    const user = userEvent.setup()
    renderModal()

    const input = await screen.findByRole('textbox', { name: /path/i })
    await user.clear(input)
    await user.type(input, '/evidence/2026/OP-KESTREL')
    await user.tab()

    expect(screen.getByText(/has not been opened/i)).toBeInTheDocument()
  })

  it('opens a pasted path from a control, not only from the Enter key', async () => {
    // Enter is invisible. A pasted path that can only be committed by a
    // keystroke nothing on screen mentions is a path most examiners will lose.
    const asked: (string | null)[] = []
    server.use(
      http.get('/api/v1/filesystem/browse', ({ request }) => {
        const p = new URL(request.url).searchParams.get('path')
        asked.push(p)
        return HttpResponse.json({ ...BROWSE, current_path: p ?? '/evidence' })
      }),
    )
    const user = userEvent.setup()
    renderModal()

    const input = await screen.findByRole('textbox', { name: /path/i })
    await user.clear(input)
    await user.type(input, '/evidence/2026/OP-KESTREL')
    await user.click(screen.getByRole('button', { name: /open this path/i }))

    await waitFor(() => expect(asked).toContain('/evidence/2026/OP-KESTREL'))
    expect(screen.queryByText(/has not been opened/i)).toBeNull()
  })

  it('shows the server refusal against the path the examiner pasted', async () => {
    // A path outside the configured evidence roots is a real case here. The
    // refusal is the server's to make and its words are the ones that belong on
    // screen — but the path the examiner typed has to stay in the box beside
    // them, or the refusal reads as being about somewhere else entirely.
    server.use(
      http.get('/api/v1/filesystem/browse', ({ request }) => {
        const p = new URL(request.url).searchParams.get('path')
        if (p === '/home/examiner/Downloads') {
          return HttpResponse.json(
            {
              error: {
                code: 'FORBIDDEN',
                message:
                  "'/home/examiner/Downloads' is not under a configured evidence root",
              },
            },
            { status: 403 },
          )
        }
        return HttpResponse.json(BROWSE)
      }),
    )
    const user = userEvent.setup()
    renderModal()

    const input = await screen.findByRole('textbox', { name: /path/i })
    await user.clear(input)
    await user.type(input, '/home/examiner/Downloads{Enter}')

    expect(
      await screen.findByText(/not under a configured evidence root/),
    ).toBeInTheDocument()
    expect(input).toHaveValue('/home/examiner/Downloads')
  })
})
