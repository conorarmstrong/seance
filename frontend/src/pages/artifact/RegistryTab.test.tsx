import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { http, HttpResponse } from 'msw'
import { describe, expect, it } from 'vitest'
import type { RegistryExplorerResponse } from '../../api/types'
import { server } from '../../test/server'
import { RegistryTab } from './RegistryTab'

const ROOT: RegistryExplorerResponse = {
  current_key_path: 'ROOT',
  parent_key_path: null,
  subkeys: [
    {
      key_path: 'ROOT\\Software',
      key_name: 'Software',
      last_modified: null,
      subkey_count: 2,
      value_count: 0,
      has_children: true,
    },
  ],
  values: [],
  breadcrumbs: [['ROOT', 'ROOT']],
}

const SOFTWARE: RegistryExplorerResponse = {
  current_key_path: 'ROOT\\Software',
  parent_key_path: 'ROOT',
  subkeys: [],
  values: [
    {
      value_name: 'Version',
      value_type: 'RegSz',
      value_data: '10.0.19041',
      raw_data_size: 20,
    },
  ],
  breadcrumbs: [
    ['ROOT', 'ROOT'],
    ['Software', 'ROOT\\Software'],
  ],
}

function mockRegistry() {
  server.use(
    http.get(
      '/api/v1/cases/:caseId/artifacts/:artifactId/registry',
      ({ request }) => {
        const keyPath = new URL(request.url).searchParams.get('key_path')
        if (keyPath === 'ROOT\\Software') return HttpResponse.json(SOFTWARE)
        return HttpResponse.json(ROOT)
      },
    ),
  )
}

// Registry root carrying transaction-log replay provenance (ROADMAP 1.12).
const REPLAYED: RegistryExplorerResponse = {
  ...ROOT,
  provenance: {
    logs_replayed: true,
    hive_dirty: true,
    replay_reason: 'recovered',
    log_format: 'new_hvle',
    log_files: ['SYSTEM.LOG1', 'SYSTEM.LOG2'],
    primary_sequence: 4210,
    secondary_sequence: 4208,
    log_entries_applied: 3,
    dirty_pages_applied: 27,
    replay_sequence_start: 4208,
    replay_sequence_end: 4210,
    hive_last_written_before: '2026-07-19T10:22:41Z',
    hive_last_written_after: '2026-07-19T10:41:05Z',
    changed_keys: ['ControlSet001\\Services\\evil'],
  },
}

const CLEAN: RegistryExplorerResponse = {
  ...ROOT,
  provenance: {
    logs_replayed: false,
    hive_dirty: false,
    replay_reason: 'clean',
    log_format: 'none',
    log_files: [],
    primary_sequence: 100,
    secondary_sequence: 100,
    log_entries_applied: 0,
    dirty_pages_applied: 0,
    replay_sequence_start: null,
    replay_sequence_end: null,
    hive_last_written_before: null,
    hive_last_written_after: null,
    changed_keys: [],
  },
}

const DIRTY_UNRECOVERED: RegistryExplorerResponse = {
  ...ROOT,
  provenance: {
    logs_replayed: false,
    hive_dirty: true,
    replay_reason: 'sequence_gap',
    log_format: 'new_hvle',
    log_files: ['SOFTWARE.LOG1'],
    primary_sequence: 4210,
    secondary_sequence: 4208,
    log_entries_applied: 0,
    dirty_pages_applied: 0,
    replay_sequence_start: null,
    replay_sequence_end: null,
    hive_last_written_before: null,
    hive_last_written_after: null,
    changed_keys: [],
  },
}

function mockRegistryResponse(resp: RegistryExplorerResponse) {
  server.use(
    http.get('/api/v1/cases/:caseId/artifacts/:artifactId/registry', () =>
      HttpResponse.json(resp),
    ),
  )
}

function renderTab() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  })
  return render(
    <QueryClientProvider client={queryClient}>
      <RegistryTab caseId="case-1" artifactId="art-hive" />
    </QueryClientProvider>,
  )
}

describe('RegistryTab', () => {
  it('navigates into a subkey and shows its values', async () => {
    mockRegistry()
    renderTab()
    const subkey = await screen.findByRole('button', { name: 'Software' })
    expect(screen.getByRole('button', { name: 'Up' })).toBeDisabled()
    await userEvent.click(subkey)
    expect(await screen.findByText('Version')).toBeInTheDocument()
    expect(screen.getByText('RegSz')).toBeInTheDocument()
    expect(screen.getByText('10.0.19041')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Up' })).toBeEnabled()
  })

  it('opens a value modal on row click and goes back up', async () => {
    mockRegistry()
    renderTab()
    await userEvent.click(
      await screen.findByRole('button', { name: 'Software' }),
    )
    await userEvent.click(await screen.findByText('Version'))
    const dialog = await screen.findByRole('dialog')
    expect(dialog).toHaveAccessibleName('Version')
    await userEvent.click(screen.getByRole('button', { name: 'Close' }))
    await userEvent.click(screen.getByRole('button', { name: 'Up' }))
    expect(
      await screen.findByRole('button', { name: 'Software' }),
    ).toBeInTheDocument()
  })

  it('does not show the previous hive while a new artifact loads (BUG-068)', async () => {
    // Artifact B's hive is gated, so its fetch is in flight right after the
    // switch — the window where keepPreviousData would surface artifact A's keys.
    let releaseB: () => void = () => {}
    const gateB = new Promise<void>((resolve) => {
      releaseB = resolve
    })
    const rootFor = (subkey: string): RegistryExplorerResponse => ({
      current_key_path: 'ROOT',
      parent_key_path: null,
      subkeys: [
        {
          key_path: `ROOT\\${subkey}`,
          key_name: subkey,
          last_modified: null,
          subkey_count: 0,
          value_count: 0,
          has_children: false,
        },
      ],
      values: [],
      breadcrumbs: [['ROOT', 'ROOT']],
    })
    server.use(
      http.get(
        '/api/v1/cases/:caseId/artifacts/:artifactId/registry',
        async ({ params }) => {
          if (params.artifactId === 'hive-B') await gateB
          return HttpResponse.json(
            params.artifactId === 'hive-A'
              ? rootFor('AlphaKey')
              : rootFor('BravoKey'),
          )
        },
      ),
    )

    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    })
    const { rerender } = render(
      <QueryClientProvider client={queryClient}>
        <RegistryTab caseId="case-1" artifactId="hive-A" />
      </QueryClientProvider>,
    )
    expect(
      await screen.findByRole('button', { name: 'AlphaKey' }),
    ).toBeInTheDocument()

    rerender(
      <QueryClientProvider client={queryClient}>
        <RegistryTab caseId="case-1" artifactId="hive-B" />
      </QueryClientProvider>,
    )

    // Artifact A's key must not render under artifact B's still-loading hive.
    expect(
      screen.queryByRole('button', { name: 'AlphaKey' }),
    ).not.toBeInTheDocument()
    expect(screen.getByText('Loading registry hive...')).toBeInTheDocument()

    releaseB()
    expect(
      await screen.findByRole('button', { name: 'BravoKey' }),
    ).toBeInTheDocument()
  })

  it('does not show another case’s hive for the same artifact id (BUG-259)', async () => {
    // Artifact UUIDs are not globally unique across cases. Gating the
    // keepPreviousData placeholder on artifactId alone lets an in-place case
    // switch render case 1's hive keys under case 2's chrome.
    let releaseCase2: () => void = () => {}
    const gate = new Promise<void>((resolve) => {
      releaseCase2 = resolve
    })
    const rootFor = (subkey: string): RegistryExplorerResponse => ({
      current_key_path: 'ROOT',
      parent_key_path: null,
      subkeys: [
        {
          key_path: `ROOT\\${subkey}`,
          key_name: subkey,
          last_modified: null,
          subkey_count: 0,
          value_count: 0,
          has_children: false,
        },
      ],
      values: [],
      breadcrumbs: [['ROOT', 'ROOT']],
    })
    server.use(
      http.get(
        '/api/v1/cases/:caseId/artifacts/:artifactId/registry',
        async ({ params }) => {
          if (params.caseId === 'case-2') await gate
          return HttpResponse.json(
            rootFor(params.caseId === 'case-1' ? 'AlphaKey' : 'BravoKey'),
          )
        },
      ),
    )

    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    })
    const { rerender } = render(
      <QueryClientProvider client={queryClient}>
        <RegistryTab caseId="case-1" artifactId="hive-shared" />
      </QueryClientProvider>,
    )
    expect(
      await screen.findByRole('button', { name: 'AlphaKey' }),
    ).toBeInTheDocument()

    // Same artifact id, different case.
    rerender(
      <QueryClientProvider client={queryClient}>
        <RegistryTab caseId="case-2" artifactId="hive-shared" />
      </QueryClientProvider>,
    )

    expect(
      screen.queryByRole('button', { name: 'AlphaKey' }),
    ).not.toBeInTheDocument()
    expect(screen.getByText('Loading registry hive...')).toBeInTheDocument()

    releaseCase2()
    expect(
      await screen.findByRole('button', { name: 'BravoKey' }),
    ).toBeInTheDocument()
  })

  it('never requests a new hive at the previous hive’s key path (B2-148 class)', async () => {
    // `keyPath` is part of the query key. Cleared in a `useEffect`, it is still
    // in hand for the whole commit in which `artifactId` has already changed,
    // and react-query fires that commit's key: hive B read at hive A's path.
    // The server answers for a path hive B may not have, and "key not found"
    // reads as a fact about hive B rather than as a stale request.
    const asked: { artifactId: string; keyPath: string | null }[] = []
    server.use(
      http.get(
        '/api/v1/cases/:caseId/artifacts/:artifactId/registry',
        ({ params, request }) => {
          const keyPath = new URL(request.url).searchParams.get('key_path')
          asked.push({ artifactId: params.artifactId as string, keyPath })
          if (keyPath === 'ROOT\\Software') return HttpResponse.json(SOFTWARE)
          return HttpResponse.json(ROOT)
        },
      ),
    )

    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    })
    const { rerender } = render(
      <QueryClientProvider client={queryClient}>
        <RegistryTab caseId="case-1" artifactId="hive-A" />
      </QueryClientProvider>,
    )
    await userEvent.click(
      await screen.findByRole('button', { name: 'Software' }),
    )
    await screen.findByText('Version')

    rerender(
      <QueryClientProvider client={queryClient}>
        <RegistryTab caseId="case-1" artifactId="hive-B" />
      </QueryClientProvider>,
    )
    await screen.findByRole('button', { name: 'Software' })

    expect(asked.some((a) => a.artifactId === 'hive-B')).toBe(true)
    for (const ask of asked.filter((a) => a.artifactId === 'hive-B')) {
      expect(ask.keyPath).toBeNull()
    }
  })

  it('shows the recovered-from-logs banner for a replayed hive', async () => {
    mockRegistryResponse(REPLAYED)
    renderTab()
    const banner = await screen.findByRole('status')
    expect(banner).toHaveTextContent('Recovered from logs')
    // Replay details: entries, dirty pages, log files, format, sequence range.
    expect(banner).toHaveTextContent('replayed 3 log entries')
    expect(banner).toHaveTextContent('27 dirty pages')
    expect(banner).toHaveTextContent('SYSTEM.LOG1, SYSTEM.LOG2')
    expect(banner).toHaveTextContent('HvLE format')
    expect(banner).toHaveTextContent('4208 -> 4210')
    expect(screen.queryByText('Clean hive')).not.toBeInTheDocument()
    // Changed keys are surfaced behind an expandable toggle.
    expect(
      screen.getByText('Show 1 changed key'),
    ).toBeInTheDocument()
  })

  it('shows the clean-hive banner when sequence numbers matched', async () => {
    mockRegistryResponse(CLEAN)
    renderTab()
    const banner = await screen.findByRole('status')
    expect(banner).toHaveTextContent('Clean hive')
    expect(banner).toHaveTextContent('no transaction-log replay needed')
    expect(screen.queryByText('Recovered from logs')).not.toBeInTheDocument()
  })

  it('shows the dirty-not-recovered banner when logs could not be applied', async () => {
    mockRegistryResponse(DIRTY_UNRECOVERED)
    renderTab()
    const banner = await screen.findByRole('status')
    expect(banner).toHaveTextContent('Dirty — not recovered')
    expect(banner).toHaveTextContent('seq 4210/4208')
    expect(banner).toHaveTextContent('sequence gap in logs')
    expect(banner).toHaveTextContent('on-disk')
    expect(screen.queryByText('Recovered from logs')).not.toBeInTheDocument()
  })

  it('renders no banner when provenance is absent (pre-feature hives)', async () => {
    mockRegistry()
    renderTab()
    // Wait for the hive to load, then confirm no provenance banner exists.
    await screen.findByRole('button', { name: 'Software' })
    expect(screen.queryByRole('status')).not.toBeInTheDocument()
  })
})
