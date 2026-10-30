import { screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Route } from 'react-router-dom'
import { describe, expect, it } from 'vitest'
import type { StageEnvelope } from './api'
import { ProcessTreePage } from './ProcessTreePage'
import {
  CASE_ID,
  IMAGE_ID,
  envelope,
  failure,
  mockImages,
  mockMemory,
  processBlob,
  processListBlob,
  record,
  renderMemory,
  stamp,
  treeBlob,
  treeNode,
} from './testing'

const ROUTES = <Route index element={<ProcessTreePage />} />

const SYSTEM = processBlob({
  address: 0x1000,
  pid: 4,
  ppid: 0,
  name: 'System',
  createTime: '2025-03-11T09:14:02Z',
})
const SMSS = processBlob({
  address: 0x2000,
  pid: 380,
  ppid: 4,
  name: 'smss.exe',
  createTime: '2025-03-11T09:14:05Z',
})

function mockTree({
  list = envelope({
    records: [record(processListBlob([SYSTEM, SMSS]), 'list-1')],
  }),
  tree = envelope({
    stage: 'process_tree',
    record_type: 'MemoryProcessTree',
    records: [
      record(
        treeBlob([
          treeNode({ address: 0x1000, pid: 4, children: [1], link: { kind: 'root' } }),
          treeNode({
            address: 0x2000,
            pid: 380,
            ppid: 4,
            parent: 0,
            depth: 1,
            link: { kind: 'unverified', detail: 'process id match only' },
          }),
        ]),
        'tree-1',
      ),
    ],
  }),
  crossview = envelope({
    stage: 'cross_view',
    record_type: 'MemoryCrossView',
    records: [
      record(
        {
          ...stamp(),
          methods: [
            { key: 'list', label: 'list walk', ran: true },
            { key: 'scan', label: 'pool scan', ran: true },
          ],
          processes: [
            { pid: 4, image_file_name: 'System', seen: { list: true, scan: true } },
            {
              pid: 380,
              image_file_name: 'smss.exe',
              seen: { list: true, scan: true },
            },
          ],
        },
        'cross-1',
      ),
    ],
  }),
}: {
  list?: StageEnvelope
  tree?: StageEnvelope
  crossview?: StageEnvelope
} = {}) {
  mockImages()
  mockMemory('processes', { case_id: CASE_ID, image_id: IMAGE_ID, list, tree })
  mockMemory('crossview', crossview)
}

describe('ProcessTreePage', () => {
  it('renders the hierarchy the analysis derived, with the depth marked for assistive technology', async () => {
    mockTree()
    renderMemory(`/cases/${CASE_ID}/memory?image=${IMAGE_ID}`, ROUTES)

    const child = await screen.findByRole('button', { name: 'smss.exe' })
    expect(child.closest('tr')).toHaveAttribute('aria-level', '2')
  })

  it('says when a parent edge rests on a process id alone, because ids are reissued', async () => {
    mockTree()
    renderMemory(`/cases/${CASE_ID}/memory?image=${IMAGE_ID}`, ROUTES)

    expect(await screen.findByText('unverified parent')).toBeInTheDocument()
  })

  it('falls back to a flat list and says so when no tree was derived', async () => {
    mockTree({
      tree: envelope({
        stage: 'process_tree',
        record_type: 'MemoryProcessTree',
        records: [],
        status: 'did_not_run',
        status_meaning: 'Nothing ran.',
        record_count: 0,
      }),
    })
    renderMemory(`/cases/${CASE_ID}/memory?image=${IMAGE_ID}`, ROUTES)

    expect(
      await screen.findByText(/No parent\/child structure was derived/i),
    ).toBeInTheDocument()
    // The notice comes from the *tree* envelope and the rows from the *list*
    // one, so the message can be on screen a tick before the fallback rows are.
    // Wait for the row rather than assuming the two settle together.
    const child = await screen.findByRole('button', { name: 'smss.exe' })
    expect(child.closest('tr')).not.toHaveAttribute('aria-level')
  })

  it('says the cross-view comparison did not run instead of leaving every row looking un-hidden', async () => {
    mockTree({
      crossview: envelope({
        stage: 'cross_view',
        record_type: 'MemoryCrossView',
        records: [],
        status: 'failed',
        status_meaning: 'Produced no results at all.',
        record_count: 0,
        failures: [failure({ stage: 'cross_view', failure: 'the pool scanner failed' })],
      }),
    })
    renderMemory(`/cases/${CASE_ID}/memory?image=${IMAGE_ID}`, ROUTES)

    expect(
      await screen.findByText(/The cross-view comparison did not run/i),
    ).toBeInTheDocument()
    expect(screen.getByText(/the pool scanner failed/)).toBeInTheDocument()
  })

  it('marks one failed strategy as not checked rather than as "not seen"', async () => {
    mockTree({
      crossview: envelope({
        stage: 'cross_view',
        record_type: 'MemoryCrossView',
        records: [
          record(
            {
              ...stamp(),
              methods: [
                { key: 'list', label: 'list walk', ran: true },
                {
                  key: 'csrss',
                  label: 'csrss handles',
                  ran: false,
                  error: 'no csrss recovered',
                },
              ],
              processes: [
                { pid: 4, image_file_name: 'System', seen: { list: true } },
              ],
            },
            'cross-1',
          ),
        ],
      }),
    })
    renderMemory(`/cases/${CASE_ID}/memory?image=${IMAGE_ID}`, ROUTES)

    expect(await screen.findByText(/csrss handles did not run/i)).toBeInTheDocument()
    expect(
      screen.getByLabelText('seen by list walk; not checked by csrss handles'),
    ).toBeInTheDocument()
  })

  it('reports a stage that did not run as an error, never as a capture with no processes', async () => {
    mockTree({
      list: envelope({
        records: [],
        status: 'failed',
        status_meaning: 'Produced no results at all.',
        record_count: 0,
        failures: [failure({ failure: 'no symbol table was admitted' })],
      }),
    })
    renderMemory(`/cases/${CASE_ID}/memory?image=${IMAGE_ID}`, ROUTES)

    expect(
      await screen.findByText(/Processes: this analysis did not run/i),
    ).toBeInTheDocument()
    expect(screen.queryByText('No process was recovered')).not.toBeInTheDocument()
  })

  it('names a process whose fields could not be read instead of leaving them blank', async () => {
    mockTree({
      list: envelope({
        records: [
          record(
            processListBlob([
              processBlob({ address: 0x3000, pid: 900, name: null }),
            ]),
            'list-1',
          ),
        ],
      }),
      tree: envelope({
        stage: 'process_tree',
        record_type: 'MemoryProcessTree',
        records: [],
        status: 'did_not_run',
        status_meaning: 'Nothing ran.',
        record_count: 0,
      }),
    })
    renderMemory(`/cases/${CASE_ID}/memory?image=${IMAGE_ID}`, ROUTES)

    expect(await screen.findAllByText('unreadable')).not.toHaveLength(0)
  })

  it('refuses to substitute a nearby process when the address names a pid that was not recovered', async () => {
    mockTree()
    renderMemory(`/cases/${CASE_ID}/memory?image=${IMAGE_ID}&pid=9999`, ROUTES)

    expect(
      await screen.findByText(/No recovered process has pid 9999/i),
    ).toBeInTheDocument()
  })

  it('opens the inspector for a selected process and loads its memory map on demand', async () => {
    mockTree()
    mockMemory(
      'processes/4/vads',
      envelope({
        stage: 'vad',
        record_type: 'MemoryProcessVads',
        per_process: true,
        pid: 4,
        records: [
          record(
            {
              ...stamp(),
              // `Vad::to_json`: `protection` is the raw index and
              // `protection_names` the decoded string, and the mapped file is
              // an envelope whose `no_mapped_file` kind is the unbacked
              // finding. Read as plain strings the column was blank on every
              // row and the writable+executable call-out could never fire.
              regions: [
                {
                  address: 0xffffe0000b1c2d00,
                  address_hex: '0xffffe0000b1c2d00',
                  depth: 3,
                  start: 0x1f23a400000,
                  start_hex: '0x1f23a400000',
                  end: 0x1f23a47ffff,
                  end_hex: '0x1f23a47ffff',
                  size: 0x80000,
                  private_memory: true,
                  protection: 6,
                  protection_names: 'PAGE_EXECUTE_READWRITE',
                  file: { kind: 'no_mapped_file' },
                  tag: 'VadS',
                  notes: [],
                },
              ],
            },
            'vad-1',
          ),
        ],
      }),
    )
    renderMemory(`/cases/${CASE_ID}/memory?image=${IMAGE_ID}`, ROUTES)

    await userEvent.click(await screen.findByRole('button', { name: 'System' }))
    const inspector = await screen.findByRole('complementary', {
      name: /Process 4 inspector/i,
    })
    await userEvent.click(within(inspector).getByRole('tab', { name: 'Memory map' }))

    expect(await screen.findByText('PAGE_EXECUTE_READWRITE')).toBeInTheDocument()
    expect(
      screen.getByText('writable + executable, unbacked'),
    ).toBeInTheDocument()
    expect(screen.getByText('private, no file')).toBeInTheDocument()
  })

  it('names each mapped image from the file the walk found behind it', async () => {
    // `LdrModule::to_json` carries no `name`: the image is identified by the
    // file mapped into its range, sent as an envelope. Read as a plain string,
    // the DLLs tab listed a row per module with no module on it.
    mockTree()
    mockMemory(
      'processes/4/modules',
      envelope({
        stage: 'dlls',
        record_type: 'MemoryProcessModules',
        per_process: true,
        pid: 4,
        records: [
          record(
            {
              ...stamp(),
              process: 0xfffff80000000000,
              modules: [
                {
                  base: 0x7ffb4c000000,
                  base_hex: '0x7ffb4c000000',
                  vad: 0xffffe0000b1c2d00,
                  vad_hex: '0xffffe0000b1c2d00',
                  in_load: true,
                  in_init: true,
                  in_mem: true,
                  mapped_file: {
                    kind: 'name',
                    name: '\\Device\\HarddiskVolume2\\Windows\\System32\\ntdll.dll',
                  },
                  unlinked: false,
                  notes: [],
                },
                {
                  base: 0x1f23a400000,
                  base_hex: '0x1f23a400000',
                  vad: 0xffffe0000b1c2e00,
                  vad_hex: '0xffffe0000b1c2e00',
                  in_load: false,
                  in_init: false,
                  in_mem: false,
                  mapped_file: { kind: 'no_mapped_file' },
                  unlinked: true,
                  notes: [],
                },
              ],
            },
            'dlls-1',
          ),
        ],
      }),
    )
    renderMemory(`/cases/${CASE_ID}/memory?image=${IMAGE_ID}`, ROUTES)

    await userEvent.click(await screen.findByRole('button', { name: 'System' }))
    const inspector = await screen.findByRole('complementary', {
      name: /Process 4 inspector/i,
    })
    await userEvent.click(within(inspector).getByRole('tab', { name: 'DLLs' }))

    expect(await screen.findByText('ntdll.dll')).toBeInTheDocument()
    expect(
      within(inspector).getByText(
        '\\Device\\HarddiskVolume2\\Windows\\System32\\ntdll.dll',
      ),
    ).toBeInTheDocument()
    // The unlinked image with nothing behind it: a finding, stated as one
    // rather than as a field nobody filled in.
    expect(within(inspector).queryAllByText('not recorded')).toHaveLength(0)
    expect(within(inspector).getAllByText('none')).not.toHaveLength(0)
  })

  it('says a per-process stage did not run rather than showing an empty module list', async () => {
    mockTree()
    mockMemory(
      'processes/4/modules',
      envelope({
        stage: 'dlls',
        record_type: 'MemoryProcessModules',
        per_process: true,
        pid: 4,
        records: [],
        status: 'did_not_run',
        status_meaning: 'Neither a result nor a failure was recorded.',
        record_count: 0,
      }),
    )
    renderMemory(`/cases/${CASE_ID}/memory?image=${IMAGE_ID}`, ROUTES)

    await userEvent.click(await screen.findByRole('button', { name: 'System' }))
    const inspector = await screen.findByRole('complementary', {
      name: /Process 4 inspector/i,
    })
    await userEvent.click(within(inspector).getByRole('tab', { name: 'DLLs' }))

    expect(
      await screen.findByText(/Loaded modules: this analysis did not run/i),
    ).toBeInTheDocument()
  })

  it('says a per-process search that stopped at a cap is undetermined, not empty', async () => {
    mockTree()
    mockMemory(
      'processes/4/handles',
      envelope({
        stage: 'handles',
        record_type: 'MemoryProcessHandles',
        per_process: true,
        pid: 4,
        records: [],
        status: 'not_determined',
        status_meaning:
          'The search for this PID stopped at the scan cap before it had seen every record.',
        record_count: 0,
      }),
    )
    renderMemory(`/cases/${CASE_ID}/memory?image=${IMAGE_ID}`, ROUTES)

    await userEvent.click(await screen.findByRole('button', { name: 'System' }))
    const inspector = await screen.findByRole('complementary', {
      name: /Process 4 inspector/i,
    })
    await userEvent.click(within(inspector).getByRole('tab', { name: 'Handles' }))

    expect(await screen.findByText(/Handles: not determined/i)).toBeInTheDocument()
  })
})
