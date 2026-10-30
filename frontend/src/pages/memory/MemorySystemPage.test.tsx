import { screen } from '@testing-library/react'
import { Route } from 'react-router-dom'
import { describe, expect, it } from 'vitest'
import { MemorySystemPage } from './MemorySystemPage'
import {
  CASE_ID,
  IMAGE_ID,
  envelope,
  failure,
  mockImages,
  mockMemory,
  record,
  renderMemory,
  stamp,
} from './testing'

const ROUTES = <Route index element={<MemorySystemPage />} />

const SERVICES = envelope({
  stage: 'services',
  record_type: 'MemoryServices',
  records: [
    record(
      {
        ...stamp(),
        // `ServiceRecord::to_json`: every text is a tagged field, because a
        // build with no such member and a value that would not read are
        // different findings. Flattened here, the table looked tested while
        // every real row rendered "not recorded" (the B8-037 class).
        services: [
          {
            address: 0xffffc00000004000,
            method: 'record_scan',
            order: 12,
            type: 0x10,
            type_names: 'WIN32_OWN_PROCESS',
            state: 'RUNNING',
            start: 'AUTO_START',
            name: { kind: 'known', value: 'Spooler' },
            display_name: { kind: 'known', value: 'Print Spooler' },
            binary: {
              kind: 'known',
              value: 'C:\\Windows\\System32\\spoolsv.exe',
            },
            pid: { kind: 'known', value: 1580 },
            registry_binary: { kind: 'not_applicable' },
            registry_dll: { kind: 'not_applicable' },
            notes: [],
          },
        ],
      },
      'svc-1',
    ),
  ],
})

const HIVES = envelope({
  stage: 'registry_hives',
  record_type: 'MemoryRegistryHives',
  records: [
    record(
      {
        ...stamp(),
        // `HiveRecord::to_json`: the name is `{kind:"path", …}`, and a hive
        // that exists only in RAM says so with `{kind:"no_backing_file"}`
        // rather than by omitting the key.
        hives: [
          {
            address: 0xffffc00000001000,
            name: {
              kind: 'path',
              text: '\\SystemRoot\\System32\\Config\\SYSTEM',
              source: 'FileFullPath',
              well_formed: true,
            },
            direction: 'forward',
          },
          {
            address: 0xffffc00000002000,
            name: { kind: 'no_backing_file' },
            direction: 'forward',
          },
        ],
      },
      'hive-1',
    ),
  ],
})

describe('MemorySystemPage', () => {
  it('lists services with the state the analysis read', async () => {
    mockImages()
    mockMemory('services', SERVICES)
    mockMemory('registry/hives', HIVES)
    renderMemory(`/cases/${CASE_ID}/memory?image=${IMAGE_ID}`, ROUTES)

    expect(await screen.findByText('Spooler')).toBeInTheDocument()
    expect(screen.getByText('RUNNING')).toBeInTheDocument()
    // Every tagged field on the row, decoded — not one cell claiming the
    // analysis recorded nothing about a service it read in full.
    expect(screen.getByText('Print Spooler')).toBeInTheDocument()
    expect(
      screen.getByText('C:\\Windows\\System32\\spoolsv.exe'),
    ).toBeInTheDocument()
    expect(screen.getByText('1580')).toBeInTheDocument()
    expect(screen.queryAllByText('not recorded')).toHaveLength(0)
  })

  it('marks a hive that exists only in RAM, so its absence from the disk evidence is expected', async () => {
    mockImages()
    mockMemory('services', SERVICES)
    mockMemory('registry/hives', HIVES)
    renderMemory(`/cases/${CASE_ID}/memory?image=${IMAGE_ID}`, ROUTES)

    expect(await screen.findByText('volatile — RAM only')).toBeInTheDocument()
    expect(
      screen.getByText('\\SystemRoot\\System32\\Config\\SYSTEM'),
    ).toBeInTheDocument()
  })

  it('reports a stage that did not run separately from one that found nothing', async () => {
    mockImages()
    mockMemory(
      'services',
      envelope({
        stage: 'services',
        record_type: 'MemoryServices',
        records: [],
        status: 'failed',
        status_meaning: 'Produced no results at all.',
        record_count: 0,
        failures: [failure({ stage: 'services', failure: 'services.exe not found' })],
      }),
    )
    mockMemory(
      'registry/hives',
      envelope({
        stage: 'registry_hives',
        record_type: 'MemoryRegistryHives',
        records: [],
        stage_ran: true,
        status: 'complete',
        status_meaning: 'Ran and produced nothing.',
        record_count: 0,
      }),
    )
    renderMemory(`/cases/${CASE_ID}/memory?image=${IMAGE_ID}`, ROUTES)

    expect(
      await screen.findByText(/Services: this analysis did not run/i),
    ).toBeInTheDocument()
    expect(
      screen.getByText('No hive was found in kernel memory'),
    ).toBeInTheDocument()
  })

  it('explains an emptied list instead of rendering a headers-only table', async () => {
    // The shape the server sends for "the walk ran and carried no entry": one
    // record whose array is empty. Before the row count reached the gate this
    // rendered a table with headers, no rows and no sentence — and, worse, one
    // fabricated row built from the record itself.
    mockImages()
    mockMemory(
      'services',
      envelope({
        stage: 'services',
        record_type: 'MemoryServices',
        records: [record({ ...stamp(), services: [] }, 'svc-empty')],
      }),
    )
    mockMemory(
      'registry/hives',
      envelope({
        stage: 'registry_hives',
        record_type: 'MemoryRegistryHives',
        records: [record({ ...stamp(), hives: [] }, 'hive-empty')],
      }),
    )
    renderMemory(`/cases/${CASE_ID}/memory?image=${IMAGE_ID}`, ROUTES)

    expect(
      await screen.findByText('No service record was recovered'),
    ).toBeInTheDocument()
    expect(
      screen.getByText('No hive was found in kernel memory'),
    ).toBeInTheDocument()
    expect(screen.queryAllByRole('table')).toHaveLength(0)
  })
})
