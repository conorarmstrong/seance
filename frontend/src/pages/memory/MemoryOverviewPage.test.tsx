import { screen, within } from '@testing-library/react'
import { Route } from 'react-router-dom'
import { describe, expect, it } from 'vitest'
import { MemoryOverviewPage } from './MemoryOverviewPage'
import {
  CASE_ID,
  IMAGE_ID,
  coverageBody,
  envelope,
  failure,
  mockImages,
  mockMemory,
  processBlob,
  processListBlob,
  record,
  renderMemory,
  stamp,
} from './testing'

const ROUTES = <Route index element={<MemoryOverviewPage />} />

const PROCESSES = {
  case_id: CASE_ID,
  image_id: IMAGE_ID,
  list: envelope({
    records: [
      record(
        processListBlob([
          processBlob({ address: 0x1000, pid: 4, name: 'System' }),
          processBlob({
            address: 0x2000,
            pid: 4402,
            name: 'notepad.exe',
            exitTime: '2025-03-11T16:02:00Z',
          }),
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
}

/**
 * The tampering stage in the shape `TamperingScan::to_json` writes it: ONE
 * record for the whole scan, a process per entry in `examined`, and that
 * process's signals inside it. The fixture used to put `signals` at the top of
 * the record, which no producer does — so the page looked tested while every
 * real capture rendered a single titleless card and a signal count of 1.
 */
const TAMPERING = envelope({
  stage: 'tampering',
  record_type: 'MemoryProcessTampering',
  records: [
    record(
      {
        ...stamp(),
        examined: [
          {
            process: 0xfffff80000000000,
            process_hex: '0xfffff80000000000',
            pid: 1064,
            image_file_name: 'svchost.exe',
            signals: [
              {
                severity: 'critical',
                title: 'Executable memory with no file behind it',
                why: 'The region is committed, private and mapped executable.',
                not_proof: 'JIT engines allocate exactly this shape.',
                detector: 'tampering.unbacked_exec',
              },
            ],
          },
        ],
        examined_count: 1,
        signalled_count: 1,
        skipped: [],
        skipped_total: 0,
      },
      'tamper-1',
    ),
  ],
})

describe('MemoryOverviewPage', () => {
  it('qualifies the process count with the rows that weaken it', async () => {
    mockImages()
    mockMemory('coverage', coverageBody([{ stage: 'processes', status: 'complete' }]))
    mockMemory('processes', PROCESSES)
    mockMemory('tampering', TAMPERING)
    renderMemory(`/cases/${CASE_ID}/memory?image=${IMAGE_ID}`, ROUTES)

    // The tile is on screen before its query settles, and an envelope that has
    // not arrived reads as "not run" — correctly, since nothing yet says the
    // stage ran. So wait for the count itself, not for the tile that hosts it.
    await screen.findByText('2 (1 exited)')
    const tile = screen.getByRole('link', { name: /^processes:/i })
    expect(within(tile).getByText('2 (1 exited)')).toBeInTheDocument()
  })

  it('shows a stage that did not run as "not run", never as zero', async () => {
    mockImages()
    mockMemory('coverage', coverageBody([{ stage: 'tampering', status: 'did_not_run' }]))
    mockMemory('processes', PROCESSES)
    mockMemory(
      'tampering',
      envelope({
        stage: 'tampering',
        record_type: 'MemoryProcessTampering',
        records: [],
        status: 'did_not_run',
        status_meaning: 'Neither a result nor a failure was recorded.',
        record_count: 0,
      }),
    )
    renderMemory(`/cases/${CASE_ID}/memory?image=${IMAGE_ID}`, ROUTES)

    const tile = await screen.findByRole('link', { name: /^tampering signals:/i })
    expect(within(tile).getByText('not run')).toBeInTheDocument()
    expect(within(tile).queryByText('0')).not.toBeInTheDocument()
  })

  it('refuses to present an unrun tampering scan as a clean capture', async () => {
    mockImages()
    mockMemory('coverage', coverageBody([{ stage: 'tampering', status: 'failed' }]))
    mockMemory('processes', PROCESSES)
    mockMemory(
      'tampering',
      envelope({
        stage: 'tampering',
        record_type: 'MemoryProcessTampering',
        records: [],
        status: 'failed',
        status_meaning: 'Produced no results at all.',
        record_count: 0,
        failures: [failure({ stage: 'tampering', failure: 'the scan crashed' })],
      }),
    )
    renderMemory(`/cases/${CASE_ID}/memory?image=${IMAGE_ID}`, ROUTES)

    expect(
      await screen.findByText(/The tampering scan did not run on this capture/i),
    ).toBeInTheDocument()
    expect(
      screen.getByText(/would read as an exculpatory finding/i),
    ).toBeInTheDocument()
  })

  it('lists the stages that did not run, so an empty lens can be interpreted', async () => {
    mockImages()
    mockMemory(
      'coverage',
      coverageBody([
        { stage: 'processes', status: 'complete' },
        { stage: 'network', status: 'did_not_run' },
      ]),
    )
    mockMemory('processes', PROCESSES)
    mockMemory('tampering', TAMPERING)
    renderMemory(`/cases/${CASE_ID}/memory?image=${IMAGE_ID}`, ROUTES)

    expect(await screen.findByText('network')).toBeInTheDocument()
    expect(screen.getByText(/1 did not run/)).toBeInTheDocument()
  })

  it('says a complete coverage run is not a statement that the machine was clean', async () => {
    mockImages()
    mockMemory('coverage', coverageBody([{ stage: 'processes', status: 'complete' }]))
    mockMemory('processes', PROCESSES)
    mockMemory('tampering', TAMPERING)
    renderMemory(`/cases/${CASE_ID}/memory?image=${IMAGE_ID}`, ROUTES)

    expect(
      await screen.findByText(/not a statement that the machine was clean/i),
    ).toBeInTheDocument()
  })

  it('renders each signal with both the observation and the benign explanation', async () => {
    mockImages()
    mockMemory('coverage', coverageBody([{ stage: 'tampering', status: 'complete' }]))
    mockMemory('processes', PROCESSES)
    mockMemory('tampering', TAMPERING)
    renderMemory(`/cases/${CASE_ID}/memory?image=${IMAGE_ID}`, ROUTES)

    expect(
      await screen.findByText(/The region is committed, private and mapped executable/),
    ).toBeInTheDocument()
    expect(
      screen.getByText('JIT engines allocate exactly this shape.'),
    ).toBeInTheDocument()
  })

  it('says every count is unqualified when the coverage table could not be loaded', async () => {
    mockImages()
    mockMemory('coverage', { error: { code: 'X', message: 'y' } }, 500)
    mockMemory('processes', PROCESSES)
    mockMemory('tampering', TAMPERING)
    renderMemory(`/cases/${CASE_ID}/memory?image=${IMAGE_ID}`, ROUTES)

    expect(
      await screen.findByText(/treat every count on this page as unqualified/i),
    ).toBeInTheDocument()
  })
})
