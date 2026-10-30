import { screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Route } from 'react-router-dom'
import { describe, expect, it } from 'vitest'
import { MemoryHandlesPage } from './MemoryHandlesPage'
import {
  CASE_ID,
  IMAGE_ID,
  envelope,
  handleBlob,
  mockImages,
  mockMemory,
  processBlob,
  processListBlob,
  record,
  renderMemory,
  stamp,
} from './testing'

const ROUTES = <Route index element={<MemoryHandlesPage />} />

function mockProcesses() {
  mockImages()
  mockMemory('processes', {
    case_id: CASE_ID,
    image_id: IMAGE_ID,
    list: envelope({
      records: [
        record(
          processListBlob([
            processBlob({ address: 0x1000, pid: 4, name: 'System' }),
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
}

describe('MemoryHandlesPage', () => {
  it('asks which process to open rather than sampling a case-wide list', async () => {
    mockProcesses()
    renderMemory(`/cases/${CASE_ID}/memory?image=${IMAGE_ID}`, ROUTES)

    expect(await screen.findByText('Choose a process')).toBeInTheDocument()
    expect(screen.getByText(/nothing is sampled/i)).toBeInTheDocument()
  })

  it('loads one process handle table from the server when a process is chosen', async () => {
    mockProcesses()
    mockMemory(
      'processes/4/handles',
      envelope({
        stage: 'handles',
        record_type: 'MemoryProcessHandles',
        per_process: true,
        pid: 4,
        records: [
          record(
            {
              ...stamp(),
              handles: [
                handleBlob({ name: '\\Device\\HarddiskVolume2\\Windows' }),
              ],
            },
            'handles-1',
          ),
        ],
      }),
    )
    renderMemory(`/cases/${CASE_ID}/memory?image=${IMAGE_ID}`, ROUTES)

    await userEvent.selectOptions(
      await screen.findByRole('combobox', { name: /process/i }),
      '4',
    )
    expect(
      await screen.findByText('\\Device\\HarddiskVolume2\\Windows'),
    ).toBeInTheDocument()
    expect(screen.getByText('0x2f4')).toBeInTheDocument()
  })

  it('keeps an unnamed object apart from a name that could not be read, and neither from "not recorded"', async () => {
    // The three ways a handle has no name on screen are three different facts
    // about the machine, and the one the table must never invent is "the
    // analysis recorded nothing" over a walk that recorded a reason (B8-037).
    mockProcesses()
    mockMemory(
      'processes/4/handles',
      envelope({
        stage: 'handles',
        record_type: 'MemoryProcessHandles',
        per_process: true,
        pid: 4,
        records: [
          record(
            {
              ...stamp(),
              handles: [
                handleBlob({
                  name: '\\REGISTRY\\MACHINE\\SOFTWARE',
                  objectType: 'Key',
                  handleValue: 0x1a0,
                }),
                handleBlob({ objectType: 'Mutant', handleValue: 0x1a4 }),
                handleBlob({
                  objectType: 'File',
                  handleValue: 0x1a8,
                  unavailable: 'the object body is not in the capture',
                }),
              ],
            },
            'handles-2',
          ),
        ],
      }),
    )
    renderMemory(`/cases/${CASE_ID}/memory?image=${IMAGE_ID}`, ROUTES)

    await userEvent.selectOptions(
      await screen.findByRole('combobox', { name: /process/i }),
      '4',
    )

    expect(
      await screen.findByText('\\REGISTRY\\MACHINE\\SOFTWARE'),
    ).toBeInTheDocument()
    // The unnamed mutant: a fact about the object.
    expect(screen.getByText('none')).toBeInTheDocument()
    // The unreadable file object: a hole in the evidence.
    expect(screen.getByText('unreadable')).toBeInTheDocument()
    // And no row claims the analysis wrote nothing down about a name.
    expect(screen.queryAllByText('not recorded')).toHaveLength(0)
  })

  it('reports a handle walk that did not run rather than a process that held nothing', async () => {
    mockProcesses()
    mockMemory(
      'processes/4/handles',
      envelope({
        stage: 'handles',
        record_type: 'MemoryProcessHandles',
        per_process: true,
        pid: 4,
        records: [],
        status: 'did_not_run',
        status_meaning: 'Neither a result nor a failure was recorded.',
        record_count: 0,
      }),
    )
    renderMemory(`/cases/${CASE_ID}/memory?image=${IMAGE_ID}`, ROUTES)

    await userEvent.selectOptions(
      await screen.findByRole('combobox', { name: /process/i }),
      '4',
    )
    expect(
      await screen.findByText(/Handles: this analysis did not run/i),
    ).toBeInTheDocument()
    expect(
      screen.queryByText('This process held no handle'),
    ).not.toBeInTheDocument()
  })

  it('says there is nothing to open when no process was recovered', async () => {
    mockImages()
    mockMemory('processes', {
      case_id: CASE_ID,
      image_id: IMAGE_ID,
      list: envelope({
        records: [],
        stage_ran: true,
        status: 'complete',
        status_meaning: 'Ran and produced nothing.',
        record_count: 0,
      }),
      tree: envelope({ records: [], record_count: 0 }),
    })
    renderMemory(`/cases/${CASE_ID}/memory?image=${IMAGE_ID}`, ROUTES)

    expect(await screen.findByText('No process was recovered')).toBeInTheDocument()
  })
})
