import { screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Route } from 'react-router-dom'
import { describe, expect, it } from 'vitest'
import { MemoryNetworkPage } from './MemoryNetworkPage'
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

const ROUTES = <Route index element={<MemoryNetworkPage />} />

function network(connections: Record<string, unknown>[]) {
  return envelope({
    stage: 'network',
    record_type: 'MemoryNetwork',
    records: [record({ ...stamp(), connections }, 'net-1')],
  })
}

/**
 * One endpoint in the shape `NetworkEndpoint::to_json` writes: the owning
 * process is `owner_pid` / `owner_process`, and the far side is `remote_*`.
 * The fixture used to invent `pid` / `process_name` / `foreign_*`, so the owner
 * column looked tested while every real row rendered the literal word
 * "process" instead of the image name the scan recovered (B8-040).
 */
const ESTABLISHED = {
  offset: 0xfffff8a00a1b2c30,
  offset_hex: '0xfffff8a00a1b2c30',
  tag: 'TcpE',
  kind: 'endpoint',
  protocol: 'TCPv4',
  local_address: '10.0.0.22',
  local_port: 52140,
  remote_address: '185.199.108.153',
  remote_port: 443,
  state: 'ESTABLISHED',
  owner_pid: 3480,
  owner_process: 'chrome.exe',
  created: '2025-03-11T11:07:41Z',
  created_filetime: 133857956610000000,
  notes: [],
}

describe('MemoryNetworkPage', () => {
  it('lists a connection with its owning process and creation time', async () => {
    mockImages()
    mockMemory('network', network([ESTABLISHED]))
    renderMemory(`/cases/${CASE_ID}/memory?image=${IMAGE_ID}`, ROUTES)

    expect(await screen.findByText('185.199.108.153:443')).toBeInTheDocument()
    expect(screen.getByText('chrome.exe (3480)')).toBeInTheDocument()
    expect(screen.getByText('2025-03-11 11:07:41Z')).toBeInTheDocument()
  })

  it('grades every row scanned, because the sockets come out of pool memory', async () => {
    mockImages()
    mockMemory('network', network([ESTABLISHED]))
    const { container } = renderMemory(
      `/cases/${CASE_ID}/memory?image=${IMAGE_ID}`,
      ROUTES,
    )

    await screen.findByText('185.199.108.153:443')
    expect(
      container.querySelector('.mem-conf-summary .badge')?.textContent,
    ).toBe('scanned')
  })

  it('says a field the analysis did not record was not recorded, rather than leaving a blank cell', async () => {
    mockImages()
    mockMemory(
      'network',
      network([
        { ...ESTABLISHED, owner_pid: undefined, owner_process: undefined },
      ]),
    )
    renderMemory(`/cases/${CASE_ID}/memory?image=${IMAGE_ID}`, ROUTES)

    expect(await screen.findAllByText('not recorded')).not.toHaveLength(0)
  })

  it('names the owning image the scan recovered, and never guesses one from the pid alone', async () => {
    mockImages()
    mockMemory(
      'network',
      network([
        ESTABLISHED,
        { ...ESTABLISHED, local_port: 52141, owner_process: undefined },
      ]),
    )
    renderMemory(`/cases/${CASE_ID}/memory?image=${IMAGE_ID}`, ROUTES)

    // The row whose owner the scan named.
    expect(await screen.findByText('chrome.exe (3480)')).toBeInTheDocument()
    // The row it did not: the pid stands alone rather than being dressed up as
    // a process, and the cell says which of the two facts is missing.
    expect(screen.getByText('pid 3480')).toBeInTheDocument()
    expect(screen.getByText('(image not named)')).toBeInTheDocument()
  })

  it('reports a scan that did not run as an error, never as a machine with no connections', async () => {
    mockImages()
    mockMemory(
      'network',
      envelope({
        stage: 'network',
        record_type: 'MemoryNetwork',
        records: [],
        status: 'failed',
        status_meaning: 'Produced no results at all.',
        record_count: 0,
        failures: [
          failure({ stage: 'network', failure: 'tcpip.sys symbols unavailable' }),
        ],
      }),
    )
    renderMemory(`/cases/${CASE_ID}/memory?image=${IMAGE_ID}`, ROUTES)

    expect(
      await screen.findByText(/Network state: this analysis did not run/i),
    ).toBeInTheDocument()
    expect(
      screen.queryByText('No network structure was recovered'),
    ).not.toBeInTheDocument()
  })

  it('explains an empty result and points at the profile rather than shrugging', async () => {
    // The shape the server actually sends for "ran and found nothing": the
    // stage emitted one record whose connection array is empty, so
    // `record_count` is 1 and only the decoded rows say the result is empty.
    mockImages()
    mockMemory('network', network([]))
    renderMemory(`/cases/${CASE_ID}/memory?image=${IMAGE_ID}`, ROUTES)

    expect(
      await screen.findByText('No network structure was recovered'),
    ).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Check the profile' })).toHaveAttribute(
      'href',
      `/cases/${CASE_ID}/memory/image?image=${IMAGE_ID}`,
    )
  })

  it('invents no connection row for a scan that recovered none', async () => {
    // The regression: an empty `connections` array read as "this record has no
    // row array", which fell through to rendering the record itself as one row
    // — a connection on screen that no scan ever reported.
    mockImages()
    mockMemory('network', network([]))
    renderMemory(`/cases/${CASE_ID}/memory?image=${IMAGE_ID}`, ROUTES)

    await screen.findByText('No network structure was recovered')
    expect(screen.queryByRole('table')).not.toBeInTheDocument()
    expect(screen.queryAllByText('not recorded')).toHaveLength(0)
  })

  it('keeps a state filter in the address so a filtered view can be cited', async () => {
    mockImages()
    mockMemory(
      'network',
      network([
        ESTABLISHED,
        { ...ESTABLISHED, state: 'CLOSED', remote_address: '45.61.136.14' },
      ]),
    )
    renderMemory(`/cases/${CASE_ID}/memory?image=${IMAGE_ID}`, ROUTES)

    await userEvent.click(await screen.findByRole('button', { name: 'CLOSED' }))
    expect(screen.getByText('45.61.136.14:443')).toBeInTheDocument()
    expect(screen.queryByText('185.199.108.153:443')).not.toBeInTheDocument()
  })
})
