import { render, screen, within } from '@testing-library/react'
import { http, HttpResponse } from 'msw'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { describe, expect, it } from 'vitest'
import { server } from '../../test/server'
import type { ParsedRecord } from './api'
import { MISSING, humanizeType } from './lib'
import { RecordsViewerPage } from './RecordsViewerPage'
import { VIEWERS } from './viewers'

/**
 * The NetworkFlow table: one row per bidirectional 5-tuple out of a packet
 * capture.
 *
 * What these tests are for, beyond "it renders": a flow table is where a C2
 * address is found, and the three things that hide one are a peer column that
 * does not say whether the address is routable, a byte count that quietly
 * excludes what the capture snaplen cut off, and a timestamp column that turns
 * "no packet carried a time" into 1970. Each of those is pinned here.
 */

const CASE_ID = 'case-1'

function flow(id: string, metadata: Record<string, unknown>): ParsedRecord {
  return {
    id,
    parent_id: 'pcap-1',
    artifact_type: 'ParsedRecord',
    metadata: { type: 'NetworkFlow', ...metadata },
  }
}

/** A TCP session to a routable address: the row an examiner is hunting. */
const TO_INTERNET = flow('f-internet', {
  protocol: 'tcp',
  local_ip: '10.0.0.5',
  local_port: 49152,
  remote_ip: '203.0.113.7',
  remote_port: 443,
  remote_is_external: true,
  packets_out: 20,
  bytes_out: 3456,
  packets_in: 22,
  bytes_in: 120000,
  packets: 42,
  bytes: 123456,
  first_seen: '2026-03-01T12:34:56Z',
  last_seen: '2026-03-01T12:35:08.5Z',
  duration_seconds: 12.5,
  tcp_state: 'handshake_seen',
  truncated_packets: 0,
})

/** Multicast DNS on the LAN, from packets that carried no timestamp at all. */
const LAN_MDNS = flow('f-mdns', {
  protocol: 'udp',
  local_ip: '10.0.0.5',
  local_port: 5353,
  remote_ip: '224.0.0.251',
  remote_port: 5353,
  remote_is_external: false,
  packets_out: 3,
  bytes_out: 300,
  packets_in: 0,
  bytes_in: 0,
  packets: 3,
  bytes: 300,
  first_seen: null,
  last_seen: null,
  duration_seconds: null,
  tcp_state: null,
  truncated_packets: 0,
})

/** A ping to the gateway, both packets cut short by the capture snaplen. */
const CUT_PING = flow('f-ping', {
  protocol: 'icmp',
  local_ip: '10.0.0.5',
  local_port: null,
  remote_ip: '10.0.0.1',
  remote_port: null,
  remote_is_external: false,
  packets_out: 1,
  bytes_out: 64,
  packets_in: 1,
  bytes_in: 64,
  packets: 2,
  bytes: 128,
  first_seen: '2026-03-01T12:00:00Z',
  last_seen: '2026-03-01T12:00:00Z',
  duration_seconds: 0,
  tcp_state: null,
  truncated_packets: 2,
  content_incomplete: true,
  content_incomplete_reason: 'short_read',
})

/** An IPv6 session, whose address already contains colons. */
const V6_SYN = flow('f-v6', {
  protocol: 'tcp',
  local_ip: '2001:db8::5',
  local_port: 51000,
  remote_ip: '2001:db8:1::1',
  remote_port: 443,
  remote_is_external: true,
  packets_out: 1,
  bytes_out: 74,
  packets_in: 0,
  bytes_in: 0,
  packets: 1,
  bytes: 74,
  first_seen: '2026-03-01T13:00:00Z',
  last_seen: '2026-03-01T13:00:00Z',
  duration_seconds: 0,
  tcp_state: 'syn_only',
  truncated_packets: 0,
})

/** A flow the emission stage stamped without a routability verdict. */
const UNCLASSIFIED = flow('f-unclassified', {
  protocol: 'udp',
  local_ip: '10.0.0.5',
  local_port: 123,
  remote_ip: '192.0.2.9',
  remote_port: 123,
  packets: 2,
  bytes: 180,
  first_seen: '2026-03-01T14:00:00Z',
  duration_seconds: 0.2,
  tcp_state: null,
  truncated_packets: 0,
})

/**
 * Serve `records` as the whole NetworkFlow population and mount the page the
 * viewer is reached through. The viewer is a rich one — it fetches its own
 * pages so it can sort and filter server-side — so it is exercised the way an
 * examiner meets it rather than handed rows it would never receive that way.
 */
async function renderFlows(records: ParsedRecord[]) {
  const def = VIEWERS['NetworkFlow']
  expect(def, 'NetworkFlow has no tailored viewer').toBeDefined()
  server.use(
    http.get(`/api/v1/cases/${CASE_ID}/records`, ({ request }) => {
      const url = new URL(request.url)
      const page = Number(url.searchParams.get('page') ?? 1)
      const pageSize = Number(url.searchParams.get('page_size') ?? 50)
      const start = (page - 1) * pageSize
      return HttpResponse.json({
        records: records.slice(start, start + pageSize),
        total: records.length,
        page,
        page_size: pageSize,
        type: 'NetworkFlow',
      })
    }),
  )
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={[`/cases/${CASE_ID}/analysis/NetworkFlow`]}>
        <Routes>
          <Route path="/cases/:caseId/analysis/:type" element={<RecordsViewerPage />} />
          <Route path="/cases/:caseId/artifacts/:artifactId" element={<div>artifact page</div>} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  )
  // The first row is on screen once the page has fetched.
  await screen.findByText(/network flows/i, undefined, { timeout: 5000 })
  await screen.findAllByRole('row', undefined, { timeout: 5000 })
}

/** The table row that carries `text` in one of its cells. */
/** The record table alone: the rich shell also draws the same values in its
 * frequency bars, and a row lookup must not land on one of those. */
function table(): HTMLElement {
  const t = document.querySelector<HTMLElement>('.rv-table')
  if (!t) throw new Error('the rich record table is not on the page')
  return t
}

/** The cell of `row` under the column headed `header`, found by heading
 * rather than by index so a leading marker column cannot shift every test. */
function cellUnder(row: HTMLElement, header: string): HTMLElement {
  const heads = within(table())
    .getAllByRole('columnheader')
    .map((h) => (h.textContent ?? '').replace(/[▲▼]/g, '').trim())
  const idx = heads.indexOf(header)
  if (idx < 0) throw new Error(`no column headed "${header}" (have ${heads.join(', ')})`)
  return within(row).getAllByRole('cell')[idx]
}

function rowWith(text: string): HTMLElement {
  const cell = within(table()).getByText(text)
  const row = cell.closest('tr')
  if (!row) throw new Error(`"${text}" is not inside a table row`)
  return row
}

describe('NetworkFlow viewer', () => {
  it('lays a flow out as protocol, both endpoints, peer class, state, counts, first seen and duration', async () => {
    await renderFlows([TO_INTERNET])

    // The rich table leads with the notable-row marker column, which has no
    // heading; the named columns follow in this order. Sortable headers carry
    // a control, so the text is trimmed of its indicator.
    const headers = within(table())
      .getAllByRole('columnheader')
      .map((h) => (h.textContent ?? '').replace(/[▲▼]/g, '').trim())
      .filter((h) => h !== '')
    expect(headers).toEqual([
      'Protocol',
      'Local',
      'Remote',
      'Peer',
      'State',
      'Packets',
      'Bytes',
      'First seen',
      'Duration',
      'Artifact',
    ])

    const row = rowWith('203.0.113.7:443')
    expect(within(row).getByText('tcp')).toBeInTheDocument()
    expect(within(row).getByText('10.0.0.5:49152')).toBeInTheDocument()
    expect(within(row).getByText('handshake seen')).toBeInTheDocument()
    expect(within(row).getByText('42')).toBeInTheDocument()
    // formatBytes, not a raw integer: 123456 B is what the examiner has to
    // read, and it reads as 120.6 KiB.
    expect(within(row).getByText('120.6 KiB')).toBeInTheDocument()
    // formatUtc: the same fixed UTC form every other time column uses.
    expect(within(row).getByText('2026-03-01 12:34:56 UTC')).toBeInTheDocument()
    expect(within(row).getByText('12.5 s')).toBeInTheDocument()
  })

  it('leaves the port off an endpoint that has none rather than printing null or zero', async () => {
    await renderFlows([CUT_PING])

    const row = rowWith('icmp')
    expect(within(row).getByText('10.0.0.5')).toBeInTheDocument()
    expect(within(row).getByText('10.0.0.1')).toBeInTheDocument()
    expect(row.textContent).not.toMatch(/:null|:0\b|:undefined/)
  })

  it('brackets an IPv6 address so its port is not read as one more hextet', async () => {
    await renderFlows([V6_SYN])

    const row = rowWith('[2001:db8:1::1]:443')
    expect(within(row).getByText('[2001:db8::5]:51000')).toBeInTheDocument()
  })

  it('spells the TCP state so syn_only does not read as a typo, and gives a stateless flow the placeholder', async () => {
    await renderFlows([V6_SYN, LAN_MDNS])

    expect(within(rowWith('[2001:db8:1::1]:443')).getByText('SYN only')).toBeInTheDocument()
    // UDP has no handshake; the state column is honestly empty, not "closed".
    const mdns = rowWith('224.0.0.251:5353')
    expect(cellUnder(mdns, 'State')).toHaveTextContent(MISSING)
  })

  it('spells every TCP state token the emission stage writes, so no row falls back to a raw token', async () => {
    // The token list is the contract in seance_plugin_pcap/src/flows.rs
    // (TcpState::as_str). A token the map does not know renders raw, which is
    // survivable, but "established_no_handshake_seen" in a table is not a
    // sentence an examiner should have to parse under oath.
    const tokens = [
      'syn_only',
      'handshake_seen',
      'handshake_partially_seen',
      'established_no_handshake_seen',
      'closed',
      'closed_no_handshake_seen',
      'reset',
      'reset_no_handshake_seen',
      'no_transport_seen',
    ]
    const records = tokens.map((t, i) =>
      flow(`f-state-${t}`, {
        protocol: 'tcp',
        local_ip: '10.0.0.5',
        local_port: 40000 + i,
        remote_ip: '203.0.113.7',
        remote_port: 443,
        remote_is_external: true,
        packets: 1,
        bytes: 60,
        tcp_state: t,
        truncated_packets: 0,
      }),
    )
    await renderFlows(records)

    for (let i = 0; i < tokens.length; i++) {
      const row = rowWith(`10.0.0.5:${40000 + i}`)
      const state = within(row).getAllByRole('cell')[4]
      // A raw token is the one with an underscore in it; "closed" and "reset"
      // are already words, so the check is for the underscore, not identity.
      expect(state, `token ${tokens[i]} rendered raw`).not.toHaveTextContent('_')
      expect(state, `token ${tokens[i]} rendered as missing`).not.toHaveTextContent(MISSING)
      expect(state.textContent?.trim(), `token ${tokens[i]} rendered empty`).not.toBe('')
    }
  })

  it('marks an external peer visibly apart from an internal one', async () => {
    await renderFlows([TO_INTERNET, LAN_MDNS])

    const external = within(rowWith('203.0.113.7:443')).getByText('external')
    expect(external).toHaveClass('badge')
    expect(external).toHaveClass('badge-accent')

    const internal = within(rowWith('224.0.0.251:5353')).getByText('internal')
    expect(internal).not.toHaveClass('badge-accent')
  })

  it('does not call an unclassified peer internal', async () => {
    // `remote_is_external` absent is "the stage did not say", and "internal"
    // is the one word that would make an examiner stop looking at it.
    await renderFlows([UNCLASSIFIED])

    const row = rowWith('192.0.2.9:123')
    expect(within(row).queryByText('internal')).not.toBeInTheDocument()
    expect(within(row).queryByText('external')).not.toBeInTheDocument()
    expect(cellUnder(row, 'Peer')).toHaveTextContent(MISSING)
  })

  it('shows a flow whose packets carried no timestamp as missing, never as the epoch', async () => {
    await renderFlows([LAN_MDNS])

    const row = rowWith('224.0.0.251:5353')
    expect(cellUnder(row, 'First seen')).toHaveTextContent(MISSING)
    expect(cellUnder(row, 'Duration')).toHaveTextContent(MISSING)
    expect(row.textContent).not.toContain('1970')
    expect(row.textContent).not.toContain('Invalid Date')
  })

  it('shows a zero-length flow as zero seconds, because two packets in the same microsecond are a fact and not an unknown', async () => {
    // The emitter sends null, not 0, for a flow with fewer than two timestamped
    // packets, so a 0 here is always two real timestamps that coincide.
    await renderFlows([CUT_PING])

    expect(within(rowWith('icmp')).getByText('0.0 s')).toBeInTheDocument()
  })

  it('says in the row when the snaplen cut packets, since the byte count excludes what was cut', async () => {
    await renderFlows([TO_INTERNET, CUT_PING])

    const cut = rowWith('icmp')
    // Two things now say it: the column's own marker, and the rich shell's
    // notable-row flag, whose reason names the count. Both must be there.
    const markers = within(cut).getAllByTitle(/snaplen/i)
    expect(markers.some((m) => /cut/i.test(m.textContent ?? ''))).toBe(true)
    expect(markers.some((m) => m.title.includes('2'))).toBe(true)

    const whole = rowWith('203.0.113.7:443')
    expect(within(whole).queryByTitle(/snaplen/i)).not.toBeInTheDocument()
  })

  it('asks the server to order by the magnitude columns, biggest first', async () => {
    // "Which flow moved the most bytes" has to be answered over the whole
    // record type, not the page that happens to be loaded, so the columns name
    // the server key rather than sorting in the browser.
    const columns = VIEWERS['NetworkFlow']?.columns ?? []
    const byKey = new Map(columns.map((c) => [c.key, c]))
    expect(byKey.get('bytes')?.sortKey).toBe('bytes')
    expect(byKey.get('bytes')?.sortDefaultOrder).toBe('desc')
    expect(byKey.get('packets')?.sortKey).toBe('packets')
    expect(byKey.get('packets')?.sortDefaultOrder).toBe('desc')
    expect(byKey.get('first_seen')?.sortKey).toBe('first_seen')
    // External peers first, as the plan asks.
    expect(byKey.get('remote_is_external')?.sortKey).toBe('remote_is_external')
    expect(byKey.get('remote_is_external')?.sortDefaultOrder).toBe('desc')
    // An endpoint cell is composed of two keys and its addresses order
    // lexically, not numerically, so it offers no sort at all rather than a
    // wrong one.
    expect(byKey.get('local_ip')?.sortKey).toBeUndefined()
    expect(byKey.get('remote_ip')?.sortKey).toBeUndefined()
  })
})

/**
 * The four record types the capture module emits are quoted by the label the
 * Records index gives them. Without curated entries, the generic PascalCase
 * splitter renders "Dns Resolution" -- an acronym cased as a word -- and
 * singular labels beside every other type's plural.
 */
describe('network capture record labels', () => {
  it('labels the four capture record types by name rather than by the PascalCase splitter', async () => {
    expect(humanizeType('NetworkCapture')).toBe('Network capture')
    expect(humanizeType('NetworkFlow')).toBe('Network flows')
    expect(humanizeType('DnsResolution')).toBe('DNS resolutions')
    expect(humanizeType('NetworkCaptureRefusal')).toBe('Network capture refusals')
  })

  it('keeps DNS in capitals wherever the generic splitter meets it', async () => {
    // A metadata key such as `dns_messages` goes through the same path.
    expect(humanizeType('dns_messages')).toBe('DNS Messages')
  })
})

/**
 * The universal pivot reaches the flow table where it matters most: the remote
 * address is the row an examiner hunts a C2 on, and it is one click from that
 * peer's whole footprint across the case. The cell is a button that pivots on
 * the bare address (not the address:port), so the pivot query is the
 * identifier, and the port stays in the display.
 */
describe('NetworkFlow viewer — pivot on the peer', () => {
  it('renders the remote endpoint as a pivot trigger on the bare address', async () => {
    await renderFlows([TO_INTERNET])
    const row = rowWith('203.0.113.7:443')
    const remote = cellUnder(row, 'Remote')
    const trigger = within(remote).getByRole('button')
    expect(trigger).toHaveTextContent('203.0.113.7:443')
    // The pivot is on the address alone — the port is display, not identity.
    expect(trigger).toHaveAttribute(
      'title',
      expect.stringContaining('Pivot on 203.0.113.7'),
    )
    expect(trigger.getAttribute('title')).not.toContain('203.0.113.7:443')
  })
})
