import { render, screen, within } from '@testing-library/react'
import { http, HttpResponse } from 'msw'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { describe, expect, it } from 'vitest'
import { server } from '../../test/server'
import type { ParsedRecord } from './api'
import { humanizeType } from './lib'
import { RecordsViewerPage } from './RecordsViewerPage'
import { GenericViewer, VIEWERS } from './viewers'

/**
 * The four protocol views out of a packet capture: HTTP transactions, TLS
 * sessions, the certificates a server presented, and who claimed which address
 * on the segment.
 *
 * UI_TESTING.md §5 makes a record type an examiner needs reaching a generic
 * key/value table a defect, and all four of these were doing exactly that —
 * the worst of them being HTTP, where the method, the status and the posted
 * form fields are three levels down inside two nested objects, so the generic
 * flat table showed none of them.
 *
 * What these tests are for, beyond "it renders": every one of these record
 * types carries an INFERENCE that would read as a fact if a column printed it
 * plainly. A response is paired to a request by order, and over a gap in the
 * stream that pairing may be wrong. A certificate's fields are as presented,
 * with no signature verified. An address claimed twice is a lead and not a
 * poisoning verdict. A TLS 1.3 session has no certificate in the capture, and
 * that says nothing about what the server sent. Each of those is pinned here.
 */

const CASE_ID = 'case-1'

function record(
  type: string,
  id: string,
  metadata: Record<string, unknown>,
): ParsedRecord {
  return {
    id,
    parent_id: 'pcap-1',
    artifact_type: 'ParsedRecord',
    metadata: { type, ...metadata },
  } as unknown as ParsedRecord
}

/**
 * Serve `records` as the whole population of `type` and mount the page the
 * viewer is reached through. All four are rich viewers — they fetch their own
 * pages so they can sort and filter server-side — so they are exercised the
 * way an examiner meets them rather than handed rows they would never receive.
 */
async function renderType(type: string, records: ParsedRecord[]) {
  const def = VIEWERS[type]
  expect(def, `${type} has no tailored viewer`).toBeDefined()
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
        type,
      })
    }),
  )
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  })
  render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={[`/cases/${CASE_ID}/analysis/${type}`]}>
        <Routes>
          <Route
            path="/cases/:caseId/analysis/:type"
            element={<RecordsViewerPage />}
          />
          <Route
            path="/cases/:caseId/artifacts/:artifactId"
            element={<div>artifact page</div>}
          />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  )
  await screen.findAllByRole('row', undefined, { timeout: 5000 })
}

/** The record table alone: the rich shell draws the same values in its
 * frequency bars, and a row lookup must not land on one of those. */
function table(): HTMLElement {
  const t = document.querySelector<HTMLElement>('.rv-table')
  if (!t) throw new Error('the rich record table is not on the page')
  return t
}

function headers(): string[] {
  return within(table())
    .getAllByRole('columnheader')
    .map((h) => (h.textContent ?? '').replace(/[▲▼]/g, '').trim())
    .filter((h) => h !== '')
}

function rowWith(text: string | RegExp): HTMLElement {
  const cell = within(table()).getByText(text)
  const row = cell.closest('tr')
  if (!row) throw new Error(`"${text}" is not inside a table row`)
  return row
}

function cellUnder(row: HTMLElement, header: string): HTMLElement {
  const heads = within(table())
    .getAllByRole('columnheader')
    .map((h) => (h.textContent ?? '').replace(/[▲▼]/g, '').trim())
  const idx = heads.indexOf(header)
  if (idx < 0) {
    throw new Error(`no column headed "${header}" (have ${heads.join(', ')})`)
  }
  return within(row).getAllByRole('cell')[idx]
}

// ---------------------------------------------------------------------------
// HTTP
// ---------------------------------------------------------------------------

/** A login POST answered 302, paired in order over an unbroken stream. */
const LOGIN_POST = record('HttpTransaction', 'h-login', {
  name: 'POST /login → 302',
  url: 'http://shop.example/login',
  host: 'shop.example',
  client_ip: '10.0.0.5',
  server_ip: '203.0.113.7',
  server_port: 80,
  pairing: 'in_order',
  pairing_basis:
    'HTTP/1.1 answers requests on one connection in order, so the nth response answers the nth request.',
  request: {
    kind: 'request',
    method: 'POST',
    target: '/login',
    content_type: 'application/x-www-form-urlencoded',
    headers_complete: true,
    headers_dropped: 0,
    body_bytes: 42,
    body_capped: false,
    body_is_whole: true,
    body_end: 'length_satisfied',
    body_artifact_id: 'body-1',
    form_fields: {
      fields: { user: 'aoife', password: 'hunter2' },
      field_count: 2,
      fields_beyond_cap: 0,
      values_truncated: 0,
      malformed_pairs: 0,
    },
    query_fields: null,
  },
  response: {
    kind: 'response',
    status: 302,
    reason: 'Found',
    content_type: 'text/html',
    headers_complete: true,
    headers_dropped: 0,
    body_bytes: 0,
    body_capped: false,
    body_is_whole: true,
    body_end: 'none',
  },
})

/** The same shape, paired across a hole in the stream: the pairing may be wrong. */
const PAIRED_OVER_A_GAP = record('HttpTransaction', 'h-gap', {
  name: 'GET /basket → 200',
  url: 'http://shop.example/basket',
  host: 'shop.example',
  pairing: 'in_order_over_a_gap',
  pairing_basis:
    'Paired by order, which is how HTTP/1.1 answers requests on one connection -- but one direction of this conversation has a gap in it, and the missing bytes may have held a whole message. THIS PAIRING MAY BE WRONG.',
  content_incomplete: true,
  content_incomplete_reason: 'unresolved_structure',
  content_incomplete_detail:
    'Paired by order over a gap; THIS PAIRING MAY BE WRONG.',
  request: {
    method: 'GET',
    target: '/basket?ref=mail&id=7',
    headers_complete: true,
    headers_dropped: 0,
    body_bytes: 0,
    body_is_whole: true,
    form_fields: null,
    query_fields: {
      fields: { ref: 'mail', id: '7' },
      field_count: 2,
      fields_beyond_cap: 3,
      values_truncated: 1,
      malformed_pairs: 0,
    },
  },
  response: {
    status: 200,
    reason: 'OK',
    content_type: 'text/html; charset=utf-8',
    headers_complete: true,
    headers_dropped: 0,
    body_bytes: 900,
    body_is_whole: true,
    body_end: 'length_satisfied',
    body_artifact_id: 'body-2',
  },
})

/** A request whose headers ran out inside the header block. */
const HEADERS_ARE_A_PREFIX = record('HttpTransaction', 'h-prefix', {
  name: 'GET /upload',
  url: 'http://shop.example/upload',
  host: 'shop.example',
  pairing: 'request_unanswered',
  pairing_basis:
    'This request has no response in the capture: the answer was not captured, or none was sent.',
  content_incomplete: true,
  content_incomplete_reason: 'short_read',
  content_incomplete_detail:
    "the request's headers are a prefix of the message's",
  request: {
    method: 'GET',
    target: '/upload',
    headers_complete: false,
    headers_dropped: 0,
    body_bytes: 0,
    body_is_whole: true,
  },
  response: null,
})

describe('HttpTransaction viewer', () => {
  it('answers what was fetched, what was sent and what came back', async () => {
    await renderType('HttpTransaction', [LOGIN_POST])

    expect(headers()).toEqual([
      'Method',
      'URL',
      'Host',
      'Status',
      'Declared type',
      'What was sent',
      'Body',
      'Paired',
      'Whole?',
      'Artifact',
    ])

    const row = rowWith('http://shop.example/login')
    expect(within(row).getByText('POST')).toBeInTheDocument()
    expect(within(row).getByText('302 Found')).toBeInTheDocument()
    expect(within(row).getByText('text/html')).toBeInTheDocument()
    // "What did they send" is the column this view exists for, and it was two
    // levels down inside `request.form_fields.fields` in the generic table.
    expect(
      within(row).getByText('user = aoife · password = hunter2'),
    ).toBeInTheDocument()
    // The body reached an artifact of its own, so the carver and the index see
    // it; the row says which side of the exchange holds one.
    expect(within(row).getByText('request')).toBeInTheDocument()
  })

  it('reads a pairing made over a gap as one that may be wrong, on the row', async () => {
    await renderType('HttpTransaction', [PAIRED_OVER_A_GAP])

    const row = rowWith('http://shop.example/basket')
    const paired = cellUnder(row, 'Paired')
    expect(paired).toHaveTextContent('in order, over a gap')
    // Not a tooltip alone: an examiner quoting a request beside a response has
    // to meet the qualification without hovering.
    expect(paired).toHaveTextContent('may be wrong')
    expect(
      within(paired).getByText('may be wrong').getAttribute('title'),
    ).toContain('THIS PAIRING MAY BE WRONG')
  })

  it('says a bounded field list is bounded rather than showing it as the whole one', async () => {
    await renderType('HttpTransaction', [PAIRED_OVER_A_GAP])

    const sent = cellUnder(rowWith('http://shop.example/basket'), 'What was sent')
    expect(sent).toHaveTextContent('ref = mail')
    const badge = within(sent).getByText('part')
    expect(badge.getAttribute('title')).toContain('past this build')
    expect(badge.getAttribute('title')).toContain('body artifact')
  })

  it('names a message that is a prefix as a prefix, not merely as incomplete', async () => {
    await renderType('HttpTransaction', [HEADERS_ARE_A_PREFIX])

    const whole = cellUnder(rowWith('http://shop.example/upload'), 'Whole?')
    // "incomplete" does not tell an examiner that the absence of a header here
    // is not evidence of its absence. "a prefix" does.
    expect(whole).toHaveTextContent('a prefix')
    expect(within(whole).getByText('a prefix').getAttribute('title')).toContain(
      'ended inside the header block',
    )
  })

  it('shows a transaction with no response as unanswered rather than as a blank status', async () => {
    await renderType('HttpTransaction', [HEADERS_ARE_A_PREFIX])

    const row = rowWith('http://shop.example/upload')
    expect(cellUnder(row, 'Paired')).toHaveTextContent('no response captured')
    // A request with no answer in the capture is an absence of evidence, so it
    // is not counted beside the server errors: it has a tile of its own, which
    // is the second place this phrase appears.
    expect(
      screen.getAllByText(/No response captured/i).length,
    ).toBeGreaterThan(1)
  })

  it('marks a row whose pairing may be wrong before anything else about it', async () => {
    await renderType('HttpTransaction', [PAIRED_OVER_A_GAP])
    const marker = within(rowWith('http://shop.example/basket')).getByText('!')
    expect(marker.getAttribute('title')).toContain('MAY BE WRONG')
  })
})

// ---------------------------------------------------------------------------
// TLS sessions
// ---------------------------------------------------------------------------

/** A TLS 1.2 session on a known-weak suite, with a certificate in the clear. */
const WEAK_TLS12 = record('TlsSession', 't-weak', {
  name: 'TLS 1.2 to legacy.example',
  server_name: 'legacy.example',
  server_name_source:
    'the client’s server_name (SNI) extension, which is what the client ASKED FOR -- not a name this build resolved or verified',
  server_ip: '203.0.113.9',
  server_port: 443,
  negotiated_version: 'TLS 1.2',
  negotiated_cipher: 'TLS_RSA_WITH_3DES_EDE_CBC_SHA',
  cipher_is_known_weak: true,
  ja3_md5: 'a0e9f5d64349fb13191bc781f81f42e1',
  certificate_subject: 'CN=legacy.example, O=Legacy Ltd',
  certificate_issuer: 'CN=Legacy CA',
  certificates: 2,
  unparsable_certificates: 1,
  certificates_unavailable: null,
})

/** A TLS 1.3 session: the certificate is not in the capture and cannot be. */
const TLS13_NO_CERTIFICATE = record('TlsSession', 't-13', {
  name: 'TLS 1.3 to shop.example',
  server_name: 'shop.example',
  server_ip: '203.0.113.7',
  server_port: 443,
  negotiated_version: 'TLS 1.3',
  negotiated_cipher: 'TLS_AES_128_GCM_SHA256',
  cipher_is_known_weak: false,
  ja3_md5: 'b1f0a2c3d4e5f60718293a4b5c6d7e8f',
  certificates: 0,
  unparsable_certificates: 0,
  certificate_subject: null,
  certificates_unavailable: 'encrypted_by_tls13',
  certificates_unavailable_statement:
    'This conversation negotiated TLS 1.3, which sends the server’s certificate inside the encrypted extensions. NO CAPTURE OF TLS 1.3 CAN HOLD THE CERTIFICATE: its absence here says nothing about what the server presented.',
  content_incomplete: true,
  content_incomplete_reason: 'encrypted',
  content_incomplete_detail: 'the certificate is inside the encrypted extensions',
})

/** A client that sent no SNI at all. */
const NO_SNI = record('TlsSession', 't-nosni', {
  name: 'TLS to 198.51.100.4 (no server name was sent)',
  server_name: null,
  server_ip: '198.51.100.4',
  server_port: 8443,
  negotiated_version: 'TLS 1.2',
  negotiated_cipher: 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
  cipher_is_known_weak: false,
  ja3_md5: null,
  certificates: 1,
  unparsable_certificates: 0,
  certificate_subject: 'CN=host.invalid',
  certificates_unavailable: null,
})

describe('TlsSession viewer', () => {
  it('answers what was connected to, with what, and what the far end claimed', async () => {
    await renderType('TlsSession', [WEAK_TLS12])

    expect(headers()).toEqual([
      'Name asked for (SNI)',
      'Server',
      'Version',
      'Cipher',
      'JA3',
      'Certificate subject',
      'Certificates',
      'Artifact',
    ])

    const row = rowWith('legacy.example')
    expect(within(row).getByText('203.0.113.9:443')).toBeInTheDocument()
    expect(within(row).getByText('TLS 1.2')).toBeInTheDocument()
    expect(
      within(row).getByText('a0e9f5d64349fb13191bc781f81f42e1'),
    ).toBeInTheDocument()
    expect(
      within(row).getByText('CN=legacy.example, O=Legacy Ltd'),
    ).toBeInTheDocument()
  })

  it('heads the SNI column as what the client asked for, never as the server', async () => {
    await renderType('TlsSession', [WEAK_TLS12])
    // A column headed "Server" would read as this build's own answer to "what
    // host is this". Nothing here resolved or verified the name.
    expect(headers()).toContain('Name asked for (SNI)')
    expect(headers()).not.toContain('Server name')
  })

  it('badges a known-weak suite as a statement about the suite, not about the conversation', async () => {
    await renderType('TlsSession', [WEAK_TLS12])

    const cipher = cellUnder(rowWith('legacy.example'), 'Cipher')
    expect(cipher).toHaveTextContent('TLS_RSA_WITH_3DES_EDE_CBC_SHA')
    const badge = within(cipher).getByText('known weak')
    expect(badge.getAttribute('title')).toContain('not a demonstration')
  })

  it('never renders a TLS 1.3 session as a server that presented no certificate', async () => {
    await renderType('TlsSession', [TLS13_NO_CERTIFICATE])

    const cell = cellUnder(rowWith('shop.example'), 'Certificate subject')
    // An empty cell here would read as "this server presented no
    // certificate", which no capture of TLS 1.3 can establish.
    expect(cell).toHaveTextContent('encrypted by TLS 1.3')
    expect(
      within(cell).getByText('encrypted by TLS 1.3').getAttribute('title'),
    ).toContain('NO CAPTURE OF TLS 1.3 CAN HOLD THE CERTIFICATE')
    // And the tile counting them says the same in its label.
    expect(
      screen.getByText(/No certificate in the capture/i),
    ).toBeInTheDocument()
  })

  it('counts the certificates it could not parse beside the ones it could', async () => {
    await renderType('TlsSession', [WEAK_TLS12])

    const cell = cellUnder(rowWith('legacy.example'), 'Certificates')
    expect(cell).toHaveTextContent('2')
    // A chain shown as two where three were presented is a false account of
    // what the server sent.
    const badge = within(cell).getByText('+1 unparsable')
    expect(badge.getAttribute('title')).toContain('could not be parsed')
  })

  it('says a client sent no server name rather than leaving the cell blank', async () => {
    await renderType('TlsSession', [NO_SNI])

    const cell = cellUnder(rowWith('198.51.100.4:8443'), 'Name asked for (SNI)')
    expect(cell).toHaveTextContent('none sent')
    expect(within(cell).getByText('none sent').getAttribute('title')).toContain(
      'not a statement that the server has none',
    )
  })
})

// ---------------------------------------------------------------------------
// TLS certificates
// ---------------------------------------------------------------------------

const CA_ISSUED = record('TlsCertificate', 'c-ca', {
  name: 'shop.example issued by Example CA',
  subject: 'CN=shop.example, O=Shop Ltd',
  subject_common_name: 'shop.example',
  issuer: 'CN=Example CA, O=Example Trust',
  issuer_common_name: 'Example CA',
  not_before: '2026-01-01T00:00:00Z',
  not_after: '2026-12-31T23:59:59Z',
  names: ['shop.example', 'www.shop.example'],
  sha256: 'a'.repeat(64),
  self_signed: false,
  signature_verified: false,
  chain_built: false,
  revocation_checked: false,
  position_in_chain: 0,
  chain_length: 2,
  server_name_requested: 'shop.example',
  covers_the_name_requested: true,
  covers_the_name_requested_meaning:
    'Whether one of this certificate’s own names matches the name the client asked for, wildcards included. It is a comparison of two strings: it is NOT a verification, which would need the signature and a trust store.',
  statement:
    'The fields above are read from the certificate the server presented. Its signature is NOT verified, no chain is built, no trust store is consulted, no revocation is checked.',
})

const SELF_ISSUED_WRONG_NAME = record('TlsCertificate', 'c-self', {
  name: 'proxy.local issued by proxy.local',
  subject: 'CN=proxy.local',
  subject_common_name: 'proxy.local',
  issuer: 'CN=proxy.local',
  issuer_common_name: 'proxy.local',
  not_before: '2025-06-01T00:00:00Z',
  not_after: '2035-06-01T00:00:00Z',
  names: ['proxy.local'],
  sha256: 'b'.repeat(64),
  self_signed: true,
  signature_verified: false,
  chain_built: false,
  revocation_checked: false,
  position_in_chain: 0,
  chain_length: 1,
  server_name_requested: 'shop.example',
  covers_the_name_requested: false,
  covers_the_name_requested_meaning:
    'It is a comparison of two strings: it is NOT a verification, which would need the signature and a trust store.',
  statement:
    'A certificate is what a host CLAIMED to be. Its signature is NOT verified.',
})

describe('TlsCertificate viewer', () => {
  it('answers who issued this, when it was good for, and what names it carries', async () => {
    await renderType('TlsCertificate', [CA_ISSUED])

    expect(headers()).toEqual([
      'Subject',
      'Issuer',
      'Name matches?',
      'Valid from',
      'Valid until',
      'Self-issued?',
      'Names',
      'SHA-256',
      'Checked?',
      'Artifact',
    ])

    // Anchored on the fingerprint: the subject common name is also one of the
    // certificate's own names, so it is in two cells of the same row.
    const row = rowWith('a'.repeat(64))
    expect(within(row).getByText('Example CA')).toBeInTheDocument()
    expect(
      within(row).getByText('2026-01-01 00:00:00 UTC'),
    ).toBeInTheDocument()
    expect(within(row).getByText('www.shop.example')).toBeInTheDocument()
    expect(within(row).getAllByText('shop.example').length).toBe(2)
  })

  it('states on every row that no signature was verified and no chain was built', async () => {
    await renderType('TlsCertificate', [CA_ISSUED])

    // Without this a row showing a subject, an issuer and a validity window
    // reads as a certificate this build checked, and nothing here checks one.
    const checked = cellUnder(rowWith('a'.repeat(64)), 'Checked?')
    expect(checked).toHaveTextContent('signature not verified')
    expect(checked).toHaveTextContent('no chain built')
    expect(checked).toHaveTextContent('no revocation check')
  })

  it('calls a self-signed certificate a subject equal to its issuer, not a verdict', async () => {
    await renderType('TlsCertificate', [SELF_ISSUED_WRONG_NAME])

    const cell = cellUnder(rowWith('b'.repeat(64)), 'Self-issued?')
    expect(cell).toHaveTextContent('subject = issuer')
    expect(
      within(cell).getByText('subject = issuer').getAttribute('title'),
    ).toContain('no signature was verified')
  })

  it('reads a name comparison as a comparison and never as validity', async () => {
    await renderType('TlsCertificate', [SELF_ISSUED_WRONG_NAME])

    const cell = cellUnder(rowWith('b'.repeat(64)), 'Name matches?')
    expect(cell).toHaveTextContent('no name matches')
    expect(
      within(cell).getByText('no name matches').getAttribute('title'),
    ).toContain('NOT a verification')
    // "valid for" would be the claim this build cannot make.
    expect(table().textContent ?? '').not.toContain('valid for')
  })
})

// ---------------------------------------------------------------------------
// ARP
// ---------------------------------------------------------------------------

const ONE_CLAIMANT = record('ArpBinding', 'a-one', {
  name: '192.168.1.20 claimed by 00:1a:2b:3c:4d:5e',
  ip: '192.168.1.20',
  macs: ['00:1a:2b:3c:4d:5e'],
  contested: false,
  contested_from: null,
  macs_beyond_cap: 0,
  packets: 12,
  source_name: 'segment.pcap',
  statement:
    'What this host CLAIMED. ARP does not authenticate, so a binding is an announcement that was believed because it arrived, not a proven fact about the hardware at this address.',
})

const CONTESTED = record('ArpBinding', 'a-two', {
  name: '192.168.1.1 claimed by 3 hardware addresses',
  ip: '192.168.1.1',
  macs: ['00:1a:2b:3c:4d:5e', 'aa:bb:cc:dd:ee:ff'],
  contested: true,
  contested_from: '2026-03-01T09:15:00Z',
  macs_beyond_cap: 1,
  packets: 340,
  source_name: 'segment.pcap',
  content_incomplete: true,
  content_incomplete_reason: 'unresolved_structure',
  content_incomplete_detail: 'more than one hardware address claimed this address',
  statement:
    'MORE THAN ONE HARDWARE ADDRESS CLAIMED THIS ADDRESS. ARP does not authenticate: a reply is believed because it arrived, so this is the signature of ARP cache poisoning -- and it is equally what a failover pair, a DHCP lease handed to another machine, a replaced network card, a virtual machine moved between hosts and a dual-homed host look like. The claims and their times are above; no verdict is reached here.',
})

describe('ArpBinding viewer', () => {
  it('answers who claimed which address, how often, and from when it was contested', async () => {
    await renderType('ArpBinding', [ONE_CLAIMANT, CONTESTED])

    expect(headers()).toEqual([
      'Address claimed',
      'Claimed by',
      'Contested?',
      'Contested from',
      'Frames',
      'Artifact',
    ])

    const row = rowWith('192.168.1.20')
    expect(within(row).getByText('00:1a:2b:3c:4d:5e')).toBeInTheDocument()
    expect(within(row).getByText('12')).toBeInTheDocument()
  })

  it('heads the address column as a claim, because ARP does not authenticate', async () => {
    await renderType('ArpBinding', [ONE_CLAIMANT])
    expect(headers()).toContain('Address claimed')
    expect(headers()).toContain('Claimed by')
  })

  it('reads a contested address as a lead with its claimants counted, not as poisoning', async () => {
    await renderType('ArpBinding', [ONE_CLAIMANT, CONTESTED])

    const cell = cellUnder(rowWith('192.168.1.1'), 'Contested?')
    // Two listed plus one past the ceiling: the count is of claimants seen,
    // and the row says how many are not listed.
    expect(cell).toHaveTextContent('3 claimants')
    expect(cell).toHaveTextContent('1 not listed')
    const title = within(cell).getByText(/3 claimants/).getAttribute('title')
    expect(title).toContain('no verdict is reached here')
    expect(title).toContain('failover pair')
  })

  it('carries the announcement sentence on an uncontested binding too', async () => {
    await renderType('ArpBinding', [ONE_CLAIMANT])

    // "192.168.1.20 is 00:1a:2b:3c:4d:5e" reads as a fact and is a claim, so
    // the qualification is on the quiet rows as well as the loud ones.
    const cell = cellUnder(rowWith('192.168.1.20'), 'Contested?')
    expect(
      within(cell).getByText('one claimant').getAttribute('title'),
    ).toContain('ARP does not authenticate')
  })

  it('shows the instant the contest began, in the same UTC form as every other time column', async () => {
    await renderType('ArpBinding', [CONTESTED])

    expect(
      cellUnder(rowWith('192.168.1.1'), 'Contested from'),
    ).toHaveTextContent('2026-03-01 09:15:00 UTC')
  })
})

describe('pcap protocol viewer coverage', () => {
  // UI_TESTING.md §5: a record type an examiner needs, reaching a generic
  // key/value table, is a defect. These four are the types the pcap plugin
  // emits that were carrying the Analysis index's "generic view" badge.
  const PCAP_TAILORED = [
    'NetworkCapture',
    'NetworkFlow',
    'DnsResolution',
    'HttpTransaction',
    'TlsSession',
    'TlsCertificate',
    'ArpBinding',
  ]

  it('registers a tailored viewer for every browsable type the pcap plugin emits', () => {
    for (const type of PCAP_TAILORED) {
      expect(VIEWERS[type], `${type} has no tailored viewer`).toBeDefined()
    }
  })

  it('names these types the way a network examiner does', () => {
    expect(humanizeType('HttpTransaction')).toContain('HTTP')
    expect(humanizeType('TlsSession')).toContain('TLS')
    expect(humanizeType('TlsCertificate')).toContain('TLS')
    // "Arp Binding" is not what this is called; an examiner reads the label.
    expect(humanizeType('ArpBinding')).toContain('ARP')
  })
})

/**
 * The NetworkList profiles: a network the machine has BEEN on.
 *
 * The two time columns are why this viewer exists. `DateCreated` and
 * `DateLastConnected` are written in the machine's local time with no zone in
 * them, and the parser publishes an instant only where it could measure the
 * offset against the profile key's own last-written timestamp. A row must
 * therefore show the instant where there is one and the local time *marked as
 * such* where there is not — a local time formatted as though it were UTC is
 * how four to six hours get onto a report.
 */
describe('NetworkProfile viewer', () => {
  /** The measured domain profile from the real Windows 7 hive. */
  const measured = record('NetworkProfile', 'np-1', {
    name: 'shieldbase.local',
    network_name: 'shieldbase.local',
    profile_name: 'shieldbase.local',
    network_kind: 'wired',
    category: 'domain',
    managed_by_a_domain: true,
    date_last_connected: '2012-04-04T11:48:39.392+00:00',
    date_last_connected_local: '2012-04-04T07:48:39.392',
    date_created: '2010-11-10T15:23:43.671+00:00',
    date_created_local: '2010-11-10T11:23:43.671',
    time_zone_basis: 'measured_against_the_keys_own_write',
    time_zone_offset_minutes: -240,
    default_gateway_mac: '00:18:f8:ea:2e:a2',
    dns_suffix: '<none>',
  })

  /** The same shape with no measurable zone: no instant may be shown. */
  const unmeasured = record('NetworkProfile', 'np-2', {
    name: 'Coffee Shop Guest',
    network_name: 'Coffee Shop Guest',
    profile_name: 'Coffee Shop Guest',
    network_kind: 'wireless',
    category: 'public',
    managed_by_a_domain: false,
    date_last_connected_local: '2013-06-01T09:15:02.500',
    time_zone_basis: 'not_decidable',
    time_zone_note:
      'NO INSTANT IS CLAIMED for this profile. Its times are written in the machine local time with no zone recorded.',
    content_incomplete: true,
    content_incomplete_reason: 'unvalidated',
  })

  it('is tailored rather than falling through to the generic table', () => {
    expect(VIEWERS['NetworkProfile']).toBeDefined()
    expect(humanizeType('NetworkProfile')).toBe('Networks joined')
  })

  it('shows the network, its kind and the gateway MAC it was recognised by', async () => {
    await renderType('NetworkProfile', [measured])
    expect(headers()).toContain('Network')
    expect(headers()).toContain('Last connected')
    const row = rowWith('shieldbase.local')
    expect(cellUnder(row, 'Kind').textContent).toContain('wired')
    expect(cellUnder(row, 'Category').textContent).toContain('domain')
    expect(cellUnder(row, 'Gateway MAC').textContent).toContain(
      '00:18:f8:ea:2e:a2',
    )
  })

  it('marks a local time whose zone was not measured rather than showing it as an instant', async () => {
    await renderType('NetworkProfile', [unmeasured])
    const row = rowWith('Coffee Shop Guest')
    const cell = cellUnder(row, 'Last connected')
    expect(cell.textContent).toContain('2013-06-01T09:15:02.500')
    expect(cell.textContent).toContain('local, zone unknown')
  })

  it('counts the rows whose time cannot be placed as their own bucket', async () => {
    await renderType('NetworkProfile', [measured, unmeasured])
    // Folding them into "wireless" or "wired" would hide that one of these
    // two networks cannot be put on a timeline at all.
    expect(screen.getByText(/No instant \(zone unknown\)/)).toBeInTheDocument()
  })
})

/**
 * The wireless profiles, macOS and Windows, on one screen.
 *
 * Four key states — in the clear, DPAPI-protected, protection not stated, and
 * no key at all — are four different findings, and on the generic table they
 * were four identical rows: the eight columns it showed were the network's
 * name in four forms and a truncated paragraph. The passphrase is what an
 * examiner opens the file for and the DPAPI case is the one they must not
 * mistake for it.
 */
describe('WifiNetwork viewer', () => {
  const clear = record('WifiNetwork', 'w-1', {
    subtype: 'windows_profile',
    platform: 'windows',
    name: 'Wi-Fi network: HomeWiFi',
    ssid: 'HomeWiFi',
    profile_name: 'HomeWiFi',
    authentication: 'WPA2PSK',
    encryption: 'AES',
    security_types: ['WPA2PSK', 'AES'],
    hidden_network: false,
    connects_automatically: true,
    key_state: 'in_the_clear',
    key: 'hunter2',
    key_statement: 'The pre-shared key is IN THIS FILE IN PLAIN TEXT',
    join_times_available: false,
    join_times_note: 'This profile carries NO timestamps',
  })
  const dpapi = record('WifiNetwork', 'w-2', {
    subtype: 'windows_profile',
    platform: 'windows',
    name: 'Wi-Fi network: Coffee Shop Guest',
    ssid: 'Coffee Shop Guest',
    authentication: 'WPA2PSK',
    security_types: ['WPA2PSK', 'AES'],
    key_state: 'dpapi_protected',
    key_dpapi: { master_key_guid: '9c0a1b2c-3d4e-5f60-7182-93a4b5c6d7e8' },
    key_statement: 'The key is a DPAPI blob encrypted under the machine master key',
    content_incomplete: true,
    content_incomplete_reason: 'encrypted',
  })
  const notStated = record('WifiNetwork', 'w-3', {
    subtype: 'windows_profile',
    platform: 'windows',
    name: 'Wi-Fi network: Airport',
    ssid: 'Airport',
    key_state: 'protection_not_stated',
    key_statement: 'THIS DOCUMENT DOES NOT SAY whether its key is protected',
    content_incomplete: true,
    content_incomplete_reason: 'unresolved_structure',
  })
  const macos = record('WifiNetwork', 'w-4', {
    subtype: 'known_network',
    platform: 'macos',
    name: 'Wi-Fi network: eduroam',
    ssid: 'eduroam',
    security_types: ['WPA2 Enterprise'],
    last_joined_rfc3339: '2022-02-14T18:26:03Z',
  })

  it('is tailored rather than falling through to the generic table', () => {
    expect(VIEWERS['WifiNetwork']).toBeDefined()
    expect(humanizeType('WifiNetwork')).toBe('Wireless networks')
  })

  it('shows a cleartext key as the value it is', async () => {
    await renderType('WifiNetwork', [clear])
    const row = rowWith('HomeWiFi')
    const cell = cellUnder(row, 'Key')
    expect(cell.textContent).toContain('in the clear')
    expect(cell.textContent).toContain('hunter2')
    expect(cellUnder(row, 'Joins by itself?').textContent).toContain('automatic')
  })

  it('never renders a protected key, an unstated one and no key as the same thing', async () => {
    await renderType('WifiNetwork', [clear, dpapi, notStated, macos])
    expect(cellUnder(rowWith('Coffee Shop Guest'), 'Key').textContent).toContain(
      'DPAPI, not decrypted',
    )
    expect(cellUnder(rowWith('Airport'), 'Key').textContent).toContain(
      'protection not stated',
    )
    // The macOS record carries no key field at all, which is a different
    // statement again from a profile that carries none.
    expect(cellUnder(rowWith('eduroam'), 'Key').textContent).toContain(
      'not recorded here',
    )
    // And the four states are counted apart on the tiles.
    expect(screen.getByText(/Key in the clear/)).toBeInTheDocument()
    expect(screen.getByText(/Key protected, not decrypted/)).toBeInTheDocument()
    expect(screen.getByText(/Protection not stated/)).toBeInTheDocument()
  })

  it('says a Windows profile carries no join time rather than showing an empty date', async () => {
    await renderType('WifiNetwork', [clear, macos])
    expect(cellUnder(rowWith('HomeWiFi'), 'Last joined').textContent).toContain(
      'no join time in this record',
    )
    expect(
      cellUnder(rowWith('eduroam'), 'Last joined').textContent,
    ).not.toContain('no join time')
  })
})

/**
 * The generic table drops every field past the eighth and said nothing about
 * it. On the wireless profiles that meant a cleartext passphrase, a
 * DPAPI-protected key and no key at all rendered as three identical rows,
 * because `key_state` was the ninth key — the same class of defect the
 * tailored viewers above exist to prevent, in the shell they all fall back to.
 */
describe('the generic table discloses what it is not showing', () => {
  function renderGeneric(metadata: Record<string, unknown>) {
    render(
      <MemoryRouter>
        <GenericViewer
          records={[record('SomeUnviewedRecord', 'g-1', metadata)]}
          caseId={CASE_ID}
          type="SomeUnviewedRecord"
        />
      </MemoryRouter>,
    )
  }

  it('names the number of fields it dropped', () => {
    const metadata: Record<string, unknown> = {}
    for (let i = 0; i < 20; i++) metadata[`field_${i}`] = `value ${i}`
    renderGeneric(metadata)
    expect(screen.getByText(/not shown here/)).toBeInTheDocument()
    // Twenty fields, eight shown: the sentence names the twelve it dropped,
    // and the number is read off the rendered text rather than typed here.
    // The number is read off the rendered text rather than typed here:
    // twenty fields, eight shown, twelve named as not shown.
    const strong = screen.getByText(/not shown here/).textContent ?? ''
    expect(strong).toMatch(/12 more/)
    const paragraph = screen.getByText(/no tailored view/).textContent ?? ''
    expect(paragraph).toMatch(/shows the 8 fields ranked highest/)
  })

  it('says nothing when every field is on the screen', () => {
    renderGeneric({ a: '1', b: '2' })
    expect(screen.queryByText(/not shown here/)).not.toBeInTheDocument()
  })
})
