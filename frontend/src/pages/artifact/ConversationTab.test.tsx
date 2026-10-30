import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { http, HttpResponse } from 'msw'
import { describe, expect, it } from 'vitest'
import { server } from '../../test/server'
import { PivotCtx } from '../../app/PivotContext'
import { ConversationTab } from './ConversationTab'
import { formatCount } from '../../lib/format'

interface Rec {
  id: string
  metadata: Record<string, unknown>
}

function rec(id: string, metadata: Record<string, unknown>): Rec {
  return { id, metadata }
}

// Alice thread (iMessage): received "hi alice", then sent "hello back" with an
// attachment. Bob thread (WhatsApp): a single received message.
const iMessages: Rec[] = [
  rec('m-a1', {
    type: 'iMessage',
    text: 'hi alice',
    date: '1700000000',
    is_from_me: false,
    direction: 'received',
    contact: 'Alice',
    chat_identifier: 'chat-alice',
    service: 'iMessage',
    has_attachments: false,
  }),
  rec('m-a2', {
    type: 'iMessage',
    text: 'hello back',
    date: '1700000300',
    is_from_me: true,
    direction: 'sent',
    contact: 'Alice',
    chat_identifier: 'chat-alice',
    service: 'iMessage',
    has_attachments: true,
  }),
]

const whatsApp: Rec[] = [
  rec('m-b1', {
    type: 'WhatsApp',
    text: 'yo from bob',
    date: '1700000200',
    is_from_me: false,
    direction: 'received',
    contact_name: 'Bob',
    remote_jid: 'bob@s.whatsapp.net',
    platform: 'Android',
    has_attachments: false,
  }),
]

/** Second chat database in the same case: Bob is here too, Carol is newer. */
const otherDbMessages: Rec[] = [
  rec('m-c1', {
    type: 'iMessage',
    text: 'carol speaking',
    date: '1700009000',
    is_from_me: false,
    direction: 'received',
    contact: 'Carol',
    chat_identifier: 'chat-carol',
    service: 'iMessage',
    has_attachments: false,
  }),
  rec('m-b2', {
    type: 'iMessage',
    // Same thread key as the WhatsApp thread selected in the first database,
    // which is what an unscoped selection latches onto.
    text: 'different bob entirely',
    date: '1700008000',
    is_from_me: false,
    direction: 'received',
    contact_name: 'Bob',
    remote_jid: 'bob@s.whatsapp.net',
    service: 'iMessage',
    has_attachments: false,
  }),
]

function mockRecords(imessage: Rec[], whatsapp: Rec[]) {
  server.use(
    http.get(
      '/api/v1/cases/:caseId/records',
      ({ request }) => {
        const url = new URL(request.url)
        const type = url.searchParams.get('type')
        // A second chat database in the same case, addressed by source_id.
        if (url.searchParams.get('source_id') === 'art-other') {
          const list = type === 'iMessage' ? otherDbMessages : []
          return HttpResponse.json({
            records: list.map((r) => ({
              id: r.id,
              parent_id: 'art-other',
              artifact_type: 'ParsedRecord',
              metadata: r.metadata,
            })),
            total: list.length,
            page: 1,
            page_size: 500,
            type,
          })
        }
        const list =
          type === 'iMessage' ? imessage : type === 'WhatsApp' ? whatsapp : []
        return HttpResponse.json({
          records: list.map((r) => ({
            id: r.id,
            parent_id: 'art-chat',
            artifact_type: 'ParsedRecord',
            metadata: r.metadata,
          })),
          total: list.length,
          page: 1,
          page_size: 500,
          type,
        })
      },
    ),
  )
}

function renderTab() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  })
  const ui = (caseId: string, artifactId: string) => (
    <QueryClientProvider client={queryClient}>
      <ConversationTab caseId={caseId} artifactId={artifactId} />
    </QueryClientProvider>
  )
  const utils = render(ui('case-1', 'art-chat'))
  return {
    ...utils,
    /** Navigate to another chat database without unmounting the tab. */
    open: (caseId: string, artifactId: string) => utils.rerender(ui(caseId, artifactId)),
  }
}

describe('ConversationTab', () => {
  it('renders threaded messages with direction classes and an attachment chip', async () => {
    mockRecords(iMessages, whatsApp)
    renderTab()
    // Both threads appear in the thread list (Alice is newest, so active).
    // Scoped to the thread list: the participant's name now also appears on
    // each message as a pivot trigger (§5.1), so a bare text query is
    // ambiguous.
    const threadList = await screen.findByTestId('av-thread-list')
    expect(
      within(threadList).getByRole('button', { name: /^Alice/ }),
    ).toBeInTheDocument()
    expect(
      within(threadList).getByRole('button', { name: /^Bob/ }),
    ).toBeInTheDocument()
    // Sent bubble carries the outgoing class; received does not.
    const sent = await screen.findByText('hello back')
    expect(sent.closest('.av-msg')).toHaveClass('av-msg-out')
    const received = screen.getByText('hi alice')
    expect(received.closest('.av-msg')).not.toHaveClass('av-msg-out')
    // Attachment chip is scoped to the sent bubble.
    const chip = screen.getByText('attachment')
    expect(chip).toHaveClass('badge')
    expect(chip.closest('.av-msg')).toHaveClass('av-msg-out')
  })

  it('switches threads', async () => {
    mockRecords(iMessages, whatsApp)
    renderTab()
    await screen.findByText('hello back')
    await userEvent.click(screen.getByText('Bob'))
    expect(await screen.findByText('yo from bob')).toBeInTheDocument()
    await waitFor(() =>
      expect(screen.queryByText('hello back')).not.toBeInTheDocument(),
    )
  })

  it('never carries a thread selection into another chat database (B2-175 class)', async () => {
    // Thread keys are the chat's own identifiers — a phone number, a JID —
    // so the same key routinely exists in two databases. The artifact page
    // stays mounted when `:artifactId` changes, so an unscoped selection
    // follows the examiner across and opens whichever thread shares the key,
    // presented as the one they picked. Here the second database opens on
    // Bob's messages instead of its own newest thread, Carol.
    mockRecords(iMessages, whatsApp)
    const { open } = renderTab()
    await screen.findByText('hello back')
    await userEvent.click(screen.getByText('Bob'))
    expect(await screen.findByText('yo from bob')).toBeInTheDocument()

    open('case-1', 'art-other')

    // The second database opens on ITS newest thread, not on the key carried
    // over from the first.
    expect(await screen.findByText('carol speaking')).toBeInTheDocument()
    expect(screen.queryByText('different bob entirely')).not.toBeInTheDocument()
  })

  it('never carries a thread selection into another case (B2-175 class)', async () => {
    // Artifact UUIDs are per-case, so the same id can name a different chat
    // database under another case; the selection has to be scoped by both.
    mockRecords(iMessages, whatsApp)
    const { open } = renderTab()
    await screen.findByText('hello back')
    await userEvent.click(screen.getByText('Bob'))
    await screen.findByText('yo from bob')

    // Same artifact id, different case: the records endpoint is case-scoped,
    // so this is the first database's content under case-2's chrome. What
    // must not survive is the selection.
    open('case-2', 'art-chat')

    await waitFor(() =>
      expect(screen.getByText('hello back')).toBeInTheDocument(),
    )
    expect(screen.queryByText('yo from bob')).not.toBeInTheDocument()
  })

  it('shows an empty state when no messaging records exist', async () => {
    mockRecords([], [])
    renderTab()
    expect(await screen.findByText('No conversations')).toBeInTheDocument()
    expect(
      screen.getByText(/No messaging records were parsed/),
    ).toBeInTheDocument()
  })

  it('says so when the safety cap stops the read short of the thread (B4-004)', async () => {
    // The viewer drains 500-row pages up to 5,000 messages per messaging type.
    // A database with more than that used to render as a complete conversation.
    const PAGE = 500
    const CAP = 5000
    const TOTAL = 6000
    server.use(
      http.get('/api/v1/cases/:caseId/records', ({ request }) => {
        const url = new URL(request.url)
        const type = url.searchParams.get('type')
        const page = Number(url.searchParams.get('page') ?? '1')
        if (type !== 'iMessage') {
          return HttpResponse.json({
            records: [],
            total: 0,
            page,
            page_size: PAGE,
            type,
          })
        }
        return HttpResponse.json({
          records: Array.from({ length: PAGE }, (_, i) => ({
            id: `m-${page}-${i}`,
            parent_id: 'art-chat',
            artifact_type: 'ParsedRecord',
            metadata: {
              type: 'iMessage',
              text: `msg ${page}-${i}`,
              date: String(1700000000 + page * PAGE + i),
              is_from_me: false,
              contact: 'Alice',
              chat_identifier: 'chat-alice',
            },
          })),
          total: TOTAL,
          page,
          page_size: PAGE,
          type,
        })
      }),
    )
    renderTab()

    const note = await screen.findByTestId('av-conv-capped', undefined, {
      timeout: 15_000,
    })
    const said = (note.textContent ?? '').replace(/\s+/g, ' ').trim()
    expect(said).toContain('stops at a safety cap')
    expect(said).toContain(
      `${formatCount(CAP)} of ${formatCount(TOTAL)} messages loaded`,
    )
  }, 30_000)

  it('reports the standard incompleteness pair stamped on messages', async () => {
    mockRecords(
      [
        rec('m-a1', {
          type: 'iMessage',
          text: 'hi alice',
          date: '1700000000',
          contact: 'Alice',
          chat_identifier: 'chat-alice',
          content_incomplete: true,
          content_incomplete_reason: 'cap_reached',
        }),
      ],
      [],
    )
    renderTab()
    expect(
      await screen.findByText(/declares itself\s+incomplete/),
    ).toBeInTheDocument()
    expect(
      screen.getByText(/a parser safety cap stopped the read/),
    ).toBeInTheDocument()
  })

  it('shows an error state when the records endpoint fails', async () => {
    server.use(
      http.get('/api/v1/cases/:caseId/records', () =>
        HttpResponse.json(
          { error: { code: 'INTERNAL', message: 'records unavailable' } },
          { status: 500 },
        ),
      ),
    )
    renderTab()
    expect(
      await screen.findByText(/Failed to load conversation/),
    ).toBeInTheDocument()
  })
})

/**
 * §5.1. A participant's name in a thread is a pivot trigger on the handle the
 * chat database stored — the identifier the rest of the case carries — so
 * "what else touches this person" is one click from the conversation. My own
 * messages have no counterparty to pivot on, and offering a dead affordance
 * on them would be worse than none.
 */
describe('ConversationTab participant pivots', () => {
  it('pivots on the stored handle, and offers nothing on my own messages', async () => {
    mockRecords(iMessages, whatsApp)
    const pivoted: string[] = []
    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    })
    render(
      <PivotCtx.Provider value={{ openPivot: (v) => pivoted.push(v) }}>
        <QueryClientProvider client={queryClient}>
          <ConversationTab caseId="case-1" artifactId="art-chat" />
        </QueryClientProvider>
      </PivotCtx.Provider>,
    )

    // The received message's sender is a trigger; the sent one ("Me") is not.
    const trigger = await screen.findByRole('button', { name: 'Alice' })
    await userEvent.click(trigger)
    expect(pivoted).toEqual(['Alice'])
    expect(screen.queryByRole('button', { name: 'Me' })).toBeNull()
    // ...but "Me" is still shown, so the bubble still says who sent it.
    expect(screen.getByText(/^Me$/)).toBeInTheDocument()
  })
})
