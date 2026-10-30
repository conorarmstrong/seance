import { useQuery } from '@tanstack/react-query'
import { useMemo } from 'react'
import {
  IncompletenessBanner,
  useIncompleteness,
} from '../../components/Incompleteness'
import { formatCount, formatUtc } from '../../lib/format'
import { useEntityScopedState } from '../../lib/useEntityScopedState'
import { getMessagingRecords, type MessagingRecord } from './api'
import { PivotName } from '../analysis/cells'

// Messaging records are parsed from the chat database as ParsedRecord children
// tagged with one of these `type` values. Kept in sync with the chat-emitting
// plugins (see comms/normalize.ts) so Signal/Telegram/Skype/etc. conversations
// are not silently empty when their ParsedRecords exist. Call logs and email are
// intentionally excluded — they are not thread/message conversations.
const MESSAGING_TYPES = [
  'iMessage',
  'WhatsApp',
  'AndroidSms',
  'Signal',
  'TelegramMessage',
  'Skype',
  'Viber',
  'Kik',
  'LINE',
  'FacebookMessenger',
  'WeChat',
  'Instagram',
  'Snapchat',
  'TwitterDM',
] as const

/** Coerce a metadata value to a non-empty display string, or null. */
function mstr(meta: Record<string, unknown>, key: string): string | null {
  const value = meta[key]
  if (value == null) return null
  if (typeof value === 'string') return value.length ? value : null
  if (typeof value === 'number' || typeof value === 'boolean') {
    return String(value)
  }
  return null
}

/** First present key from a list of candidates. */
function mfirst(meta: Record<string, unknown>, keys: string[]): string | null {
  for (const key of keys) {
    const value = mstr(meta, key)
    if (value != null) return value
  }
  return null
}

/** Coerce a metadata value to a boolean flag (bool / 0-1 / "true"). */
function mbool(meta: Record<string, unknown>, key: string): boolean {
  const value = meta[key]
  if (typeof value === 'boolean') return value
  if (typeof value === 'number') return value !== 0
  if (typeof value === 'string') return value === 'true' || value === '1'
  return false
}

/** Coerce a raw timestamp (ISO string or unix seconds/ms) to an ISO string. */
function toIso(raw: string): string {
  const n = Number(raw)
  if (raw.trim() !== '' && !Number.isNaN(n) && !/[-:T]/.test(raw)) {
    const ms = n > 1e12 ? n : n * 1000
    return new Date(ms).toISOString()
  }
  return raw
}

// Fields used to group messages into threads and to label them. iMessage and
// WhatsApp expose different columns, so both key sets are tried in order.
const THREAD_KEYS = [
  'chat_identifier',
  'remote_jid',
  'chat_subject',
  'chat_display_name',
  'contact_jid',
  'contact',
  'contact_name',
  'phone_number',
]
const LABEL_KEYS = [
  'chat_display_name',
  'chat_subject',
  'contact_name',
  'contact',
  'chat_identifier',
  'remote_jid',
  'contact_jid',
  'phone_number',
]
const SENDER_KEYS = [
  'contact',
  'contact_name',
  'chat_display_name',
  'chat_identifier',
  'phone_number',
  'remote_jid',
  'contact_jid',
]

interface Message {
  id: string
  text: string | null
  iso: string | null
  fromMe: boolean
  sender: string
  /** The handle the database stored, for the pivot; `null` for my own
   *  messages and for a message nobody attributed. */
  senderHandle: string | null
  tag: string | null
  hasAttachment: boolean
  sortKey: number
}

interface Thread {
  key: string
  label: string
  messages: Message[]
  lastTime: number
}

/** Group flat messaging records into threads, sorted newest-thread first. */
function buildThreads(records: MessagingRecord[]): Thread[] {
  const map = new Map<string, Thread>()
  for (const record of records) {
    const m = record.metadata
    const key = mfirst(m, THREAD_KEYS) ?? 'Unknown'
    const fromMe = mbool(m, 'is_from_me') || mstr(m, 'direction') === 'sent'
    const dateRaw = mstr(m, 'date')
    const iso = dateRaw && dateRaw !== '0' ? toIso(dateRaw) : null
    const parsed = iso ? Date.parse(iso) : NaN
    const sortKey = Number.isNaN(parsed) ? 0 : parsed
    const message: Message = {
      id: record.id,
      text: mstr(m, 'text'),
      iso,
      fromMe,
      sender: fromMe ? 'Me' : (mfirst(m, SENDER_KEYS) ?? 'Unknown'),
      senderHandle: fromMe ? null : mfirst(m, SENDER_KEYS),
      tag: mfirst(m, ['service', 'platform']),
      hasAttachment:
        mbool(m, 'has_attachments') || mbool(m, 'cache_has_attachments'),
      sortKey,
    }
    let thread = map.get(key)
    if (!thread) {
      thread = { key, label: mfirst(m, LABEL_KEYS) ?? key, messages: [], lastTime: 0 }
      map.set(key, thread)
    }
    thread.messages.push(message)
    if (sortKey > thread.lastTime) thread.lastTime = sortKey
  }
  const threads = [...map.values()]
  for (const thread of threads) {
    thread.messages.sort((a, b) => a.sortKey - b.sortKey)
  }
  threads.sort((a, b) => b.lastTime - a.lastTime)
  return threads
}

export function ConversationTab({
  caseId,
  artifactId,
}: {
  caseId: string
  artifactId: string
}) {
  const query = useQuery({
    queryKey: ['artifact-conversation', caseId, artifactId],
    queryFn: async () => {
      const groups = await Promise.all(
        MESSAGING_TYPES.map(async (type) => ({
          type,
          ...(await getMessagingRecords(caseId, artifactId, type)),
        })),
      )
      const records = groups.flatMap((g) => g.records)
      // A per-type safety cap stopped at least one drain: what is below is a
      // floor for those types, not the conversation.
      const cappedTypes = groups
        .filter((g) => g.truncated)
        .map((g) => ({
          type: g.type,
          loaded: g.records.length,
          total: g.total,
          cap: g.cap,
        }))
      return { records, cappedTypes }
    },
  })

  const records = query.data?.records
  const cappedTypes = query.data?.cappedTypes ?? []
  const threads = useMemo(() => buildThreads(records ?? []), [records])
  // The parsers stamp the standard incompleteness pair on records they could
  // not finish reading; a chat database read part-way says so there and
  // nowhere else.
  const incompleteness = useIncompleteness(records)
  // The thread on screen belongs to THIS chat database in THIS case. Thread
  // keys are the chat's own identifiers — a phone number, a JID, `Unknown` —
  // so the same key routinely exists in two different databases and in two
  // different cases. This page stays mounted when `:artifactId` (or `:caseId`)
  // changes, so an unscoped selection follows the examiner into the next chat
  // database and silently opens whichever thread happens to share the key,
  // presented as the thread they picked. Scoped on both ids because artifact
  // UUIDs are per-case (BUG-259 class).
  const scopeKey = `${caseId}/${artifactId}`
  const [activeKey, setActiveKey] = useEntityScopedState<string | null>(
    scopeKey,
    null,
  )
  const active = threads.find((t) => t.key === activeKey) ?? threads[0] ?? null

  if (query.isPending) {
    return <div className="loading">Loading conversation...</div>
  }
  if (query.isError) {
    return (
      <div className="error-note">
        Failed to load conversation: {query.error.message}
      </div>
    )
  }
  if (threads.length === 0) {
    return (
      <div className="empty-state">
        <h3>No conversations</h3>
        <p>No messaging records were parsed from this database.</p>
      </div>
    )
  }

  return (
    <div>
      {/* Outside `.av-conv`: that is a two-column grid, and a banner dropped
          into it becomes a column rather than a heading over the whole view. */}
      {cappedTypes.length > 0 && (
        <div
          className="warn-note incomplete-note"
          role="note"
          data-testid="av-conv-capped"
        >
          <p className="incomplete-lede">
            This conversation view stops at a safety cap. The threads and
            message counts below are a floor, not the contents of the database:
            messages exist in this evidence that are not shown here.
          </p>
          <ul className="incomplete-reasons">
            {cappedTypes.map((c) => (
              <li key={c.type}>
                <span className="badge badge-warn">{c.type}</span>{' '}
                <span>
                  {formatCount(c.loaded)} of {formatCount(c.total)}{' '}
                  messages loaded; the viewer reads at most{' '}
                  {formatCount(c.cap)} per messaging type.
                </span>
              </li>
            ))}
          </ul>
        </div>
      )}
      <IncompletenessBanner summary={incompleteness} noun="messages" />
      <div className="av-conv">
      <div className="panel av-threads" data-testid="av-thread-list">
        {threads.map((thread) => (
          <button
            key={thread.key}
            className={
              thread.key === active?.key ? 'av-thread active' : 'av-thread'
            }
            onClick={() => setActiveKey(thread.key)}
          >
            <span>{thread.label}</span>
            <span className="av-thread-count">{thread.messages.length}</span>
          </button>
        ))}
      </div>
      <div className="panel">
        {active && active.messages.length > 0 ? (
          <div className="av-msgs">
            {active.messages.map((message) => (
              <div
                key={message.id}
                className={message.fromMe ? 'av-msg av-msg-out' : 'av-msg'}
              >
                <div className="av-msg-meta mono">
                  {/* The sender is a pivot trigger on the handle the database
                      stored (§5.1): one click from everything else in the case
                      that touches this participant. */}
                  <PivotName
                    pivotOn={message.senderHandle}
                    label={message.sender}
                  />
                  {' · '}
                  {message.iso ? formatUtc(message.iso) : '—'}
                  {message.tag ? ` · ${message.tag}` : ''}
                </div>
                <div className="av-msg-body">{message.text ?? '—'}</div>
                {message.hasAttachment && (
                  <span className="badge av-msg-attach">attachment</span>
                )}
              </div>
            ))}
          </div>
        ) : (
          <p className="av-note">No messages in this thread.</p>
        )}
      </div>
      </div>
    </div>
  )
}
