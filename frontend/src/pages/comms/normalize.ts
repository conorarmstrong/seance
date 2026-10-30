import type { ParsedRecord } from '../analysis/api'
import { metaBool, metaStr } from '../analysis/lib'
import { toEpochMs } from '../execution/normalize'

export type CommChannel =
  | 'iMessage'
  | 'WhatsApp'
  | 'Signal'
  | 'SMS'
  | 'Call'
  | 'Email'
  | 'Viber'
  | 'Kik'
  | 'Skype'
  | 'LINE'
  | 'Telegram'
  | 'Messenger'
  | 'WeChat'
  | 'Instagram'
  | 'Snapchat'
  | 'Twitter'
export type CommDirection = 'in' | 'out' | 'unknown'

/**
 * What a communication row can actually show, and — when it can show nothing —
 * what it is instead.
 *
 * A row that dead-ends is the defect this type exists to prevent. The comms
 * table used to carry no content at all, so reading an exchange meant clicking
 * through to a record page whose only tab is the raw JSON of one message. The
 * fix is not to dump the blob into the table: it is to render the field the
 * record holds, and where there is no such field, to name what the record IS.
 * "No text — this is a call, 2:34" and "no text recorded" are different facts,
 * and neither of them is an empty cell.
 */
export type CommContent =
  /** The message text as the parser recorded it. */
  | { kind: 'text'; text: string }
  /** An email's subject. The body is not loaded by this page. */
  | { kind: 'subject'; text: string }
  /** A call has no text; its duration is what there is to say. */
  | { kind: 'call'; durationSeconds: number | null }
  /** Nothing renderable, and the reason, in a sentence. */
  | { kind: 'none'; because: string }

/** One normalised communication event across all messaging/call/email sources. */
export interface CommEvent {
  artifactId: string
  contact: string
  channel: CommChannel
  direction: CommDirection
  time: number | null
  /** The ParsedRecord type this came from, which the record viewers key on. */
  recordType: string
  /**
   * The conversation this message belongs to, as the SERVER groups
   * conversations — or null where no thread view exists for the type (calls,
   * a call) or where the key could not be addressed. See `threadKeyOf`.
   */
  threadKey: string | null
  /** What the row shows, or what it is instead. */
  content: CommContent
}

/**
 * The channel label each ParsedRecord type is shown under. Exported because the
 * server-side ranking endpoint is parameterised by the type name on the left
 * while the page's tiles are labelled with the channel on the right, so the
 * tile filter has to be translated back through this map before it can be sent.
 * Deriving the inverse from this one declaration is what stops the two drifting
 * — a hand-written second map would send a stale type name and be answered with
 * an empty ranking that reads as a fact about the case.
 */
export const CHANNEL_OF: Record<string, CommChannel> = {
  iMessage: 'iMessage',
  WhatsApp: 'WhatsApp',
  Signal: 'Signal',
  AndroidSms: 'SMS',
  CallLog: 'Call',
  EmailMessage: 'Email',
  Viber: 'Viber',
  Kik: 'Kik',
  Skype: 'Skype',
  LINE: 'LINE',
  TelegramMessage: 'Telegram',
  FacebookMessenger: 'Messenger',
  WeChat: 'WeChat',
  Instagram: 'Instagram',
  Snapchat: 'Snapchat',
  TwitterDM: 'Twitter',
}

/** ParsedRecord types the communications view correlates. Keep in sync with the
 * chat-emitting plugins so a new messenger shows up in the unified timeline. */
export const COMMS_TYPES = [
  'iMessage',
  'WhatsApp',
  'Signal',
  'AndroidSms',
  'CallLog',
  'EmailMessage',
  'Viber',
  'Kik',
  'Skype',
  'LINE',
  'TelegramMessage',
  'FacebookMessenger',
  'WeChat',
  'Instagram',
  'Snapchat',
  'TwitterDM',
] as const

/**
 * The metadata keys a thread is grouped on, per record type.
 *
 * MIRRORS `SqliteConnection::thread_key_expr` (seance_db/src/lib.rs), key for
 * key and in order. It has to, and the consequence of drift is worse than an
 * empty screen: `MessagingViewer` opens the FIRST thread in its list when the
 * `conv` key it is handed matches none of them, so a key computed even slightly
 * differently from the server's lands the examiner in somebody else's
 * conversation, reached by clicking a row bearing the right correspondent's
 * name. `normalize.test.ts` pins every entry for that reason.
 *
 * Types absent from this table — `CallLog` — have no thread view to address,
 * which is why the server returns no key expression for them either.
 *
 * `EmailMessage` is the one entry that is a SINGLE field rather than a
 * fallback chain, and deliberately so. Email has no thread field in the
 * evidence; it has a chain of `Message-ID` / `In-Reply-To` / `References`
 * headers, and `seance_plugin_email::thread` walks that chain at parse time and
 * publishes its root as `email_thread_key`. So there is nothing to COALESCE
 * here, and a message with no key belongs to no exchange the evidence can
 * address — it gets no link, and the record says why (§5.14).
 */
const THREAD_KEYS: Record<string, string[]> = {
  iMessage: ['chat_identifier', 'chat_display_name', 'contact'],
  EmailMessage: ['email_thread_key'],
  WhatsApp: ['contact_jid', 'remote_jid', 'from_jid', 'chat_subject'],
  AndroidSms: ['chat_identifier', 'contact', 'thread_id'],
  Signal: ['chat_identifier', 'chat_display_name', 'contact', 'thread_id'],
  Instagram: ['chat_identifier', 'conversation_id', 'thread_id'],
  Snapchat: ['chat_identifier', 'conversation_id', 'thread_id'],
  TwitterDM: ['chat_identifier', 'conversation_id', 'thread_id'],
  // The server's GENERIC_THREAD_KEY, shared by the remaining messengers.
  Skype: GENERIC_THREAD_KEYS(),
  LINE: GENERIC_THREAD_KEYS(),
  TelegramMessage: GENERIC_THREAD_KEYS(),
  Viber: GENERIC_THREAD_KEYS(),
  Kik: GENERIC_THREAD_KEYS(),
  WeChat: GENERIC_THREAD_KEYS(),
  FacebookMessenger: GENERIC_THREAD_KEYS(),
}

function GENERIC_THREAD_KEYS(): string[] {
  return [
    'chat_identifier',
    'chat_display_name',
    'conversation_id',
    'thread_id',
    'contact',
  ]
}

/**
 * A metadata value usable as a conversation key, or null.
 *
 * Deliberately stricter than `metaStr`: only a non-empty STRING counts. The
 * server reads the grouped key back as TEXT and drops any conversation whose
 * key did not decode as one, so a thread keyed on a numeric `thread_id` is not
 * in the list the viewer loads at all. Coercing that number here would produce
 * a key that matches nothing — and an unmatched key does not show an error, it
 * opens the first thread in the list. Withholding the link is the only
 * behaviour that cannot mislead.
 */
/**
 * The conversation key for a record, or null where none can be addressed.
 *
 * The walk reproduces SQL `COALESCE`, which stops at the first key that is
 * PRESENT — not at the first key that happens to be a string. So a record whose
 * first present key holds a number is grouped by the server under that number,
 * a key its own conversation list then discards; the thread is not in the
 * viewer's list, and handing the viewer any key at all would open the first
 * thread instead. Such a record gets no conversation link, and the row says so.
 */
function threadKeyOf(type: string, m: Record<string, unknown>): string | null {
  const keys = THREAD_KEYS[type]
  if (!keys) return null
  for (const key of keys) {
    const v = m[key]
    // `json_extract` returns SQL NULL only for a key that is absent or null;
    // everything else — including an empty string — terminates the COALESCE.
    if (v == null) continue
    return typeof v === 'string' && v.length > 0 ? v : null
  }
  // Every key absent. Most of the server's expressions end in the literal
  // 'unknown', so those records are grouped into a thread of that name and the
  // link lands on that same catch-all thread.
  //
  // `EmailMessage` is the exception, and the server's expression has no such
  // fallback: a message carrying none of the three threading headers belongs
  // to no exchange the evidence can address, and grouping every such message
  // in a mailbox under one key would present a conversation that never
  // existed. Those messages are absent from the thread list, so a link
  // offered here would land on somebody else's exchange (§5.14).
  return type === 'EmailMessage' ? null : 'unknown'
}

/**
 * iMessage writes U+FFFC (object replacement) into a message's text where an
 * attachment sits. A message whose whole text is that placeholder carries no
 * text, and the row says so rather than drawing a replacement box.
 */
function messageText(raw: string | null): string | null {
  if (raw == null) return null
  const cleaned = raw.replace(/￼/g, '').trim()
  return cleaned.length > 0 ? cleaned : null
}

/** What this record has to show, or what it is instead. */
function contentOf(type: string, m: Record<string, unknown>): CommContent {
  if (type === 'CallLog') {
    const secs = m['duration_seconds']
    return {
      kind: 'call',
      durationSeconds: typeof secs === 'number' ? secs : null,
    }
  }
  if (type === 'EmailMessage') {
    const subject = metaStr(m, 'subject')
    if (subject) return { kind: 'subject', text: subject }
    return {
      kind: 'none',
      because: 'This email record carries no subject line.',
    }
  }

  const raw = metaStr(m, 'text') ?? metaStr(m, 'body') ?? metaStr(m, 'message')
  const text = messageText(raw)
  if (text) return { kind: 'text', text }
  if (raw != null) {
    return {
      kind: 'none',
      because: 'The only text this record carries is an attachment placeholder.',
    }
  }
  return { kind: 'none', because: 'This record carries no message text.' }
}

/**
 * Normalise one comms ParsedRecord type into unified events. Summary rows and
 * rows without a counterparty are dropped. Direction is derived from
 * `is_from_me` / a `direction` field where present.
 */
export function normalizeComms(
  type: string,
  records: ParsedRecord[],
): CommEvent[] {
  const channel = CHANNEL_OF[type]
  if (!channel) return []

  const out: CommEvent[] = []
  for (const r of records) {
    const m = r.metadata
    if (metaStr(m, 'subtype') === 'summary') continue

    const contact =
      metaStr(m, 'contact') ??
      metaStr(m, 'chat_display_name') ??
      metaStr(m, 'contact_name') ??
      metaStr(m, 'chat_identifier') ??
      metaStr(m, 'sender') ??
      metaStr(m, 'sender_screen_name') ??
      metaStr(m, 'contact_jid') ??
      metaStr(m, 'remote_jid') ??
      metaStr(m, 'from') ??
      metaStr(m, 'from_name')
    if (!contact) continue

    let direction: CommDirection = 'unknown'
    if (m['is_from_me'] != null) {
      // An explicit is_from_me settles it: not-from-me means inbound.
      direction = metaBool(m, 'is_from_me') ? 'out' : 'in'
    } else {
      const d = metaStr(m, 'direction')?.toLowerCase()
      if (d === 'sent' || d === 'outgoing' || d === 'out') direction = 'out'
      else if (d === 'received' || d === 'incoming' || d === 'in') direction = 'in'
      // Otherwise leave it 'unknown' — a source that did not record direction
      // (e.g. LINE has no is-from-me flag) must not be shown as received.
    }

    out.push({
      artifactId: r.id,
      contact,
      channel,
      direction,
      time: toEpochMs(m, ['date', 'timestamp']),
      recordType: type,
      threadKey: threadKeyOf(type, m),
      content: contentOf(type, m),
    })
  }
  return out
}
