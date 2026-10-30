// Runs in the plain node environment: this file touches no DOM (UI-023).
// @vitest-environment node
import { describe, expect, it } from 'vitest'
import type { ParsedRecord } from '../analysis/api'
import { normalizeComms } from './normalize'

function rec(id: string, metadata: Record<string, unknown>): ParsedRecord {
  return { id, parent_id: null, artifact_type: 'ParsedRecord', metadata }
}

describe('normalizeComms', () => {
  it('normalises messaging with direction from is_from_me and unix-second dates', () => {
    const events = normalizeComms('iMessage', [
      rec('m1', { contact: '+111', text: 'hi', date: 1_700_000_000, is_from_me: true }),
      rec('m2', { contact: '+111', text: 'yo', date: 1_700_000_100, is_from_me: false }),
    ])
    expect(events).toHaveLength(2)
    expect(events[0]).toMatchObject({
      contact: '+111',
      channel: 'iMessage',
      direction: 'out',
      time: 1_700_000_000_000,
    })
    expect(events[1].direction).toBe('in')
  })

  it('correlates the additional messengers into their own channels', () => {
    const cases: [string, string, string][] = [
      ['Viber', 'Viber', 'contact'],
      ['Kik', 'Kik', 'contact'],
      ['Skype', 'Skype', 'contact'],
      ['LINE', 'LINE', 'chat_identifier'],
      ['TelegramMessage', 'Telegram', 'contact'],
      ['FacebookMessenger', 'Messenger', 'contact'],
      ['WeChat', 'WeChat', 'contact'],
    ]
    for (const [type, channel, contactKey] of cases) {
      const events = normalizeComms(type, [
        rec('m', { [contactKey]: 'Alice', text: 'hi', date: 1_700_000_000, is_from_me: true }),
      ])
      expect(events).toHaveLength(1)
      expect(events[0]).toMatchObject({ channel, contact: 'Alice', direction: 'out' })
    }
  })

  it('leaves direction unknown when the source records neither is_from_me nor direction', () => {
    // A record with no direction signal must not be guessed as received.
    const events = normalizeComms('iMessage', [
      rec('u', { contact: '+111', text: 'no direction signal', date: 1_700_000_000 }),
    ])
    expect(events[0].direction).toBe('unknown')
  })

  it('maps channel per source type and reads email/call fields', () => {
    expect(normalizeComms('AndroidSms', [rec('s', { contact: 'A' })])[0].channel).toBe('SMS')
    expect(normalizeComms('CallLog', [rec('c', { contact: 'B', direction: 'incoming' })])[0]).toMatchObject({
      channel: 'Call',
      direction: 'in',
    })
    expect(normalizeComms('EmailMessage', [rec('e', { from: 'x@y.com' })])[0]).toMatchObject({
      channel: 'Email',
      contact: 'x@y.com',
    })
  })

  it('drops summary rows, rows without a counterparty, and unknown types', () => {
    expect(normalizeComms('iMessage', [rec('s', { subtype: 'summary', contact: 'A' })])).toEqual([])
    expect(normalizeComms('iMessage', [rec('n', { text: 'no contact' })])).toEqual([])
    expect(normalizeComms('Nope', [rec('x', { contact: 'A' })])).toEqual([])
  })
})

describe('conversation addressing', () => {
  it('keys a message thread exactly as the server groups conversations', () => {
    // These expectations mirror `SqliteConnection::thread_key_expr`
    // (seance_db/src/lib.rs). A key computed differently from the server's
    // would not match any thread in the list the viewer loads, and the viewer
    // falls back to the FIRST thread when a `conv` it is given is unknown — so
    // a drift here silently opens the wrong conversation under the right
    // contact's name. Pinned per platform for that reason.
    const cases: [string, Record<string, unknown>, string][] = [
      ['iMessage', { chat_identifier: 'chat123', contact: '+111' }, 'chat123'],
      ['iMessage', { chat_display_name: 'Family', contact: '+111' }, 'Family'],
      ['iMessage', { contact: '+111' }, '+111'],
      ['WhatsApp', { contact_jid: '44@s.whatsapp.net', contact: 'A' }, '44@s.whatsapp.net'],
      ['WhatsApp', { remote_jid: 'r@g.us', contact: 'A' }, 'r@g.us'],
      ['AndroidSms', { chat_identifier: 'sms-1', contact: 'A' }, 'sms-1'],
      ['AndroidSms', { contact: 'A' }, 'A'],
      ['Signal', { chat_identifier: 'sig-1', contact: 'A' }, 'sig-1'],
      ['Instagram', { chat_identifier: 'ig-1', contact: 'A' }, 'ig-1'],
      ['Instagram', { conversation_id: 'ig-2', contact: 'A' }, 'ig-2'],
      ['Skype', { chat_identifier: 'sk-1', contact: 'A' }, 'sk-1'],
      ['TelegramMessage', { conversation_id: 'tg-1', contact: 'A' }, 'tg-1'],
      ['WeChat', { contact: 'A' }, 'A'],
    ]
    for (const [type, metadata, key] of cases) {
      const events = normalizeComms(type, [rec('m', metadata)])
      expect(events[0].threadKey, `${type} ${JSON.stringify(metadata)}`).toBe(key)
      expect(events[0].recordType).toBe(type)
    }
  })

  it('withholds a conversation link where the key is not a string the server can group on', () => {
    // The server decodes the thread key as TEXT and DROPS a conversation whose
    // key came back as an integer, so such a thread is not in the list the
    // viewer loads at all. Linking to it would land on the first thread
    // instead — the wrong conversation, under the right contact's name.
    const numericKey = normalizeComms('Instagram', [
      rec('m', { contact: 'Alice', conversation_id: 42 }),
    ])
    expect(numericKey[0].contact).toBe('Alice')
    expect(numericKey[0].threadKey).toBeNull()

    // A key EARLIER in the chain being a proper string settles it, exactly as
    // SQL COALESCE would.
    const withStringKey = normalizeComms('Instagram', [
      rec('m', { contact: 'Alice', chat_identifier: 'ig-9', conversation_id: 42 }),
    ])
    expect(withStringKey[0].threadKey).toBe('ig-9')

    // A record carrying none of the keys is grouped by the server under the
    // literal 'unknown', and the link may address that thread.
    const noKeys = normalizeComms('Instagram', [rec('m', { contact: 'Alice' })])
    expect(noKeys[0].threadKey).toBe('unknown')
  })

  it('gives a call no conversation key, because there is no thread view', () => {
    expect(normalizeComms('CallLog', [rec('c', { contact: 'B' })])[0].threadKey).toBeNull()
  })

  /**
   * Email threads on the key `seance_plugin_email::thread` derived from the
   * RFC 5322 headers, and the server's expression for it has NO `'unknown'`
   * fallback — unlike every other channel's. So a message carrying none of the
   * three headers gets no key here either: it is absent from the server's
   * thread list, and a link offered for it would open somebody else's exchange
   * (§5.14).
   */
  it('threads email on the key the parser derived, and declines when there is none', () => {
    expect(
      normalizeComms('EmailMessage', [
        rec('e', { from: 'x@y.com', email_thread_key: 'root@example.com' }),
      ])[0].threadKey,
    ).toBe('root@example.com')
    expect(
      normalizeComms('EmailMessage', [rec('e', { from: 'x@y.com' })])[0].threadKey,
    ).toBeNull()
  })
})

describe('what the row shows instead of a serialised blob', () => {
  it('carries the message text the record actually holds', () => {
    const events = normalizeComms('iMessage', [
      rec('m', { contact: '+111', text: 'meet at 9' }),
    ])
    expect(events[0].content).toEqual({ kind: 'text', text: 'meet at 9' })
  })

  it('names what a call holds rather than pretending it has text', () => {
    const events = normalizeComms('CallLog', [
      rec('c', { contact: 'B', duration_seconds: 154 }),
    ])
    expect(events[0].content).toEqual({ kind: 'call', durationSeconds: 154 })

    const noDuration = normalizeComms('CallLog', [rec('c', { contact: 'B' })])
    expect(noDuration[0].content).toEqual({ kind: 'call', durationSeconds: null })
  })

  it('shows an email by its subject and says the body is not on this page', () => {
    const events = normalizeComms('EmailMessage', [
      rec('e', { from: 'x@y.com', subject: 'Invoice 42' }),
    ])
    expect(events[0].content).toEqual({ kind: 'subject', text: 'Invoice 42' })
  })

  it('says why there is no text rather than leaving the cell blank', () => {
    const noText = normalizeComms('iMessage', [rec('m', { contact: '+111' })])
    expect(noText[0].content).toEqual({
      kind: 'none',
      because: 'This record carries no message text.',
    })

    // iMessage writes U+FFFC where an attachment sits. A message whose entire
    // text is that placeholder has no text, and saying so is different from
    // rendering a box.
    const placeholderOnly = normalizeComms('iMessage', [
      rec('m', { contact: '+111', text: '￼' }),
    ])
    expect(placeholderOnly[0].content).toEqual({
      kind: 'none',
      because:
        'The only text this record carries is an attachment placeholder.',
    })
  })
})
