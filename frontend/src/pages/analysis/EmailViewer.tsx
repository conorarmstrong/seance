import { useMemo, useState } from 'react'
import type { ReactNode } from 'react'
import { useSearchParams } from 'react-router-dom'
import { formatCount, formatUtc } from '../../lib/format'
import type { RecordMetadata } from './api'
import { AggregateEmpty, LoadMoreNote, useAggregatedRecords } from './aggregate'
import { toIso } from './cells'
import { MISSING, metaFirst, metaStr } from './lib'
import { IncompletenessBanner } from '../../components/Incompleteness'
import { ScopeNote } from '../../components/MeasuredScope'
import { EMAIL_BODY_SCOPE } from '../../lib/measuredScope'
import type { ViewerProps } from './viewers'

function dateLabel(m: RecordMetadata): string {
  const d = metaFirst(m, ['date'])
  return d ? formatUtc(toIso(d)) : MISSING
}

/**
 * When a message was sent, in unix seconds, or `null`.
 *
 * `date_epoch` first, because that is the field the server sorts and pages a
 * thread on and the two have to agree; the RFC 3339 string is the fallback for
 * a record written before the readers published the integer.
 */
function sentAt(m: RecordMetadata): number | null {
  const epoch = m['date_epoch']
  if (typeof epoch === 'number' && epoch > 0) return epoch
  const raw = metaFirst(m, ['date'])
  if (!raw) return null
  const t = Date.parse(toIso(raw))
  return Number.isNaN(t) ? null : Math.floor(t / 1000)
}

function fromLabel(m: RecordMetadata): string {
  const name = metaStr(m, 'from_name')
  const addr = metaStr(m, 'from')
  if (name && addr) return `${name} <${addr}>`
  return name ?? addr ?? 'Unknown sender'
}

/** Body text: prefer plain text; fall back to formatted HTML. */
function bodyOf(m: RecordMetadata): { text: string; isHtml: boolean } | null {
  const text = metaStr(m, 'body_text')
  if (text && text.trim()) return { text, isHtml: false }
  const html = metaStr(m, 'body_html')
  if (html && html.trim()) return { text: html, isHtml: true }
  return null
}

/**
 * The bucket for messages that belong to no addressable exchange (§5.14).
 *
 * Spelled with a leading space and a space in the middle so it cannot collide
 * with a real `Message-ID`, which is an addr-spec and carries neither.
 */
const NO_THREAD = ' not threaded'

/**
 * The exchange a message belongs to.
 *
 * Read off the record and never re-derived here:
 * `seance_plugin_email::thread` computed it from the `Message-ID` /
 * `In-Reply-To` / `References` headers, and the server groups on the same
 * field. A message with no key belongs to no exchange the evidence can
 * address, and carries its own sentence saying why.
 */
function threadKeyOf(m: RecordMetadata): string {
  return metaStr(m, 'email_thread_key') ?? NO_THREAD
}

/** One exchange, assembled from the messages on screen. */
interface Thread {
  key: string
  /** The newest message's subject: the line a reader recognises it by. */
  label: string
  /** Oldest first — an email thread is read top-down, unlike a chat. */
  messages: { id: string; metadata: RecordMetadata }[]
  /**
   * The weakest basis any message in it was grouped on. One message grouped by
   * `In-Reply-To` alone is enough for the exchange to be a fragment of a
   * longer one, so the weakest is the one that qualifies the thread.
   */
  basis: string | null
  newest: number | null
}

/**
 * Render email HTML in a sandboxed iframe. `sandbox=""` blocks scripts, forms
 * and navigation; the injected CSP blocks every remote resource, so opening a
 * message can't execute code, phone home to the sender, or alter the evidence.
 * Remote images are not loaded — only inline (data:) images render.
 */
function EmailHtmlFrame({ html }: { html: string }) {
  const srcDoc = useMemo(
    () =>
      `<!doctype html><html><head><meta charset="utf-8">` +
      `<meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src data:; style-src 'unsafe-inline'; font-src data:; media-src data:">` +
      `<base target="_blank">` +
      `<style>html,body{margin:0;padding:10px;background:#fff;color:#111;` +
      `font-family:-apple-system,system-ui,sans-serif;font-size:13px;line-height:1.5}` +
      `img{max-width:100%}a{color:#1a5fb4}</style></head><body>${html}</body></html>`,
    [html],
  )
  return (
    <iframe
      className="an-mail-frame"
      title="Email body"
      sandbox=""
      srcDoc={srcDoc}
    />
  )
}

function Header({
  label,
  value,
  mono,
}: {
  label: string
  value: string | null
  mono?: boolean
}) {
  if (!value) return null
  return (
    <div className="an-mail-hrow">
      <dt>{label}</dt>
      <dd className={mono ? 'mono' : undefined}>{value}</dd>
    </div>
  )
}

/**
 * What qualifies the exchange on screen, or nothing.
 *
 * Rendered above the messages rather than beside the thread in the list,
 * because it qualifies what a reader is about to read: a thread assembled from
 * `In-Reply-To` alone may be a fragment of a longer exchange, and a reader who
 * takes it for the whole of one has been misled by this screen.
 */
function ThreadBasisNote({ thread }: { thread: Thread }) {
  if (thread.key === NO_THREAD) {
    return (
      <p className="warn-note" role="note" data-testid="an-mail-no-thread-note">
        These messages carry no <span className="mono">Message-ID</span>,{' '}
        <span className="mono">In-Reply-To</span> or{' '}
        <span className="mono">References</span> header, so the exchange each
        belongs to cannot be addressed from the evidence. They are listed
        together because none of them could be threaded — <strong>not</strong>{' '}
        because they belong together.
      </p>
    )
  }
  if (thread.basis === 'in_reply_to') {
    return (
      <p className="warn-note" role="note" data-testid="an-mail-basis-note">
        At least one message here carries no{' '}
        <span className="mono">References</span> header and was grouped by the
        parent its <span className="mono">In-Reply-To</span> names. A reply to a
        reply then keys on its own parent, so a longer exchange can appear as
        more than one thread: this may be a fragment rather than the whole of
        it.
      </p>
    )
  }
  return null
}

export function EmailViewer({ caseId, type }: ViewerProps): ReactNode {
  const [sel, setSel] = useState<string | null>(null)
  const [openThread, setOpenThread] = useState<string | null>(null)
  // `?conv=` and `?focus=` are what the Communications table links into, so a
  // row there opens the exchange it belongs to at the right message.
  const [params, setParams] = useSearchParams()

  const load = useAggregatedRecords(caseId, type, {
    queryKey: 'analysis-email',
    loadingLabel: 'Loading messages…',
  })

  const messages = load.records
  const sorted = useMemo(
    () =>
      [...messages].sort(
        (a, b) => (sentAt(b.metadata) ?? 0) - (sentAt(a.metadata) ?? 0),
      ),
    [messages],
  )

  const threads = useMemo<Thread[]>(() => {
    const byKey = new Map<string, Thread>()
    for (const r of sorted) {
      const key = threadKeyOf(r.metadata)
      let t = byKey.get(key)
      if (!t) {
        t = {
          key,
          // `sorted` is newest-first, so the first message seen for a key is
          // the newest one, and its subject names the thread.
          label: metaStr(r.metadata, 'subject') ?? '(no subject)',
          messages: [],
          basis: null,
          newest: sentAt(r.metadata),
        }
        byKey.set(key, t)
      }
      t.messages.push(r)
      const basis = metaStr(r.metadata, 'email_thread_basis')
      if (basis === 'in_reply_to') t.basis = 'in_reply_to'
      else if (t.basis == null) t.basis = basis
    }
    const out = [...byKey.values()]
    // Each exchange reads oldest-first, which is how email is read.
    for (const t of out) t.messages.reverse()
    return out.sort((a, b) => {
      // The unthreadable residue goes last: it is not an exchange.
      if ((a.key === NO_THREAD) !== (b.key === NO_THREAD)) {
        return a.key === NO_THREAD ? 1 : -1
      }
      return (b.newest ?? 0) - (a.newest ?? 0)
    })
  }, [sorted])

  const convParam = params.get('conv')
  const focusId = params.get('focus')
  const activeThread =
    threads.find((t) => t.key === convParam) ??
    threads.find((t) => t.key === openThread) ??
    threads[0] ??
    null
  const inThread = activeThread?.messages ?? []
  const focused =
    focusId && inThread.some((r) => r.id === focusId) ? focusId : null
  const chosen = sel && inThread.some((r) => r.id === sel) ? sel : null
  // Newest last in a thread, and the newest message is the one to open.
  const active = focused ?? chosen ?? inThread[inThread.length - 1]?.id ?? null
  const open = inThread.find((r) => r.id === active) ?? null

  const selectThread = (key: string) => {
    setOpenThread(key)
    setSel(null)
    // Clear a deep link rather than leaving it to override the click.
    if (convParam != null || focusId != null) {
      setParams(
        (prev) => {
          const next = new URLSearchParams(prev)
          next.delete('conv')
          next.delete('focus')
          return next
        },
        { replace: true },
      )
    }
  }

  if (load.gate) return load.gate
  if (sorted.length === 0) {
    return (
      <AggregateEmpty
        title="No messages"
        body="No email messages were parsed."
        loaded={messages.length}
        listed={sorted.length}
        listedNoun="mail message"
      />
    )
  }

  const body = open ? bodyOf(open.metadata) : null

  return (
    <div>
      {/* This viewer loads its own records, so the page shell's banner (over its
          page-1 fetch) does not describe what is on screen here (B4-023). */}
      <IncompletenessBanner
        summary={load.incompleteness}
        noun="email messages"
      />
      <div className="an-mail">
        <aside className="an-mail-list" aria-label="Conversations">
          {load.truncated && (
            <LoadMoreNote
              shown={sorted.length}
              total={load.total}
              onLoadMore={load.loadMore}
            />
          )}
          {/* A thread assembled from a truncated set of messages is a partial
              thread, and the count beside it is a floor. Said once, above the
              list, because every row in it is affected. */}
          {load.truncated && (
            <p
              className="warn-note"
              role="note"
              data-testid="an-mail-partial-threads"
            >
              {formatCount(sorted.length)} of {formatCount(load.total)} messages
              are loaded, so an exchange below may be missing messages that are
              in the evidence and the count beside each is a floor, not a total.
              Load the rest before relying on a thread being complete.
            </p>
          )}
          {threads.map((t) => (
            <button
              key={t.key}
              type="button"
              className={
                t.key === activeThread?.key
                  ? 'an-mail-item selected'
                  : 'an-mail-item'
              }
              data-testid="an-mail-thread"
              aria-pressed={t.key === activeThread?.key}
              onClick={() => selectThread(t.key)}
            >
              <div className="an-mail-subject">
                {t.key === NO_THREAD ? 'Not in any exchange' : t.label}
              </div>
              <div className="an-mail-from">
                {formatCount(t.messages.length)}{' '}
                {t.messages.length === 1 ? 'message' : 'messages'}
                {t.key === NO_THREAD ? ' that could not be threaded' : ''}
              </div>
              <div className="an-mail-date mono">
                {t.newest != null
                  ? formatUtc(new Date(t.newest * 1000).toISOString())
                  : MISSING}
              </div>
            </button>
          ))}
        </aside>

        <section className="an-mail-thread" aria-label="Conversation">
          {activeThread && <ThreadBasisNote thread={activeThread} />}
          <div className="an-mail-thread-list">
            {inThread.map((r) => (
              <button
                key={r.id}
                type="button"
                className={r.id === active ? 'an-mail-msg selected' : 'an-mail-msg'}
                data-testid="an-mail-item"
                aria-pressed={r.id === active}
                onClick={() => setSel(r.id)}
              >
                <span className="an-mail-from">{fromLabel(r.metadata)}</span>
                <span className="an-mail-subject">
                  {metaStr(r.metadata, 'subject') ?? '(no subject)'}
                </span>
                <span className="an-mail-date mono">{dateLabel(r.metadata)}</span>
              </button>
            ))}
          </div>

          {open && (
            <div className="an-mail-read">
              <h3 className="an-mail-read-subject">
                {metaStr(open.metadata, 'subject') ?? '(no subject)'}
              </h3>
              <dl className="an-mail-headers">
                <Header label="From" value={fromLabel(open.metadata)} mono />
                <Header label="To" value={metaStr(open.metadata, 'to')} mono />
                <Header label="Cc" value={metaStr(open.metadata, 'cc')} mono />
                {/* A blind copy is a finding about who could see whom, and it
                    was reaching the record and stopping there. Shown as its
                    own header, never folded into Cc. */}
                <Header label="Bcc" value={metaStr(open.metadata, 'bcc')} mono />
                {/* Addresses whose recipient type the parser did not
                    recognise: deliberately not guessed into a header, so they
                    have to be shown as what they are or they are lost. */}
                <Header
                  label="Recipient type not recognised"
                  value={metaStr(open.metadata, 'recipients_unrecognised_type')}
                  mono
                />
                <Header label="Date" value={dateLabel(open.metadata)} mono />
                {/* What the date was read AS, where the parser could not
                    establish it. Printed beside the date rather than hidden in
                    a tooltip: a date read under the wrong epoch is 31 years
                    out and looks entirely ordinary. */}
                <Header label="Date basis" value={metaStr(open.metadata, 'date_basis')} />
                {/* A recipient or attachment count that is really "at least
                    this many". A floor printed as a total understates who saw
                    the message. */}
                <Header
                  label="Recipients"
                  value={metaStr(open.metadata, 'recipient_count_is_a_floor')}
                />
                <Header
                  label="Attachments"
                  value={metaStr(open.metadata, 'attachment_count_is_a_floor')}
                />
                {/* What this reader has and has not been proven against. */}
                <Header label="Basis" value={metaStr(open.metadata, 'basis_statement')} />
                {/* How this message was placed in the exchange above, in the
                    parser's own words. A grouping an examiner cannot see the
                    basis of is one they cannot test. */}
                <Header
                  label="Threaded by"
                  value={metaStr(open.metadata, 'email_thread_basis_note')}
                />
                <Header
                  label="Not threaded"
                  value={metaStr(
                    open.metadata,
                    'email_thread_unavailable_reason',
                  )}
                />
              </dl>
              {body ? (
                <>
                  {body.isHtml ? (
                    <div data-testid="an-mail-body">
                      <div className="an-mail-html-note">
                        Rendered HTML · remote content blocked
                      </div>
                      <EmailHtmlFrame html={body.text} />
                    </div>
                  ) : (
                    <pre className="an-mail-body" data-testid="an-mail-body">
                      {body.text}
                    </pre>
                  )}
                  {/* The parser cuts the body at 64 KiB and says so on
                      `body_truncated`; nothing read that key, so a cut message
                      reached the reading pane as the whole message. Printed
                      beneath the text rather than badged beside it: a body is
                      read, quoted and screenshotted, and none of those carry a
                      hover. */}
                  <ScopeNote metadata={open.metadata} spec={EMAIL_BODY_SCOPE} />
                </>
              ) : (
                <>
                  {/* An artifact that CANNOT hold a body says so in its own
                      words. "No body was captured" reads as a capture that
                      missed one; Apple Mail's Envelope Index is an index and
                      never held one, and the difference decides whether an
                      examiner goes looking for the message elsewhere. */}
                  <p className="an-mail-nobody">
                    {metaStr(open.metadata, 'body_absent_reason') ??
                      'No body was captured for this message (headers only).'}
                  </p>
                  {/* Mail's own one-line preview, where the record carries
                      one. On a machine whose mail was server-hosted this is
                      frequently the only text of the message on the disk, so
                      dropping it loses evidence — but it is labelled, because
                      a snippet shown as a body would be read as the whole
                      message. */}
                  {metaStr(open.metadata, 'snippet') && (
                    <div className="an-mail-snippet" data-testid="an-mail-snippet">
                      <div className="an-mail-html-note">
                        The index&rsquo;s own one-line preview · not the message
                        body
                      </div>
                      <pre className="an-mail-body">
                        {metaStr(open.metadata, 'snippet')}
                      </pre>
                    </div>
                  )}
                </>
              )}
            </div>
          )}
        </section>
      </div>
    </div>
  )
}
