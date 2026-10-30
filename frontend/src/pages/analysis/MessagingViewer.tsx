import { Fragment, useEffect, useMemo, useRef, useState } from 'react'
import type { ReactNode } from 'react'
import { useInfiniteQuery, useQuery, useQueryClient } from '@tanstack/react-query'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { DERIVED_THUMBNAIL_NOTE, useThumbnail } from '../../lib/thumbnails'
import { useEntityScopedState } from '../../lib/useEntityScopedState'
import { formatBytes, formatCount, formatUtc, truncateHash } from '../../lib/format'
import { getArtifact } from '../../api/resources'
import { fetchContentBlob } from '../gallery/api'
import type {
  ConversationCursor,
  ParsedRecord,
  RecordMetadata,
} from './api'
import {
  getConversationMessages,
  getConversations,
  resolveFiles,
  searchConversations,
} from './api'
import { PivotName, toIso } from './cells'
import { MISSING, metaBool, metaFirst, metaNum, metaStr } from './lib'
import { useContactIndex } from './contactNames'
import {
  ArtifactIncompleteness,
  IncompleteBadge,
  IncompletenessBanner,
  useIncompleteness,
} from '../../components/Incompleteness'
import type { ViewerProps } from './viewers'

/**
 * Per-platform behaviour for the shared threaded-conversation UI. iMessage and
 * WhatsApp store the same shape of data under different keys, so the viewer is
 * a single component parameterised by these accessors.
 */
interface MsgCfg {
  /** Separate ParsedRecord type carrying attachments, if any. */
  attachmentType?: string
  /** Bubble palette, following each app's own convention (iMessage blue, SMS
   * and WhatsApp green, Signal blue) so a chat reads like it did on the device. */
  theme:
    | 'imessage'
    | 'sms'
    | 'whatsapp'
    | 'signal'
    | 'instagram'
    | 'snapchat'
    | 'twitter'
    | 'viber'
    | 'kik'
    | 'skype'
    | 'line'
    | 'telegram'
    | 'messenger'
    | 'wechat'
  /** Display name for a received message's sender. Conversation grouping,
   * labels and group detection are done server-side (see /conversations). */
  senderName: (m: RecordMetadata) => string
}

/** Messages rendered per scrollback step. */
const WINDOW = 60
/**
 * How many scrollback pages stay in memory at once.
 *
 * react-query drops from the opposite end when this is exceeded, so loading
 * older history EVICTS the newest messages. The pane then shows a middle slice
 * of the thread whose last message is not the last message: a screenshot or an
 * export of it would present the conversation as having ended there. Whenever
 * eviction has happened the pane says so — see `windowEvicted` below.
 */
const MAX_PAGES = 8
// Sort/cursor sentinel for messages with no recovered timestamp: far above any
// real unix date, so they sort to the end. MUST match the DB query sentinel
// (10000000000000) so the frontend cursor and DB ordering agree.
const NO_DATE_ORDER_BASE = 10000000000000

/** Message epoch in seconds; `date` is unix seconds for both platforms. */
function msgTime(m: RecordMetadata): number {
  const n = metaNum(m, 'date')
  if (n != null) return n
  const raw = metaFirst(m, ['date'])
  if (raw) {
    const t = Date.parse(toIso(raw))
    if (!Number.isNaN(t)) return t / 1000
  }
  return 0
}

/** True when the message carries a real recovered timestamp. */
function hasDate(m: RecordMetadata): boolean {
  return msgTime(m) > 0
}

/** Ordering key: real time when known, else parked after everything in the
 *  order the bodies were recovered from disk (recovery_index). */
function msgOrder(m: RecordMetadata): number {
  if (hasDate(m)) return msgTime(m)
  return NO_DATE_ORDER_BASE + (metaNum(m, 'recovery_index') ?? 0)
}

/**
 * Every id sorts below this one, so pairing it with an ordering value asks for
 * "everything at or older than that value" without excluding any message that
 * happens to share it.
 */
const HIGHEST_ID = 'ffffffff-ffff-ffff-ffff-ffffffffffff'

/**
 * Where the pane opens: the newest page, or the page containing a search hit.
 *
 * Both halves of the cursor must be sent or the server refuses the request, so
 * opening at a hit pairs the instant just after it with the highest possible
 * id. The result is a superset of the old timestamp-only behaviour — it can
 * only ever include more of the surrounding second, never less, which is the
 * right direction to err in.
 *
 * Every subsequent cursor comes from the server's `next_cursor` and is not
 * computed here. It cannot be: the ordering value alone does not identify a
 * position when messages share one, which is what B8-001 was about.
 */
function openingCursor(
  at: number | null | undefined,
): ConversationCursor | undefined {
  if (at == null || !Number.isFinite(at)) return undefined
  return { before: at + 1, before_id: HIGHEST_ID }
}

/** Cursor equality by value. Two cursors built for the same position are
 *  distinct objects, so identity would never match. */
function sameCursor(
  a: ConversationCursor | undefined,
  b: ConversationCursor | undefined,
): boolean {
  if (a == null || b == null) return a == null && b == null
  return a.before === b.before && a.before_id === b.before_id
}

/** Whether sent/received could be established. A carved body has no direction
 *  column, so is_from_me/direction come back null rather than a real boolean. */
function directionKnown(m: RecordMetadata): boolean {
  return metaStr(m, 'direction') != null || typeof m['is_from_me'] === 'boolean'
}

/** The word shown wherever a direction-derived attribution cannot be made. */
const UNDETERMINED_DIRECTION = 'not determined'

const UNDETERMINED_DIRECTION_MEANING =
  'This message never recorded a direction, so which side sent it and which received it was not established. ' +
  'Nothing here assigns a sender; this is not a finding that the message was received.'

/**
 * Whether the correspondent on this record was selected, or stood in for.
 *
 * `seance_plugin_android_sms` stamps `peer_undetermined` on an MMS whose
 * direction was never recorded: on MMS the direction is what chooses between
 * the `from` (137) and `to` (151) address rows, so with it absent neither can
 * be used and the thread's own address stands in. The thread address is a real,
 * sourced value — it is just the conversation's address, not this message's
 * selected correspondent, and the Contact row rendered the two identically.
 */
function peerUndetermined(m: RecordMetadata): boolean {
  return metaBool(m, 'peer_undetermined')
}

const PEER_UNDETERMINED_MEANING =
  "The correspondent on this message could not be selected from its own address rows, because the direction that chooses between them was never recorded. The value shown is the conversation thread's address standing in for it."

function fromMe(m: RecordMetadata): boolean {
  return metaBool(m, 'is_from_me') || metaStr(m, 'direction') === 'sent'
}

function whenLabel(t: number): string {
  return t > 0 ? formatUtc(new Date(t * 1000).toISOString()) : MISSING
}

/** UTC calendar day, for grouping a conversation into days. */
function dayKey(t: number): string {
  return t > 0 ? new Date(t * 1000).toISOString().slice(0, 10) : ''
}

/**
 * Date shown on a conversation's day divider. Always absolute — a phone says
 * "Today", but a report is read long after the device was seized, so a relative
 * label would be ambiguous evidence. The per-message timestamp is unchanged.
 *
 * The locale is pinned for the same reason every count in this app is pinned
 * (see `formatCount`): left to the runtime, "Fri, 3 April 2020" becomes
 * "Fr., 3. April 2020" on a de-DE machine, and two examiners reading one
 * conversation would see the same day written two ways. en-GB rather than the
 * en-US used for numbers because a divider reads as prose — day before month,
 * with the month spelled out, which no locale can misread as a date in the
 * other order.
 */
function dayLabel(t: number): string {
  if (t <= 0) return 'Unknown date'
  return new Date(t * 1000).toLocaleDateString('en-GB', {
    weekday: 'short',
    day: 'numeric',
    month: 'long',
    year: 'numeric',
    timeZone: 'UTC',
  })
}

/** The media's on-device path, as stored by the chat database. */
function attachmentPath(m: RecordMetadata): string | null {
  return metaStr(m, 'filename')
}

/** Message this attachment belongs to, from the chat db's join table. */
function attachmentMsgKey(m: RecordMetadata): string | null {
  const guid = metaStr(m, 'message_guid')
  if (guid) return `g:${guid}`
  const rowid = metaNum(m, 'message_rowid')
  return rowid != null ? `r:${rowid}` : null
}

/** Key identifying a message so its attachments can be found. */
function msgKeys(m: RecordMetadata): string[] {
  const keys: string[] = []
  const guid = metaStr(m, 'guid')
  if (guid) keys.push(`g:${guid}`)
  // `rowid` for chat.db, `pk` for WhatsApp's Core Data schema.
  for (const key of ['rowid', 'pk'] as const) {
    const n = metaNum(m, key)
    if (n != null) keys.push(`r:${n}`)
  }
  return keys
}

/**
 * iMessage writes U+FFFC (object replacement) into a message's text where an
 * attachment sits. Strip it so a media-only message reads as media rather than
 * a row of placeholder boxes; text either side is preserved verbatim.
 */
function displayText(raw: string | null): string | null {
  if (raw == null) return null
  const cleaned = raw.replace(/￼/g, '').trim()
  return cleaned.length > 0 ? cleaned : null
}

/**
 * Attachment chip: filename + mime + size, showing the image itself once its
 * bytes have been located in the evidence. Clickable when resolved, opening
 * the artifact; unresolved attachments stay as plain (non-clickable) chips,
 * because the metadata row exists but the file was not in the backup.
 */
function AttachmentChip({
  record,
  caseId,
  artifactId,
  lookup,
  onSelect,
}: {
  record: ParsedRecord
  caseId: string
  artifactId?: string
  /**
   * State of the batched path→artifact lookup this chip's `artifactId` comes
   * from. Without it a missing id is indistinguishable from a lookup that has
   * not finished (or failed), and the chip asserted "not in evidence" over
   * media that is in the backup (B4-025).
   */
  lookup: 'pending' | 'resolved' | 'failed'
  /** Select the message this attachment belongs to (single click). */
  onSelect: () => void
}) {
  const navigate = useNavigate()
  const m = record.metadata
  const name = metaFirst(m, ['transfer_name', 'filename']) ?? 'attachment'
  const mime = metaStr(m, 'mime_type')
  const size = metaNum(m, 'total_bytes')
  const isImage = !!mime && mime.startsWith('image/')
  const thumb = useThumbnail(caseId, artifactId)
  const openable = !!artifactId

  return (
    <div
      className={openable ? 'an-att-chip an-att-chip-link' : 'an-att-chip'}
      data-testid="an-att-chip"
      role={openable ? 'button' : undefined}
      title={openable ? 'Double-click to open the file artifact' : undefined}
      onClick={onSelect}
      onDoubleClick={(e) => {
        if (!openable) return
        // Open the media, not the message: stop the bubble's own double-click.
        e.stopPropagation()
        navigate(`/cases/${caseId}/artifacts/${artifactId}`)
      }}
    >
      {thumb ? (
        <>
          <img className="an-att-thumb" src={thumb.url} alt={name} />
          {/* The server did not decode this preview from the attachment's own
              bytes — it came from the device's thumbnail cache or a video
              keyframe. Such a preview can disagree with, and outlive, the file
              it was made from, so a chip that showed it plainly would present
              it as a picture of the evidence (B8-004). */}
          {thumb.fromDeviceCache && (
            <span
              className="badge badge-warn an-att-derived"
              role="note"
              data-testid="an-derived-thumb"
              title={DERIVED_THUMBNAIL_NOTE}
              aria-label={DERIVED_THUMBNAIL_NOTE}
            >
              ⚠ not from this file
            </span>
          )}
        </>
      ) : (
        <span
          className={isImage ? 'an-att-icon an-att-icon-img' : 'an-att-icon'}
          aria-hidden
        >
          {isImage ? 'IMG' : 'FILE'}
        </span>
      )}
      <div className="an-att-body">
        <div className="an-att-name mono" title={name}>
          {name}
        </div>
        <div className="an-att-meta mono">
          {mime ?? 'unknown'}
          {size != null ? ` · ${formatBytes(size)}` : ''}
          {!artifactId &&
            (lookup === 'resolved'
              ? ' · not in evidence'
              : lookup === 'failed'
                ? ' · lookup failed'
                : ' · locating…')}
        </div>
        {/* An attachment row the parser could not finish reading: the declared
            size above then describes the file the chat database recorded, not
            the bytes this ingest holds. Shown on the chip because a chip is
            where an examiner meets the attachment first. */}
        <IncompleteBadge metadata={m} />
      </div>
    </div>
  )
}

/** The source table a record was read from — authoritative from the parser
 * when present, else derived from the record type and platform. */
function sourceTable(m: RecordMetadata): string {
  const explicit = metaStr(m, 'source_table')
  if (explicit) return explicit
  const type = metaStr(m, 'type')
  const ios = metaStr(m, 'platform') !== 'Android'
  switch (type) {
    case 'WhatsApp':
      return ios ? 'ZWAMESSAGE' : 'messages'
    case 'WhatsAppAttachment':
      return ios ? 'ZWAMEDIAITEM' : 'message_media'
    case 'iMessage':
      return 'message'
    case 'iMessageAttachment':
      return 'attachment'
    default:
      return metaStr(m, 'subtype') ?? '-'
  }
}

/** A two-column key/value block; empty values are dropped. */
function KvTable({ rows }: { rows: [string, ReactNode][] }) {
  const shown = rows.filter(([, v]) => v != null && v !== '')
  if (shown.length === 0) return null
  return (
    <table className="an-props-table mono">
      <tbody>
        {shown.map(([k, v]) => (
          <tr key={k}>
            <td>{k}</td>
            <td>{v}</td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}

/** A short audio player for a voice-note attachment (loaded on demand). */
function AudioPreview({
  caseId,
  artifactId,
}: {
  caseId: string
  artifactId: string
}) {
  // Both the handle and the failure belong to the attachment they were obtained
  // for. This player is reused as the conversation scrolls, and the fetch below
  // is asynchronous, so an unscoped handle keeps PLAYING the previous voice note
  // under the new row for as long as the next fetch takes — a recording
  // attributed to a message that does not contain it. An unscoped `error` says
  // "audio unavailable" about an attachment nothing has tried to read yet.
  const attachment = `${caseId}/${artifactId}`
  const [url, setUrl] = useEntityScopedState<string | null>(attachment, null)
  const [error, setError] = useEntityScopedState(attachment, false)
  useEffect(() => {
    let revoke: string | null = null
    let cancelled = false
    setError(false)
    fetchContentBlob(caseId, artifactId)
      .then((blob) => {
        if (cancelled) return
        revoke = URL.createObjectURL(blob)
        setUrl(revoke)
      })
      .catch(() => {
        // Surface the failure instead of leaving the row stuck on
        // "loading audio..." forever (auth/content errors) (BUG-171).
        if (!cancelled) setError(true)
      })
    return () => {
      cancelled = true
      if (revoke) URL.revokeObjectURL(revoke)
    }
    // The setters are memoized on the attachment they write to, so they change
    // exactly when `caseId`/`artifactId` do: listing them adds no extra runs and
    // keeps a settled fetch writing to the attachment it was started for.
  }, [caseId, artifactId, setUrl, setError])
  if (error)
    return (
      <div className="an-props-att-meta mono">audio unavailable</div>
    )
  if (!url) return <div className="an-props-att-meta mono">loading audio...</div>
  // eslint-disable-next-line jsx-a11y/media-has-caption
  return <audio className="an-props-audio" src={url} controls />
}

/** A media attachment: a preview (image/video poster/audio player) plus the
 * file's own forensic properties (hashes, dates), and an open action. */
function MediaBlock({
  caseId,
  record,
  artifactId,
}: {
  caseId: string
  record: ParsedRecord
  artifactId?: string
}) {
  const navigate = useNavigate()
  const m = record.metadata
  const name = metaFirst(m, ['transfer_name', 'filename']) ?? 'attachment'
  const mime = metaStr(m, 'mime_type') ?? ''
  const size = metaNum(m, 'total_bytes')
  const isImage = mime.startsWith('image/')
  const isVideo = mime.startsWith('video/')
  const isAudio = mime.startsWith('audio/')
  const thumb = useThumbnail(caseId, isImage || isVideo ? artifactId : undefined)

  const fileQuery = useQuery({
    queryKey: ['artifact', caseId, artifactId],
    queryFn: () => getArtifact(caseId, artifactId!),
    enabled: !!artifactId,
    staleTime: Infinity,
  })
  const fm = (fileQuery.data?.metadata ?? {}) as RecordMetadata
  const md5 = metaFirst(fm, ['md5', 'md5_hash'])
  const sha256 = metaFirst(fm, ['sha256', 'sha256_hash'])
  const fileModified = metaFirst(fm, ['modified', 'last_modified'])

  return (
    <div className="an-props-att">
      {/* The attachment row's own stamps, in full. `Size` below is what the
          chat database declared; if the parser says the content behind it is
          short, the preview and any hash taken from it cover part of a file. */}
      <ArtifactIncompleteness metadata={m} />
      {/* And the located file's stamps, which are a different claim: the media
          artifact itself may be a partial carve or a short read. */}
      <ArtifactIncompleteness metadata={fileQuery.data?.metadata} />
      {thumb && (
        <span className="an-props-media-preview">
          <img src={thumb.url} alt={name} />
          {isVideo && <span className="an-props-media-badge">VIDEO</span>}
          {thumb.fromDeviceCache && (
            <span
              className="badge badge-warn an-att-derived"
              role="note"
              data-testid="an-derived-media"
              title={DERIVED_THUMBNAIL_NOTE}
              aria-label={DERIVED_THUMBNAIL_NOTE}
            >
              ⚠ not from this file
            </span>
          )}
        </span>
      )}
      {isAudio && artifactId && (
        <AudioPreview caseId={caseId} artifactId={artifactId} />
      )}
      <KvTable
        rows={[
          ['File', <span key="file" title={name}>{name}</span>],
          ['MIME', mime || 'unknown'],
          ['Size', size != null ? formatBytes(size) : null],
          ['Row', metaNum(m, 'rowid') ?? metaNum(m, 'message_rowid') ?? null],
          ['MD5', md5 ? <span key="md5" title={md5}>{truncateHash(md5)}</span> : null],
          [
            'SHA256',
            sha256 ? (
              <span key="sha256" title={sha256}>{truncateHash(sha256)}</span>
            ) : null,
          ],
          ['File modified', fileModified ? formatUtc(fileModified) : null],
          [
            'In evidence',
            artifactId ? 'yes' : 'no - file not found in this acquisition',
          ],
        ]}
      />
      {artifactId && (
        <button
          type="button"
          className="btn an-props-open"
          onClick={() => navigate(`/cases/${caseId}/artifacts/${artifactId}`)}
        >
          Open media artifact
        </button>
      )}
    </div>
  )
}

/** Forensic inspector for the selected message: provenance (database, table,
 * row), the parties, the message itself, its media with previews and file
 * properties, and a full raw-field dump. */
function MessageProperties({
  record,
  caseId,
  mine,
  contactLabel,
  atts,
  onOpenMessage,
}: {
  record: ParsedRecord
  caseId: string
  mine: boolean
  contactLabel: string
  atts: { record: ParsedRecord; artifactId?: string }[]
  onOpenMessage: () => void
}) {
  const navigate = useNavigate()
  const [showRaw, setShowRaw] = useState(false)
  const m = record.metadata
  const t = msgTime(m)
  const text = displayText(metaStr(m, 'text'))

  const parentQuery = useQuery({
    queryKey: ['artifact', caseId, record.parent_id],
    queryFn: () => getArtifact(caseId, record.parent_id!),
    enabled: !!record.parent_id,
    staleTime: Infinity,
  })
  const pm = (parentQuery.data?.metadata ?? {}) as RecordMetadata
  const dbName = metaStr(pm, 'name')
  const dbPath = metaFirst(pm, ['relative_path', 'path'])
  const row = metaNum(m, 'rowid') ?? metaNum(m, 'pk') ?? metaNum(m, 'id')

  const fromJid = metaFirst(m, ['from_jid', 'sender_jid'])
  const toJid = metaStr(m, 'to_jid')
  const owner = 'Me (device owner)'
  // `mine` is `fromMe(m)`, which is FALSE both for a message the device
  // received and for a message that never recorded a direction at all. Reading
  // From/To/Direction off it therefore printed "From: <contact>", "To: Me
  // (device owner)" and "Direction: received" for a row whose direction column
  // was NULL — three attributions of a message nobody established the sender
  // of. The conversation bubble already declines to claim this
  // (`directionKnown`); this panel did not, and it is the surface an examiner
  // quotes. So the three rows say the same thing the bubble says.
  const dirKnown = directionKnown(m)
  const undeterminedParty = (
    <span className="an-muted" title={UNDETERMINED_DIRECTION_MEANING}>
      {UNDETERMINED_DIRECTION}
    </span>
  )
  const from = !dirKnown
    ? undeterminedParty
    : mine
      ? owner
      : `${contactLabel}${fromJid ? ` - ${fromJid}` : ''}`
  const to = !dirKnown
    ? undeterminedParty
    : mine
      ? `${contactLabel}${toJid ? ` - ${toJid}` : ''}`
      : owner

  // A stood-in correspondent must not render as a selected one. Null stays
  // null so `KvTable` drops the row exactly as it did before.
  const contactValue = metaFirst(m, ['contact_name', 'contact'])
  const contactRow: ReactNode =
    contactValue != null && peerUndetermined(m) ? (
      <span className="an-sig" title={PEER_UNDETERMINED_MEANING}>
        <span>{contactValue}</span>
        <span className="badge badge-warn">not selected for this message</span>
      </span>
    ) : (
      contactValue
    )

  const rawRows: [string, ReactNode][] = Object.entries(m)
    .filter(([k, v]) => k !== 'name' && v != null && v !== '')
    .map(([k, v]) => [
      k,
      typeof v === 'object' ? JSON.stringify(v) : String(v),
    ])

  return (
    <div className="an-props-inner">
      {/* Before the provenance, not after it: if this message's own stamps say
          the text below is not all of it, that governs everything the panel
          then presents as this message's content. */}
      <ArtifactIncompleteness metadata={m} />
      <h3 className="an-props-title">Provenance</h3>
      <KvTable
        rows={[
          [
            'Database',
            record.parent_id ? (
              <button
                key="database"
                type="button"
                className="link-button"
                title={dbPath ?? undefined}
                onClick={() =>
                  navigate(`/cases/${caseId}/artifacts/${record.parent_id}`)
                }
              >
                {dbName ?? 'open source database'}
              </button>
            ) : null,
          ],
          ['Table', sourceTable(m)],
          ['Row', row],
          [
            'Record',
            <button
              key="record"
              type="button"
              className="link-button"
              onClick={() => navigate(`/cases/${caseId}/artifacts/${record.id}`)}
            >
              {record.id.slice(0, 8)}...
            </button>,
          ],
        ]}
      />

      <h4 className="an-props-sub">Parties</h4>
      <KvTable
        rows={[
          ['From', from],
          ['To', to],
          [
            'Direction',
            dirKnown ? (
              (metaStr(m, 'direction') ?? (mine ? 'sent' : 'received'))
            ) : (
              <span key="direction" className="an-muted" title={UNDETERMINED_DIRECTION_MEANING}>
                {UNDETERMINED_DIRECTION}
              </span>
            ),
          ],
          ['Contact', contactRow],
          ['Phone', metaStr(m, 'phone_number')],
          ['Group', metaBool(m, 'is_group') ? 'yes' : null],
        ]}
      />

      <h4 className="an-props-sub">Message</h4>
      <KvTable
        rows={[
          ['When', whenLabel(t)],
          ['Type', metaStr(m, 'type')],
          ['GUID', metaStr(m, 'guid')],
          ['Starred', metaBool(m, 'starred') ? 'yes' : null],
        ]}
      />
      {text && <div className="an-props-text">{text}</div>}

      {atts.length > 0 && (
        <>
          <h4 className="an-props-sub">Media ({atts.length})</h4>
          {atts.map(({ record: a, artifactId }) => (
            <MediaBlock
              key={a.id}
              caseId={caseId}
              record={a}
              artifactId={artifactId}
            />
          ))}
        </>
      )}

      <button
        type="button"
        className="link-button an-props-raw-toggle"
        onClick={() => setShowRaw((v) => !v)}
      >
        {showRaw ? 'Hide' : 'Show'} all fields ({rawRows.length})
      </button>
      {showRaw && <KvTable rows={rawRows} />}

      <div className="an-props-actions">
        <button
          type="button"
          className="btn btn-primary"
          onClick={onOpenMessage}
        >
          Open message artifact
        </button>
      </div>
    </div>
  )
}

function makeMessagingViewer(cfg: MsgCfg): (props: ViewerProps) => ReactNode {
  return function MessagingViewer({ caseId, type }: ViewerProps) {
    const [sel, setSel] = useState<string | null>(null)
    const queryClient = useQueryClient()

    // Search state lives in the URL so the browser's back button returns to the
    // results: `q` is the query, `conv`/`focus`/`at` open a specific hit's
    // conversation at that message.
    const [params, setParams] = useSearchParams()
    const q = params.get('q') ?? ''
    const convParam = params.get('conv')
    const focusId = params.get('focus')
    const atParam = params.get('at')
    const at = atParam ? Number(atParam) : undefined
    const updateParams = (updates: Record<string, string | null>) => {
      setParams(
        (prev) => {
          const next = new URLSearchParams(prev)
          for (const [k, v] of Object.entries(updates)) {
            if (v == null) next.delete(k)
            else next.set(k, v)
          }
          return next
        },
        { replace: false },
      )
    }

    const [searchTerm, setSearchTerm] = useState(q)
    useEffect(() => setSearchTerm(q), [q])
    const searchQuery = useQuery({
      queryKey: ['conversation-search', caseId, type, q],
      queryFn: () => searchConversations(caseId, type, q),
      enabled: q.trim().length >= 2,
      staleTime: 30_000,
    })
    const searchHits = searchQuery.data?.hits ?? []
    // Defaults chosen so an old server that sends only `hits` is reported as
    // "we were not told", never as "this is everything": `truncated` false with
    // a full page would be a claim the server never made. A full page with no
    // label is therefore still flagged here.
    const searchLimit = searchQuery.data?.limit ?? 100
    const searchTruncated =
      searchQuery.data != null &&
      (searchQuery.data.truncated || searchHits.length >= searchLimit)
    const searchLowerBound =
      searchQuery.data != null &&
      (searchQuery.data.count_is_lower_bound || searchTruncated)

    // The full correspondent list is aggregated in SQL, so every conversation
    // is listed immediately however many messages the database holds.
    const threadsQuery = useQuery({
      queryKey: ['conversations', caseId, type],
      queryFn: () => getConversations(caseId, type),
      staleTime: 60_000,
    })
    // The address book resolves handles to names. Shown alongside the handle,
    // never instead of it: the name is an inference from the device's
    // contacts, not something the chat database recorded.
    const contacts = useContactIndex(caseId)
    const threads = threadsQuery.data ?? []


    // A conversation opened from a search hit (URL `conv`) wins over the manual
    // selection so browser back/forward moves between results and threads.
    const active =
      convParam && threads.some((t) => t.key === convParam)
        ? convParam
        : sel && threads.some((t) => t.key === sel)
          ? sel
          : (threads[0]?.key ?? null)
    const activeThread = threads.find((t) => t.key === active) ?? null

    // Show the results list when a query is set and no hit has been opened yet.
    const showingResults = q.trim().length >= 2 && !convParam
    const threadLabel = (key: string) =>
      contacts.lookup(key) ??
      threads.find((t) => t.key === key)?.label ??
      key

    // Messages for the selected conversation only, walked backwards a page at a
    // time. Older pages are dropped once the examiner scrolls far past them
    // (maxPages), so a long session over a huge thread stays bounded.
    const messagesQuery = useInfiniteQuery({
      // Opening from a search hit loads the page ending at that message (its
      // date + 1s), so the match is on screen without scrolling the whole thread.
      queryKey: ['conversation-messages', caseId, type, active, at],
      initialPageParam: openingCursor(at),
      queryFn: ({ pageParam }) =>
        getConversationMessages(caseId, type, active!, pageParam, WINDOW),
      // The cursor comes from the server, and carries both an ordering value
      // and the id that breaks ties on it. Computing it here from the last
      // record's timestamp is what the old code did, and the server now
      // refuses that (400): resuming from an ordering value alone drops every
      // message sharing it with the last one on the page.
      //
      // `hasMore` rather than `records.length < WINDOW`: a page shortened by
      // undecodable rows comes back under the limit while more messages exist,
      // and inferring the end from a short page ended the thread early.
      getNextPageParam: (last) => (last.hasMore ? last.nextCursor : undefined),
      enabled: !!active,
      maxPages: MAX_PAGES,
    })

    // Has the sliding window thrown away the newest messages?
    //
    // `pageParams[0]` is the cursor of the newest page currently held. While
    // nothing has been evicted it is still the cursor the thread was opened
    // with (undefined for "newest", or the search hit's timestamp). Once
    // react-query drops the first page to honour MAX_PAGES it no longer is —
    // which is the exact moment the bottom of the pane stops being the end of
    // the conversation. Derived from the query rather than counted by hand so
    // it cannot drift out of step with what is actually rendered.
    // Compared by value, not identity: the cursor is an object now, and
    // `openingCursor` builds a fresh one on every render, so `!==` would report
    // eviction on the first page of every thread.
    const openedAtCursor = openingCursor(at)
    const pageCursors = messagesQuery.data?.pageParams as
      | (ConversationCursor | undefined)[]
      | undefined
    const windowEvicted =
      pageCursors != null &&
      pageCursors.length > 0 &&
      !sameCursor(pageCursors[0], openedAtCursor)

    // Pages arrive newest-first; render oldest-first so the conversation reads
    // the way it did on the phone.
    //
    // Deduplicated by id: the cursor deliberately overlaps the second each page
    // ends in (see `nextCursor`), so the messages at that second arrive twice.
    // Rendering both would double them in the thread and in any count taken
    // from it.
    const shown = useMemo(() => {
      const pages = messagesQuery.data?.pages ?? []
      const byId = new Map<string, ParsedRecord>()
      for (const page of pages) {
        for (const record of page.records) {
          if (!byId.has(record.id)) byId.set(record.id, record)
        }
      }
      return [...byId.values()].sort(
        (a, b) => msgOrder(a.metadata) - msgOrder(b.metadata),
      )
    }, [messagesQuery.data])

    // A burst of messages sharing one timestamp used to stall scrollback: a
    // timestamp-only cursor could not step past it, and the pane said so. The
    // server's cursor now carries the tie-breaking id, so the position is always
    // unambiguous and the stall cannot arise. `cursorStalled` is gone rather
    // than left wired to a condition that can no longer be true.
    const heldPages = messagesQuery.data?.pages ?? []

    // Messages these pages fetched and could not decode. The thread on screen
    // is short by this many that DO exist in the evidence — an absence the
    // examiner must not read as a gap in the conversation itself.
    const undecodableShown = heldPages.reduce(
      (total, page) => total + (page.undecodable ?? 0),
      0,
    )

    // The parsers stamp the standard incompleteness pair on messages they could
    // not finish reading (a half-read database, an undecodable body). This
    // viewer loads its own messages, so the page shell's banner does not cover
    // them and the pair would otherwise reach nobody (B4-023).
    const incompleteness = useIncompleteness(shown)

    // Carved bodies have no recovered timestamp; warn once at the top so their
    // trailing, undated position isn't mistaken for the true chat order.
    const undatedCount = useMemo(
      () => shown.filter((m) => !hasDate(m.metadata)).length,
      [shown],
    )

    // The conversation opens at the newest message and only loads older pages
    // when the reader scrolls up to them. Without this the top sentinel is in
    // view from the start, so it loads older pages in a loop — and maxPages
    // evicts the newest ones, making the thread walk backwards on its own.
    const convoRef = useRef<HTMLDivElement>(null)
    const scrolledFor = useRef<string | null>(null)
    // Distance from the bottom captured just before an older page loads, so the
    // reader keeps their place instead of jumping when it prepends.
    const anchorFromBottom = useRef<number | null>(null)

    // Throw the window away and reload from the newest message. Resetting the
    // query is the only way back: react-query pages in one direction here, so
    // once the newest pages are evicted there is nothing to "fetch previous".
    const backToNewest = () => {
      scrolledFor.current = null
      anchorFromBottom.current = null
      void queryClient.resetQueries({
        queryKey: ['conversation-messages', caseId, type, active, at],
      })
    }

    const canLoadOlder = !!messagesQuery.hasNextPage
    const loadOlder = useRef<() => void>(() => {})
    loadOlder.current = () => {
      if (messagesQuery.hasNextPage && !messagesQuery.isFetchingNextPage) {
        const el = convoRef.current
        if (el) anchorFromBottom.current = el.scrollHeight - el.scrollTop
        void messagesQuery.fetchNextPage()
      }
    }

    useEffect(() => {
      const el = convoRef.current
      if (!el || !active) return
      // Opened from a search hit: centre and highlight that message instead of
      // jumping to the newest.
      if (focusId) {
        const target = el.querySelector(`[data-msg-id="${focusId}"]`)
        if (target) {
          ;(target as HTMLElement).scrollIntoView({ block: 'center' })
          setSelectedId(focusId)
          scrolledFor.current = active
        }
        return
      }
      if (anchorFromBottom.current != null) {
        // Older messages just prepended: restore the reader's position.
        el.scrollTop = el.scrollHeight - anchorFromBottom.current
        anchorFromBottom.current = null
        return
      }
      if (scrolledFor.current !== active && shown.length > 0) {
        // First page of a freshly opened thread: jump to the newest message.
        el.scrollTop = el.scrollHeight
        scrolledFor.current = active
      }
      // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [active, shown, focusId])

    // Scroll sentinel above the oldest rendered message. Guarded because
    // IntersectionObserver is absent in some test environments; the explicit
    // "Load older" button remains the accessible (and fallback) path.
    const topRef = useRef<HTMLDivElement>(null)
    useEffect(() => {
      const el = topRef.current
      if (!el || typeof IntersectionObserver === 'undefined') return
      // Root is the conversation itself, so "reached the top" is measured
      // against the scrolled pane, not the whole viewport — a thread opened at
      // the bottom then does not immediately fetch older pages.
      const io = new IntersectionObserver(
        (entries) => {
          if (entries.some((e) => e.isIntersecting)) loadOlder.current()
        },
        { root: convoRef.current },
      )
      io.observe(el)
      return () => io.disconnect()
    }, [active, canLoadOlder])

    // Media for the messages on screen, returned with them by the server, so a
    // database holding thousands of attachments costs nothing to browse.
    // Deduplicated for the same reason as `shown`: overlapping pages re-serve
    // the attachments of the messages they re-serve.
    const threadAttachments = useMemo(() => {
      const byId = new Map<string, ParsedRecord>()
      for (const page of messagesQuery.data?.pages ?? []) {
        for (const attachment of page.attachments) {
          if (!byId.has(attachment.id)) byId.set(attachment.id, attachment)
        }
      }
      return [...byId.values()]
    }, [messagesQuery.data])

    // Attachments carry the pair independently of the messages they hang off: a
    // media row whose bytes were only half read sits under a message that
    // parsed cleanly. Summarised separately so the noun in the banner is the
    // truth — folding them into the message tally would report a count of
    // "messages" that includes rows that are not messages.
    const attachmentIncompleteness = useIncompleteness(threadAttachments)

    // Did the server's attachment fetch hit its row cap on any page held here?
    //
    // Separate from the incompleteness pair above: that is the parser saying a
    // media row it DID return is short, this is the server saying rows are
    // missing altogether. A capped page returns exactly the cap and looks
    // identical to a complete one, so the message bubbles below would show
    // fewer chips than the messages had, silently.
    const attachmentsCapped = useMemo(
      () =>
        (messagesQuery.data?.pages ?? []).some((p) => p.attachmentsTruncated),
      [messagesQuery.data],
    )

    // Locate each attachment's media in the evidence, in one batched call, so
    // the chip can show the picture and open the artifact.
    const attachmentPaths = useMemo(
      () =>
        threadAttachments
          .map((a) => attachmentPath(a.metadata))
          .filter((p): p is string => !!p),
      [threadAttachments],
    )
    const filesQuery = useQuery({
      queryKey: ['attachment-files', caseId, attachmentPaths.join('|')],
      queryFn: () => resolveFiles(caseId, attachmentPaths),
      enabled: attachmentPaths.length > 0,
      staleTime: Infinity,
    })
    const fileFor = (m: RecordMetadata): string | undefined => {
      const p = attachmentPath(m)
      return p ? filesQuery.data?.[p] : undefined
    }
    // "No match" and "we have not looked yet / the lookup failed" are different
    // statements about the evidence and must not render alike (B4-025).
    const lookupState: 'pending' | 'resolved' | 'failed' =
      attachmentPaths.length === 0 || filesQuery.isSuccess
        ? 'resolved'
        : filesQuery.isError
          ? 'failed'
          : 'pending'

    // Attachments grouped by the message they belong to (chat.db's
    // message_attachment_join). Anything with no such link stays in the side
    // panel rather than being guessed onto a message.
    const attachmentsByMsg = useMemo(() => {
      const map = new Map<string, ParsedRecord[]>()
      for (const a of threadAttachments) {
        const key = attachmentMsgKey(a.metadata)
        if (!key) continue
        const list = map.get(key)
        if (list) list.push(a)
        else map.set(key, [a])
      }
      return map
    }, [threadAttachments])

    // A selected message drives the properties inspector on the right. Cleared
    // when the conversation changes.
    const navigate = useNavigate()
    const [selectedId, setSelectedId] = useState<string | null>(null)
    useEffect(() => {
      setSelectedId(null)
    }, [active])
    const openMessageArtifact = (id: string) =>
      navigate(`/cases/${caseId}/artifacts/${id}`)

    const selected = useMemo(() => {
      if (!selectedId) return null
      const rec = shown.find((r) => r.id === selectedId)
      if (!rec) return null
      const atts = msgKeys(rec.metadata).flatMap(
        (k) => attachmentsByMsg.get(k) ?? [],
      )
      return { rec, atts }
    }, [selectedId, shown, attachmentsByMsg])

    if (threadsQuery.isPending) {
      return <div className="loading">Loading conversations…</div>
    }
    if (threadsQuery.isError) {
      return <div className="error-note">{(threadsQuery.error as Error).message}</div>
    }
    if (threads.length === 0) {
      return (
        <div className="empty-state">
          <h3>No conversations</h3>
          <p>No messages were parsed for this type.</p>
        </div>
      )
    }

    return (
      <div className={`an-chat an-theme-${cfg.theme}`}>
        <aside className="an-thread-list" aria-label="Conversations">
          <form
            className="an-search"
            onSubmit={(e) => {
              e.preventDefault()
              const term = searchTerm.trim()
              // Setting `q` (and clearing any open hit) is a history push, so
              // back returns here.
              updateParams({
                q: term || null,
                conv: null,
                focus: null,
                at: null,
              })
            }}
          >
            <input
              className="input an-search-input"
              type="search"
              placeholder="Search messages…"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              aria-label="Search messages"
            />
            {q && (
              <button
                type="button"
                className="an-search-clear"
                aria-label="Clear search"
                onClick={() =>
                  updateParams({ q: null, conv: null, focus: null, at: null })
                }
              >
                ×
              </button>
            )}
          </form>
          <div className="an-chat-note">
            {formatCount(threads.length)} conversation
            {threads.length === 1 ? '' : 's'}
          </div>
          {contacts.truncated && (
            <div className="an-chat-note" role="status">
              Address book too large to fully index; some handles may show
              unnamed.
            </div>
          )}
          {threads.map((t) => (
            <button
              key={t.key}
              type="button"
              className={t.key === active ? 'an-thread selected' : 'an-thread'}
              data-testid="an-thread"
              onClick={() => {
                setSel(t.key)
                // Manual selection leaves search mode.
                updateParams({ conv: null, focus: null, at: null, q: null })
              }}
            >
              <div className="an-thread-top">
                <span className="an-thread-name">
                  {contacts.lookup(t.key) ?? t.label}
                </span>
                <span className="an-thread-count mono">
                  {formatCount(t.count)}
                </span>
              </div>
              <div className="an-thread-preview">
                {displayText(t.last_preview) ?? '(no text)'}
              </div>
              {contacts.lookup(t.key) && (
                <div className="an-thread-handle mono">{t.key}</div>
              )}
              <div className="an-thread-sub">
                {t.is_group && <span className="badge">group</span>}
                {t.tag && <span className="an-thread-tag">{t.tag}</span>}
                <span className="mono an-thread-time">
                  {whenLabel(t.last_time)}
                </span>
              </div>
            </button>
          ))}
        </aside>

        {showingResults ? (
          <section className="an-chat-main" aria-label="Search results">
            <header className="an-chat-head">
              <span className="an-chat-title">Results for “{q}”</span>
              <span className="an-chat-key mono">
                {searchQuery.isSuccess
                  ? // The server stops at its limit without counting past it, so
                    // a full page and a complete answer look alike unless the
                    // count is labelled. "At least N" is the honest reading when
                    // it says so.
                    `${searchHits.length === 0 || !searchLowerBound ? '' : 'at least '}${searchHits.length} match${
                      searchHits.length === 1 ? '' : 'es'
                    }`
                  : ''}
              </span>
            </header>
            <div className="an-convo an-results">
              {/* A capped hit list is not the match set. The endpoint stops at
                  its limit without counting past it and says so; discarding
                  that label made "23 matches" mean "the first 23 of an unknown
                  number" on the surface most likely to be quoted in court. */}
              {searchTruncated && (
                <div className="warn-note" role="note" data-testid="an-search-capped">
                  <strong>This is not every match.</strong> The search stopped at{' '}
                  {formatCount(searchLimit)} hits without counting the rest,
                  so messages containing “{q}” exist that are not listed here.
                  Narrow the term before treating this list as the set of
                  matching messages.
                </div>
              )}
              {searchQuery.isPending ? (
                <div className="loading">Searching…</div>
              ) : searchQuery.isError ? (
                // A failed search must never render as "no messages match":
                // that is the tool asserting an absence it never established.
                <div className="error-note" role="note">
                  The search failed:{' '}
                  {(searchQuery.error as Error).message}. Nothing follows about
                  whether any message contains “{q}”.
                </div>
              ) : searchHits.length === 0 ? (
                <div className="empty-state">
                  <p>No messages match “{q}”.</p>
                </div>
              ) : (
                searchHits.map((hit) => (
                  <button
                    key={hit.id}
                    type="button"
                    className="an-result"
                    onClick={() =>
                      updateParams({
                        conv: hit.thread_key,
                        focus: hit.id,
                        at: String(hit.date),
                        q: null,
                      })
                    }
                  >
                    <div className="an-result-top">
                      <span className="an-result-who">
                        {threadLabel(hit.thread_key)}
                      </span>
                      <span className="an-result-time mono">
                        {whenLabel(hit.date)}
                      </span>
                    </div>
                    <div className="an-result-text">
                      {displayText(hit.text) ?? hit.text}
                    </div>
                  </button>
                ))
              )}
            </div>
          </section>
        ) : (
        <section className="an-chat-main" aria-label="Messages">
          <header className="an-chat-head">
            <span className="an-chat-title">
              {(activeThread && contacts.lookup(activeThread.key)) ??
                activeThread?.label}
            </span>
            {activeThread?.is_group && <span className="badge">group chat</span>}
            <span className="an-chat-key mono">{activeThread?.key}</span>
          </header>
          {undatedCount > 0 && (
            <div className="an-undated-note" role="note">
              {formatCount(undatedCount)} message
              {undatedCount === 1 ? '' : 's'} had no recoverable date and appear
              at the end.
            </div>
          )}
          {undecodableShown > 0 && (
            <div
              className="warn-note"
              role="note"
              data-testid="an-undecodable-messages"
            >
              <strong>
                {formatCount(undecodableShown)} message
                {undecodableShown === 1 ? '' : 's'} in this thread could not be
                decoded.
              </strong>{' '}
              They exist in the evidence and are not shown here, so this
              conversation is short by that many. The gap is in the decoding,
              not in what was said.
            </div>
          )}
          {windowEvicted && (
            <div className="an-window-note" role="note">
              <strong>This is a window, not the end of the thread.</strong> Only{' '}
              {MAX_PAGES} pages of scrollback are held at once, so loading older
              messages unloaded the newest ones. The last message below is not
              the last message in the conversation.{' '}
              <button
                type="button"
                className="link-button"
                onClick={backToNewest}
              >
                Back to the newest messages
              </button>
            </div>
          )}
          <IncompletenessBanner
            summary={incompleteness}
            noun="messages"
            scopeNote="Only the messages currently held in this scrollback window were checked; older pages carry their own stamps."
          />
          <IncompletenessBanner
            summary={attachmentIncompleteness}
            noun="attachments"
            scopeNote="These are the media rows for the messages in this window."
          />
          {attachmentsCapped && (
            <div
              className="warn-note"
              role="note"
              data-testid="an-att-capped"
            >
              <strong>Media is missing from this view.</strong> The server
              stopped fetching attachments for these messages at its row cap, so
              messages below may show fewer photos, videos or files than they
              actually carried. Absence of a chip on a message here is not
              evidence the message had no attachment.
            </div>
          )}
          <div className="an-convo" data-testid="an-convo" ref={convoRef}>
            <div ref={topRef} className="an-convo-top" />
            {canLoadOlder && (
              <button
                type="button"
                className="an-load-older"
                onClick={() => loadOlder.current()}
              >
                {messagesQuery.isFetchingNextPage
                  ? 'Loading older messages…'
                  : 'Load older messages'}
              </button>
            )}
            {shown.map((r, i) => {
              const m = r.metadata
              const mine = fromMe(m)
              const handle = cfg.senderName(m)
              const who = mine ? 'Me' : (contacts.lookup(handle) ?? handle)
              const hasMedia = metaNum(m, 'media_size') != null
              const t = msgTime(m)
              const dated = hasDate(m)
              // Divider whenever the calendar day changes, as a phone shows it.
              // Undated (carved) bodies get one "no date" divider where the run
              // begins instead of a bogus 1970 day.
              const prevDated = i > 0 ? hasDate(shown[i - 1].metadata) : false
              const prev = i > 0 ? msgTime(shown[i - 1].metadata) : null
              const newDay = dated
                ? prev === null || dayKey(prev) !== dayKey(t)
                : false
              const startUndated = !dated && (i === 0 || prevDated)
              const inlineAtts = msgKeys(m).flatMap(
                (k) => attachmentsByMsg.get(k) ?? [],
              )
              const text = displayText(metaStr(m, 'text'))
              return (
                <Fragment key={r.id}>
                  {newDay && (
                    <div className="an-day-sep" data-testid="an-day-sep">
                      <span>{dayLabel(t)}</span>
                    </div>
                  )}
                  {startUndated && (
                    <div className="an-day-sep" data-testid="an-day-sep">
                      <span>No recovered date</span>
                    </div>
                  )}
                  <div className={mine ? 'an-msg an-msg-me' : 'an-msg'}>
                    <div
                      data-msg-id={r.id}
                      className={
                        selectedId === r.id
                          ? 'an-msg-bubble is-selected'
                          : 'an-msg-bubble'
                      }
                      tabIndex={0}
                      role="button"
                      aria-pressed={selectedId === r.id}
                      // Click selects (properties on the right); double-click
                      // opens the message as a full artifact.
                      onClick={() => setSelectedId(r.id)}
                      onDoubleClick={() => openMessageArtifact(r.id)}
                    >
                      <div className="an-msg-head">
                        {/* The name shown is the resolved contact; the pivot
                            is on the handle the database stored, which is the
                            identifier the rest of the case carries (§5.1). A
                            message of mine has no counterparty to pivot on. */}
                        <PivotName
                          className="an-msg-who"
                          pivotOn={mine ? null : handle}
                          label={who}
                        />
                        <span className="an-msg-time mono">
                          {dated ? whenLabel(t) : ''}
                        </span>
                        {metaBool(m, 'recovered') && (
                          <span
                            className="an-msg-recovered"
                            title={`Recovered from deleted space (${
                              metaStr(m, 'recovery_source') ?? 'unknown'
                            }, confidence ${metaNum(m, 'confidence') ?? '?'})`}
                          >
                            recovered
                          </span>
                        )}
                        {/* The banner above says HOW MANY messages in this
                            window are short; this says WHICH. Without it an
                            examiner reading a thread cannot tell the truncated
                            message from the ones either side of it, and a
                            screenshot of the bubble carries no warning at
                            all. */}
                        <IncompleteBadge metadata={m} />
                      </div>
                      {text != null ? (
                        <div className="an-msg-text">{text}</div>
                      ) : (
                        inlineAtts.length === 0 && (
                          <div className="an-msg-text">{MISSING}</div>
                        )
                      )}
                      {inlineAtts.length > 0 && (
                        <div className="an-msg-atts">
                          {inlineAtts.map((a) => (
                            <AttachmentChip
                              key={a.id}
                              record={a}
                              caseId={caseId}
                              artifactId={fileFor(a.metadata)}
                              lookup={lookupState}
                              onSelect={() => setSelectedId(r.id)}
                            />
                          ))}
                        </div>
                      )}
                      {inlineAtts.length === 0 &&
                        (metaBool(m, 'has_attachments') || hasMedia) && (
                          <div className="an-msg-foot">
                            <span className="badge">
                              {hasMedia ? 'media' : 'attachment'}
                            </span>
                          </div>
                        )}
                      {!directionKnown(m) && (
                        <div className="an-msg-nodir">
                          Direction (Sent/Received) Not Determinable
                        </div>
                      )}
                    </div>
                  </div>
                </Fragment>
              )
            })}
          </div>
        </section>
        )}

        <aside className="an-props" aria-label="Message properties">
          {selected
            ? (() => {
                const sm = selected.rec.metadata
                const mine = fromMe(sm)
                const handle = cfg.senderName(sm)
                const contactLabel = contacts.lookup(handle) ?? handle
                return (
                  <MessageProperties
                    record={selected.rec}
                    caseId={caseId}
                    mine={mine}
                    contactLabel={contactLabel}
                    atts={selected.atts.map((a) => ({
                      record: a,
                      artifactId: fileFor(a.metadata),
                    }))}
                    onOpenMessage={() => openMessageArtifact(selected.rec.id)}
                  />
                )
              })()
            : (
                <div className="an-props-empty">
                  Select a message to see its properties. Double-click a message
                  — or a photo — to open the full artifact.
                </div>
              )}
        </aside>
      </div>
    )
  }
}

export const IMessageViewer = makeMessagingViewer({
  attachmentType: 'iMessageAttachment',
  theme: 'imessage',
  senderName: (m) => metaFirst(m, ['contact']) ?? 'Unknown',
})

export const WhatsAppViewer = makeMessagingViewer({
  attachmentType: 'WhatsAppAttachment',
  theme: 'whatsapp',
  senderName: (m) =>
    metaFirst(m, ['contact_name', 'phone_number', 'remote_jid', 'contact_jid']) ?? 'Unknown',
})

export const AndroidSmsViewer = makeMessagingViewer({
  theme: 'sms',
  senderName: (m) => metaFirst(m, ['contact', 'chat_display_name']) ?? 'Unknown',
})

export const SignalViewer = makeMessagingViewer({
  theme: 'signal',
  senderName: (m) => metaFirst(m, ['sender', 'contact']) ?? 'Unknown',
})

export const InstagramViewer = makeMessagingViewer({
  theme: 'instagram',
  senderName: (m) => metaFirst(m, ['contact', 'sender_id']) ?? 'Unknown',
})

export const SnapchatViewer = makeMessagingViewer({
  theme: 'snapchat',
  senderName: (m) => metaFirst(m, ['contact', 'sender_id']) ?? 'Unknown',
})

export const TwitterDmViewer = makeMessagingViewer({
  theme: 'twitter',
  senderName: (m) =>
    metaFirst(m, ['contact', 'sender_screen_name', 'sender_id']) ?? 'Unknown',
})

// A shared correspondent resolver covering the identifier fields the remaining
// messengers use, so one config serves them all.
const genericSender = (m: RecordMetadata) =>
  metaFirst(m, [
    'contact',
    'contact_name',
    'chat_display_name',
    'sender',
    'chat_identifier',
    'contact_jid',
    'remote_jid',
  ]) ?? 'Unknown'

export const ViberViewer = makeMessagingViewer({ theme: 'viber', senderName: genericSender })
export const KikViewer = makeMessagingViewer({ theme: 'kik', senderName: genericSender })
export const SkypeViewer = makeMessagingViewer({ theme: 'skype', senderName: genericSender })
export const LineViewer = makeMessagingViewer({ theme: 'line', senderName: genericSender })
export const TelegramViewer = makeMessagingViewer({ theme: 'telegram', senderName: genericSender })
export const MessengerViewer = makeMessagingViewer({
  theme: 'messenger',
  senderName: genericSender,
})
export const WeChatViewer = makeMessagingViewer({ theme: 'wechat', senderName: genericSender })
