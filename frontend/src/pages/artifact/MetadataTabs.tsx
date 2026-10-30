import { useEffect, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Copy, Check } from 'lucide-react'
import type { Artifact } from '../../api/types'
import { getArtifact } from '../../api/resources'
import { ArtifactIncompleteness } from '../../components/Incompleteness'
import { formatBytes, formatUtc } from '../../lib/format'
import { pivotTarget } from '../../lib/pivotable'
import { PivotMono } from '../analysis/cells'
import { metadataNumber, metadataString } from './lib'
import { TimestampPanel } from './TimestampPanel'

interface Card {
  label: string
  value: string
  mono?: boolean
  copy?: boolean
  badgeClass?: string
}

export function CopyButton({ value, label }: { value: string; label: string }) {
  const [copied, setCopied] = useState(false)
  useEffect(() => {
    if (!copied) return
    const timer = setTimeout(() => setCopied(false), 1500)
    return () => clearTimeout(timer)
  }, [copied])
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(value)
      setCopied(true)
    } catch {
      // Clipboard unavailable (insecure context); nothing to do.
    }
  }
  return (
    <button
      type="button"
      className="av-copy icon-btn"
      aria-label={`Copy ${label}`}
      onClick={copy}
    >
      {copied ? <Check size={13} /> : <Copy size={13} />}
      <span className="sr-only">{copied ? 'Copied' : 'Copy'}</span>
    </button>
  )
}

function overviewCards(artifact: Artifact): Card[] {
  const md = artifact.metadata
  const cards: Card[] = []
  const size = metadataNumber(md, 'size') ?? metadataNumber(md, 'file_size')
  if (size != null) cards.push({ label: 'Size', value: formatBytes(size) })
  const sourcePath =
    metadataString(md, 'source_path') ?? metadataString(md, 'path')
  if (sourcePath) {
    cards.push({ label: 'Source path', value: sourcePath, mono: true })
  }
  const timestampKeys: [string, string][] = [
    ['created', 'Created'],
    ['created_at', 'Created'],
    ['modified', 'Modified'],
    ['accessed', 'Accessed'],
  ]
  const seenLabels = new Set<string>()
  for (const [key, label] of timestampKeys) {
    const value = metadataString(md, key)
    if (value && !seenLabels.has(label)) {
      seenLabels.add(label)
      cards.push({ label, value: formatUtc(value), mono: true })
    }
  }
  for (const [key, label] of [
    ['acquisition_md5', 'Acquisition MD5'],
    ['acquisition_sha1', 'Acquisition SHA1'],
    ['acquisition_sha256', 'Acquisition SHA256'],
    ['md5', 'MD5'],
    ['sha1', 'SHA1'],
    ['sha256', 'SHA256'],
  ] as const) {
    const value = metadataString(md, key)
    if (value) cards.push({ label, value, mono: true, copy: true })
  }
  // Acquisition-baseline integrity state. Parse-while-hashing queues evidence
  // for processing while its baseline is still being hashed, so an artifact can
  // legitimately show "Verifying" before its acquisition hashes appear above.
  const integrityState = metadataString(md, 'integrity_state')
  if (integrityState) {
    const states: Record<string, { value: string; badgeClass: string }> = {
      verifying: { value: 'Verifying…', badgeClass: 'badge badge-warn' },
      baseline_recorded: {
        value: 'Baseline recorded',
        badgeClass: 'badge badge-ok',
      },
      acquisition_failed: {
        value: 'Baseline failed',
        badgeClass: 'badge badge-danger',
      },
    }
    const entry = states[integrityState] ?? {
      value: integrityState,
      badgeClass: 'badge',
    }
    cards.push({ label: 'Integrity', value: entry.value, badgeClass: entry.badgeClass })
  }
  if (md.acquisition_hash_reused === true) {
    cards.push({
      label: 'Acquisition baseline',
      value: 'Reused (bytes not re-read this ingest)',
      badgeClass: 'badge',
    })
  }
  const carvingOffset = metadataNumber(md, 'carving_offset_absolute')
  if (carvingOffset != null) {
    cards.push({
      label: 'Carving offset',
      value: `0x${carvingOffset.toString(16)} (${carvingOffset})`,
      mono: true,
    })
  }
  const carvingSignature = metadataString(md, 'carving_signature')
  if (carvingSignature) {
    cards.push({
      label: 'Carving signature',
      value: carvingSignature,
      mono: true,
    })
  }
  if (typeof md.carving_validated === 'boolean') {
    cards.push({
      label: 'Carving validation',
      value: md.carving_validated ? 'Validated' : 'Not validated',
      badgeClass: md.carving_validated ? 'badge badge-ok' : 'badge',
    })
  }
  if (md.carving_below_minimum === true) {
    cards.push({
      label: 'Carve length',
      value: 'Below declared size',
      badgeClass: 'badge',
    })
  }
  const hashedAt = metadataNumber(md, 'acquisition_hashed_at')
  if (hashedAt != null) {
    cards.push({
      label: 'Acquired',
      value: formatUtc(new Date(hashedAt * 1000).toISOString()),
      mono: true,
    })
  }
  return cards
}

export function OverviewTab({
  artifact,
  caseId,
}: {
  artifact: Artifact
  caseId?: string
}) {
  const own = overviewCards(artifact)

  // A parsed record (a Signal-backup summary, a chat message) carries only what
  // its parser emitted, so it has no size or dates of its own. Those belong to
  // the file it was parsed from, so fall back to the parent's — labelled as
  // such, never presented as the record's own facts.
  const parentQuery = useQuery({
    queryKey: ['artifact-parent', caseId, artifact.parent_id],
    queryFn: () => getArtifact(caseId!, artifact.parent_id!),
    enabled: own.length === 0 && !!caseId && !!artifact.parent_id,
    staleTime: Infinity,
    retry: false,
  })

  const inherited = parentQuery.data ? overviewCards(parentQuery.data) : []
  const cards = own.length > 0 ? own : inherited
  const fromParent = own.length === 0 && inherited.length > 0

  return (
    <>
      {/* Before any of the facts, because it qualifies all of them: a size, a
          hash or a timestamp taken from a partially-parsed artifact describes
          the part that was parsed. Read off THIS artifact's metadata only —
          the parent's completeness says nothing about this record. */}
      <ArtifactIncompleteness metadata={artifact.metadata} />
      {fromParent && (
        <p className="av-inherited-note">
          From the source file{' '}
          <span className="mono">
            {metadataString(parentQuery.data!.metadata, 'name') ?? 'this record was parsed from'}
          </span>
          , which holds this record.
        </p>
      )}
      {cards.length === 0 ? (
        <div className="empty-state">
          <h3>No common metadata</h3>
          <p>Use “Show all properties” below for everything recorded on this artifact.</p>
        </div>
      ) : (
        <div className="av-cards">
          {cards.map((card) => (
            <div key={card.label} className="av-card">
              <span className="av-label">{card.label}</span>
              {card.badgeClass ? (
                <span className={card.badgeClass}>{card.value}</span>
              ) : (
                <span className={card.mono ? 'av-value mono' : 'av-value'}>
                  {card.value}
                </span>
              )}
              {card.copy && (
                <CopyButton value={card.value} label={card.label} />
              )}
            </div>
          ))}
        </div>
      )}
      <TimestampPanel metadata={artifact.metadata} />
    </>
  )
}

export function PropertiesTab({
  metadata,
}: {
  metadata: Record<string, unknown>
}) {
  const keys = Object.keys(metadata).sort()
  if (keys.length === 0) {
    return (
      <div className="empty-state">
        <h3>No metadata</h3>
        <p>This artifact has no recorded metadata.</p>
      </div>
    )
  }
  return (
    <table className="data-table av-kv">
      <thead>
        <tr>
          <th>Key</th>
          <th>Value</th>
        </tr>
      </thead>
      <tbody>
        {keys.map((key) => {
          const value = metadata[key]
          const isNested = value !== null && typeof value === 'object'
          // An identifier here is one click from its footprint across the
          // case (§1.0). The key decides: `pivotTarget` allow-lists the
          // identifier classes, so a count, a flag or one of the product's
          // own incompleteness sentences stays plain text rather than
          // offering a pivot that would only return noise.
          const pivot = isNested ? null : pivotTarget(key, value)
          return (
            <tr key={key}>
              <td className="mono">{key}</td>
              <td>
                {isNested ? (
                  <pre className="av-json">
                    {JSON.stringify(value, null, 2)}
                  </pre>
                ) : pivot !== null ? (
                  <PivotMono pivotOn={pivot} />
                ) : (
                  <span className="mono">{String(value)}</span>
                )}
              </td>
            </tr>
          )
        })}
      </tbody>
    </table>
  )
}

export function RawJsonTab({
  metadata,
}: {
  metadata: Record<string, unknown>
}) {
  return <pre className="av-json av-text">{JSON.stringify(metadata, null, 2)}</pre>
}
