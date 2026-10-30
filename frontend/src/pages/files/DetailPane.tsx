import { useQuery } from '@tanstack/react-query'
import { useEffect, useState } from 'react'
import { Copy, Check } from 'lucide-react'
import { getArtifact } from '../../api/resources'
import { HexView } from '../../components/hex/HexView'
import { ArtifactIncompleteness } from '../../components/Incompleteness'
import { formatBytes, formatCount, formatUtc, truncateHash } from '../../lib/format'
import { incompleteReasonLabel } from '../../lib/incompleteness'
import { useObjectUrl } from '../../lib/useObjectUrl'
import { fetchThumbnail, getFileHex } from './api'
import type { FileRow } from './types'

const HEX_PREVIEW_BYTES = 512

function formatMetaValue(value: unknown): string {
  if (value == null) return '—'
  if (typeof value === 'object') return JSON.stringify(value)
  return String(value)
}

/** Row-level hash pulled from metadata (include_metadata=true). */
function hashValue(
  metadata: Record<string, unknown> | null | undefined,
  key: string,
): string | null {
  const value = metadata?.[key]
  return typeof value === 'string' && value.length > 0 ? value : null
}

function CopyHash({ label, value }: { label: string; value: string }) {
  const [copied, setCopied] = useState(false)
  async function copy() {
    try {
      await navigator.clipboard?.writeText(value)
      setCopied(true)
      setTimeout(() => setCopied(false), 1500)
    } catch {
      // Clipboard unavailable; leave the value on screen to copy manually.
    }
  }
  return (
    <div className="fg-hash-row">
      <span className="fg-hash-label">{label}</span>
      <span className="fg-hash-value mono" title={value}>
        {truncateHash(value)}
      </span>
      <button
        type="button"
        className={copied ? 'fg-copy fg-copy-done' : 'fg-copy'}
        aria-label={`Copy ${label}`}
        onClick={copy}
      >
        {copied ? <Check size={13} /> : <Copy size={13} />}
        <span className="sr-only">{copied ? 'Copied' : 'Copy'}</span>
      </button>
    </div>
  )
}

function Thumbnail({ caseId, item }: { caseId: string; item: FileRow }) {
  const thumb = useQuery({
    queryKey: ['file-thumb', caseId, item.id],
    queryFn: () => fetchThumbnail(caseId, item.id),
    staleTime: Infinity,
    // The object URL is revoked on unmount, so the cache entry must not outlive
    // the component: reselecting the same file must refetch a fresh blob rather
    // than read back an already-revoked URL and render a broken image
    // (BUG-167). Mirrors the gallery cells' gcTime: 0.
    gcTime: 0,
    retry: false,
  })

  // The query holds bytes; the URL is minted and revoked by this component, so
  // deselecting the file mid-fetch cannot orphan a handle (B4-027).
  const url = useObjectUrl(`${caseId}/${item.id}/96`, thumb.data?.blob ?? null)
  // `X-Thumbnail-Source: device-cache` — the server did not decode these pixels
  // from this file. A cached preview can outlive and disagree with the file it
  // was made from, so it is not a picture of the evidence unless said so.
  const derived = thumb.data?.fromDeviceCache === true

  // Non-images (404) and failures simply render nothing.
  if (!url) return null
  return (
    <>
      <img
        className="fg-thumb"
        src={url}
        alt={
          derived
            ? `Thumbnail of ${item.name} (not decoded from this file)`
            : `Thumbnail of ${item.name}`
        }
      />
      {derived && (
        <div className="warn-note" role="note" data-testid="fg-derived-thumb">
          This preview was <strong>not decoded from this file</strong> — the
          server built it from the device&rsquo;s own thumbnail cache or a video
          keyframe. It may not match the bytes held in evidence.
        </div>
      )}
    </>
  )
}

export function DetailPane({
  caseId,
  item,
  onOpen,
}: {
  caseId: string
  item: FileRow
  onOpen: () => void
}) {
  const [tab, setTab] = useState<'meta' | 'hex'>('meta')
  useEffect(() => setTab('meta'), [item.id])

  const md5 = hashValue(item.metadata, 'md5')
  const sha256 = hashValue(item.metadata, 'sha256')

  const artifact = useQuery({
    queryKey: ['artifact', caseId, item.id],
    queryFn: () => getArtifact(caseId, item.id),
  })

  // A file so fragmented that its run list was truncated (>4096 runs) can only
  // be partially reconstructed; its content and hashes cover the runs we kept.
  const runsComplete =
    (artifact.data?.metadata.data_runs_complete ??
      item.metadata?.data_runs_complete) !== false
  // Striped across devices (btrfs RAID0/10/5/6) with only one device present:
  // the off-device regions are zero-filled, not the real bytes.
  const multiDeviceIncomplete =
    (artifact.data?.metadata.data_incomplete_multi_device ??
      item.metadata?.data_incomplete_multi_device) === true
  const hex = useQuery({
    queryKey: ['file-hex', caseId, item.id, 0, HEX_PREVIEW_BYTES],
    queryFn: () => getFileHex(caseId, item.id, 0, HEX_PREVIEW_BYTES),
    enabled: tab === 'hex' && !item.is_directory,
  })

  return (
    <div className="fg-detail">
      <div className="fg-detail-head">
        {!item.is_directory && <Thumbnail caseId={caseId} item={item} />}
        <span className="fg-detail-name mono" title={item.path}>
          {item.path}
        </span>
        <button type="button" className="btn btn-primary" onClick={onOpen}>
          Open
        </button>
      </div>
      <div className="fg-tabs" role="tablist">
        <button
          type="button"
          role="tab"
          aria-selected={tab === 'meta'}
          className={tab === 'meta' ? 'fg-tab active' : 'fg-tab'}
          onClick={() => setTab('meta')}
        >
          Metadata
        </button>
        {!item.is_directory && (
          <button
            type="button"
            role="tab"
            aria-selected={tab === 'hex'}
            className={tab === 'hex' ? 'fg-tab active' : 'fg-tab'}
            onClick={() => setTab('hex')}
          >
            Hex preview
          </button>
        )}
      </div>
      <div className="fg-detail-body">
        {/* The standard pair the whole plugin tree stamps. It sits beside the
            two older, filesystem-specific flags above rather than replacing
            them: those name a precise condition this file is in, while the pair
            carries whatever reason the parser that produced this artifact
            recorded. The row metadata is merged UNDER the fetched artifact's,
            not replaced by it: the warning is then on screen before the
            artifact query settles, and a stamp present on only one of the two
            still reaches the examiner. The neighbouring flags below fall back
            the same way, key by key. */}
        <ArtifactIncompleteness
          metadata={
            artifact.data
              ? { ...(item.metadata ?? {}), ...artifact.data.metadata }
              : item.metadata
          }
        />
        {!item.is_directory && !runsComplete && (
          <div className="warn-note" role="alert">
            Content incomplete: this file is too fragmented for its full run
            list to be stored (over 4096 fragments). The preview, export, and
            hashes cover only the retained runs.
          </div>
        )}
        {!item.is_directory && multiDeviceIncomplete && (
          <div className="warn-note" role="alert">
            Content incomplete: this file is striped across multiple devices and
            only one was provided. Regions on the other device(s) are zero-filled,
            not the real bytes.
          </div>
        )}
        {tab === 'meta' ? (
          <>
            {(md5 || sha256) && (
              <div className="fg-hashes">
                {md5 && <CopyHash label="MD5" value={md5} />}
                {sha256 && <CopyHash label="SHA256" value={sha256} />}
              </div>
            )}
            <table className="fg-meta-table mono">
              <tbody>
                <tr>
                  <td>Path</td>
                  <td>{item.path}</td>
                </tr>
                <tr>
                  <td>Size</td>
                  <td>{item.is_directory ? '—' : formatBytes(item.size)}</td>
                </tr>
                <tr>
                  <td>Created</td>
                  <td>{formatUtc(item.created)}</td>
                </tr>
                <tr>
                  <td>Modified</td>
                  <td>{formatUtc(item.modified)}</td>
                </tr>
                <tr>
                  <td>Accessed</td>
                  <td>{formatUtc(item.accessed)}</td>
                </tr>
                {artifact.data && (
                  <>
                    <tr>
                      <td>Artifact ID</td>
                      <td>{artifact.data.id}</td>
                    </tr>
                    <tr>
                      <td>Type</td>
                      <td>{artifact.data.artifact_type}</td>
                    </tr>
                    {Object.entries(artifact.data.metadata).map(
                      ([key, value]) => (
                        <tr key={key}>
                          <td>{key}</td>
                          <td>{formatMetaValue(value)}</td>
                        </tr>
                      ),
                    )}
                  </>
                )}
              </tbody>
            </table>
            {artifact.isPending && (
              <div className="loading">Loading metadata…</div>
            )}
            {artifact.isError && (
              <div className="error-note">
                Failed to load metadata: {artifact.error.message}
              </div>
            )}
          </>
        ) : hex.isPending ? (
          <div className="loading">Loading hex…</div>
        ) : hex.isError ? (
          <div className="error-note">
            Failed to load hex: {hex.error.message}
          </div>
        ) : hex.data ? (
          <>
            {/* `limit` is what was READABLE, which the server rewrites when a
                read comes up short. Deriving the headline from the request
                (`min(HEX_PREVIEW_BYTES, total_size)`) therefore claimed bytes
                that were never read, and the shortfall showed only as a preview
                that ended sooner than expected (B4-022). */}
            <div className="fg-hex-size mono">
              First {formatCount(hex.data.limit)} bytes of{' '}
              {formatBytes(hex.data.total_size)} total
            </div>
            {hex.data.content_incomplete === true && (
              <div
                className="error-note"
                role="alert"
                data-testid="fg-hex-short"
              >
                The read came up short of the{' '}
                {formatCount(
                  hex.data.requested_bytes ??
                    Math.min(HEX_PREVIEW_BYTES, hex.data.total_size),
                )}{' '}
                bytes requested
                {hex.data.content_incomplete_reason
                  ? `: ${incompleteReasonLabel(hex.data.content_incomplete_reason)}`
                  : ''}
                . The preview below stops where the read failed, not where the
                file ends.
              </div>
            )}
            <HexView
              offset={hex.data.offset}
              hex={hex.data.hex}
              ascii={hex.data.ascii}
            />
          </>
        ) : null}
      </div>
    </div>
  )
}
