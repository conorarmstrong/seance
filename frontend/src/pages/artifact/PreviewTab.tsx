import { useQuery, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { formatBytes } from '../../lib/format'
import { downloadFile } from '../../lib/download'
import { useEntityScopedQuery } from '../../lib/useEntityScopedQuery'
import { useEntityScopedState } from '../../lib/useEntityScopedState'
import { useObjectUrl } from '../../lib/useObjectUrl'
import { fetchThumbnailBlob } from '../gallery/api'
import { fetchContentBlob, fetchContentRangeBytes } from './api'
import { decodeText, detectEncoding } from './ContentTabs'
import type { PreviewKind } from './lib'
import {
  delimiterFor,
  detectStructured,
  parseDelimited,
  prettyJson,
  prettyXml,
  type StructuredKind,
} from './structured'

const IMAGE_CAP = 32 * 1024 * 1024
const TEXT_CHUNK = 262144

function DownloadFallback({
  caseId,
  artifactId,
  name,
  size,
  title,
  message,
}: {
  caseId: string
  artifactId: string
  name: string
  size: number | null
  title?: string
  message?: string
}) {
  return (
    <div className="empty-state">
      <h3>{title ?? 'Too large to preview'}</h3>
      <p>
        {message ??
          `This artifact is ${
            size != null ? formatBytes(size) : 'over 32 MiB'
          }; previews are capped at 32 MiB. Download it instead.`}
      </p>
      <button
        type="button"
        className="btn"
        onClick={() =>
          void downloadFile(
            `/cases/${caseId}/artifacts/${artifactId}/content`,
            name,
          )
        }
      >
        Download
      </button>
    </div>
  )
}

const OFFICE_LABELS: Record<string, string> = {
  doc: 'Word document',
  docx: 'Word document',
  xls: 'Excel spreadsheet',
  xlsx: 'Excel spreadsheet',
  ppt: 'PowerPoint presentation',
  pptx: 'PowerPoint presentation',
  odt: 'OpenDocument text',
  ods: 'OpenDocument spreadsheet',
  odp: 'OpenDocument presentation',
}

/** Plays browser-supported video (mp4/webm/mov-H.264); other codecs
 * (wmv/avi/mkv) fail to decode and fall back to a download card. The bytes are
 * fetched with the Authorization header (like image/text), not a bare cookie-
 * only <video src>, so Bearer-only sessions can play video too. */
function VideoPreview({
  caseId,
  artifactId,
  name,
}: {
  caseId: string
  artifactId: string
  name: string
}) {
  // The component instance is reused across navigation, so a decode failure
  // must not outlive the video it was raised for: the next artifact would open
  // on "Your browser can't decode this video format" — a claim about a file
  // the browser never tried to play. Scoped rather than cleared in an effect,
  // because the effect runs after the frame in which the ids have already
  // changed has been committed, so that false verdict is on screen for the new
  // artifact before it is repaired.
  const [failed, setFailed] = useEntityScopedState(
    `${caseId}/${artifactId}/${name}`,
    false,
  )

  const query = useQuery({
    queryKey: ['artifact-preview-video', caseId, artifactId],
    staleTime: Infinity,
    retry: false,
    queryFn: () => fetchContentBlob(caseId, artifactId),
  })
  const blob = query.data ?? null
  // Scoped to the artifact the bytes came from: an unscoped handle still points
  // at the previous video in the first frame after a navigation, and that frame
  // renders it under the new artifact's name.
  const url = useObjectUrl(`${caseId}/${artifactId}`, blob)

  if (failed) {
    return (
      <DownloadFallback
        caseId={caseId}
        artifactId={artifactId}
        name={name}
        size={null}
        title="Can't play this video"
        message="Your browser can't decode this video format. Download it to view in a media player."
      />
    )
  }
  if (query.isError) {
    return (
      <div className="error-note">
        Failed to load preview: {query.error.message}
      </div>
    )
  }
  if (!url) {
    return <div className="loading">Loading video preview...</div>
  }
  return (
    <video
      className="av-preview-video"
      controls
      preload="metadata"
      src={url}
      onError={() => setFailed(true)}
    >
      <track kind="captions" />
    </video>
  )
}

/** Office documents can't render in-browser; identify the type and offer a
 * download, pointing at the Text/Hex tabs for inspection. */
function OfficePreview({
  caseId,
  artifactId,
  name,
}: {
  caseId: string
  artifactId: string
  name: string
}) {
  const ext = name.slice(name.lastIndexOf('.') + 1).toLowerCase()
  const label = OFFICE_LABELS[ext] ?? 'Office document'
  return (
    <DownloadFallback
      caseId={caseId}
      artifactId={artifactId}
      name={name}
      size={null}
      title={label}
      message={`In-browser preview isn't available for a ${label.toLowerCase()}. Download it to open, or use the Text and Hex tabs to inspect the raw content.`}
    />
  )
}

/** Renders a PDF in the browser's built-in viewer via <object>, over an
 * authenticated blob (not a bare cookie-only <object data>) so Bearer-only
 * sessions render it too; falls back to a download card if the fetch fails or
 * the browser can't display it inline. */
function PdfPreview({
  caseId,
  artifactId,
  name,
}: {
  caseId: string
  artifactId: string
  name: string
}) {
  const query = useQuery({
    queryKey: ['artifact-preview-pdf', caseId, artifactId],
    staleTime: Infinity,
    retry: false,
    queryFn: () => fetchContentBlob(caseId, artifactId),
  })
  const blob = query.data ?? null
  // Scoped: see `useObjectUrl`. A PDF handed to `<object data=…>` a frame late
  // renders the previous exhibit's pages under this one's filename.
  const url = useObjectUrl(`${caseId}/${artifactId}`, blob)

  if (query.isError) {
    return (
      <DownloadFallback
        caseId={caseId}
        artifactId={artifactId}
        name={name}
        size={null}
        title="Can't display this PDF"
        message="Your browser can't render this PDF inline. Download it to view, or use the Text and Hex tabs."
      />
    )
  }
  if (!url) {
    return <div className="loading">Loading PDF preview...</div>
  }
  return (
    <object
      className="av-pdf"
      data={url}
      type="application/pdf"
      aria-label={`PDF preview of ${name}`}
    >
      <DownloadFallback
        caseId={caseId}
        artifactId={artifactId}
        name={name}
        size={null}
        title="Can't display this PDF"
        message="Your browser can't render this PDF inline. Download it to view, or use the Text and Hex tabs."
      />
    </object>
  )
}

function ImagePreview({
  caseId,
  artifactId,
  name,
  sizeHint,
}: {
  caseId: string
  artifactId: string
  name: string
  sizeHint: number | null
}) {
  // HEIC/HEIF (HEVC-coded) and TIFF can't be decoded by browsers from their raw
  // bytes, so show the server-rendered thumbnail (as the gallery lightbox does).
  // The thumbnail is small, so the original-bytes size cap does not gate it.
  const serverThumb = /\.(hei[cf]|tiff?)$/i.test(name)
  const tooLarge = !serverThumb && sizeHint != null && sizeHint > IMAGE_CAP
  const query = useQuery({
    queryKey: ['artifact-preview-image', caseId, artifactId, serverThumb],
    enabled: !tooLarge,
    staleTime: Infinity,
    queryFn: () =>
      serverThumb
        ? fetchThumbnailBlob(caseId, artifactId, 512)
        : fetchContentBlob(caseId, artifactId),
  })
  const overCap =
    !serverThumb && query.data != null && query.data.size > IMAGE_CAP
  const blob = !tooLarge && !overCap && query.data ? query.data : null

  // `serverThumb` is part of the scope as well as the query key: it decides
  // WHICH bytes are wanted (the server's rendering of a HEIC, or the original),
  // and a handle carried across that decision shows the wrong one.
  const url = useObjectUrl(`${caseId}/${artifactId}/${serverThumb}`, blob)

  if (tooLarge || overCap) {
    return (
      <DownloadFallback
        caseId={caseId}
        artifactId={artifactId}
        name={name}
        size={sizeHint ?? query.data?.size ?? null}
      />
    )
  }
  if (query.isError) {
    return (
      <div className="error-note">
        Failed to load preview: {query.error.message}
      </div>
    )
  }
  if (!url) {
    return <div className="loading">Loading image preview...</div>
  }
  return <img className="av-preview-img" src={url} alt={name} />
}

/** Render detected JSON/XML as indented text and CSV/TSV as a grid, falling
 * back to the raw text when it doesn't parse (e.g. a truncated preview). */
function StructuredView({
  kind,
  text,
  name,
}: {
  kind: StructuredKind
  text: string
  name: string
}) {
  if (kind === 'csv') {
    const rows = parseDelimited(text, delimiterFor(name))
    if (!rows || rows.length === 0) {
      return <pre className="av-text mono">{text}</pre>
    }
    const [head, ...body] = rows
    return (
      <div className="av-csv-scroll">
        <table className="data-table av-csv">
          <thead>
            <tr>
              {head.map((h, i) => (
                <th key={i}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {body.map((r, ri) => (
              <tr key={ri}>
                {head.map((_, ci) => (
                  <td key={ci} className="mono">
                    {r[ci] ?? ''}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    )
  }
  const formatted = kind === 'json' ? prettyJson(text) : prettyXml(text)
  return <pre className="av-text mono">{formatted ?? text}</pre>
}

function TextPreview({
  caseId,
  artifactId,
  name,
}: {
  caseId: string
  artifactId: string
  name: string
}) {
  const queryClient = useQueryClient()
  // Both ids identify the content: artifact UUIDs are not globally unique
  // across cases, so gating on artifactId alone would let an in-place case
  // switch preview case A's text under case B (BUG-259).
  const scopeKey = `${caseId}/${artifactId}`
  // How much has been loaded belongs to the artifact it was loaded from.
  // Scoped rather than cleared in a `useEffect`: `chunkCount` is part of the
  // query key below, so on the render where the ids have already changed but
  // the effect has not run, react-query fetches the NEW artifact at the OLD
  // artifact's chunk count — ranges past the end of a smaller file, and a
  // "first N KiB" caption naming an amount the examiner never asked for
  // (B2-148 class).
  const [chunkCount, setChunkCount] = useEntityScopedState(scopeKey, 1)
  const [pretty, setPretty] = useState(true)

  const query = useEntityScopedQuery<{ text: string; done: boolean }>(scopeKey, {
    queryKey: ['artifact-preview-text', caseId, artifactId, chunkCount],
    queryFn: async () => {
      const parts: Uint8Array[] = []
      let total = 0
      let done = false
      for (let i = 0; i < chunkCount && !done; i++) {
        // Each 256 KiB range is fetched once and cached; "Load more" only
        // requests the next range. Fetch raw bytes (not UTF-8 text) so the
        // encoding is preserved for detection below.
        const chunk = await queryClient.fetchQuery({
          queryKey: ['artifact-preview-text-chunk', caseId, artifactId, i],
          staleTime: Infinity,
          queryFn: () =>
            fetchContentRangeBytes(
              caseId,
              artifactId,
              i * TEXT_CHUNK,
              (i + 1) * TEXT_CHUNK - 1,
            ),
        })
        parts.push(chunk.bytes)
        total += chunk.byteLength
        const loadedEnd = i * TEXT_CHUNK + chunk.byteLength
        done =
          chunk.byteLength < TEXT_CHUNK ||
          (chunk.totalSize != null && loadedEnd >= chunk.totalSize)
      }
      // Concatenate all loaded bytes and decode once with BOM/heuristic
      // encoding detection, so UTF-16LE/BE Windows logs and configs render as
      // readable text instead of mojibake or empty output (BUG-170). The Text
      // tab already decodes this way; the default Preview must match.
      const merged = new Uint8Array(total)
      let off = 0
      for (const p of parts) {
        merged.set(p, off)
        off += p.byteLength
      }
      const text = decodeText(merged, detectEncoding(merged))
      return { text, done }
    },
  })

  // keepPreviousData shows the previous artifact's text as a placeholder on a
  // content switch; the shared gate withholds it so it never renders here.
  if (query.isError) {
    return (
      <div className="error-note">
        Failed to load preview: {query.error?.message}
      </div>
    )
  }
  const data = query.scoped
  if (data == null) {
    return <div className="loading">Loading text preview...</div>
  }
  if (!data.text) {
    return (
      <div className="empty-state">
        <h3>No content</h3>
        <p>This artifact has no readable content.</p>
      </div>
    )
  }
  const structured = detectStructured(name, data.text)

  return (
    <div>
      <p className="av-note">
        {data.done
          ? 'Text preview of the full content.'
          : `Text preview of the first ${chunkCount * 256} KiB.`}
        {structured && (
          <span className="av-fmt-toggle" role="group" aria-label="View format">
            <button
              type="button"
              className={pretty ? 'av-fmt-btn selected' : 'av-fmt-btn'}
              aria-pressed={pretty}
              onClick={() => setPretty(true)}
            >
              {structured === 'csv' ? 'Table' : 'Pretty'}
            </button>
            <button
              type="button"
              className={!pretty ? 'av-fmt-btn selected' : 'av-fmt-btn'}
              aria-pressed={!pretty}
              onClick={() => setPretty(false)}
            >
              Raw
            </button>
          </span>
        )}
      </p>
      {structured && pretty ? (
        <StructuredView kind={structured} text={data.text} name={name} />
      ) : (
        <pre className="av-text mono">{data.text}</pre>
      )}
      {!data.done && (
        <button
          className="btn av-load-more"
          disabled={query.isFetching}
          onClick={() => setChunkCount(chunkCount + 1)}
        >
          Load more
        </button>
      )}
    </div>
  )
}

export function PreviewTab({
  caseId,
  artifactId,
  kind,
  name,
  sizeHint,
}: {
  caseId: string
  artifactId: string
  kind: PreviewKind
  name: string
  sizeHint: number | null
}) {
  if (kind === 'image') {
    return (
      <ImagePreview
        caseId={caseId}
        artifactId={artifactId}
        name={name}
        sizeHint={sizeHint}
      />
    )
  }
  if (kind === 'video') {
    return <VideoPreview caseId={caseId} artifactId={artifactId} name={name} />
  }
  if (kind === 'pdf') {
    return <PdfPreview caseId={caseId} artifactId={artifactId} name={name} />
  }
  if (kind === 'office') {
    return <OfficePreview caseId={caseId} artifactId={artifactId} name={name} />
  }
  return <TextPreview caseId={caseId} artifactId={artifactId} name={name} />
}
