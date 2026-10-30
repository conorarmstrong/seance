import {
  useMutation,
  useQuery,
  useQueryClient,
} from '@tanstack/react-query'
import {
  Fragment,
  useEffect,
  useState,
  type CSSProperties,
  type PointerEvent as ReactPointerEvent,
} from 'react'
import { Link, useLocation, useNavigate, useParams } from 'react-router-dom'
import { Bookmark, Download, PanelRightOpen, ShieldCheck } from 'lucide-react'
import { PersonalMarkButton } from '../assignments/PersonalMarkButton'
import { downloadFile } from '../../lib/download'
import {
  checkArtifactHash,
  createBookmark,
  deleteBookmark,
  getArtifact,
  getBookmarkedIds,
} from '../../api/resources'
import type { Artifact } from '../../api/types'
import { useToast } from '../../components/toast/ToastProvider'
import { formatUtc, truncateHash } from '../../lib/format'
import { useEntityScopedState } from '../../lib/useEntityScopedState'
import {
  getArtifactAncestors,
  getIntegrityChecks,
  getJob,
  startVerify,
  thumbnailAvailable,
  type IntegrityCheck,
} from './api'
import { AllocationMapTab } from './AllocationMapTab'
import { ChildrenTab } from './ChildrenTab'
import { ConversationTab } from './ConversationTab'
import { HexTab, TextTab } from './ContentTabs'
import { DiskMapTab } from './DiskMapTab'
import { EntropyTab } from './EntropyTab'
import { FilesTab } from './FilesTab'
import { FragmentationTab } from './FragmentationTab'
import { TreemapTab } from './TreemapTab'
import { UnlockPanel } from './UnlockPanel'
import { ArtifactInspector } from './ArtifactInspector'
import {
  artifactDisplayName,
  canProbeThumbnail,
  hasByteContent,
  metadataBool,
  metadataMarker,
  metadataString,
  metadataNumber,
  previewKindForName,
  tabsForArtifact,
  type PreviewKind,
  type TabId,
} from './lib'
import { MemoryTab } from './MemoryTab'
import { RawJsonTab } from './MetadataTabs'
import { PreviewTab } from './PreviewTab'
import { ProcessingTab, RunModuleTab } from './ProcessingTabs'
import { RelatedTimelineTab } from './RelatedTimelineTab'
import { RegistryTab } from './RegistryTab'
import { getMemoryImages } from '../memory/api'
import type { MemoryImagesResponse } from '../memory/api'
import { useEntityScopedQuery } from '../../lib/useEntityScopedQuery'
import './artifact.css'

function VerifyPanel({ check }: { check: IntegrityCheck }) {
  const statusBadge = {
    verified: ['badge badge-ok', 'Verified'],
    mismatch: ['badge badge-danger', 'Mismatch'],
    no_baseline: ['badge', 'No baseline'],
    no_reference: ['badge', 'No reference hash'],
    // The content ran out before its declared size, so the digests cover a
    // fragment. That is neither a pass nor a mismatch and must not be dressed
    // as either — `details` carries the byte counts.
    incomplete: ['badge badge-warn', 'Incomplete — could not read it all'],
  }[check.status] ?? ['badge', check.status]

  const hash = (value: string | null) =>
    value ? (
      <span className="mono" title={value}>
        {truncateHash(value)}
      </span>
    ) : (
      <span>—</span>
    )

  return (
    <div className="panel av-verify">
      <div className="av-verify-row">
        <span className="av-label">Status</span>
        <span className={statusBadge[0]}>{statusBadge[1]}</span>
      </div>
      <div className="av-verify-row">
        <span className="av-label">Checked</span>
        <span className="mono">{formatUtc(check.timestamp)}</span>
      </div>
      <div className="av-verify-row">
        <span className="av-label">MD5 computed / expected</span>
        {hash(check.computed_md5)} / {hash(check.expected_md5)}
      </div>
      <div className="av-verify-row">
        <span className="av-label">SHA1 computed / expected</span>
        {hash(check.computed_sha1)} / {hash(check.expected_sha1)}
      </div>
      <div className="av-verify-row">
        <span className="av-label">SHA256 computed / expected</span>
        {hash(check.computed_sha256)} / {hash(check.expected_sha256)}
      </div>
      {check.details && (
        <div className="av-verify-row">
          <span className="av-label">Detail</span>
          <span>{check.details}</span>
        </div>
      )}
    </div>
  )
}

/// Origin of a file carried inside a backup container (e.g. WhatsApp media).
/// The bytes themselves record no origin; this is resolved server-side from the
/// container's iOS-backup metadata (domain -> app, media path -> correspondent).
function ProvenancePanel({ prov }: { prov: Record<string, unknown> }) {
  const str = (k: string) => (typeof prov[k] === 'string' ? (prov[k] as string) : null)
  const app = str('source_app')
  if (prov.origin_ambiguous === true) {
    return (
      <div className="panel av-verify av-provenance">
        <div className="av-provenance-head">
          <span className="av-provenance-title">Origin / Provenance</span>
          <span className="badge">Origin ambiguous</span>
        </div>
        {str('container') && (
          <div className="av-verify-row">
            <span className="av-label">Container</span>
            <span className="mono">{str('container')}</span>
          </div>
        )}
        <div className="av-note">{str('note')}</div>
      </div>
    )
  }
  const rows: [string, string | null][] = [
    ['Correspondent', str('correspondent')],
    ['In-app path', str('in_app_path')],
    ['Container', str('container')],
    ['App domain', str('app_domain')],
    ['Container created', str('container_created')],
    ['Container modified', str('container_modified')],
  ]
  return (
    <div className="panel av-verify av-provenance">
      <div className="av-provenance-head">
        <span className="av-provenance-title">Origin / Provenance</span>
        {app && <span className="badge badge-accent">{app}</span>}
      </div>
      {rows
        .filter(([, v]) => v)
        .map(([label, v]) => (
          <div className="av-verify-row" key={label}>
            <span className="av-label">{label}</span>
            <span className="mono">{v}</span>
          </div>
        ))}
      <div className="av-note">
        Carried inside a backup container from {app ?? 'an app'}. The file itself
        records no origin — this is resolved from the container&rsquo;s iOS-backup
        metadata.
      </div>
    </div>
  )
}

function useElapsedSeconds(active: boolean): number {
  const [elapsed, setElapsed] = useState(0)
  useEffect(() => {
    if (!active) {
      setElapsed(0)
      return
    }
    const started = Date.now()
    const timer = setInterval(
      () => setElapsed(Math.floor((Date.now() - started) / 1000)),
      1000,
    )
    return () => clearInterval(timer)
  }, [active])
  return elapsed
}

export function ArtifactPage({
  caseId: caseIdProp,
  artifactId: artifactIdProp,
  embedded = false,
}: {
  caseId?: string
  artifactId?: string
  embedded?: boolean
} = {}) {
  const params = useParams() as { caseId?: string; artifactId?: string }
  const caseId = caseIdProp ?? (params.caseId as string)
  const artifactId = artifactIdProp ?? (params.artifactId as string)
  const location = useLocation()
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const toast = useToast()

  const artifactQuery = useQuery({
    queryKey: ['artifact', caseId, artifactId],
    queryFn: () => getArtifact(caseId, artifactId),
  })
  const artifact = artifactQuery.data

  const ancestorsQuery = useQuery({
    queryKey: ['artifact-ancestors', caseId, artifactId],
    enabled: artifact != null,
    queryFn: () => getArtifactAncestors(caseId, artifactId),
  })

  // One cheap per-case lookup, shared by every artifact page in the case, that
  // answers "was a RAM capture decoded from THIS file?". A failure here must
  // not blank the page: without it the Memory tab is simply absent, which is
  // the same as before this tab existed.
  //
  // Sits with the other queries and above the early returns below: placed after
  // them it ran on some renders and not others, which changes the hook count
  // and takes the whole artifact page down with it.
  //
  // `useEntityScopedQuery`, not a plain `useQuery`, because `MemoryLayout`
  // shares this exact key and that wrapper stores `{__scope, value}` rather
  // than the response. A plain query here writes an untagged response into the
  // same cache entry, so the Memory section reads `__scope === undefined`,
  // judges the data to belong to another case, and — with its `staleTime:
  // Infinity` — sits on the loading skeleton forever. The mismatch breaks
  // whichever of the two mounts second, in both directions.
  const memoryImages = useEntityScopedQuery<MemoryImagesResponse>(caseId, {
    queryKey: ['memory', caseId, 'images'],
    queryFn: () => getMemoryImages(caseId),
    staleTime: Infinity,
    retry: false,
  })

  const hashCheckQuery = useQuery({
    queryKey: ['artifact-hash-check', caseId, artifactId],
    queryFn: () => checkArtifactHash(caseId, artifactId),
  })

  const integrityQuery = useQuery({
    queryKey: ['artifact-integrity', caseId, artifactId],
    queryFn: () => getIntegrityChecks(caseId, artifactId),
  })
  const latestCheck = integrityQuery.data?.[0] ?? null

  const bookmarkedQuery = useQuery({
    queryKey: ['bookmarks', caseId, 'ids'],
    queryFn: () => getBookmarkedIds(caseId),
  })
  const isBookmarked = bookmarkedQuery.data?.includes(artifactId) ?? false

  // The desired action is read from the live cache at click time (below), not a
  // render-time closure, and applied optimistically. That keeps overlapping or
  // double clicks a correct toggle instead of a double-create / double-delete.
  const bookmarkMutation = useMutation<
    unknown,
    Error,
    boolean,
    { previous: string[] | undefined }
  >({
    mutationFn: (shouldBookmark: boolean) =>
      shouldBookmark
        ? createBookmark(caseId, { artifact_id: artifactId })
        : deleteBookmark(caseId, artifactId),
    onMutate: async (shouldBookmark) => {
      await queryClient.cancelQueries({
        queryKey: ['bookmarks', caseId, 'ids'],
      })
      const previous = queryClient.getQueryData<string[]>([
        'bookmarks',
        caseId,
        'ids',
      ])
      queryClient.setQueryData<string[]>(
        ['bookmarks', caseId, 'ids'],
        (old = []) =>
          shouldBookmark
            ? old.includes(artifactId)
              ? old
              : [...old, artifactId]
            : old.filter((id) => id !== artifactId),
      )
      return { previous }
    },
    onError: (error, _shouldBookmark, context) => {
      if (context?.previous !== undefined) {
        queryClient.setQueryData(
          ['bookmarks', caseId, 'ids'],
          context.previous,
        )
      }
      toast.error(`Failed to update bookmark: ${error.message}`)
    },
    onSettled: () =>
      queryClient.invalidateQueries({ queryKey: ['bookmarks', caseId] }),
  })
  const toggleBookmark = () => {
    const ids =
      queryClient.getQueryData<string[]>(['bookmarks', caseId, 'ids']) ?? []
    bookmarkMutation.mutate(!ids.includes(artifactId))
  }

  // Verification runs as a background job: start it, poll the job until it
  // finishes, then refetch the recorded integrity checks for the verdict.
  // Verification is per-artifact IN A CASE: navigating to a different artifact,
  // or to the same artifact id under a different case, must drop any in-flight
  // job and error so B does not inherit A's "Verifying…" state, and A's
  // completion toast/refresh never lands on B. Artifact UUIDs are per-case, so
  // resetting on artifactId alone left a case switch polling
  // `getJob(caseB, jobIdFromA)` and invalidating case B's integrity view on
  // case A's verdict. Resetting in an effect would not have been enough either:
  // the poll query is configured during the render in which the ids have
  // already changed, so the wrong-case request is issued before any effect runs
  // (B2-023). Scoped state makes the stale job id unreadable from that render
  // onwards, and `enabled: verifyJobId != null` then abandons A's poll.
  const verifyScope = `${caseId}/${artifactId}`
  const [verifyJobId, setVerifyJobId] = useEntityScopedState<string | null>(
    verifyScope,
    null,
  )
  const [verifyError, setVerifyError] = useEntityScopedState<string | null>(
    verifyScope,
    null,
  )
  // Separate from `verifyError`, which is the JOB's verdict. This one is the
  // client losing sight of the job, which says nothing about the exhibit.
  const [verifyLost, setVerifyLost] = useEntityScopedState<string | null>(
    verifyScope,
    null,
  )
  // The start request is scoped by its VARIABLES, not by the render that
  // handles its response. react-query invokes the latest `onSuccess`, so after
  // a navigation the callback holds the setter for whatever artifact is on
  // screen now — and `setVerifyJobId` would then deposit artifact A's job id
  // into artifact B's scope. The poll would run `getJob(caseB, jobFromA)` and
  // artifact B's integrity panel would refresh on artifact A's verdict: an
  // exhibit reported "verified" on a digest computed over different bytes.
  // Carrying the scope in the mutation variables and comparing it to the live
  // scope makes a late response land nowhere instead of on the wrong exhibit
  // (the same rule `useEntityScopedState` applies to its setters).
  const startVerifyMutation = useMutation({
    mutationFn: (target: {
      caseId: string
      artifactId: string
      scope: string
    }) => startVerify(target.caseId, target.artifactId),
    onSuccess: (started, target) => {
      if (target.scope !== verifyScope) return
      setVerifyError(null)
      setVerifyLost(null)
      setVerifyJobId(started.job_id)
    },
    onError: (error, target) => {
      if (target.scope !== verifyScope) return
      setVerifyError(error.message)
      toast.error(`Failed to start verification: ${error.message}`)
    },
  })
  const beginVerify = () =>
    startVerifyMutation.mutate({ caseId, artifactId, scope: verifyScope })
  const verifyJobQuery = useQuery({
    queryKey: ['verify-job', caseId, verifyJobId],
    enabled: verifyJobId != null,
    queryFn: () => getJob(caseId, verifyJobId as string),
    refetchInterval: 1500,
  })
  const verifyJob = verifyJobQuery.data
  useEffect(() => {
    if (verifyJobId == null || verifyJob == null) return
    if (verifyJob.status === 'complete') {
      setVerifyJobId(null)
      toast.success('Integrity verification complete')
      queryClient.invalidateQueries({
        queryKey: ['artifact-integrity', caseId, artifactId],
      })
      queryClient.invalidateQueries({
        queryKey: ['artifact', caseId, artifactId],
      })
    } else if (verifyJob.status === 'failed') {
      setVerifyJobId(null)
      const message = verifyJob.error_message ?? 'Verification job failed'
      setVerifyError(message)
      toast.error(`Verification failed: ${message}`)
    }
  }, [verifyJob, verifyJobId, caseId, artifactId, queryClient, toast])
  // The poll itself failing had no branch at all: the page stayed on
  // "Verifying integrity…" forever, Verify stayed disabled, and nothing said
  // why — which looks like a verification still running long after the client
  // stopped being able to see it (B8-022). Stop waiting, and say that this is
  // the client losing the job rather than a verdict on the exhibit.
  const verifyPollError = verifyJobQuery.isError
    ? (verifyJobQuery.error as Error).message
    : null
  useEffect(() => {
    if (verifyJobId == null || verifyPollError == null) return
    setVerifyJobId(null)
    setVerifyLost(verifyPollError)
    toast.error(`Lost contact with the verification job: ${verifyPollError}`)
  }, [verifyPollError, verifyJobId, setVerifyJobId, setVerifyLost, toast])
  // "Verifying…" belongs to the artifact the run was started for. `isPending`
  // alone is a property of the mutation, not of what is on screen, so it would
  // paint a progress bar over an artifact nobody started a verification on.
  const startPendingHere =
    startVerifyMutation.isPending &&
    startVerifyMutation.variables?.scope === verifyScope
  const verifying = startPendingHere || verifyJobId != null
  const verifyElapsed = useElapsedSeconds(verifying)

  // Preview: raster/text file extensions get a preview tab directly; other
  // content-bearing artifacts are probed via the thumbnail endpoint.
  const displayName = artifact ? artifactDisplayName(artifact) : ''
  const extPreviewKind = artifact ? previewKindForName(displayName) : null
  const thumbProbeQuery = useQuery({
    queryKey: ['artifact-thumb-probe', caseId, artifactId],
    enabled:
      artifact != null && extPreviewKind == null && canProbeThumbnail(artifact),
    staleTime: Infinity,
    retry: false,
    queryFn: () => thumbnailAvailable(caseId, artifactId),
  })
  const previewKind: PreviewKind | null =
    extPreviewKind ?? (thumbProbeQuery.data ? 'image' : null)

  // Inspector pane geometry persists across artifacts (per-browser).
  const [inspectorWidth, setInspectorWidth] = useState(() => {
    const stored = Number(localStorage.getItem('seance.inspector.width'))
    return Number.isFinite(stored) && stored >= 280 && stored <= 560
      ? stored
      : 340
  })
  const [inspectorCollapsed, setInspectorCollapsed] = useState(
    () => localStorage.getItem('seance.inspector.collapsed') === '1',
  )
  useEffect(() => {
    try {
      localStorage.setItem('seance.inspector.width', String(inspectorWidth))
    } catch {
      // storage unavailable; width just won't persist
    }
  }, [inspectorWidth])
  useEffect(() => {
    try {
      localStorage.setItem(
        'seance.inspector.collapsed',
        inspectorCollapsed ? '1' : '0',
      )
    } catch {
      // storage unavailable
    }
  }, [inspectorCollapsed])

  // Drag the divider: inspector width tracks the pointer, clamped to a usable
  // band. Listeners are torn down on release.
  const beginInspectorResize = (e: ReactPointerEvent) => {
    e.preventDefault()
    const move = (ev: PointerEvent) => {
      setInspectorWidth(
        Math.min(560, Math.max(280, window.innerWidth - ev.clientX - 16)),
      )
    }
    const up = () => {
      window.removeEventListener('pointermove', move)
      window.removeEventListener('pointerup', up)
    }
    window.addEventListener('pointermove', move)
    window.addEventListener('pointerup', up)
  }

  if (artifactQuery.isPending) {
    return <div className="loading">Loading artifact...</div>
  }
  if (artifactQuery.isError) {
    return (
      <div className="error-note">
        Failed to load artifact: {artifactQuery.error.message}
      </div>
    )
  }

  const loaded = artifact as Artifact
  const name = displayName
  // `scoped`, not `data`: `data` may still be the previous case's list while a
  // case switch is in flight, and offering a Memory tab on this artifact
  // because a DIFFERENT case held a capture is evidence misattribution.
  const memoryImage =
    memoryImages.scoped?.images.find(
      (i) => i.source_artifact_id === artifactId,
    ) ?? null

  const tabs = tabsForArtifact(loaded, previewKind, memoryImage?.image_id ?? null)
  const hashTab = location.hash.replace(/^#/, '')
  const hashIsTab = tabs.some((t) => t.id === hashTab)
  // Default view: previewable files (image/text/office/video by extension) open
  // on their preview; everything else opens with no auto-view — the center
  // prompts for one, and the metadata is already in the Inspector, so there is
  // nothing to auto-load.
  const defaultTab: TabId | null =
    extPreviewKind && tabs.some((t) => t.id === 'preview') ? 'preview' : null
  const activeTab: TabId | null = hashIsTab ? (hashTab as TabId) : defaultTab
  // Keep the current search params (e.g. the workbench's ?artifact=) when
  // switching tabs — a bare `#id` navigation would drop them and blank the
  // embedded page.
  const selectTab = (id: TabId) =>
    navigate({ hash: id, search: location.search }, { replace: true })
  const ancestors = ancestorsQuery.data ?? []
  const parents = ancestors.slice(0, -1)

  return (
    <div className="av-page">
      {!embedded && parents.length > 0 && (
        <nav className="av-breadcrumb" aria-label="Ancestry">
          {parents.map((ancestor) => (
            <Fragment key={ancestor.id}>
              <Link to={`/cases/${caseId}/artifacts/${ancestor.id}`}>
                {ancestor.name}
              </Link>
              <span className="av-breadcrumb-sep">/</span>
            </Fragment>
          ))}
          <span>{name}</span>
        </nav>
      )}
      <div className="av-title-row">
        <h1 className="page-title">{name}</h1>
        <span className="badge badge-accent">{loaded.artifact_type}</span>
        {hashCheckQuery.data?.map((match) => {
          const notable = match.set_type.toLowerCase() === 'notable'
          return (
            <span
              key={match.hash_set_id}
              className={notable ? 'badge badge-danger' : 'badge badge-ok'}
              title={match.product_name ?? undefined}
            >
              {`${notable ? 'Notable' : 'Known'}: ${match.hash_set_name}`}
            </span>
          )
        })}
        {metadataBool(loaded.metadata, 'efs_encrypted') && (
          <span
            className="badge badge-danger"
            title="EFS-encrypted file. Downloaded/previewed content is the raw encrypted bytes on disk, not the plaintext — decryption requires the user's key."
          >
            Encrypted (EFS)
          </span>
        )}
        {metadataBool(loaded.metadata, 'deleted') && (
          <span
            className="badge badge-danger"
            title="Recovered from unallocated space — the file was deleted. Recovered content may be incomplete or partially overwritten."
          >
            Deleted
          </span>
        )}
        {['contiguous_assumed', 'unallocated_clusters_in_order'].includes(
          metadataString(loaded.metadata, 'deleted_recovery_method') ?? '',
        ) && (
          <span
            className="badge badge-danger"
            title="Recovered by reading clusters from the start cluster in order, stepping over clusters now in use by other files. This is byte-correct only if the file was not fragmented and none of its clusters were reused; otherwise the recovered content is wrong."
          >
            Unverified recovery
          </span>
        )}
        {/*
          `metadataMarker`, not `metadataBool`: this marker is a reason STRING
          from MFT and F2FS ("ntfs_lznt1_oversize", "f2fs") and a boolean only
          from BTRFS, so `metadataBool` returned null for every NTFS artifact and
          this badge never rendered on them. The examiner lost the warning that
          the bytes on offer are not the file — and, because the badge below is
          gated on its negation, was told instead that "the content shown is
          decompressed", which is precisely what had failed. The reason code is
          put in the title now that the producers distinguish them, so an
          examiner can tell a stream too large to expand at ingest (recoverable
          on demand) from a corrupt compression descriptor (never recoverable).
        */}
        {metadataMarker(loaded.metadata, 'compression_unsupported') && (
          <span
            className="badge badge-danger"
            title={`Compressed content that could not be decompressed for re-serving. The downloaded/previewed bytes are the raw compressed data on disk, not the real file.${
              metadataString(loaded.metadata, 'compression_unsupported')
                ? ` Reason: ${metadataString(loaded.metadata, 'compression_unsupported')}.`
                : ''
            }`}
          >
            Content unavailable
          </span>
        )}
        {metadataMarker(loaded.metadata, 'compressed') &&
          !metadataMarker(loaded.metadata, 'compression_unsupported') && (
            <span className="badge" title="Stored compressed on disk; the content shown is decompressed.">
              Compressed
            </span>
          )}
        {loaded.metadata.data_runs_complete === false && (
          <span
            className="badge badge-danger"
            title="Too fragmented for its full run list to be stored (over 4096 fragments). The preview, export, and hashes cover only the retained runs."
          >
            Content incomplete (fragmented)
          </span>
        )}
        {metadataBool(loaded.metadata, 'data_incomplete_multi_device') && (
          <span
            className="badge badge-danger"
            title="Stored striped across multiple devices (btrfs RAID0/10/5/6) but only one device was provided. Regions on the other device(s) are zero-filled, not the real bytes."
          >
            Content incomplete (multi-device)
          </span>
        )}
        {metadataString(loaded.metadata, 'content_reconstruction') === 'reconstructed' && (
          <span
            className="badge badge-ok"
            title="Shadow copy point-in-time content reconstructed from the VSS store chain and allocation bitmaps. Preview and download serve the snapshot's bytes as of its creation time."
          >
            Content reconstructed
          </span>
        )}
        {metadataString(loaded.metadata, 'content_reconstruction') ===
          'unavailable_requires_store_chain' && (
          <span
            className="badge badge-danger"
            title="Shadow copy enumerated, but its point-in-time content is not reconstructed here: that requires resolving the VSS store chain and allocation bitmaps. Use a dedicated tool (e.g. libvshadow) to read snapshot content."
          >
            Content not reconstructed
          </span>
        )}
        {metadataBool(loaded.metadata, 'logs_replayed') && (
          <span
            className="badge badge-ok"
            title="Hive was dirty at acquisition; pending changes were replayed from its .LOG1/.LOG2 transaction logs before parsing. Registry values reflect the recovered state."
          >
            Logs replayed
          </span>
        )}
        {metadataBool(loaded.metadata, 'hive_dirty') &&
          !metadataBool(loaded.metadata, 'logs_replayed') && (
            <span
              className="badge badge-danger"
              title="Hive was dirty (sequence numbers mismatched) but the transaction logs could not be applied. Registry values may be stale."
            >
              Dirty hive (not recovered)
            </span>
          )}
        <div className="av-actions">
          <button
            className="btn"
            aria-label={isBookmarked ? 'Remove bookmark' : 'Add bookmark'}
            disabled={bookmarkMutation.isPending || bookmarkedQuery.isPending}
            onClick={toggleBookmark}
          >
            <Bookmark size={15} fill={isBookmarked ? 'currentColor' : 'none'} />
            {isBookmarked ? 'Bookmarked' : 'Bookmark'}
          </button>
          <PersonalMarkButton caseId={caseId} artifactId={artifactId} />
          {hasByteContent(loaded.artifact_type) && (
            <>
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
                <Download size={15} /> Download
              </button>
              <button
                className="btn"
                disabled={verifying}
                onClick={beginVerify}
              >
                <ShieldCheck size={15} /> Verify Integrity
              </button>
            </>
          )}
        </div>
      </div>
      {verifying && (
        <div className="panel av-verify-progress">
          <div
            className="av-progress"
            role="progressbar"
            aria-label="Verifying integrity"
          />
          <span className="av-note">
            Verifying integrity... {verifyElapsed}s elapsed
          </span>
        </div>
      )}
      {verifyError && !verifying && (
        <div className="error-note">Verification failed: {verifyError}</div>
      )}
      {verifyLost && !verifying && (
        <div className="error-note" role="note" data-testid="av-verify-lost">
          The verification job&rsquo;s status could not be read: {verifyLost}.
          This page has stopped waiting for it. The run may still be finishing
          on the server — reload this artifact to see its result. Nothing here
          is a verdict on the exhibit, and any check shown below is the last one
          recorded, not the outcome of this run.
        </div>
      )}
      {latestCheck && <VerifyPanel check={latestCheck} />}
      {loaded.metadata.provenance != null &&
        typeof loaded.metadata.provenance === 'object' && (
          <ProvenancePanel
            prov={loaded.metadata.provenance as Record<string, unknown>}
          />
        )}
      <UnlockPanel caseId={caseId} artifact={loaded} />
      <div
        className="av-workspace"
        data-collapsed={inspectorCollapsed}
        style={{ '--insp-w': `${inspectorWidth}px` } as CSSProperties}
      >
        <div className="av-main">
          <div className="av-tabs" role="tablist">
            {tabs.map((tab) => (
              <button
                key={tab.id}
                role="tab"
                aria-selected={activeTab === tab.id}
                className={activeTab === tab.id ? 'av-tab active' : 'av-tab'}
                onClick={() => selectTab(tab.id)}
              >
                {tab.label}
              </button>
            ))}
            {inspectorCollapsed && (
              <button
                type="button"
                className="av-tab av-insp-show"
                onClick={() => setInspectorCollapsed(false)}
              >
                <PanelRightOpen size={14} /> Inspector
              </button>
            )}
          </div>
          {activeTab === 'memory' && memoryImage && (
            <MemoryTab caseId={caseId} image={memoryImage} />
          )}
          {activeTab === 'preview' && previewKind && (
            <PreviewTab
              caseId={caseId}
              artifactId={artifactId}
              kind={previewKind}
              name={name}
              sizeHint={
                metadataNumber(loaded.metadata, 'size') ??
                metadataNumber(loaded.metadata, 'file_size')
              }
            />
          )}
          {activeTab === 'diskmap' && (
            <DiskMapTab caseId={caseId} artifactId={artifactId} />
          )}
          {activeTab === 'allocation' && (
            <AllocationMapTab caseId={caseId} artifactId={artifactId} />
          )}
          {activeTab === 'files' && (
            <FilesTab caseId={caseId} artifactId={artifactId} />
          )}
          {activeTab === 'treemap' && (
            <TreemapTab caseId={caseId} artifactId={artifactId} />
          )}
          {activeTab === 'entropy' && (
            <EntropyTab caseId={caseId} artifactId={artifactId} />
          )}
          {activeTab === 'layout' && (
            <FragmentationTab metadata={loaded.metadata} />
          )}
          {activeTab === 'hex' && (
            <HexTab caseId={caseId} artifactId={artifactId} />
          )}
          {activeTab === 'text' && (
            <TextTab caseId={caseId} artifactId={artifactId} />
          )}
          {activeTab === 'children' && (
            <ChildrenTab
              caseId={caseId}
              artifactId={artifactId}
              parentType={loaded.artifact_type}
            />
          )}
          {activeTab === 'registry' && (
            <RegistryTab caseId={caseId} artifactId={artifactId} />
          )}
          {activeTab === 'conversation' && (
            <ConversationTab caseId={caseId} artifactId={artifactId} />
          )}
          {activeTab === 'rawjson' && (
            <RawJsonTab metadata={loaded.metadata} />
          )}
          {activeTab === 'timeline' && (
            <RelatedTimelineTab
              caseId={caseId}
              artifactId={artifactId}
              parentId={loaded.parent_id}
            />
          )}
          {activeTab === 'processing' && (
            <ProcessingTab caseId={caseId} artifactId={artifactId} />
          )}
          {activeTab === 'run' && (
            <RunModuleTab
              caseId={caseId}
              artifactId={artifactId}
              artifactType={loaded.artifact_type}
            />
          )}
          {activeTab === null && (
            <div className="empty-state av-view-empty">
              <h3>Select a view</h3>
              <p>
                Choose a tab above to inspect this artifact. Its metadata is in
                the Inspector on the right.
              </p>
            </div>
          )}
        </div>
        {!inspectorCollapsed && (
          <div className="av-insp-col">
            <div
              className="av-insp-resize"
              role="separator"
              aria-orientation="vertical"
              aria-label="Resize inspector"
              onPointerDown={beginInspectorResize}
            />
            <ArtifactInspector
              caseId={caseId}
              artifact={loaded}
              previewKind={previewKind}
              onCollapse={() => setInspectorCollapsed(true)}
            />
          </div>
        )}
      </div>
    </div>
  )
}
