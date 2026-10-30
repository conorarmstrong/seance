import { useEffect, useRef, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Folder,
  CheckSquare,
  Square,
  ArrowUp,
  CornerDownLeft,
  X,
} from 'lucide-react'
import {
  browseFilesystem,
  getActiveProfile,
  getEvidenceRoots,
  ingestSource,
  listModules,
  listProfiles,
} from '../../api/resources'
import { trackIngest } from '../../hooks/processing'
import { formatBytes } from '../../lib/format'
import { useToast } from '../toast/ToastProvider'
import { Modal } from '../Modal'
import {
  BUILT_IN_PROFILE_NAMES,
  resolveProfileGovernance,
} from './profileScope'
import { ProfileScopeNote } from './ProfileScopeNote'
import './ingest.css'

/**
 * True when `path` is `root` itself or lives inside it. A plain
 * `startsWith(root)` is a text prefix, not a path boundary: `/data2/case`
 * "starts with" `/data`, so the shorter root would win and the modal would name
 * the wrong allowlisted tree (BUG-264). Both separators are accepted because a
 * root may be a Windows path.
 */
export function isUnderRoot(path: string, root: string): boolean {
  if (!root) return false
  const trimmed = root.replace(/[/\\]+$/, '')
  // A root that is exactly the separator (`/`) contains everything below it.
  if (trimmed === '') return path.startsWith('/') || path.startsWith('\\')
  if (path === trimmed) return true
  const next = path.charAt(trimmed.length)
  return path.startsWith(trimmed) && (next === '/' || next === '\\')
}

/** The most specific configured root containing `path`, if any. */
export function activeRoot(roots: string[], path: string): string | undefined {
  return roots
    .filter((r) => isUnderRoot(path, r))
    .sort((a, b) => b.length - a.length)[0]
}

const EVIDENCE_TYPES = [
  { value: 'auto', label: 'Auto-detect' },
  { value: 'RawEvidence', label: 'Raw evidence (dd, image)' },
  { value: 'Container', label: 'Container (E01, zip, vdisk)' },
  { value: 'FileContent', label: 'Single file' },
]

/**
 * The value sent for a raw declaration. It is not a format name: it carries the
 * `memory_image: true` flag instead, which asserts "this file is memory" without
 * claiming a format the evidence could contradict.
 */
const MEMORY_RAW = 'raw'

/**
 * Formats the memory pipeline can be told to read a source as. Each value is the
 * name the analysis parses; the labels say which ones actually need declaring.
 *
 * Only `raw` is headerless. Everything below it announces itself in its own
 * bytes and is picked up without any declaration, so naming one here is an
 * override — and one the header can contradict, in which case the header wins
 * and the disagreement is recorded against the image.
 *
 * Every value here must be a name the analysis actually parses
 * (`DECLARABLE_FORMAT_NAMES` in `seance_memory/src/format.rs`, mirrored by
 * `MEMORY_FORMAT_NAMES` in `seance_api/src/lib.rs`). A name it does not
 * recognise is dropped in silence: the ingest succeeds, no memory record is
 * emitted, and the examiner is told nothing — so an option the analysis cannot
 * read is worse than no option at all. `hibernation` was exactly that until the
 * analysis learned the name; it is offered again because the declaration is now
 * honoured, and its label says what that gets you.
 */
/**
 * The Windows hibernation format.
 *
 * Séance reads a hibernation file's header (state, recorded hibernation time,
 * page size) and reconstructs its physical address space: the Windows 10/11 x64
 * restore sets are walked and each page block decompressed (both plain Xpress
 * and Xpress-Huffman), so the file is analysed like any other memory image —
 * processes, modules, connections and the rest. A block that does not decode,
 * and older layouts (Windows 7 and earlier), are reported as stated gaps rather
 * than guessed; the record says which.
 */
const HIBERNATION = 'hibernation'

const MEMORY_FORMATS: { value: string; label: string }[] = [
  { value: 'crash64', label: 'Windows crash dump, 64-bit (PAGEDU64)' },
  { value: 'crash32', label: 'Windows crash dump, 32-bit (PAGEDUMP)' },
  { value: 'avml', label: 'AVML' },
  { value: 'lime', label: 'LiME' },
  { value: 'elf', label: 'ELF core (virsh, VirtualBox, QEMU dump-guest-memory)' },
  { value: 'qemu', label: 'QEMU savevm' },
  { value: 'vmware', label: 'VMware snapshot (.vmss, .vmsn, .vmem)' },
  {
    value: HIBERNATION,
    label: 'Windows hibernation file (hiberfil.sys)',
  },
]

/**
 * Name suffixes that mark a headerless memory capture, mirroring
 * `HEADERLESS_MEMORY_SUFFIXES` in `seance_memory/src/module.rs`.
 *
 * `.raw`, `.dd`, `.bin` and `.img` are deliberately absent: they are ordinary
 * disk-image extensions, and a prompt that fires on every case is one nobody
 * reads.
 */
const HEADERLESS_MEMORY_SUFFIXES = ['.mem', '.vmem', '.ram']

/**
 * The selected sources whose names look like a headerless memory capture.
 *
 * A name is not evidence and this never declares anything — it only decides
 * whether the examiner is asked. The declaration itself stays theirs to make.
 *
 * Exported for the regression test: an undeclared capture is accepted as
 * ordinary evidence and yields no memory record, no warning and no
 * processing-log row, which is output identical to a case that never had a
 * capture in it (MEM-014). `seance_memory` writes that sentence to the run log,
 * which an examiner does not read; this is the same prompt where the decision
 * is actually made.
 */
export function undeclaredMemoryCaptures(selected: string[]): string[] {
  return selected.filter((file) => {
    const lower = file.toLowerCase()
    return HEADERLESS_MEMORY_SUFFIXES.some((suffix) => lower.endsWith(suffix))
  })
}

/** Last path component, for either separator — a root may be a Windows path. */
function baseName(file: string): string {
  return file.split(/[/\\]/).pop() ?? file
}

/**
 * Turn the declaration into the request keys.
 *
 * Exported for the regression test: this mapping is the whole point of the
 * control, and getting it wrong is invisible in the UI — the ingest succeeds
 * either way and the memory stages simply never run.
 */
export function memoryDeclaration(
  declared: boolean,
  format: string,
): { memory_image?: true; memory_image_format?: string } {
  if (!declared) return {}
  // "Raw" is not a format claim, so it must not travel as one: an examiner who
  // said "this is memory" has not said "this is a LiME capture", and only the
  // latter can be contradicted by a header.
  if (format === MEMORY_RAW) return { memory_image: true }
  return { memory_image_format: format }
}

export function IngestModal({
  caseId,
  onClose,
}: {
  caseId: string
  onClose: () => void
}) {
  const toast = useToast()
  const queryClient = useQueryClient()
  // The case a mutation must have been sent to for its result to belong here.
  // Assigned during render so a response settling between the switching render
  // and its passive effects is still tested against the right case.
  const activeCase = useRef(caseId)
  activeCase.current = caseId
  const [path, setPath] = useState('~')
  // What the examiner is typing into the path line, or null when they are not
  // typing and the line simply shows where the browser is. The lab convention
  // is that a path arrives on the clipboard from the acquisition ticket, and
  // six levels of clicking to reach a path you already have is the first thing
  // this product asked a time-pressed examiner to do.
  const [pathDraft, setPathDraft] = useState<string | null>(null)
  const [selected, setSelected] = useState<string[]>([])
  const [evidenceType, setEvidenceType] = useState('auto')
  const [profile, setProfile] = useState('')
  // The examiner's declaration that the selected source is a memory capture.
  // Nothing in the file can establish this for a raw dump, so it is a human
  // assertion and is treated as one throughout.
  const [declareMemory, setDeclareMemory] = useState(false)
  const [memoryFormat, setMemoryFormat] = useState(MEMORY_RAW)

  const browse = useQuery({
    // The case is part of the key, not just the request: the server authorises
    // the listing against the case that asked for it, so a directory read for
    // one case is not a cached answer for another.
    queryKey: ['fs-browse', caseId, path],
    // Tag each response with the path it belongs to so a placeholder left over
    // from the previous directory (kept by placeholderData below) can be told
    // apart from the current path's data.
    queryFn: async () => ({
      ...(await browseFilesystem(caseId, path)),
      _path: path,
    }),
    placeholderData: (prev) => prev,
  })
  // placeholderData keeps the previous directory's entries on screen while the
  // new path loads; those entries belong to the old directory, so clicking one
  // quickly would select/queue a file from the wrong path (BUG-202). Gate on the
  // path identity so stale entries are treated as "still loading" instead.
  const browseStale = browse.data != null && browse.data._path !== path
  const dir = browseStale ? undefined : browse.data
  const profiles = useQuery({
    queryKey: ['profiles', caseId],
    queryFn: () => listProfiles(caseId),
  })
  // The profile is CASE state: the server activates whatever an ingest names
  // and leaves it in force for every later ingest. Until this call the modal
  // presented the choice as belonging to one ingest and labelled its own empty
  // option "Default (all modules)", which was a false statement about every
  // ingest after the first triage run.
  const activeProfile = useQuery({
    queryKey: ['profile-active', caseId],
    queryFn: () => getActiveProfile(caseId),
  })
  // The population a profile's module list is measured against. Without it the
  // modal can name a profile but not say what it excludes, and it says exactly
  // that rather than implying nothing is excluded.
  const modules = useQuery({
    queryKey: ['modules', 'all'],
    queryFn: () => listModules(),
    staleTime: 5 * 60 * 1000,
  })
  const registry = modules.data?.map((m) => m.id)
  const governance = resolveProfileGovernance({
    selection: profile,
    profiles: profiles.data,
    active: activeProfile.data,
    registry,
  })
  // Profiles the examiner created, minus the built-ins: the server materialises
  // `triage` and `deep` as real rows on first use, so after one triage ingest
  // the list returned a "triage" row that appeared beside this modal's own
  // "Triage" option — two entries for one profile.
  const customProfiles = (profiles.data ?? []).filter(
    (p) => !BUILT_IN_PROFILE_NAMES.includes(p.name),
  )
  const activeName =
    activeProfile.data === undefined ? null : (activeProfile.data?.name ?? null)
  const profileStateLoading =
    activeProfile.isPending || profiles.isPending || modules.isPending
  // Configured evidence roots, so the browser can switch between them rather
  // than being pinned to the first one. Case-scoped like the listing itself —
  // the server will not name the evidence store to a request that names no case.
  const roots = useQuery({
    queryKey: ['evidence-roots', caseId],
    queryFn: () => getEvidenceRoots(caseId),
  })

  // The sources are written to the case that was open when `mutate()` ran, but
  // `onSuccess` runs in the latest render's closure. Reading `caseId` there
  // refreshed the tree and stats of whichever case is on screen when the last
  // upload settles, leaving the case that actually received the evidence
  // showing a tree without it. Carry the case the requests were sent to through
  // the mutation (B5-031).
  // A declaration names one file. Applying it to a batch would assert that
  // every selected source is a memory capture, which is never what the examiner
  // meant when they ticked the box with one file chosen.
  const memoryDeclared = declareMemory && selected.length === 1
  // Selected sources named like a headerless capture, while no declaration is
  // being made. Asking here is the only place the question gets answered: after
  // ingest the omission is invisible, because "not memory" and "memory nobody
  // declared" produce the same empty memory section (MEM-014).
  const undeclaredCaptures = declareMemory
    ? []
    : undeclaredMemoryCaptures(selected)

  // Any other way of moving (a directory row, Up, the root switcher) makes a
  // half-typed path stale, and a stale draft would keep showing a location the
  // browser is no longer at. Discarding it there is disclosed BEFORE the fact,
  // by the note the pending draft puts on screen, rather than after it.
  useEffect(() => {
    setPathDraft(null)
  }, [path])

  // Where the browser actually is, as opposed to what the path line is showing.
  const browsingPath = dir?.current_path ?? path
  // A path the examiner has entered but not yet opened.
  //
  // This is the state the path line used to throw away on blur: an examiner
  // pastes the path from the acquisition ticket, clicks a directory row or the
  // Ingest button, and the line reverts to the directory the browser was
  // already in with nothing saying the paste was dropped — data loss presented
  // as a no-op. The draft is now kept instead, and while it is uncommitted it
  // says so, because a path line that shows one location while the listing
  // below shows another is a claim that needs a caveat attached to it.
  const draft = pathDraft?.trim() ?? ''
  const pendingPath = draft !== '' && draft !== browsingPath ? draft : null

  /** Open a path the examiner entered, and retire the draft that named it. */
  function openPendingPath() {
    if (pendingPath == null) return
    setPath(pendingPath)
    setPathDraft(null)
  }

  const ingest = useMutation({
    mutationFn: async () => {
      const forCase = caseId
      // Sequential on purpose: the ingest endpoint is rate-limited.
      // The endpoint returns immediately ({artifact_id, status:"hashing"});
      // hashing and queueing continue in the background and stream over
      // SSE, so we register each artifact/source pair for event matching.
      const failures: { file: string; message: string }[] = []
      for (const file of selected) {
        try {
          const response = await ingestSource(forCase, {
            path: file,
            // A declared memory capture is raw evidence by definition, and the
            // memory pipeline only sees sources ingested as such. Leaving it to
            // extension-based auto-detection is how a `.raw` or `.mem` ends up
            // classified as something the memory module never subscribes to,
            // and the declaration then does nothing at all.
            artifact_type: memoryDeclared
              ? 'RawEvidence'
              : selected.length > 1
                ? 'auto'
                : evidenceType,
            profile: profile || undefined,
            ...memoryDeclaration(memoryDeclared, memoryFormat),
          })
          trackIngest(forCase, {
            artifactId: response.artifact_id,
            source: file,
          })
        } catch (e) {
          failures.push({
            file,
            message: e instanceof Error ? e.message : 'Ingest failed',
          })
        }
      }
      return { failures, forCase }
    },
    onSuccess: ({ failures, forCase }) => {
      const queued = selected.length - failures.length
      // Naming a profile activates it on the CASE, and the server does that
      // before it ever looks at the file — so even a request that then failed
      // may have changed which profile governs every later ingest. Refresh the
      // two answers every profile disclosure is built from, or this modal's
      // next open and the dashboard's scope note report the old state.
      if (profile) {
        queryClient.invalidateQueries({ queryKey: ['profile-active', forCase] })
        queryClient.invalidateQueries({ queryKey: ['profiles', forCase] })
      }
      if (queued > 0) {
        // Always the case the evidence went to, never the one on screen.
        queryClient.invalidateQueries({ queryKey: ['tree', forCase] })
        queryClient.invalidateQueries({ queryKey: ['case', forCase] })
        const where =
          forCase === activeCase.current
            ? ''
            : ' in the case it was started from, not the one open now'
        toast.success(
          (queued === 1
            ? 'Evidence queued — hashing started'
            : `${queued} sources queued — hashing started`) + where,
        )
      }
      for (const { file, message } of failures) {
        toast.error(`${file.split('/').pop()}: ${message}`)
      }
      if (failures.length === 0) onClose()
    },
  })

  const toggle = (filePath: string) => {
    setSelected((prev) =>
      prev.includes(filePath)
        ? prev.filter((p) => p !== filePath)
        : [...prev, filePath],
    )
  }

  return (
    <Modal
      title="Ingest Evidence"
      onClose={onClose}
      footer={
        <>
          <button className="btn" onClick={onClose}>
            Cancel
          </button>
          <button
            className="btn btn-primary"
            disabled={selected.length === 0 || ingest.isPending}
            onClick={() => ingest.mutate()}
          >
            {ingest.isPending
              ? 'Submitting…'
              : `Ingest ${selected.length || ''} ${selected.length === 1 ? 'source' : 'sources'}`}
          </button>
        </>
      }
    >
      <div className="ingest-options">
        <label>
          Evidence type
          <select
            className="select"
            value={memoryDeclared ? 'RawEvidence' : evidenceType}
            disabled={selected.length > 1 || memoryDeclared}
            onChange={(e) => setEvidenceType(e.target.value)}
          >
            {EVIDENCE_TYPES.map((t) => (
              <option key={t.value} value={t.value}>
                {t.label}
              </option>
            ))}
          </select>
        </label>
        <label>
          Analysis profile
          <select
            className="select"
            value={profile}
            onChange={(e) => setProfile(e.target.value)}
          >
            {/*
              The empty option names the profile it leaves in force. It does not
              mean "all modules": the server only touches the active profile
              when the request names one, so choosing nothing here runs this
              ingest under whatever the last one activated.
            */}
            <option value="">
              {activeProfile.isPending
                ? 'Change nothing — reading the case profile…'
                : activeProfile.data === undefined
                  ? "Change nothing — the case's profile could not be read"
                  : activeName
                    ? `Change nothing — keep the case profile: ${activeName}`
                    : 'Change nothing — no profile, every module runs'}
            </option>
            <option value="triage">Triage — a subset of modules</option>
            <option value="deep">Deep — every module</option>
            {customProfiles.map((p) => (
              <option key={p.id} value={p.id}>
                {p.name}
                {p.is_active ? ' (active)' : ''}
              </option>
            ))}
          </select>
        </label>
      </div>

      {/* A pending request is not a failed one: rendering the note before the
          answers arrive would say "could not be read" about a query still in
          flight, and a disclosure that cries wolf stops being read. */}
      {profileStateLoading ? (
        <div className="ingest-profile-note ingest-profile-loading">
          Reading which analysis profile governs this ingest…
        </div>
      ) : (
        <ProfileScopeNote
          governance={governance}
          context="ingest"
          registered={registry?.length ?? null}
        />
      )}

      <section className="ingest-memory" aria-label="Memory capture declaration">
        <label className="ingest-memory-toggle">
          <input
            type="checkbox"
            checked={declareMemory}
            onChange={(e) => setDeclareMemory(e.target.checked)}
          />
          <span>I declare this source to be a capture of physical memory</span>
        </label>

        {undeclaredCaptures.length > 0 && (
          <p
            className="ingest-memory-warning"
            role="note"
            aria-label="Undeclared memory capture"
          >
            {undeclaredCaptures.map(baseName).join(', ')}{' '}
            {undeclaredCaptures.length === 1 ? 'is' : 'are'} named like a
            headerless memory capture. A name is not evidence, so Séance will
            not read one as memory on the strength of it: ingesting one
            undeclared produces no memory record at all — no warning, no
            processing-log row — and every memory stage reports that it did not
            run, which reads exactly like a case with no capture in it. If it is
            a capture of physical memory, tick the box above.
          </p>
        )}

        {declareMemory && selected.length > 1 && (
          <p className="ingest-memory-note">
            A declaration is made about one file. {selected.length} sources are
            selected, so it will not be sent — ingest the memory capture on its
            own.
          </p>
        )}

        {declareMemory && selected.length <= 1 && (
          <>
            <label className="ingest-memory-format">
              <span>Declared format</span>
              <select
                className="select"
                value={memoryFormat}
                onChange={(e) => setMemoryFormat(e.target.value)}
              >
                <option value={MEMORY_RAW}>
                  Raw / dd — no header (this is what needs declaring)
                </option>
                <optgroup label="Has a header — detected without declaring">
                  {MEMORY_FORMATS.map((f) => (
                    <option key={f.value} value={f.value}>
                      {f.label}
                    </option>
                  ))}
                </optgroup>
              </select>
            </label>
            <p className="ingest-memory-warning">
              This is your assertion about the evidence, and it is recorded as
              one. A raw dump has no header, so nothing in the file can confirm
              or contradict what you declare here. If the file is not what you
              declare, the analysis will fail or be wrong, and it will be wrong
              in your name. The formats listed under &ldquo;has a header&rdquo;
              are identified automatically and need no declaration; naming one
              here overrides nothing, because a header that disagrees wins and
              the disagreement is recorded against the image.
            </p>
            {memoryFormat === HIBERNATION && (
              <p className="ingest-memory-note">
                A hibernation file is identified, its header read (state, the
                time the machine wrote it, page size) and its physical memory{' '}
                <strong>reconstructed</strong> — the Windows 10/11 x64 restore
                sets are walked and decompressed (both plain Xpress and
                Xpress-Huffman), so it is analysed like any other memory image. A
                block that does not decode, and older (Windows 7 and earlier)
                layouts, are reported as stated gaps rather than guessed.
              </p>
            )}
            <p className="ingest-memory-note">
              Declared captures are ingested as raw evidence.
            </p>
          </>
        )}
      </section>

      {(roots.data?.roots.length ?? 0) > 1 && (
        <label className="ingest-root">
          <span>Evidence root</span>
          <select
            className="mono"
            value={
              activeRoot(roots.data!.roots, path) ?? roots.data!.roots[0]
            }
            onChange={(e) => setPath(e.target.value)}
          >
            {roots.data!.roots.map((r) => (
              <option key={r} value={r}>
                {r}
              </option>
            ))}
          </select>
        </label>
      )}

      <div className="ingest-path mono">
        <button
          className="btn"
          // Don't offer "Up" past a configured root — its parent is outside the
          // allowlist and would just error.
          disabled={
            !dir?.parent_path ||
            (roots.data?.roots.includes(dir?.current_path ?? '') ?? false)
          }
          onClick={() => setPath(dir!.parent_path!)}
        >
          <ArrowUp size={14} /> Up
        </button>
        {/*
          Editable, because the server already owns the validation: it
          normalises the path and refuses anything outside the configured
          evidence roots with a message this modal renders below, so a mistyped
          or out-of-root paste gets the same honest error as any other bad path.
          Submitting on Enter only — an ingest browser that re-fetched on every
          keystroke would walk half-typed directories.
        */}
        <input
          className="mono ingest-path-input"
          aria-label="Evidence path"
          placeholder="Paste an evidence path, or browse below"
          title={dir?.current_path}
          value={pathDraft ?? browsingPath}
          aria-describedby={pendingPath ? 'ingest-path-pending' : undefined}
          onChange={(e) => setPathDraft(e.target.value)}
          onKeyDown={(e) => {
            if (e.key !== 'Enter') return
            e.preventDefault()
            openPendingPath()
            setPathDraft(null)
          }}
          // A draft with something in it is the examiner's typing and is kept:
          // blur is what happens when they reach for the next control, not a
          // decision to abandon what they entered. An EMPTY box is different —
          // there is nothing to lose, and leaving it empty would hide where the
          // browser is — so that one goes back to showing the location.
          onBlur={() => {
            if ((pathDraft ?? '').trim() === '') setPathDraft(null)
          }}
        />
        {/*
          The commit that does not require knowing about Enter. The keystroke
          stays — it is faster and an examiner who paged here with the keyboard
          expects it — but a path that can only be opened by an unadvertised
          key is a path most examiners will lose.
        */}
        <button
          type="button"
          className="btn"
          aria-label="Open this path"
          disabled={pendingPath == null}
          onClick={openPendingPath}
        >
          <CornerDownLeft size={14} /> Open
        </button>
      </div>
      {pendingPath != null && (
        <p className="warn-note ingest-path-pending" id="ingest-path-pending">
          <strong className="mono">{pendingPath}</strong> has not been opened
          yet — the listing below is still {browsingPath}. Choose Open, or press
          Enter, to go there; moving the browser some other way first will
          discard what you typed. If the path does not exist, or lies outside
          this server's configured evidence roots, opening it is what puts the
          server's refusal on screen.
        </p>
      )}

      <div className="ingest-browser" role="listbox" aria-label="Server files">
        {(browse.isLoading || browseStale) && (
          <div className="loading">Reading directory…</div>
        )}
        {browse.isError && (
          // The server's own words, not a generic failure. A refusal to read
          // the evidence store is now a real answer this endpoint gives — it is
          // reserved for administrators unless the deployment says otherwise —
          // and "Could not read this directory" would read as a broken path
          // rather than as a decision someone made about who may look.
          <div className="error-note">
            {browse.error instanceof Error && browse.error.message
              ? browse.error.message
              : 'Could not read this directory.'}
          </div>
        )}
        {dir?.entries.map((entry) => {
          const isSelected = selected.includes(entry.path)
          return (
            <div
              key={entry.path}
              className={`ingest-entry ${isSelected ? 'selected' : ''}`}
              onClick={() =>
                entry.is_dir ? setPath(entry.path) : toggle(entry.path)
              }
            >
              {/*
                A directory is a source in its own right, not only a place to
                look: an iOS backup, a logical file-set acquisition and an
                extracted evidence folder are all directories, and the parsers
                that read them take the directory rather than a file inside it
                (plugin.mobile.ios_backup joins "Manifest.db" onto the path it
                is handed). Selection therefore lives on its own control, so
                the row click can still mean "look inside" for a directory
                while the control means "examine this" for anything (LIVE-013).
              */}
              <button
                type="button"
                className="ingest-entry-select"
                aria-label={`${isSelected ? 'Deselect' : 'Select'} ${entry.name}`}
                aria-pressed={isSelected}
                onClick={(event) => {
                  event.stopPropagation()
                  toggle(entry.path)
                }}
              >
                {isSelected ? (
                  <CheckSquare size={16} className="ingest-icon-checked" />
                ) : (
                  <Square size={16} />
                )}
              </button>
              {entry.is_dir && (
                <span className="ingest-entry-icon" aria-hidden="true">
                  <Folder size={17} className="ingest-icon-folder" />
                </span>
              )}
              <span className="ingest-entry-name">{entry.name}</span>
              {!entry.is_dir && (
                <span className="ingest-entry-size mono">
                  {formatBytes(entry.size)}
                </span>
              )}
            </div>
          )
        })}
      </div>

      {selected.length > 0 && (
        <div className="ingest-selected">
          {selected.map((file) => (
            <span key={file} className="badge badge-accent" title={file}>
              {file.split('/').pop()}
              <button
                className="link-button icon-btn"
                aria-label={`Remove ${file}`}
                onClick={() => toggle(file)}
              >
                <X size={13} />
              </button>
            </span>
          ))}
        </div>
      )}
    </Modal>
  )
}
