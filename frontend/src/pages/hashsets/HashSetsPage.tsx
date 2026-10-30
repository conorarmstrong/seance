import { useState } from 'react'
import { SkeletonTable } from '../../components/Skeleton'
import { useParams } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  createHashSet,
  deleteHashSet,
  exportVicsHashSet,
  importVicsHashSet,
  listHashSets,
} from '../../api/resources'
import type { HashSetInfo } from '../../api/types'
import { Modal } from '../../components/Modal'
import { useToast } from '../../components/toast/ToastProvider'
import { formatCount, formatUtc } from '../../lib/format'
import { useEntityScopedState } from '../../lib/useEntityScopedState'
import { HitsPanel } from './HitsPanel'
import { uploadFile } from './upload'
import './hashsets.css'

interface ImportResult {
  imported: number
  total_parsed: number
}

function setTypeBadge(setType: string) {
  if (setType === 'known') return <span className="badge badge-ok">Known good</span>
  if (setType === 'notable') return <span className="badge badge-danger">Notable</span>
  return <span className="badge">{setType}</span>
}

export function HashSetsPage() {
  const { caseId } = useParams<{ caseId: string }>()
  const queryClient = useQueryClient()
  const toast = useToast()

  // Hash sets are per-case and this page stays mounted when `:caseId` changes,
  // so every one of these holds a case A row while the chrome reads case B:
  // the hits panel would query case B with case A's hash_set_id (an empty
  // result that looks like "no matches in this case"), and Import/Delete would
  // POST/DELETE `/cases/<caseB>/hash_sets/<idFromA>` — a write aimed at the
  // wrong case. Scoping the state to the case it was opened under means the
  // stale value is never readable, with no post-render effect window in which
  // a request could already have been fired (B2-016).
  const [showCreate, setShowCreate] = useEntityScopedState(caseId ?? '', false)
  const [showVicsImport, setShowVicsImport] = useEntityScopedState(caseId ?? '', false)
  const [importTarget, setImportTarget] = useEntityScopedState<HashSetInfo | null>(
    caseId ?? '',
    null,
  )
  const [deleteTarget, setDeleteTarget] = useEntityScopedState<HashSetInfo | null>(
    caseId ?? '',
    null,
  )
  const [hitsView, setHitsView] = useEntityScopedState<{
    hashSetId: string | null
    title: string
  } | null>(caseId ?? '', null)

  const listQuery = useQuery({
    queryKey: ['hash-sets', caseId],
    queryFn: () => listHashSets(caseId!),
    enabled: !!caseId,
  })

  const invalidate = (forCase = caseId) =>
    queryClient.invalidateQueries({ queryKey: ['hash-sets', forCase] })

  // A delete still in flight when the case changes removed a set from case A,
  // but the confirmation and the list refresh would have landed on case B.
  // Carry the case the request was sent to so the report matches the write.
  const deleteMutation = useMutation({
    mutationFn: (hashSetId: string) => {
      const forCase = caseId!
      return deleteHashSet(forCase, hashSetId).then(() => ({ forCase }))
    },
    onSuccess: ({ forCase }) => {
      invalidate(forCase)
      if (forCase !== caseId) return
      toast.success('Hash set deleted')
      setDeleteTarget(null)
    },
    onError: (err: Error) => toast.error(err.message),
  })

  return (
    <div>
      <h1 className="page-title">Hash sets</h1>
      <div className="page-actions">
        <button className="btn btn-primary" onClick={() => setShowCreate(true)}>
          New hash set
        </button>
        <button className="btn" onClick={() => setShowVicsImport(true)}>
          Import VICS
        </button>
        <button
          className="btn"
          onClick={() => setHitsView({ hashSetId: null, title: 'All hits' })}
        >
          All hits
        </button>
      </div>

      {listQuery.isPending && <SkeletonTable rows={10} cols={5} label="Loading hash sets" />}
      {listQuery.isError && (
        <div className="error-note">{listQuery.error.message}</div>
      )}
      {listQuery.data && listQuery.data.length === 0 && (
        <div className="empty-state">
          <h3>No hash sets</h3>
          <p>
            Create a hash set, then import known-good or notable hashes to
            filter and flag files across the case.
          </p>
        </div>
      )}
      {listQuery.data && listQuery.data.length > 0 && (
        <div className="panel">
          <table className="data-table">
            <thead>
              <tr>
                <th>Name</th>
                <th>Type</th>
                <th>Algorithm</th>
                <th>Entries</th>
                <th>Description</th>
                <th>Imported</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {listQuery.data.map((set) => (
                <tr key={set.id}>
                  <td>{set.name}</td>
                  <td>{setTypeBadge(set.set_type)}</td>
                  <td className="mono">{set.hash_algorithm.toUpperCase()}</td>
                  <td className="hs-count">{formatCount(set.entry_count)}</td>
                  <td className="hs-desc" title={set.description ?? undefined}>
                    {set.description ?? '—'}
                  </td>
                  <td className="mono">
                    {formatUtc(new Date(set.imported_at * 1000).toISOString())}
                  </td>
                  <td>
                    <div className="hs-actions">
                      <button
                        className="btn"
                        onClick={() =>
                          setHitsView({
                            hashSetId: set.id,
                            title: `Hits: ${set.name}`,
                          })
                        }
                      >
                        View hits
                      </button>
                      <button
                        className="btn"
                        onClick={() => setImportTarget(set)}
                      >
                        Import
                      </button>
                      <button
                        className="btn"
                        onClick={async () => {
                          try {
                            const doc = await exportVicsHashSet(caseId!, set.id)
                            const blob = new Blob(
                              [JSON.stringify(doc, null, 2)],
                              { type: 'application/json' },
                            )
                            const url = URL.createObjectURL(blob)
                            const a = document.createElement('a')
                            a.href = url
                            a.download = `${set.name.replace(/[^\w.-]+/g, '_')}.vics.json`
                            a.click()
                            URL.revokeObjectURL(url)
                          } catch (e) {
                            toast.error(
                              e instanceof Error ? e.message : 'VICS export failed',
                            )
                          }
                        }}
                      >
                        Export VICS
                      </button>
                      <button
                        className="btn btn-danger"
                        onClick={() => setDeleteTarget(set)}
                      >
                        Delete
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {hitsView && caseId && (
        <HitsPanel
          key={hitsView.hashSetId ?? '__all__'}
          caseId={caseId}
          hashSetId={hitsView.hashSetId}
          title={hitsView.title}
          onClose={() => setHitsView(null)}
        />
      )}

      {showCreate && caseId && (
        <CreateHashSetModal
          caseId={caseId}
          onClose={() => setShowCreate(false)}
          onCreated={() => {
            invalidate()
            toast.success('Hash set created')
            setShowCreate(false)
          }}
        />
      )}

      {importTarget && caseId && (
        <ImportModal
          caseId={caseId}
          hashSet={importTarget}
          onClose={() => setImportTarget(null)}
          onImported={(result) => {
            invalidate()
            toast.success(
              `Imported ${result.imported} of ${result.total_parsed} parsed hashes`,
            )
            setImportTarget(null)
          }}
        />
      )}

      {showVicsImport && caseId && (
        <VicsImportModal
          caseId={caseId}
          onClose={() => setShowVicsImport(false)}
          onImported={(entries) => {
            invalidate()
            toast.success(`Imported ${formatCount(entries)} VICS entries`)
            setShowVicsImport(false)
          }}
        />
      )}

      {deleteTarget && (
        <Modal
          title="Delete hash set"
          onClose={() => setDeleteTarget(null)}
          footer={
            <>
              <button className="btn" onClick={() => setDeleteTarget(null)}>
                Cancel
              </button>
              <button
                className="btn btn-danger"
                disabled={deleteMutation.isPending}
                onClick={() => deleteMutation.mutate(deleteTarget.id)}
              >
                Delete
              </button>
            </>
          }
        >
          <p>
            Delete <strong>{deleteTarget.name}</strong>? Its{' '}
            {formatCount(deleteTarget.entry_count)} entries will be removed
            and matching will stop using this set.
          </p>
        </Modal>
      )}
    </div>
  )
}

function VicsImportModal({
  caseId,
  onClose,
  onImported,
}: {
  caseId: string
  onClose: () => void
  onImported: (entries: number) => void
}) {
  const toast = useToast()
  const [name, setName] = useState('')
  const [json, setJson] = useState('')

  const readFile = (file: File) => {
    const reader = new FileReader()
    reader.onload = () => {
      setJson(String(reader.result ?? ''))
      if (!name.trim()) setName(file.name.replace(/\.[^.]+$/, ''))
    }
    reader.readAsText(file)
  }

  const importMutation = useMutation({
    mutationFn: () =>
      importVicsHashSet(caseId, { name: name.trim(), vics_json: json }),
    onSuccess: (r) => onImported(r.entries_imported),
    onError: (err: Error) => toast.error(err.message),
  })

  return (
    <Modal
      title="Import Project VIC / CAID (VICS)"
      onClose={onClose}
      footer={
        <>
          <button className="btn" onClick={onClose}>
            Cancel
          </button>
          <button
            className="btn btn-primary"
            disabled={!name.trim() || !json.trim() || importMutation.isPending}
            onClick={() => importMutation.mutate()}
          >
            Import
          </button>
        </>
      }
    >
      <div className="hs-form">
        <p className="hs-hint">
          Load a VICS 2.0 JSON hash set. Each media hash keeps its VIC category
          and attributes; a set containing pertinent categories (1/2) is flagged
          notable. VIC/CAID data is restricted and is never shipped with Séance.
        </p>
        <label>
          Name
          <input
            className="input"
            value={name}
            onChange={(e) => setName(e.target.value)}
            required
          />
        </label>
        <label>
          VICS file
          <input
            className="input"
            type="file"
            accept=".json,application/json"
            onChange={(e) => {
              const f = e.target.files?.[0]
              if (f) readFile(f)
            }}
          />
        </label>
        <label>
          …or paste JSON
          <textarea
            className="input"
            rows={8}
            value={json}
            onChange={(e) => setJson(e.target.value)}
            placeholder='{"value":[{"MD5":"…","Category":1}]}'
          />
        </label>
      </div>
    </Modal>
  )
}

function CreateHashSetModal({
  caseId,
  onClose,
  onCreated,
}: {
  caseId: string
  onClose: () => void
  onCreated: () => void
}) {
  const toast = useToast()
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const [setType, setSetType] = useState('known')
  const [algorithm, setAlgorithm] = useState('md5')

  const createMutation = useMutation({
    mutationFn: () =>
      createHashSet(caseId, {
        name: name.trim(),
        description: description.trim() || undefined,
        set_type: setType,
        hash_algorithm: algorithm,
      }),
    onSuccess: onCreated,
    onError: (err: Error) => toast.error(err.message),
  })

  return (
    <Modal
      title="New hash set"
      onClose={onClose}
      footer={
        <>
          <button className="btn" onClick={onClose}>
            Cancel
          </button>
          <button
            className="btn btn-primary"
            disabled={!name.trim() || createMutation.isPending}
            onClick={() => createMutation.mutate()}
          >
            Create
          </button>
        </>
      }
    >
      <div className="hs-form">
        <label>
          Name
          <input
            className="input"
            value={name}
            onChange={(e) => setName(e.target.value)}
            required
          />
        </label>
        <label>
          Description
          <input
            className="input"
            value={description}
            onChange={(e) => setDescription(e.target.value)}
          />
        </label>
        <label>
          Type
          <select
            className="select"
            value={setType}
            onChange={(e) => setSetType(e.target.value)}
          >
            <option value="known">Known good (filter out matches)</option>
            <option value="notable">Notable (flag matches)</option>
          </select>
        </label>
        <label>
          Algorithm
          <select
            className="select"
            value={algorithm}
            onChange={(e) => setAlgorithm(e.target.value)}
          >
            <option value="md5">MD5</option>
            <option value="sha1">SHA1</option>
            <option value="sha256">SHA256</option>
          </select>
        </label>
      </div>
    </Modal>
  )
}

function ImportModal({
  caseId,
  hashSet,
  onClose,
  onImported,
}: {
  caseId: string
  hashSet: HashSetInfo
  onClose: () => void
  onImported: (result: ImportResult) => void
}) {
  const toast = useToast()
  const [file, setFile] = useState<File | null>(null)
  const [progress, setProgress] = useState(0)

  const importMutation = useMutation({
    mutationFn: (f: File) => {
      setProgress(0)
      return uploadFile<ImportResult>(
        `/cases/${caseId}/hash_sets/${hashSet.id}/import`,
        f,
        setProgress,
      )
    },
    onSuccess: onImported,
    onError: (err: Error) => toast.error(err.message),
  })

  const pct = Math.round(progress * 100)

  return (
    <Modal
      title={`Import into ${hashSet.name}`}
      onClose={onClose}
      footer={
        <>
          <button className="btn" onClick={onClose}>
            Cancel
          </button>
          <button
            className="btn btn-primary"
            disabled={!file || importMutation.isPending}
            onClick={() => file && importMutation.mutate(file)}
          >
            Import
          </button>
        </>
      }
    >
      <div className="hs-form">
        <label>
          Hash file
          <input
            type="file"
            accept=".csv,.txt"
            onChange={(e) => setFile(e.target.files?.[0] ?? null)}
          />
        </label>
      </div>
      {importMutation.isPending && (
        <div
          className="hs-progress"
          role="progressbar"
          aria-label="Upload progress"
          aria-valuemin={0}
          aria-valuemax={100}
          aria-valuenow={pct}
        >
          <div className="hs-progress-fill" style={{ width: `${pct}%` }} />
        </div>
      )}
      <div className="hs-formats">
        <h4>Accepted formats</h4>
        <ul>
          <li>
            Plain CSV or text: one <span className="mono">hash</span> per
            line, optionally <span className="mono">hash,product</span>.
          </li>
          <li>
            NSRL RDS exports: standard NSRL CSV rows are detected and the
            hash and product name columns are imported.
          </li>
        </ul>
      </div>
    </Modal>
  )
}
