import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useEffect, useMemo, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { MoreHorizontal } from 'lucide-react'
import { createCase, deleteCase, listCases } from '../../api/resources'
import type { Case } from '../../api/types'
import { useAuth } from '../../auth/AuthProvider'
import { ThemeSelect } from '../../themes/ThemeSelect'
import { BusyBar } from '../../components/BusyBar'
import { Modal } from '../../components/Modal'
import { useToast } from '../../components/toast/ToastProvider'
import { formatUtc } from '../../lib/format'
import './cases.css'

function statusBadgeClass(status: string): string {
  if (status === 'open') return 'badge badge-ok'
  if (status === 'closed') return 'badge'
  return 'badge badge-accent'
}

function capitalize(value: string): string {
  return value.charAt(0).toUpperCase() + value.slice(1)
}

export function CasesPage() {
  const { authMode, logout } = useAuth()
  const navigate = useNavigate()
  const toast = useToast()
  const queryClient = useQueryClient()

  const [search, setSearch] = useState('')
  const [statusFilter, setStatusFilter] = useState('all')
  const [sortBy, setSortBy] = useState<'created' | 'name'>('created')
  const [menuFor, setMenuFor] = useState<string | null>(null)
  const [showCreate, setShowCreate] = useState(false)
  const [deleteTarget, setDeleteTarget] = useState<Case | null>(null)

  const casesQuery = useQuery({ queryKey: ['cases'], queryFn: () => listCases() })
  const cases = casesQuery.data ?? []

  // Close the open card menu on outside click or Escape.
  useEffect(() => {
    if (menuFor === null) return
    const onMouseDown = (e: MouseEvent) => {
      const el = e.target instanceof Element ? e.target : null
      if (el?.closest('.cases-menu, .cases-menu-button')) return
      setMenuFor(null)
    }
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setMenuFor(null)
    }
    document.addEventListener('mousedown', onMouseDown)
    document.addEventListener('keydown', onKeyDown)
    return () => {
      document.removeEventListener('mousedown', onMouseDown)
      document.removeEventListener('keydown', onKeyDown)
    }
  }, [menuFor])

  const statuses = useMemo(
    () => Array.from(new Set(cases.map((c) => c.status))).sort(),
    [cases],
  )

  const visible = useMemo(() => {
    const needle = search.trim().toLowerCase()
    const filtered = cases.filter((c) => {
      if (statusFilter !== 'all' && c.status !== statusFilter) return false
      if (!needle) return true
      return (
        c.name.toLowerCase().includes(needle) ||
        (c.reference_number ?? '').toLowerCase().includes(needle)
      )
    })
    return [...filtered].sort((a, b) =>
      sortBy === 'name'
        ? a.name.localeCompare(b.name)
        : b.created_at.localeCompare(a.created_at),
    )
  }, [cases, search, statusFilter, sortBy])

  const deleteMutation = useMutation({
    mutationFn: (id: string) => deleteCase(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['cases'] })
      setDeleteTarget(null)
      toast.success('Case deleted')
    },
    onError: (error: Error) => toast.error(error.message),
  })

  return (
    <div className="cases-shell">
      <BusyBar />
      <header className="cases-header">
        <span className="cases-wordmark">SÉANCE</span>
        <button className="btn btn-primary" onClick={() => setShowCreate(true)}>
          New Case
        </button>
        {/* Reachable here as well as in case settings: the full picker lives
            behind a case, and an examiner who finds the default hard to read
            should not have to open somebody's case to change it. */}
        <ThemeSelect />
        {/* Hidden only when the server has positively told us it enforces no
            authentication: there is then no session to end, and a Sign out that
            does nothing implies one exists. */}
        {authMode === 'disabled' ? (
          <span className="mono" title="Started with SEANCE_AUTH_ENABLED=false">
            no sign-in required
          </span>
        ) : (
          <button className="btn" onClick={logout}>
            Sign out
          </button>
        )}
      </header>

      <div className="cases-body">
        {casesQuery.isPending && <div className="loading">Loading cases…</div>}
        {casesQuery.isError && (
          <div className="error-note">{casesQuery.error.message}</div>
        )}

        {casesQuery.isSuccess && cases.length === 0 && (
          <div className="empty-state">
            <h3>No cases yet</h3>
            <p>Create your first case to start an examination.</p>
          </div>
        )}

        {casesQuery.isSuccess && cases.length > 0 && (
          <>
            <div className="cases-toolbar">
              <input
                className="input cases-search"
                placeholder="Search by name or reference…"
                aria-label="Search cases"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
              />
              <select
                className="select"
                aria-label="Filter by status"
                value={statusFilter}
                onChange={(e) => setStatusFilter(e.target.value)}
              >
                <option value="all">All statuses</option>
                {statuses.map((s) => (
                  <option key={s} value={s}>
                    {capitalize(s)}
                  </option>
                ))}
              </select>
              <select
                className="select"
                aria-label="Sort by"
                value={sortBy}
                onChange={(e) => setSortBy(e.target.value as 'created' | 'name')}
              >
                <option value="created">Newest first</option>
                <option value="name">Name</option>
              </select>
            </div>

            {visible.length === 0 ? (
              <div className="empty-state">
                <h3>No matching cases</h3>
                <p>Adjust the search or status filter.</p>
              </div>
            ) : (
              <div className="cases-grid">
                {visible.map((c) => (
                  <div key={c.id} className="cases-card">
                    <div className="cases-card-top">
                      <div className="cases-card-name">{c.name}</div>
                      <span className={statusBadgeClass(c.status)}>
                        {c.status}
                      </span>
                      <button
                        className="cases-menu-button"
                        aria-label={`Actions for ${c.name}`}
                        aria-expanded={menuFor === c.id}
                        onClick={() =>
                          setMenuFor(menuFor === c.id ? null : c.id)
                        }
                      >
                        <MoreHorizontal size={16} />
                      </button>
                    </div>
                    {menuFor === c.id && (
                      <div className="cases-menu" role="menu">
                        <button
                          onClick={() => {
                            setMenuFor(null)
                            setDeleteTarget(c)
                          }}
                        >
                          Delete case
                        </button>
                      </div>
                    )}
                    <div className="cases-card-meta">
                      {c.reference_number && (
                        <div className="cases-meta-row">
                          <span className="cases-meta-label">ref</span>
                          <span className="mono">{c.reference_number}</span>
                        </div>
                      )}
                      {c.examiner_name && (
                        <div className="cases-meta-row">
                          <span className="cases-meta-label">examiner</span>
                          <span>{c.examiner_name}</span>
                        </div>
                      )}
                      <div className="cases-meta-row">
                        <span className="cases-meta-label">created</span>
                        <span className="mono">{formatUtc(c.created_at)}</span>
                      </div>
                      {c.last_accessed_at && (
                        <div className="cases-meta-row">
                          <span className="cases-meta-label">last opened</span>
                          <span className="mono">
                            {formatUtc(c.last_accessed_at)}
                          </span>
                        </div>
                      )}
                    </div>
                    <div className="cases-card-foot">
                      <Link className="btn" to={`/cases/${c.id}`}>
                        Open
                      </Link>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </>
        )}
      </div>

      {showCreate && (
        <NewCaseModal
          onClose={() => setShowCreate(false)}
          onCreated={(created) => {
            queryClient.invalidateQueries({ queryKey: ['cases'] })
            navigate(`/cases/${created.id}`)
          }}
        />
      )}

      {deleteTarget && (
        <DeleteCaseModal
          target={deleteTarget}
          busy={deleteMutation.isPending}
          onClose={() => setDeleteTarget(null)}
          onConfirm={() => deleteMutation.mutate(deleteTarget.id)}
        />
      )}
    </div>
  )
}

function NewCaseModal({
  onClose,
  onCreated,
}: {
  onClose: () => void
  onCreated: (created: Case) => void
}) {
  const toast = useToast()
  const [name, setName] = useState('')
  const [reference, setReference] = useState('')
  const [examiner, setExaminer] = useState('')

  const createMutation = useMutation({
    mutationFn: () =>
      createCase({
        name: name.trim(),
        reference_number: reference.trim() || undefined,
        examiner_name: examiner.trim() || undefined,
      }),
    onSuccess: (created) => onCreated(created),
    onError: (error: Error) => toast.error(error.message),
  })

  return (
    <Modal
      title="New Case"
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
      <div className="cases-form-row">
        <label htmlFor="new-case-name">Name</label>
        <input
          id="new-case-name"
          className="input"
          value={name}
          onChange={(e) => setName(e.target.value)}
          autoFocus
        />
      </div>
      <div className="cases-form-row">
        <label htmlFor="new-case-ref">Reference number</label>
        <input
          id="new-case-ref"
          className="input mono"
          value={reference}
          onChange={(e) => setReference(e.target.value)}
        />
      </div>
      <div className="cases-form-row">
        <label htmlFor="new-case-examiner">Examiner name</label>
        <input
          id="new-case-examiner"
          className="input"
          value={examiner}
          onChange={(e) => setExaminer(e.target.value)}
        />
      </div>
    </Modal>
  )
}

function DeleteCaseModal({
  target,
  busy,
  onClose,
  onConfirm,
}: {
  target: Case
  busy: boolean
  onClose: () => void
  onConfirm: () => void
}) {
  const [confirmText, setConfirmText] = useState('')

  return (
    <Modal
      title="Delete case"
      onClose={onClose}
      footer={
        <>
          <button className="btn" onClick={onClose}>
            Cancel
          </button>
          <button
            className="btn btn-danger"
            disabled={confirmText !== target.name || busy}
            onClick={onConfirm}
          >
            Delete
          </button>
        </>
      }
    >
      <p className="cases-confirm-hint">
        This permanently deletes the case and all of its artifacts.
      </p>
      <div className="cases-form-row">
        <label htmlFor="delete-case-confirm">
          Type the case name ({target.name}) to confirm
        </label>
        <input
          id="delete-case-confirm"
          className="input"
          value={confirmText}
          onChange={(e) => setConfirmText(e.target.value)}
          autoFocus
        />
      </div>
    </Modal>
  )
}
