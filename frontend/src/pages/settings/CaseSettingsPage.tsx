import { useRef, useState } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  activateProfile,
  deleteCase,
  deleteProfile,
  getCase,
  listProfiles,
  updateCase,
} from '../../api/resources'
import type { Case, IngestionProfile } from '../../api/types'
import { Modal } from '../../components/Modal'
import { useToast } from '../../components/toast/ToastProvider'
import { formatUtc } from '../../lib/format'
import { ThemePicker } from '../../themes/ThemePicker'
import './settings.css'

export function CaseSettingsPage() {
  const { caseId } = useParams<{ caseId: string }>()

  const caseQuery = useQuery({
    queryKey: ['case', caseId],
    queryFn: () => getCase(caseId!),
    enabled: !!caseId,
  })

  return (
    <div>
      <h1 className="page-title">Case settings</h1>
      {caseQuery.isPending && <div className="loading">Loading case…</div>}
      {caseQuery.isError && (
        <div className="error-note">{caseQuery.error.message}</div>
      )}
      {caseQuery.data && caseId && (
        <>
          <div className="panel">
            <h2 className="panel-title">Case details</h2>
            <CaseForm key={caseQuery.data.id} caseId={caseId} data={caseQuery.data} />
          </div>

          {/* Not a property of the case, and said so: this panel is the
              examiner's own display preference, stored against their account
              and applied to every case they open. It lives here because this is
              the only settings surface the product has. */}
          <div className="panel">
            <h2 className="panel-title">Appearance</h2>
            <p className="set-hint">
              How Séance looks to you. This is yours, not the case&rsquo;s: it
              follows your account to any workstation and changes nothing about
              the evidence or about what anyone else sees.
            </p>
            <ThemePicker />
          </div>

          <div className="panel">
            <h2 className="panel-title">Case record</h2>
            <dl className="set-meta">
              <dt>Case ID</dt>
              <dd className="mono">{caseQuery.data.id}</dd>
              <dt>Status</dt>
              <dd>{caseQuery.data.status}</dd>
              <dt>Created</dt>
              <dd className="mono">{formatUtc(caseQuery.data.created_at)}</dd>
              <dt>Last accessed</dt>
              <dd className="mono">
                {formatUtc(caseQuery.data.last_accessed_at)}
              </dd>
            </dl>
          </div>

          {/*
            Keyed on the case for the same reason CaseForm is: this page stays
            mounted when `:caseId` changes, and both panels hold a confirmation
            dialog aimed at a specific record. Unkeyed, "Delete profile" stays
            open across the switch and confirms against case A's profile id
            under case B's path, and the danger zone keeps its typed
            confirmation — case A's name already accepted — pointing at
            deleteCase(caseB) (B2-055).
          */}
          <ProfilesPanel key={caseId} caseId={caseId} />
          <DangerZone
            key={caseId}
            caseId={caseId}
            caseName={caseQuery.data.name}
          />
        </>
      )}
    </div>
  )
}

function CaseForm({ caseId, data }: { caseId: string; data: Case }) {
  const queryClient = useQueryClient()
  const toast = useToast()
  const [name, setName] = useState(data.name)
  const [referenceNumber, setReferenceNumber] = useState(
    data.reference_number ?? '',
  )
  const [examinerName, setExaminerName] = useState(data.examiner_name ?? '')

  // The save targets the case that was open when `mutate()` ran, but
  // `onSuccess` runs in the latest render's closure. Reading `caseId` there
  // confirmed "Saved" over another case and refreshed that case instead of the
  // one whose record changed (B5-012 class).
  const activeCase = useRef(caseId)
  activeCase.current = caseId
  const saveMutation = useMutation({
    mutationFn: () => {
      const forCase = caseId
      return updateCase(forCase, {
        name: name.trim(),
        reference_number: referenceNumber.trim(),
        examiner_name: examinerName.trim(),
      }).then(() => forCase)
    },
    onSuccess: (forCase) => {
      queryClient.invalidateQueries({ queryKey: ['case', forCase] })
      if (forCase !== activeCase.current) return
      toast.success('Saved')
    },
    onError: (err: Error) => toast.error(err.message),
  })

  return (
    <div className="set-form">
      <label>
        Case name
        <input
          className="input"
          value={name}
          onChange={(e) => setName(e.target.value)}
          required
        />
      </label>
      <label>
        Reference number
        <input
          className="input"
          value={referenceNumber}
          onChange={(e) => setReferenceNumber(e.target.value)}
        />
      </label>
      <label>
        Examiner name
        <input
          className="input"
          value={examinerName}
          onChange={(e) => setExaminerName(e.target.value)}
        />
      </label>
      <div className="set-form-actions">
        <button
          className="btn btn-primary"
          disabled={!name.trim() || saveMutation.isPending}
          onClick={() => saveMutation.mutate()}
        >
          Save
        </button>
      </div>
    </div>
  )
}

function ProfilesPanel({ caseId }: { caseId: string }) {
  const queryClient = useQueryClient()
  const toast = useToast()
  const [deleteTarget, setDeleteTarget] = useState<IngestionProfile | null>(
    null,
  )

  const profilesQuery = useQuery({
    queryKey: ['profiles', caseId],
    queryFn: () => listProfiles(caseId),
  })

  // Same as CaseForm: carry the case the request was sent to through the
  // mutation rather than reading the render's latest one in `onSuccess`.
  const activeCase = useRef(caseId)
  activeCase.current = caseId
  const invalidate = (forCase: string) =>
    queryClient.invalidateQueries({ queryKey: ['profiles', forCase] })

  const activateMutation = useMutation({
    mutationFn: (profileId: string) => {
      const forCase = caseId
      return activateProfile(forCase, profileId).then(() => forCase)
    },
    onSuccess: (forCase) => {
      void invalidate(forCase)
      if (forCase !== activeCase.current) return
      toast.success('Profile activated')
    },
    onError: (err: Error) => toast.error(err.message),
  })

  const deleteMutation = useMutation({
    mutationFn: (profileId: string) => {
      const forCase = caseId
      return deleteProfile(forCase, profileId).then(() => forCase)
    },
    onSuccess: (forCase) => {
      void invalidate(forCase)
      if (forCase !== activeCase.current) return
      toast.success('Profile deleted')
      setDeleteTarget(null)
    },
    onError: (err: Error) => toast.error(err.message),
  })

  return (
    <div className="panel">
      <h2 className="panel-title">Ingestion profiles</h2>
      {profilesQuery.isPending && (
        <div className="loading">Loading profiles…</div>
      )}
      {profilesQuery.isError && (
        <div className="error-note">{profilesQuery.error.message}</div>
      )}
      {profilesQuery.data && profilesQuery.data.length === 0 && (
        <div className="empty-state">
          <h3>No profiles</h3>
          <p>Ingestion profiles control which modules run during ingest.</p>
        </div>
      )}
      {profilesQuery.data && profilesQuery.data.length > 0 && (
        <table className="data-table">
          <thead>
            <tr>
              <th>Name</th>
              <th>Description</th>
              <th>Enabled modules</th>
              <th>Status</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {profilesQuery.data.map((profile) => (
              <tr key={profile.id}>
                <td>{profile.name}</td>
                <td>{profile.description}</td>
                <td>{profile.enabled_modules.length}</td>
                <td>
                  {profile.is_active && (
                    <span className="badge badge-accent">Active</span>
                  )}
                </td>
                <td>
                  {!profile.is_active && (
                    <button
                      className="btn"
                      disabled={activateMutation.isPending}
                      onClick={() => activateMutation.mutate(profile.id)}
                    >
                      Activate
                    </button>
                  )}{' '}
                  <button
                    className="btn btn-danger"
                    onClick={() => setDeleteTarget(profile)}
                  >
                    Delete
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      {deleteTarget && (
        <Modal
          title="Delete profile"
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
            Delete the profile <strong>{deleteTarget.name}</strong>? Ingestion
            will fall back to the default module set.
          </p>
        </Modal>
      )}
    </div>
  )
}

function DangerZone({ caseId, caseName }: { caseId: string; caseName: string }) {
  const navigate = useNavigate()
  const toast = useToast()
  const [showConfirm, setShowConfirm] = useState(false)
  const [confirmText, setConfirmText] = useState('')

  const deleteMutation = useMutation({
    mutationFn: () => deleteCase(caseId),
    onSuccess: () => {
      navigate('/')
    },
    onError: (err: Error) => toast.error(err.message),
  })

  return (
    <div className="panel set-danger">
      <h2 className="panel-title">Danger zone</h2>
      <div className="set-danger-body">
        <p>
          Permanently delete this case, including all artifacts, timeline
          events, bookmarks, hash sets, and audit history.
        </p>
        <button className="btn btn-danger" onClick={() => setShowConfirm(true)}>
          Delete case
        </button>
      </div>

      {showConfirm && (
        <Modal
          title="Delete case"
          onClose={() => {
            setShowConfirm(false)
            setConfirmText('')
          }}
          footer={
            <>
              <button
                className="btn"
                onClick={() => {
                  setShowConfirm(false)
                  setConfirmText('')
                }}
              >
                Cancel
              </button>
              <button
                className="btn btn-danger"
                disabled={confirmText !== caseName || deleteMutation.isPending}
                onClick={() => deleteMutation.mutate()}
              >
                Delete permanently
              </button>
            </>
          }
        >
          <p>
            This cannot be undone. All evidence references, parsed artifacts,
            timeline events, bookmarks, and the audit trail for{' '}
            <strong>{caseName}</strong> will be removed.
          </p>
          <label className="set-confirm">
            Type the case name to confirm
            <input
              className="input"
              value={confirmText}
              onChange={(e) => setConfirmText(e.target.value)}
              placeholder={caseName}
            />
          </label>
        </Modal>
      )}
    </div>
  )
}
