import { useState, type FormEvent } from 'react'
import type { VirtualColumnDef } from '../../api/types'
import { Modal } from '../../components/Modal'

export function ColumnSettingsModal({
  columns,
  visibleIds,
  creating,
  onToggle,
  onCreate,
  onDelete,
  onClose,
}: {
  columns: VirtualColumnDef[]
  visibleIds: string[]
  creating: boolean
  onToggle: (id: string, visible: boolean) => void
  onCreate: (name: string, paths: string[]) => void
  onDelete: (id: string) => void
  onClose: () => void
}) {
  const [name, setName] = useState('')
  const [paths, setPaths] = useState('')
  const [formError, setFormError] = useState<string | null>(null)

  const submit = (e: FormEvent) => {
    e.preventDefault()
    const trimmedName = name.trim()
    const pathList = paths
      .split(',')
      .map((p) => p.trim())
      .filter(Boolean)
    if (!trimmedName || pathList.length === 0) {
      setFormError('Name and at least one JSON path are required')
      return
    }
    if (pathList.some((p) => !p.startsWith('$'))) {
      setFormError('JSON paths must start with $ (e.g. $.filename)')
      return
    }
    setFormError(null)
    onCreate(trimmedName, pathList)
    setName('')
    setPaths('')
  }

  return (
    <Modal
      title="Column settings"
      onClose={onClose}
      footer={
        <button className="btn" onClick={onClose}>
          Done
        </button>
      }
    >
      <div>
        {columns.map((col) => (
          <div key={col.id} className="tl-col-row">
            <label className="tl-check-label">
              <input
                type="checkbox"
                checked={visibleIds.includes(col.id)}
                onChange={(e) => onToggle(col.id, e.target.checked)}
              />
              <span className="tl-col-name">{col.name}</span>
            </label>
            <span className="tl-col-desc">
              {col.description}
              {col.built_in && ' (built-in)'}
            </span>
            {!col.built_in && (
              <button
                className="btn btn-danger tl-col-delete"
                aria-label={`Delete ${col.name}`}
                onClick={() => onDelete(col.id)}
              >
                Delete
              </button>
            )}
          </div>
        ))}
        {columns.length === 0 && (
          <div className="empty-state">
            <h3>No virtual columns</h3>
            <p>Create one below to surface fields from event details.</p>
          </div>
        )}
      </div>
      <form className="tl-col-form" onSubmit={submit}>
        <div className="tl-form-field">
          <label htmlFor="tl-col-name-input">Column name</label>
          <input
            id="tl-col-name-input"
            className="input"
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="e.g. Process Name"
          />
        </div>
        <div className="tl-form-field">
          <label htmlFor="tl-col-paths-input">
            JSON paths (comma-separated)
          </label>
          <input
            id="tl-col-paths-input"
            className="input mono"
            value={paths}
            onChange={(e) => setPaths(e.target.value)}
            placeholder="$.process_name, $.image_path"
          />
        </div>
        {formError && <div className="tl-form-error">{formError}</div>}
        <div>
          <button className="btn btn-primary" type="submit" disabled={creating}>
            {creating ? 'Adding…' : 'Add column'}
          </button>
        </div>
      </form>
    </Modal>
  )
}
