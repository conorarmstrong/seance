import { useState } from 'react'
import type { ReactNode } from 'react'
import type { ParsedRecord } from './api'
import { MISSING, metaStr } from './lib'
import type { ViewerProps } from './viewers'

type Json = unknown

function isBranch(v: Json): v is Record<string, Json> | Json[] {
  return v != null && typeof v === 'object'
}

function leafText(v: Json): string {
  if (v === null) return 'null'
  if (typeof v === 'string') return v
  if (typeof v === 'number' || typeof v === 'boolean') return String(v)
  return String(v)
}

function TreeNode({
  label,
  value,
  depth,
  defaultOpen,
}: {
  label: string
  value: Json
  depth: number
  defaultOpen: boolean
}) {
  const [open, setOpen] = useState(defaultOpen)

  if (!isBranch(value)) {
    return (
      <div className="an-tree-leaf" style={{ paddingLeft: depth * 14 }}>
        <span className="an-tree-key mono">{label}</span>
        <span className="an-tree-val mono">{leafText(value)}</span>
      </div>
    )
  }

  const entries: [string, Json][] = Array.isArray(value)
    ? value.map((v, i) => [String(i), v])
    : Object.entries(value)
  const kind = Array.isArray(value) ? `array[${entries.length}]` : `dict{${entries.length}}`

  return (
    <div className="an-tree-branch">
      <button
        type="button"
        className="an-tree-toggle"
        aria-expanded={open}
        onClick={() => setOpen((o) => !o)}
        style={{ paddingLeft: depth * 14 }}
      >
        <span className="an-tree-caret">{open ? '▾' : '▸'}</span>
        <span className="an-tree-key mono">{label}</span>
        <span className="an-tree-kind">{kind}</span>
      </button>
      {open &&
        entries.map(([k, v]) => (
          <TreeNode key={k} label={k} value={v} depth={depth + 1} defaultOpen={false} />
        ))}
    </div>
  )
}

export function PlistViewer({ records }: ViewerProps): ReactNode {
  const [sel, setSel] = useState<string | null>(null)
  const active = sel && records.some((r) => r.id === sel) ? sel : records[0]?.id
  const open: ParsedRecord | undefined = records.find((r) => r.id === active)
  const content = open?.metadata['content']
  const preview = open ? metaStr(open.metadata, 'content_preview') : null

  return (
    <div className="an-plist">
      <aside className="an-plist-list" aria-label="Property lists">
        {records.map((r) => (
          <button
            key={r.id}
            type="button"
            className={r.id === active ? 'an-plist-item selected' : 'an-plist-item'}
            data-testid="an-plist-item"
            onClick={() => setSel(r.id)}
          >
            <div className="an-plist-name mono">{metaStr(r.metadata, 'filename') ?? r.id}</div>
            <div className="an-plist-type">{metaStr(r.metadata, 'plist_type') ?? MISSING}</div>
          </button>
        ))}
      </aside>

      <section className="an-plist-tree" aria-label="Contents" data-testid="an-plist-tree">
        {content != null ? (
          <TreeNode label="root" value={content} depth={0} defaultOpen />
        ) : preview ? (
          <pre className="an-mail-body">{preview}</pre>
        ) : (
          <div className="empty-state">
            <h3>No parsed content</h3>
            <p>This property list was too large to include inline.</p>
          </div>
        )}
      </section>
    </div>
  )
}
