import { useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { LayoutGrid, ListTree } from 'lucide-react'
import { analyzeCategory, listModules } from '../../api/resources'
import { ContextMenu, type ContextMenuItem } from '../ContextMenu'
import { formatCount } from '../../lib/format'
import { useEntityScopedState } from '../../lib/useEntityScopedState'
import { useToast } from '../toast/ToastProvider'
import { EvidenceTree } from './EvidenceTree'
import { LogicalTree } from './LogicalTree'
import './tree.css'

type Lens = 'physical' | 'logical'
const LENS_KEY = 'seance.navigator.lens'

function initialLens(): Lens {
  try {
    return localStorage.getItem(LENS_KEY) === 'logical' ? 'logical' : 'physical'
  } catch {
    return 'physical'
  }
}

interface MenuState {
  x: number
  y: number
  node: { type: string; label: string; count: number }
}

/**
 * The case navigator (sidebar) with two lenses on the same evidence: Physical
 * (the acquisition tree) and Logical (examiner categories). It is the single
 * navigator — its rows link into the workbench content pane. Right-clicking a
 * logical type opens a menu that runs analysis across it (/analyze). The lens
 * choice persists per browser.
 */
export function NavigatorPanel({ caseId }: { caseId: string }) {
  const [lens, setLens] = useState<Lens>(initialLens)
  // The lens is a per-browser preference and survives anything. The open
  // context menu does not: it names one case's record type and prints that
  // case's record count in its header, and the sidebar stays mounted when
  // `:caseId` changes. Left unscoped it hangs over the new case still reading
  // "Pictures · 12,480 records" — a count taken from evidence that is no
  // longer on screen — and its "Run …" items queue that analysis against the
  // new case. Scoped state resolves during render, so the menu is gone in the
  // first frame the new case is shown rather than one frame later.
  const [menu, setMenu] = useEntityScopedState<MenuState | null>(caseId, null)
  const navigate = useNavigate()
  const toast = useToast()
  const queryClient = useQueryClient()
  // The case a mutation must have been sent to for its result to belong here.
  // Assigned during render, not from an effect: a request settling between the
  // switching render and its passive effects would otherwise be checked against
  // the previous case.
  const activeCase = useRef(caseId)
  activeCase.current = caseId

  const choose = (next: Lens) => {
    setLens(next)
    try {
      localStorage.setItem(LENS_KEY, next)
    } catch {
      // storage unavailable; choice just won't persist
    }
  }

  // Modules that can be re-run against parsed records; drives the menu.
  const modulesQuery = useQuery({
    queryKey: ['modules', 'ParsedRecord'],
    queryFn: () => listModules('ParsedRecord'),
  })
  // The write goes to the case that was open when `mutate()` ran, but
  // `onSuccess` runs in the latest render's closure. Reading `caseId` there
  // confirmed the run over case B's chrome and refreshed B's job list, while
  // case A — the one that actually received the analysis — kept showing a stale
  // list. Carry the case the request was sent to through the mutation, the way
  // the filters and hash-set pages already do (B5-012).
  const analyzeMutation = useMutation({
    mutationFn: (vars: { moduleId: string; recordType: string }) => {
      const forCase = caseId
      return analyzeCategory(forCase, vars.moduleId, vars.recordType).then(
        (res) => ({ res, forCase }),
      )
    },
    onSuccess: ({ res, forCase }, vars) => {
      // Always the case the run was queued against, never the one on screen.
      queryClient.invalidateQueries({ queryKey: ['jobs', forCase] })
      const where =
        forCase === activeCase.current
          ? ''
          : ' in the case it was started from, not the one open now'
      toast.success(
        `Queued ${vars.moduleId} on ${formatCount(res.targets)} record(s)` +
          (res.truncated ? ' (capped)' : '') +
          where,
      )
    },
    onError: (err) => toast.error(`Failed to queue analysis: ${err.message}`),
  })

  const menuItems = (node: MenuState['node']): ContextMenuItem[] => {
    const items: ContextMenuItem[] = [
      {
        label: 'Open results',
        onClick: () =>
          navigate(
            `/cases/${caseId}/analysis/${encodeURIComponent(node.type)}`,
          ),
        separatorAfter: true,
      },
    ]
    if (modulesQuery.isLoading) {
      items.push({ label: 'Loading analyses…', disabled: true })
    } else if ((modulesQuery.data?.length ?? 0) === 0) {
      items.push({
        label: 'No analyses available for this type',
        disabled: true,
      })
    } else {
      for (const mod of modulesQuery.data ?? []) {
        items.push({
          label: `Run ${mod.id}`,
          note: mod.execution_mode,
          onClick: () =>
            analyzeMutation.mutate({
              moduleId: mod.id,
              recordType: node.type,
            }),
        })
      }
    }
    return items
  }

  return (
    <div className="nav-panel">
      <div className="nav-lens" role="tablist" aria-label="Navigator lens">
        <button
          type="button"
          role="tab"
          aria-selected={lens === 'physical'}
          className={lens === 'physical' ? 'nav-lens-btn on' : 'nav-lens-btn'}
          onClick={() => choose('physical')}
        >
          <ListTree size={14} /> Physical
        </button>
        <button
          type="button"
          role="tab"
          aria-selected={lens === 'logical'}
          className={lens === 'logical' ? 'nav-lens-btn on' : 'nav-lens-btn'}
          onClick={() => choose('logical')}
        >
          <LayoutGrid size={14} /> Logical
        </button>
      </div>
      {lens === 'physical' ? (
        <EvidenceTree caseId={caseId} />
      ) : (
        <LogicalTree
          caseId={caseId}
          onTypeContextMenu={(e, node) => {
            e.preventDefault()
            setMenu({ x: e.clientX, y: e.clientY, node })
          }}
        />
      )}
      {menu && (
        <ContextMenu
          x={menu.x}
          y={menu.y}
          header={`${menu.node.label} · ${formatCount(menu.node.count)} records`}
          footer="Analyses add derived records for review — they never alter the originals."
          items={menuItems(menu.node)}
          onClose={() => setMenu(null)}
        />
      )}
    </div>
  )
}
