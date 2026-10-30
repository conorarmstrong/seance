import { useQuery } from '@tanstack/react-query'
import { NavLink, Outlet, useNavigate, useParams } from 'react-router-dom'
import { Suspense } from 'react'
import { ChevronLeft } from 'lucide-react'
import { getCase } from '../api/resources'
import { getMemoryImages } from '../pages/memory/api'
import { useEntityScopedQuery } from '../lib/useEntityScopedQuery'
import { NAV_SECTIONS, memoryCountBadge } from './nav'
import { buildCaseCommands } from './commands'
import { useMainScrollRestoration } from './mainScroll'
import { CommandPalette } from '../components/CommandPalette'
import { ProcessingProvider, useProcessing } from './ProcessingContext'
import { PivotProvider } from './PivotContext'
import { TimeWindowProvider } from './TimeWindowContext'
import { TimeWindowBar } from '../components/TimeWindowBar'
import { BusyBar } from '../components/BusyBar'
import { NavigatorPanel } from '../components/tree/NavigatorPanel'
import { ProcessingPanel } from '../components/processing/ProcessingPanel'
import { IngestButton } from '../components/ingest/IngestButton'
import { CustodyStrip } from './CustodyStrip'
import { CaseUnavailable } from './CaseUnavailable'
import { useAuth } from '../auth/AuthProvider'
import './app.css'

export function CaseLayout() {
  const { caseId } = useParams() as { caseId: string }
  const { session, authMode, logout } = useAuth()
  const navigate = useNavigate()

  // ⌘K command palette: jump to any view or run a full-text search. The list
  // lives in commands.ts, derived from the rail rather than restated beside it —
  // a hand-kept second list is how five whole analytical surfaces came to be
  // missing from the palette.
  const commands = buildCaseCommands(caseId, navigate)

  // How many RAM captures the case holds, for the Memory badge. Entity-scoped so
  // that switching cases never shows the previous case's count under the new
  // case's rail. A failure here must not break the shell — the badge simply
  // stays hidden (memoryCountBadge(undefined) === null).
  const memoryImages = useEntityScopedQuery(JSON.stringify({ caseId }), {
    queryKey: ['memory-images', caseId],
    queryFn: () => getMemoryImages(caseId),
    retry: false,
  })
  const memoryBadge = memoryCountBadge(memoryImages.scoped?.image_count)

  // `.main-content` is the only thing in the shell that scrolls, so neither
  // the browser's own restoration nor react-router's <ScrollRestoration> (both
  // of which manage `window`) ever apply to it. This gives Back its position
  // back and gives a forward navigation the top of the page.
  const mainScroll = useMainScrollRestoration<HTMLElement>()

  const caseQuery = useQuery({
    queryKey: ['case', caseId],
    queryFn: () => getCase(caseId),
    retry: false,
  })
  const kase = caseQuery.data

  // The case failed to load. A 404 means it is gone — deleted, or the
  // workspace reset while it was open — and gets a clear dead-end with a way
  // back rather than a broken shell. Anything else (the server busy behind an
  // ingest, a timeout) says nothing about the case and gets a retry; saying
  // "deleted" for those was HUNT-078.
  if (caseQuery.isError) {
    return <CaseUnavailable error={caseQuery.error} onRetry={() => void caseQuery.refetch()} />
  }

  return (
    <ProcessingProvider caseId={caseId}>
      <PivotProvider caseId={caseId}>
      <TimeWindowProvider caseId={caseId}>
      <div className="shell">
        <BusyBar />
      <CommandPalette
        commands={commands}
        onSearch={(query) =>
          navigate(`/cases/${caseId}/search?q=${encodeURIComponent(query)}`)
        }
      />
      <aside className="sidebar">
        <div className="sidebar-head">
          <NavLink to="/" className="wordmark" title="All cases">
            SÉANCE
          </NavLink>
        </div>
        <NavLink to="/" className="all-cases-link">
          <ChevronLeft size={14} aria-hidden="true" /> All cases
        </NavLink>
        <div className="case-card">
          <div className="case-card-name">{kase?.name ?? '…'}</div>
          {kase?.reference_number && (
            <div className="case-card-ref mono">{kase.reference_number}</div>
          )}
        </div>
        <nav className="side-nav" aria-label="Case navigation">
          {NAV_SECTIONS.map((group) => (
            <div className="side-nav-group" key={group.section}>
              <div className="side-nav-label">{group.section}</div>
              {group.items.map((item) => (
                <NavLink
                  key={item.label}
                  to={item.to}
                  end={item.end}
                  className={({ isActive }) =>
                    isActive ? 'side-link active' : 'side-link'
                  }
                >
                  <item.icon size={16} className="side-link-icon" />
                  <span className="side-link-label">{item.label}</span>
                  {item.to === 'memory' && memoryBadge !== null && (
                    <span
                      className="side-link-badge"
                      title={`${memoryBadge} memory captures in this case`}
                    >
                      {memoryBadge}
                    </span>
                  )}
                </NavLink>
              ))}
            </div>
          ))}
        </nav>
        <IngestButton caseId={caseId} />
        <ProcessingPanelSlot />
        <div className="tree-section">
          <NavigatorPanel caseId={caseId} />
        </div>
        <div className="sidebar-foot">
          {authMode === 'disabled' ? (
            // Reachable without a session only because the server runs with
            // SEANCE_AUTH_ENABLED=false, which attributes every action to the
            // local operator. Name that, rather than leaving the blank where a
            // username goes and a Sign out that ends nothing.
            <span className="mono" title="Started with SEANCE_AUTH_ENABLED=false">
              no sign-in required
            </span>
          ) : (
            <>
              <span className="mono">{session?.username}</span>
              <button className="link-button" onClick={logout}>
                Sign out
              </button>
            </>
          )}
        </div>
      </aside>
      <div className="main-column">
        {/* The persistent time window (§1.1). Above the scrolling content and
            inside the main column, so it stays on screen on every case page
            and names what is narrowing the view the examiner is reading. */}
        <TimeWindowBar caseId={caseId} />
        <main
          className="main-content"
          ref={mainScroll.ref}
          onScroll={mainScroll.onScroll}
        >
          {/* Each case page is a lazy chunk; only the content area shows the
              fallback while it loads, keeping the shell in place.

              Keyed on the case so that changing `:caseId` REMOUNTS the routed
              page instead of re-rendering it in place. Client-side navigation
              between two cases keeps this layout mounted, and every page below
              is a long-lived component holding local state that names things in
              one case: a selected row, a typed-but-unsubmitted filter, an open
              dialog's target id. Re-rendering in place carries all of it into
              the next case, where artifact and set UUIDs are per-case and a
              carried id can still hit a real row — the wrong one. Remounting
              here removes the whole class at the boundary; the per-page
              `useEntityScopedState` guards remain, because they also cover the
              ids that change WITHOUT this key moving (`:artifactId`, the memory
              `?image=`). */}
          <Suspense key={caseId} fallback={<div className="loading">Loading…</div>}>
            <Outlet />
          </Suspense>
        </main>
        <CustodyStripSlot
          examiner={kase?.examiner_name ?? session?.username ?? null}
          reference={kase?.reference_number ?? null}
        />
      </div>
      </div>
      </TimeWindowProvider>
      </PivotProvider>
    </ProcessingProvider>
  )
}

// Context-connected slots for the processing state. They live below the
// ProcessingProvider and read the live state via useProcessing, so an SSE
// update re-renders only these small components -- not the routed page in the
// <Outlet/>, whose element the provider passes straight through.
function ProcessingPanelSlot() {
  return <ProcessingPanel state={useProcessing()} />
}

function CustodyStripSlot({
  examiner,
  reference,
}: {
  examiner: string | null
  reference: string | null
}) {
  return (
    <CustodyStrip
      examiner={examiner}
      reference={reference}
      processing={useProcessing()}
    />
  )
}
