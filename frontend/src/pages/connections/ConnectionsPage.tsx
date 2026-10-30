import { useQuery } from "@tanstack/react-query";
import { useNavigate, useParams } from "react-router-dom";
import { useEntityScopedState } from "../../lib/useEntityScopedState";
import { usePivot } from "../../app/PivotContext";
import { getCommunicationGraph } from "./api";
import { ForceGraph } from "./ForceGraph";
import type { CommNode } from "./types";
import { formatCount } from "../../lib/format";
import "./connections.css";

const KIND_LABEL: Record<string, string> = {
  self: "Device owner",
  contact: "Messaging contact",
  email: "Email address",
};

export function ConnectionsPage() {
  const { caseId = "" } = useParams();
  const navigate = useNavigate();
  const { openPivot } = usePivot();
  // The page stays mounted across a `:caseId` change, so a node picked in case
  // A would keep its detail panel open under case B — presenting one case's
  // participant, message count and "search records for this participant" button
  // as if it belonged to the other (B2-018).
  const [selected, setSelected] = useEntityScopedState<CommNode | null>(
    caseId,
    null,
  );

  const query = useQuery({
    queryKey: ["connections", caseId],
    queryFn: () => getCommunicationGraph(caseId),
    enabled: caseId !== "",
  });

  const graph = query.data;

  return (
    <div className="cx-page">
      <div className="cx-head">
        <div>
          <h1 className="page-title">Connections</h1>
          <p className="cx-sub">
            Communication network across parsed messaging and email — who
            contacted whom, weighted by volume.
          </p>
        </div>
        {graph && graph.nodes.length > 0 && (
          <div className="cx-stats mono">
            <span>
              <b>{formatCount(graph.total_participants)}</b> participants
            </span>
            <span>
              <b>{formatCount(graph.edges.length)}</b> links
            </span>
          </div>
        )}
      </div>

      {query.isPending ? (
        <div className="loading">Building communication network…</div>
      ) : query.isError ? (
        <div className="error-note">
          Failed to build the network: {query.error.message}
        </div>
      ) : !graph || graph.nodes.length === 0 ? (
        <div className="empty-state">
          <h3>No communication records</h3>
          <p>
            Ingest messaging (iMessage, WhatsApp, Android SMS) or email evidence
            to map the communication network.
          </p>
        </div>
      ) : (
        <div className="cx-body">
          <div className="cx-graph panel">
            {/* The key and the drawing must be the same three colours. They
                were two sets of literals — one here, one in the canvas — and a
                legend that names a colour the graph does not draw is worse than
                no legend. Both read the palette's own tokens now. */}
            <div className="cx-legend mono">
              <span>
                <i className="cx-dot cx-dot-self" /> Device owner
              </span>
              <span>
                <i className="cx-dot cx-dot-contact" /> Contact
              </span>
              <span>
                <i className="cx-dot cx-dot-email" /> Email
              </span>
              <span className="cx-hint">
                node size = volume · click a participant
              </span>
            </div>
            <ForceGraph
              nodes={graph.nodes}
              edges={graph.edges}
              selectedId={selected?.id ?? null}
              onSelect={setSelected}
            />
            {graph.truncated && (
              <div className="cx-trunc mono">
                Showing the {graph.nodes.length} most-connected of{" "}
                {formatCount(graph.total_participants)} participants.
              </div>
            )}
          </div>

          {selected && (
            <ParticipantDetail
              caseId={caseId}
              node={selected}
              onClose={() => setSelected(null)}
              onPivot={openPivot}
              onSearch={(label) =>
                navigate(
                  `/cases/${caseId}/search?q=${encodeURIComponent(label)}`,
                )
              }
            />
          )}
        </div>
      )}
    </div>
  );
}

/**
 * The panel for one selected participant.
 *
 * Its own component so it can be tested directly: selection happens through a
 * canvas click the test environment cannot make, and the pivot this panel
 * offers (§5.1) is the point of the screen rather than decoration.
 */
export function ParticipantDetail({
  node,
  onClose,
  onPivot,
  onSearch,
}: {
  caseId: string;
  node: CommNode;
  onClose: () => void;
  onPivot: (value: string) => void;
  onSearch: (label: string) => void;
}) {
  return (
    <aside className="cx-detail panel">
      <button className="cx-close" aria-label="Close" onClick={onClose}>
        ×
      </button>
      <div className="cx-detail-kind mono">
        {KIND_LABEL[node.kind] ?? node.kind}
      </div>
      <div className="cx-detail-label">{node.label}</div>
      {node.label !== node.id && (
        <div className="cx-detail-id mono">{node.id}</div>
      )}
      <div className="cx-detail-metric">
        <span className="mono cx-metric-n">{formatCount(node.weight)}</span>
        <span className="cx-metric-l">messages / emails involved</span>
      </div>
      {node.kind !== "self" && (
        <>
          {/* The pivot first: it answers "what else in this case touches this
              participant", grouped by record kind, without leaving the graph
              (§5.1). Search stays beside it for the full hit list — the two
              answer different questions, so neither replaces the other. The
              pivot is on the node's `id`, the address the graph was built
              from, rather than its display label. */}
          <button
            className="btn btn-primary cx-search"
            onClick={() => onPivot(node.id)}
          >
            Pivot on this participant
          </button>
          <button className="btn cx-search" onClick={() => onSearch(node.label)}>
            Search records for this participant
          </button>
        </>
      )}
    </aside>
  );
}
