import { useEffect, useMemo, useRef, useState } from "react";
import { useThemeVersion } from "../../themes/useThemeVersion";
import type { CommNode, CommEdge } from "./types";

/**
 * The graph's ink, read from the applied palette.
 *
 * A canvas is where the contrast guard cannot follow: it measures token-valued
 * `color:` declarations in stylesheets, and this drawing has none. So these
 * were literals chosen for the palette the product shipped with — near-white
 * labels on a charcoal ground — and under any light palette the labels were
 * white on white. Reading the tokens makes the graph follow whatever is
 * applied, and puts its colours back under the same gate as everything else.
 *
 * `read` is `getComputedStyle(...).getPropertyValue` in the browser and a stub
 * in the tests. It returns an empty string for a property that is not set, and
 * drawing with an empty string paints nothing at all — a node that silently
 * vanishes — so every value has a fallback.
 */
export function graphColors(read: (name: string) => string) {
  const token = (name: string, fallback: string) =>
    read(name).trim() || fallback;
  const text0 = token("--text-0", "#16181d");
  const accent = token("--accent", "#4e3ed4");
  return {
    /** One colour per kind of participant: the owner, a messaging peer, an address. */
    kind: {
      self: accent,
      contact: token("--info", "#1c599d"),
      email: token("--ok", "#1a6539"),
    } as Record<string, string>,
    /** A participant whose kind this build has no colour for. */
    kindOther: token("--text-2", "#545964"),
    /** The label of a node the examiner is reading. */
    label: text0,
    /** The label of every other node: present, and not competing. */
    labelQuiet: token("--text-2", "#545964"),
    /** The ring on the selected node, and on the hovered one. */
    selected: accent,
    hovered: token("--border-1", "#bcc3ce"),
    /** Edges: the ones touching the hovered node, and the rest. */
    edgeActive: accent,
    edge: token("--border-1", "#bcc3ce"),
  };
}

interface P {
  x: number;
  y: number;
  vx: number;
  vy: number;
}

function truncate(s: string, n: number): string {
  return s.length > n ? s.slice(0, n - 1) + "…" : s;
}

/**
 * Fit a settled layout into the panel it is drawn in: the scale and offsets
 * that map layout coordinates to canvas pixels (UI-027).
 *
 * Exported for its own test. The invariants are the whole point and they are
 * cheap to state: every node lands inside the frame with room for its circle
 * and its label, the aspect ratio is preserved (one scale, not two), and a
 * graph small enough to be magnified is magnified only so far.
 */
export function fitView(
  pos: { x: number; y: number }[],
  w: number,
  h: number,
): { s: number; tx: number; ty: number } {
  if (pos.length === 0) return { s: 1, tx: 0, ty: 0 };
  let minX = Infinity;
  let maxX = -Infinity;
  let minY = Infinity;
  let maxY = -Infinity;
  for (const p of pos) {
    if (p.x < minX) minX = p.x;
    if (p.x > maxX) maxX = p.x;
    if (p.y < minY) minY = p.y;
    if (p.y > maxY) maxY = p.y;
  }
  // Room for the biggest node (radius 15 at most) and a label beside it.
  const pad = 45;
  const spanX = Math.max(1, maxX - minX);
  const spanY = Math.max(1, maxY - minY);
  const s = Math.min(
    Math.max(0.05, (w - 2 * pad) / spanX),
    Math.max(0.05, (h - 2 * pad) / spanY),
    2.5,
  );
  return {
    s,
    tx: (w - s * spanX) / 2 - s * minX,
    ty: (h - s * spanY) / 2 - s * minY,
  };
}

/**
 * Canvas force-directed communication graph. Runs a cooling
 * Fruchterman-Reingold-style layout, then stays interactive: hover to
 * highlight a participant and their links, click to select. Honors
 * prefers-reduced-motion by settling the layout in one pass.
 */
export function ForceGraph({
  nodes,
  edges,
  selectedId,
  onSelect,
}: {
  nodes: CommNode[];
  edges: CommEdge[];
  selectedId: string | null;
  onSelect: (n: CommNode | null) => void;
}) {
  const wrapRef = useRef<HTMLDivElement>(null);
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const posRef = useRef<P[]>([]);
  const rafRef = useRef<number | null>(null);
  const drawRef = useRef<() => void>(() => {});
  const [size, setSize] = useState({ w: 800, h: 560 });
  const [hoverId, setHoverId] = useState<string | null>(null);

  const index = useMemo(() => {
    const m = new Map<string, number>();
    nodes.forEach((n, i) => m.set(n.id, i));
    return m;
  }, [nodes]);

  const maxWeight = useMemo(
    () => Math.max(1, ...nodes.map((n) => n.weight)),
    [nodes],
  );
  const maxEdge = useMemo(
    () => Math.max(1, ...edges.map((e) => e.weight)),
    [edges],
  );
  // Adjacency for the highlighted node, so hover dims everything unrelated.
  const neighbors = useMemo(() => {
    const m = new Map<string, Set<string>>();
    for (const e of edges) {
      if (!m.has(e.source)) m.set(e.source, new Set());
      if (!m.has(e.target)) m.set(e.target, new Set());
      m.get(e.source)!.add(e.target);
      m.get(e.target)!.add(e.source);
    }
    return m;
  }, [edges]);

  const radius = (n: CommNode) => 4 + 11 * Math.sqrt(n.weight / maxWeight);

  /**
   * The mapping from layout coordinates to canvas pixels, recomputed on every
   * draw and shared with hit-testing (UI-027).
   *
   * The simulation is a force layout, and a force layout's equilibrium is set
   * by its own constants, not by the size of the panel it is shown in: for this
   * one the repulsion and attraction coefficients put the resting separation of
   * two linked nodes at several times the frame's width. The positions used to
   * be clamped into the frame instead, which does not scale a graph — it piles
   * every node onto the border and throws away the structure between them. A
   * twelve-participant case drew as a rectangle of dots with the labels
   * colliding in one corner.
   *
   * So the layout runs unclamped, and the drawing fits what it produced: the
   * bounding box of the nodes is scaled and centred into the panel, with room
   * for the largest node and its label. Scale is capped so a two-node graph is
   * not magnified into two circles the size of the panel.
   */
  const viewRef = useRef({ s: 1, tx: 0, ty: 0 });

  // Keep a fresh draw closure (reads current hover/selection) in a ref so the
  // animation loop and hover redraws both use up-to-date highlight state.
  drawRef.current = () => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;
    const dpr = window.devicePixelRatio || 1;
    const { w, h } = size;
    if (canvas.width !== w * dpr || canvas.height !== h * dpr) {
      canvas.width = w * dpr;
      canvas.height = h * dpr;
    }
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, w, h);
    // Read once per frame rather than per node: the palette cannot change
    // mid-frame, and `getComputedStyle` is not free.
    const style = getComputedStyle(document.documentElement);
    const colors = graphColors((name) => style.getPropertyValue(name));
    const pos = posRef.current;
    const hi = hoverId;
    const nbr = hi ? neighbors.get(hi) : null;
    // One transform for this frame, kept for the pointer to use as well: a
    // graph that is drawn somewhere other than where it is clicked is worse
    // than one that is drawn badly.
    const view = fitView(pos, w, h);
    viewRef.current = view;
    const X = (p: P) => p.x * view.s + view.tx;
    const Y = (p: P) => p.y * view.s + view.ty;

    // edges
    for (const e of edges) {
      const si = index.get(e.source);
      const ti = index.get(e.target);
      if (si == null || ti == null) continue;
      const a = pos[si];
      const b = pos[ti];
      if (!a || !b) continue;
      const active = hi && (e.source === hi || e.target === hi);
      // The edge's weight is in its width and its presence is in its alpha:
      // the ink is the palette's, and only how loudly it is drawn changes.
      ctx.globalAlpha = active ? 0.5 : hi ? 0.12 : 0.34;
      ctx.strokeStyle = active ? colors.edgeActive : colors.edge;
      ctx.lineWidth = active ? 1.6 : 0.4 + 1.8 * (e.weight / maxEdge);
      ctx.beginPath();
      ctx.moveTo(X(a), Y(a));
      ctx.lineTo(X(b), Y(b));
      ctx.stroke();
    }
    ctx.globalAlpha = 1;

    // nodes
    ctx.textBaseline = "middle";
    for (let i = 0; i < nodes.length; i++) {
      const nd = nodes[i];
      const p = pos[i];
      if (!p) continue;
      const r = radius(nd);
      const isHover = nd.id === hi;
      const isSel = nd.id === selectedId;
      const related = !hi || isHover || (nbr ? nbr.has(nd.id) : false);
      ctx.globalAlpha = related ? 1 : 0.22;
      const px = X(p);
      const py = Y(p);
      ctx.beginPath();
      ctx.arc(px, py, r, 0, Math.PI * 2);
      ctx.fillStyle = colors.kind[nd.kind] || colors.kindOther;
      ctx.fill();
      if (isSel || isHover) {
        ctx.lineWidth = 2;
        ctx.strokeStyle = isSel ? colors.selected : colors.hovered;
        ctx.stroke();
      }
      if (r > 9 || isHover || isSel) {
        ctx.globalAlpha = related ? 1 : 0.22;
        ctx.fillStyle = isHover || isSel ? colors.label : colors.labelQuiet;
        ctx.font = '11px ui-monospace, "IBM Plex Mono", monospace';
        // Keep the label on-canvas. A node near the right edge would otherwise
        // draw its label off the right of the frame, where it is invisible —
        // which on a small graph (every node near an edge) means an unlabelled
        // participant, useless in a comms graph. When the label would overflow
        // the right, draw it to the LEFT of the node instead.
        const label = truncate(nd.label, 24);
        const labelW = ctx.measureText(label).width;
        const rightX = px + r + 4;
        const leftX = px - r - 4 - labelW;
        if (rightX + labelW > size.w - 2 && leftX >= 2) {
          // Flipping left keeps it in frame.
          ctx.fillText(label, leftX, py);
        } else {
          // Neither side fits cleanly (a narrow panel, or a node near both
          // edges): clamp into the frame rather than draw it where it cannot
          // be seen. An unlabelled participant is useless in a comms graph.
          ctx.fillText(
            label,
            Math.max(2, Math.min(rightX, size.w - 2 - labelW)),
            py,
          );
        }
      }
      ctx.globalAlpha = 1;
    }
  };

  // Observe container size.
  useEffect(() => {
    const el = wrapRef.current;
    if (!el) return;
    const ro = new ResizeObserver(() => {
      const r = el.getBoundingClientRect();
      setSize({ w: Math.max(320, r.width), h: Math.max(380, r.height) });
    });
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  // Build + run the simulation whenever the graph or size changes.
  useEffect(() => {
    const { w, h } = size;
    const n = nodes.length;
    if (n === 0) {
      const c = canvasRef.current?.getContext("2d");
      c?.clearRect(0, 0, w, h);
      return;
    }
    const pos: P[] = nodes.map((_, i) => {
      const a = (i / n) * Math.PI * 2;
      const jitter = 0.55 + 0.45 * (((i * 97) % 100) / 100);
      const rr = Math.min(w, h) * 0.34 * jitter;
      return {
        x: w / 2 + Math.cos(a) * rr,
        y: h / 2 + Math.sin(a) * rr,
        vx: 0,
        vy: 0,
      };
    });
    posRef.current = pos;

    const eidx = edges
      .map((e) => ({
        s: index.get(e.source),
        t: index.get(e.target),
        w: e.weight,
      }))
      .filter(
        (e): e is { s: number; t: number; w: number } =>
          e.s != null && e.t != null,
      );
    // Ideal edge length. `sqrt(area/n)` is the usual choice, but for a very
    // small graph it exceeds the frame — two nodes get an ideal separation
    // wider than the panel, so repulsion flings them to opposite edges and the
    // graph reads as two dots on a hairline. Cap it to a fraction of the
    // shorter side so a small graph settles near the centre with room for
    // labels on both sides.
    const k = Math.min(Math.sqrt((w * h) / n) * 0.78, Math.min(w, h) * 0.26);
    const reduced = window.matchMedia?.(
      "(prefers-reduced-motion: reduce)",
    ).matches;
    let alpha = 1;

    const tick = () => {
      for (let i = 0; i < n; i++) {
        const pi = pos[i];
        for (let j = i + 1; j < n; j++) {
          const pj = pos[j];
          let dx = pi.x - pj.x;
          let dy = pi.y - pj.y;
          let d2 = dx * dx + dy * dy;
          if (d2 < 0.01) {
            dx = (i % 7) - 3;
            dy = (j % 7) - 3;
            d2 = dx * dx + dy * dy + 0.01;
          }
          const d = Math.sqrt(d2);
          const f = ((k * k) / d) * 0.9;
          const fx = (dx / d) * f;
          const fy = (dy / d) * f;
          pi.vx += fx;
          pi.vy += fy;
          pj.vx -= fx;
          pj.vy -= fy;
        }
      }
      for (const e of eidx) {
        const pi = pos[e.s];
        const pj = pos[e.t];
        const dx = pi.x - pj.x;
        const dy = pi.y - pj.y;
        const d = Math.sqrt(dx * dx + dy * dy) || 0.01;
        const wf = 1 + Math.log2(1 + e.w);
        const f = ((d * d) / k) * 0.006 * wf;
        const fx = (dx / d) * f;
        const fy = (dy / d) * f;
        pi.vx -= fx;
        pi.vy -= fy;
        pj.vx += fx;
        pj.vy += fy;
      }
      for (let i = 0; i < n; i++) {
        const p = pos[i];
        p.vx += (w / 2 - p.x) * 0.0022;
        p.vy += (h / 2 - p.y) * 0.0022;
        p.vx *= 0.85;
        p.vy *= 0.85;
        const mv = 14 * alpha + 1;
        p.vx = Math.max(-mv, Math.min(mv, p.vx));
        p.vy = Math.max(-mv, Math.min(mv, p.vy));
        // No clamp to the frame: the centring force above is what keeps the
        // layout bounded, and the drawing fits whatever box it settles into
        // (`fitView`). Clamping here was what turned a graph into a rectangle
        // of dots on the border (UI-027).
        p.x += p.vx * alpha;
        p.y += p.vy * alpha;
      }
      alpha *= 0.985;
    };

    if (reduced) {
      for (let i = 0; i < 320; i++) tick();
      drawRef.current();
      return;
    }
    let frames = 0;
    const loop = () => {
      tick();
      drawRef.current();
      frames++;
      if (alpha > 0.03 && frames < 640) {
        rafRef.current = requestAnimationFrame(loop);
      } else {
        rafRef.current = null;
      }
    };
    rafRef.current = requestAnimationFrame(loop);
    return () => {
      if (rafRef.current) cancelAnimationFrame(rafRef.current);
      rafRef.current = null;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [nodes, edges, size, index]);

  // Redraw on hover/selection change once the layout has settled.
  // A canvas does not re-paint when a custom property changes, so the graph
  // would keep the previous palette's ink until something else happened to
  // redraw it. `useThemeVersion` re-renders on a theme change and this redraws.
  const themeVersion = useThemeVersion();

  useEffect(() => {
    if (rafRef.current == null) drawRef.current();
  }, [hoverId, selectedId, themeVersion]);

  // Pointer hit-testing against node positions.
  function nodeAt(cssX: number, cssY: number): CommNode | null {
    const pos = posRef.current;
    const { s, tx, ty } = viewRef.current;
    for (let i = nodes.length - 1; i >= 0; i--) {
      const p = pos[i];
      if (!p) continue;
      const r = radius(nodes[i]) + 3;
      // Compared in canvas pixels, where the radius is measured, so the target
      // stays the size it looks whatever the fit scale is.
      const dx = cssX - (p.x * s + tx);
      const dy = cssY - (p.y * s + ty);
      if (dx * dx + dy * dy <= r * r) return nodes[i];
    }
    return null;
  }

  return (
    <div ref={wrapRef} className="cx-canvas-wrap">
      <canvas
        ref={canvasRef}
        style={{
          width: size.w,
          height: size.h,
          cursor: hoverId ? "pointer" : "default",
        }}
        onMouseMove={(e) => {
          const rect = e.currentTarget.getBoundingClientRect();
          const hit = nodeAt(e.clientX - rect.left, e.clientY - rect.top);
          setHoverId(hit?.id ?? null);
        }}
        onMouseLeave={() => setHoverId(null)}
        onClick={(e) => {
          const rect = e.currentTarget.getBoundingClientRect();
          const hit = nodeAt(e.clientX - rect.left, e.clientY - rect.top);
          onSelect(hit);
        }}
      />
    </div>
  );
}
