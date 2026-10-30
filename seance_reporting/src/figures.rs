//! The visualisations baked into generated reports (ROADMAP §2.10).
//!
//! Two figures, both computed from the same [`ReportData`] every renderer
//! reads: events over time, bucketed, from the listed timeline; and the
//! communications network, participants as nodes and exchanges as weighted
//! links. Each is laid out here into a small shape model ([`Figure`]) that the
//! HTML and DOCX renderers write out as SVG and the PDF renderer draws with
//! its own primitives, so the three documents show the same picture.
//!
//! Three rules hold for every figure. Its layout is a pure function of the
//! data — sorted inputs, no randomness, fixed-precision numbers — so two
//! renders of the same case are byte-identical. It states on its own face what
//! it was computed from and what it leaves out (the bucket size, the counts,
//! the caps it hit), because a figure is the part of a report most likely to
//! be lifted out and shown on its own. And nothing is drawn that the data does
//! not hold: no parseable timestamps, or no participants, means no figure.
//!
//! [`ReportData`]: crate::report::ReportData

use crate::report::{ReportCommunicationGraph, ReportTimelineEvent};
use chrono::{DateTime, NaiveDate, NaiveDateTime, Utc};

/// Fill for the single timeline series.
const SERIES_BLUE: &str = "#2a78d6";
/// Node fills by kind. The three are the first three categorical slots of the
/// report's palette, which validate against each other for colour-vision
/// deficiency; the legend names each kind in words as well.
const KIND_SELF: &str = "#eb6834";
const KIND_CONTACT: &str = "#2a78d6";
const KIND_EMAIL: &str = "#1baf7a";
const KIND_OTHER: &str = "#8a94a0";
const INK: &str = "#222222";
const INK_MUTED: &str = "#556677";
const INK_ALERT: &str = "#7a1620";
const GRID: &str = "#d7dde3";
const EDGE: &str = "#8a94a0";
const SURFACE: &str = "#ffffff";

/// The fewest bars a timeline figure aims for. The bucket width chosen is the
/// coarsest on the ladder that still yields at least this many, so a span is
/// never flattened into a handful of bars when a finer width would show its
/// shape. A span shorter than eleven hours gets fewer, on the finest width.
const MIN_BUCKETS: i64 = 12;
/// The most bars a timeline figure can carry below the ladder's top rung.
/// A width w is chosen only when the next coarser width W would give at
/// most `MIN_BUCKETS - 1` bars, i.e. both ends lie within that many
/// consecutive W-buckets, so the span is at most (MIN_BUCKETS - 1) x W less
/// one second; the ends can each straddle a w-edge, so the count is at most
/// floor(span / w) + 2. The widest step on the ladder is 30 days to 365
/// days (12.17x), which gives floor((11 x 365 d - 1 s) / 30 d) + 2 = 135;
/// every other step is 10x or less. The figure states its own bucket count
/// on its face regardless. On the top rung (3650 days) there is no coarser
/// width, so a span of more than 1,340 years is not bounded by this; a unit
/// test derives the number from the ladder and an integration test reaches
/// it, rather than trusting this comment.
pub const MAX_BUCKETS: usize = 135;
/// The most participants a communications figure draws. Beyond it the ring
/// becomes a smear; the rest are named in the table beside the figure and the
/// caption says how many there were.
pub const MAX_DRAWN_PARTICIPANTS: usize = 40;
/// Above this many participants the figure labels each with its rank in the
/// participant table rather than its name: forty names around a ring
/// overwrite one another, and an unreadable label is worse than a number
/// that the table beside the figure resolves.
pub const MAX_NAMED_PARTICIPANTS: usize = 16;
/// Above this many links the figure stops printing a count on each link;
/// the widths still scale with the count and the Links table carries the
/// numbers.
pub const MAX_LABELLED_LINKS: usize = 24;

/// One drawable shape. Coordinates are in figure units, origin top-left.
#[derive(Debug, Clone, PartialEq)]
pub enum Shape {
    Rect {
        x: f64,
        y: f64,
        w: f64,
        h: f64,
        fill: String,
        stroke: Option<String>,
    },
    Line {
        x1: f64,
        y1: f64,
        x2: f64,
        y2: f64,
        stroke: String,
        width: f64,
    },
    Circle {
        cx: f64,
        cy: f64,
        r: f64,
        fill: String,
        stroke: String,
    },
    Text {
        x: f64,
        y: f64,
        text: String,
        size: f64,
        /// `start`, `middle` or `end`, as SVG spells them.
        anchor: String,
        bold: bool,
        fill: String,
    },
}

/// A laid-out figure: a canvas and the shapes on it, in paint order.
#[derive(Debug, Clone, PartialEq)]
pub struct Figure {
    pub width: f64,
    pub height: f64,
    pub shapes: Vec<Shape>,
}

impl Figure {
    pub fn new(width: f64, height: f64) -> Self {
        Self {
            width,
            height,
            shapes: Vec::new(),
        }
    }

    pub fn rect(&mut self, x: f64, y: f64, w: f64, h: f64, fill: &str, stroke: Option<&str>) {
        self.shapes.push(Shape::Rect {
            x,
            y,
            w,
            h,
            fill: fill.to_string(),
            stroke: stroke.map(str::to_string),
        });
    }

    pub fn line(&mut self, x1: f64, y1: f64, x2: f64, y2: f64, stroke: &str, width: f64) {
        self.shapes.push(Shape::Line {
            x1,
            y1,
            x2,
            y2,
            stroke: stroke.to_string(),
            width,
        });
    }

    pub fn circle(&mut self, cx: f64, cy: f64, r: f64, fill: &str, stroke: &str) {
        self.shapes.push(Shape::Circle {
            cx,
            cy,
            r,
            fill: fill.to_string(),
            stroke: stroke.to_string(),
        });
    }

    #[allow(clippy::too_many_arguments)]
    pub fn text(
        &mut self,
        x: f64,
        y: f64,
        text: &str,
        size: f64,
        anchor: &str,
        bold: bool,
        fill: &str,
    ) {
        self.shapes.push(Shape::Text {
            x,
            y,
            text: text.to_string(),
            size,
            anchor: anchor.to_string(),
            bold,
            fill: fill.to_string(),
        });
    }

    /// The figure as a standalone SVG document.
    ///
    /// Every number is written with one decimal place and every string goes
    /// through the XML escaper, so the output is a deterministic function of
    /// the shape list and cannot be broken by a participant's label.
    pub fn to_svg(&self) -> String {
        let mut s = String::with_capacity(4096);
        s.push_str(&format!(
            "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"{w}\" height=\"{h}\" \
             viewBox=\"0 0 {w} {h}\" font-family=\"Helvetica, Arial, sans-serif\">\n",
            w = n(self.width),
            h = n(self.height)
        ));
        s.push_str(&format!(
            "<rect x=\"0\" y=\"0\" width=\"{}\" height=\"{}\" fill=\"{}\"/>\n",
            n(self.width),
            n(self.height),
            SURFACE
        ));
        for shape in &self.shapes {
            match shape {
                Shape::Rect {
                    x,
                    y,
                    w,
                    h,
                    fill,
                    stroke,
                } => {
                    s.push_str(&format!(
                        "<rect x=\"{}\" y=\"{}\" width=\"{}\" height=\"{}\" fill=\"{}\"",
                        n(*x),
                        n(*y),
                        n(*w),
                        n(*h),
                        xml(fill)
                    ));
                    if let Some(stroke) = stroke {
                        s.push_str(&format!(" stroke=\"{}\" stroke-width=\"1\"", xml(stroke)));
                    }
                    s.push_str("/>\n");
                }
                Shape::Line {
                    x1,
                    y1,
                    x2,
                    y2,
                    stroke,
                    width,
                } => s.push_str(&format!(
                    "<line x1=\"{}\" y1=\"{}\" x2=\"{}\" y2=\"{}\" stroke=\"{}\" stroke-width=\"{}\"/>\n",
                    n(*x1),
                    n(*y1),
                    n(*x2),
                    n(*y2),
                    xml(stroke),
                    n(*width)
                )),
                Shape::Circle {
                    cx,
                    cy,
                    r,
                    fill,
                    stroke,
                } => s.push_str(&format!(
                    "<circle cx=\"{}\" cy=\"{}\" r=\"{}\" fill=\"{}\" stroke=\"{}\" stroke-width=\"2\"/>\n",
                    n(*cx),
                    n(*cy),
                    n(*r),
                    xml(fill),
                    xml(stroke)
                )),
                Shape::Text {
                    x,
                    y,
                    text,
                    size,
                    anchor,
                    bold,
                    fill,
                } => s.push_str(&format!(
                    "<text x=\"{}\" y=\"{}\" font-size=\"{}\" text-anchor=\"{}\"{} fill=\"{}\">{}</text>\n",
                    n(*x),
                    n(*y),
                    n(*size),
                    xml(anchor),
                    if *bold { " font-weight=\"bold\"" } else { "" },
                    xml(fill),
                    xml(text)
                )),
            }
        }
        s.push_str("</svg>\n");
        s
    }
}

/// Fixed one-decimal formatting, so a coordinate never depends on the
/// platform's shortest-representation float printing.
fn n(v: f64) -> String {
    let s = format!("{v:.1}");
    if s == "-0.0" {
        "0.0".to_string()
    } else {
        s
    }
}

fn xml(s: &str) -> String {
    crate::report::xml_escape(s)
}

// ---------------------------------------------------------------------------
// Timeline
// ---------------------------------------------------------------------------

/// One bar of the timeline histogram.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct TimelineBucket {
    /// Bucket start, RFC 3339 UTC.
    pub start: String,
    /// Bucket start as Unix seconds.
    pub start_unix: i64,
    pub count: i64,
}

/// Events over time, bucketed.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct TimelineFigure {
    /// Contiguous from the first occupied bucket to the last, zero-filled.
    pub buckets: Vec<TimelineBucket>,
    pub bucket_seconds: i64,
    /// The bucket width in words, e.g. `1 day`.
    pub bucket_label: String,
    /// Events that fell into a bucket.
    pub plotted: usize,
    /// Listed events whose timestamp could not be parsed. Stated on the
    /// figure: an event the figure cannot place is still an event.
    pub unparseable: usize,
    /// Events the report lists (the bounded slice).
    pub listed: usize,
    /// Events the case holds, which may exceed `listed`.
    pub case_total: i64,
}

/// Bucket widths in ascending order. Fixed widths aligned to the Unix epoch,
/// not calendar months or years: an epoch-aligned 30-day bucket is stated as
/// exactly that, where a "month" would claim a calendar the data was never
/// cut on.
const BUCKET_LADDER: [(i64, &str); 7] = [
    (3_600, "1 hour"),
    (6 * 3_600, "6 hours"),
    (86_400, "1 day"),
    (7 * 86_400, "7 days"),
    (30 * 86_400, "30 days"),
    (365 * 86_400, "365 days"),
    (3_650 * 86_400, "3650 days"),
];

/// Parse a report timestamp to Unix seconds.
///
/// The API writes RFC 3339; the other forms are what the report's own
/// helpers and older fixtures produce. Anything else is unparseable and is
/// counted as such rather than guessed at.
fn parse_timestamp(s: &str) -> Option<i64> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
        return Some(dt.timestamp());
    }
    for fmt in [
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S UTC",
    ] {
        if let Ok(dt) = NaiveDateTime::parse_from_str(s, fmt) {
            return Some(dt.and_utc().timestamp());
        }
    }
    NaiveDate::parse_from_str(s, "%Y-%m-%d")
        .ok()
        .and_then(|d| d.and_hms_opt(0, 0, 0))
        .map(|dt| dt.and_utc().timestamp())
}

fn rfc3339_utc(unix: i64) -> String {
    DateTime::<Utc>::from_timestamp(unix, 0)
        .map(|dt| dt.format("%Y-%m-%dT%H:%M:%SZ").to_string())
        .unwrap_or_else(|| format!("unix:{unix}"))
}

fn axis_date(unix: i64, bucket_seconds: i64) -> String {
    let fmt = if bucket_seconds >= 86_400 {
        "%Y-%m-%d"
    } else {
        "%Y-%m-%d %H:%M"
    };
    DateTime::<Utc>::from_timestamp(unix, 0)
        .map(|dt| dt.format(fmt).to_string())
        .unwrap_or_else(|| format!("unix:{unix}"))
}

/// Bucket the listed timeline. `None` when no listed event has a parseable
/// timestamp — there is nothing to plot, and an empty chart would read as a
/// finding.
pub fn timeline_figure(events: &[ReportTimelineEvent], case_total: i64) -> Option<TimelineFigure> {
    let mut stamps: Vec<i64> = Vec::with_capacity(events.len());
    let mut unparseable = 0usize;
    for e in events {
        match parse_timestamp(&e.timestamp) {
            Some(t) => stamps.push(t),
            None => unparseable += 1,
        }
    }
    if stamps.is_empty() {
        return None;
    }
    stamps.sort_unstable();
    let first = stamps[0];
    let last = stamps[stamps.len() - 1];

    let (bucket_seconds, bucket_label) = BUCKET_LADDER
        .iter()
        .rev()
        .copied()
        .find(|(w, _)| last.div_euclid(*w) - first.div_euclid(*w) + 1 >= MIN_BUCKETS)
        .unwrap_or(BUCKET_LADDER[0]);

    let first_idx = first.div_euclid(bucket_seconds);
    let last_idx = last.div_euclid(bucket_seconds);
    let mut counts = vec![0i64; (last_idx - first_idx + 1) as usize];
    for t in &stamps {
        counts[(t.div_euclid(bucket_seconds) - first_idx) as usize] += 1;
    }
    let buckets = counts
        .into_iter()
        .enumerate()
        .map(|(i, count)| {
            let start_unix = (first_idx + i as i64) * bucket_seconds;
            TimelineBucket {
                start: rfc3339_utc(start_unix),
                start_unix,
                count,
            }
        })
        .collect();

    Some(TimelineFigure {
        buckets,
        bucket_seconds,
        bucket_label: bucket_label.to_string(),
        plotted: stamps.len(),
        unparseable,
        listed: events.len(),
        case_total,
    })
}

impl TimelineFigure {
    /// Events the case holds beyond the listed slice, when it was capped.
    pub fn not_listed(&self) -> i64 {
        (self.case_total - self.listed as i64).max(0)
    }

    fn span_words(&self) -> String {
        let from = self.buckets.first().map(|b| b.start_unix).unwrap_or(0);
        let to = self
            .buckets
            .last()
            .map(|b| b.start_unix + self.bucket_seconds - 1)
            .unwrap_or(0);
        format!(
            "{} to {}",
            axis_date(from, self.bucket_seconds),
            axis_date(to, self.bucket_seconds)
        )
    }

    /// The caption: what the figure was computed from and what it omits.
    pub fn caption(&self) -> String {
        let mut c = format!(
            "Events over time, computed from the {} timeline event(s) listed in this report: \
             {} plotted in {} bucket(s) of {} ({}, UTC; bucket boundaries are aligned to the \
             Unix epoch, not to calendar months)",
            self.listed,
            self.plotted,
            self.buckets.len(),
            self.bucket_label,
            self.span_words()
        );
        if self.unparseable > 0 {
            c.push_str(&format!(
                ", {} not plotted because their timestamp could not be parsed",
                self.unparseable
            ));
        }
        c.push('.');
        let missing = self.not_listed();
        if missing > 0 {
            c.push_str(&format!(
                " The case holds {} events; the {} later than the listed slice are not plotted, \
                 so the right-hand end of this figure is not the end of the recorded activity.",
                self.case_total, missing
            ));
        } else {
            c.push_str(&format!(
                " The listed events are all {} event(s) the case holds.",
                self.case_total.max(self.listed as i64)
            ));
        }
        c
    }

    /// Lay the histogram out.
    pub fn to_figure(&self) -> Figure {
        const W: f64 = 960.0;
        const H: f64 = 360.0;
        const LEFT: f64 = 64.0;
        const RIGHT: f64 = 20.0;
        const TOP: f64 = 56.0;
        const BOTTOM: f64 = 64.0;
        let mut f = Figure::new(W, H);

        f.text(
            LEFT,
            22.0,
            &format!(
                "Timeline: {} events in {} buckets of {}",
                self.plotted,
                self.buckets.len(),
                self.bucket_label
            ),
            18.0,
            "start",
            true,
            INK,
        );
        let mut caveats = Vec::new();
        let missing = self.not_listed();
        if missing > 0 {
            caveats.push(format!(
                "INCOMPLETE: the case holds {} events; {} later than the listed slice are not plotted",
                self.case_total, missing
            ));
        }
        if self.unparseable > 0 {
            caveats.push(format!(
                "{} listed event(s) not plotted: timestamp could not be parsed",
                self.unparseable
            ));
        }
        if !caveats.is_empty() {
            f.text(
                LEFT,
                42.0,
                &caveats.join("; "),
                13.0,
                "start",
                true,
                INK_ALERT,
            );
        }

        let plot_w = W - LEFT - RIGHT;
        let plot_h = H - TOP - BOTTOM;
        let max = self
            .buckets
            .iter()
            .map(|b| b.count)
            .max()
            .unwrap_or(0)
            .max(1);

        // Grid at 0, half and max; recessive.
        for (frac, label) in [(0.0, 0), (0.5, max / 2), (1.0, max)] {
            let y = TOP + plot_h - plot_h * frac;
            f.line(LEFT, y, LEFT + plot_w, y, GRID, 1.0);
            f.text(
                LEFT - 8.0,
                y + 4.0,
                &label.to_string(),
                13.0,
                "end",
                false,
                INK_MUTED,
            );
        }

        let nb = self.buckets.len().max(1) as f64;
        let slot = plot_w / nb;
        let gap = if slot > 6.0 { 2.0 } else { 0.0 };
        for (i, b) in self.buckets.iter().enumerate() {
            if b.count == 0 {
                continue;
            }
            let h = plot_h * (b.count as f64 / max as f64);
            f.rect(
                LEFT + slot * i as f64 + gap / 2.0,
                TOP + plot_h - h,
                (slot - gap).max(1.0),
                h,
                SERIES_BLUE,
                None,
            );
        }

        // Axis labels: first, middle and last bucket starts.
        let axis_y = TOP + plot_h + 18.0;
        let last = self.buckets.len() - 1;
        let mid = last / 2;
        let label_at = |f: &mut Figure, idx: usize, anchor: &str| {
            let x = LEFT + slot * idx as f64 + slot / 2.0;
            f.text(
                x,
                axis_y,
                &axis_date(self.buckets[idx].start_unix, self.bucket_seconds),
                13.0,
                anchor,
                false,
                INK_MUTED,
            );
        };
        label_at(&mut f, 0, "start");
        if last >= 2 {
            label_at(&mut f, mid, "middle");
        }
        if last >= 1 {
            label_at(&mut f, last, "end");
        }
        f.text(
            LEFT,
            H - 14.0,
            &format!(
                "Each bar is one bucket of {}; bar height is the number of listed events whose timestamp falls in it. Times are UTC.",
                self.bucket_label
            ),
            12.0,
            "start",
            false,
            INK_MUTED,
        );
        f
    }
}

// ---------------------------------------------------------------------------
// Communications graph
// ---------------------------------------------------------------------------

/// A drawn participant.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct CommsFigureNode {
    pub id: String,
    pub label: String,
    pub kind: String,
    pub weight: i64,
    pub x: f64,
    pub y: f64,
    pub r: f64,
}

/// A drawn link.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct CommsFigureEdge {
    /// Indices into [`CommsFigure::nodes`].
    pub a: usize,
    pub b: usize,
    pub weight: i64,
}

/// The communications network as drawn.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct CommsFigure {
    /// Drawn participants, heaviest first (ties by id), at most
    /// [`MAX_DRAWN_PARTICIPANTS`].
    pub nodes: Vec<CommsFigureNode>,
    /// Links between drawn participants.
    pub edges: Vec<CommsFigureEdge>,
    /// Participants in the data (before the drawing cap).
    pub participants_in_data: usize,
    /// Participants the store counted before its own cap.
    pub total_participants: i64,
    /// Links in the data that touch an undrawn participant.
    pub links_not_drawn: usize,
    /// The store's own truncation flag.
    pub truncated: bool,
    pub unusable_email_records: i64,
}

/// The kind a node carries, in words for the legend.
pub fn kind_words(kind: &str) -> &'static str {
    match kind {
        "self" => "device owner",
        "contact" => "messaging contact",
        "email" => "email correspondent",
        _ => "other",
    }
}

fn kind_fill(kind: &str) -> &'static str {
    match kind {
        "self" => KIND_SELF,
        "contact" => KIND_CONTACT,
        "email" => KIND_EMAIL,
        _ => KIND_OTHER,
    }
}

/// Shorten a label for the figure; the full text is in the table beside it.
fn short_label(label: &str) -> String {
    const MAX: usize = 24;
    let count = label.chars().count();
    if count <= MAX {
        label.to_string()
    } else {
        let mut s: String = label.chars().take(MAX - 1).collect();
        s.push('\u{2026}');
        s
    }
}

/// Lay the network out. `None` when there is no participant to draw.
///
/// Deterministic: participants are sorted by weight then id, the device
/// owner (kind `self`) sits at the centre when drawn, and the rest are
/// placed on a ring in that order.
pub fn comms_figure(graph: &ReportCommunicationGraph) -> Option<CommsFigure> {
    if graph.nodes.is_empty() {
        return None;
    }
    let mut ordered: Vec<&crate::report::ReportCommNode> = graph.nodes.iter().collect();
    ordered.sort_by(|a, b| b.weight.cmp(&a.weight).then_with(|| a.id.cmp(&b.id)));
    ordered.truncate(MAX_DRAWN_PARTICIPANTS);

    const W: f64 = 960.0;
    const H: f64 = 560.0;
    let (cx, cy) = (W / 2.0, H / 2.0 + 20.0);
    let ring = 190.0;
    let max_w = ordered.iter().map(|n| n.weight).max().unwrap_or(1).max(1) as f64;
    let radius = |w: i64| 8.0 + 14.0 * ((w.max(0) as f64) / max_w).sqrt();

    let centre_idx = ordered.iter().position(|n| n.kind == "self");
    let on_ring = ordered.len() - usize::from(centre_idx.is_some());
    let mut nodes = Vec::with_capacity(ordered.len());
    let mut ring_i = 0usize;
    for (i, node) in ordered.iter().enumerate() {
        let (x, y) = if Some(i) == centre_idx {
            (cx, cy)
        } else {
            let angle = -std::f64::consts::FRAC_PI_2
                + std::f64::consts::TAU * ring_i as f64 / on_ring.max(1) as f64;
            ring_i += 1;
            (cx + ring * angle.cos(), cy + ring * angle.sin())
        };
        nodes.push(CommsFigureNode {
            id: node.id.clone(),
            label: node.label.clone(),
            kind: node.kind.clone(),
            weight: node.weight,
            x,
            y,
            r: radius(node.weight),
        });
    }

    let index: std::collections::HashMap<&str, usize> = nodes
        .iter()
        .enumerate()
        .map(|(i, n)| (n.id.as_str(), i))
        .collect();
    let mut edges = Vec::new();
    let mut links_not_drawn = 0usize;
    for e in &graph.edges {
        match (index.get(e.source.as_str()), index.get(e.target.as_str())) {
            (Some(&a), Some(&b)) => edges.push(CommsFigureEdge {
                a,
                b,
                weight: e.weight,
            }),
            _ => links_not_drawn += 1,
        }
    }
    edges.sort_by(|x, y| {
        y.weight
            .cmp(&x.weight)
            .then_with(|| x.a.cmp(&y.a))
            .then_with(|| x.b.cmp(&y.b))
    });

    Some(CommsFigure {
        nodes,
        edges,
        participants_in_data: graph.nodes.len(),
        total_participants: graph.total_participants,
        links_not_drawn,
        truncated: graph.truncated,
        unusable_email_records: graph.unusable_email_records,
    })
}

impl CommsFigure {
    /// The caption: what the figure was computed from and what it omits.
    pub fn caption(&self) -> String {
        let total = self
            .total_participants
            .max(self.participants_in_data as i64);
        // The figure names a participant only up to MAX_NAMED_PARTICIPANTS
        // and prints a count on each link only up to MAX_LABELLED_LINKS (see
        // to_figure); the caption says which case this figure is, because it
        // is printed under the figure in every format and is read as a
        // description of what the figure carries.
        let naming = if self.nodes.len() <= MAX_NAMED_PARTICIPANTS {
            format!(
                "each of the {} drawn participants is named",
                self.nodes.len()
            )
        } else {
            format!(
                "the {} drawn participants are more than the {} the figure names, so each is \
                 numbered by its rank in the Participants table beside it",
                self.nodes.len(),
                MAX_NAMED_PARTICIPANTS
            )
        };
        let labelling = if self.edges.len() <= MAX_LABELLED_LINKS {
            format!(
                "each of the {} link(s) is labelled with the number of exchanges it aggregates",
                self.edges.len()
            )
        } else {
            format!(
                "the {} link(s) are more than the {} the figure labels individually, so no \
                 link carries its count on the figure: link width scales with the number of \
                 exchanges and the counts are in the Links table",
                self.edges.len(),
                MAX_LABELLED_LINKS
            )
        };
        let mut c = format!(
            "Communications network, computed from the parsed messaging and email records: \
             {} of {} participants drawn (those party to the most exchanges), with {} link(s) \
             among them; {}; {}, and a link is a record that two parties exchanged a message, \
             not a relationship. {} link(s) to participants not drawn are omitted from the \
             figure but not from the table beside it.",
            self.nodes.len(),
            total,
            self.edges.len(),
            naming,
            labelling,
            self.links_not_drawn
        );
        if self.truncated {
            c.push_str(
                " The source query was truncated: participants beyond its cap, or email rows \
                 beyond its ceiling, were never read, so this network is a subset of what the \
                 evidence holds.",
            );
        }
        if self.unusable_email_records > 0 {
            c.push_str(&format!(
                " {} email record(s) were read but contributed no link (absent metadata, \
                 undecodable content or no sender), so the email side of this network is \
                 incomplete.",
                self.unusable_email_records
            ));
        }
        c
    }

    /// Lay the network out.
    pub fn to_figure(&self) -> Figure {
        const W: f64 = 960.0;
        const H: f64 = 560.0;
        let mut f = Figure::new(W, H);
        f.text(
            20.0,
            24.0,
            &format!(
                "Communications: {} participants, {} links",
                self.nodes.len(),
                self.edges.len()
            ),
            18.0,
            "start",
            true,
            INK,
        );
        // Legend: colour and words, never colour alone. A kind outside the
        // three the store names is drawn in the "other" colour, so the
        // legend names that too whenever such a participant is drawn.
        let mut lx = 20.0;
        let has_other = self
            .nodes
            .iter()
            .any(|n| !matches!(n.kind.as_str(), "self" | "contact" | "email"));
        let kinds: &[&str] = if has_other {
            &["self", "contact", "email", "other"]
        } else {
            &["self", "contact", "email"]
        };
        for kind in kinds {
            f.circle(lx + 6.0, 44.0, 6.0, kind_fill(kind), SURFACE);
            let words = kind_words(kind);
            f.text(lx + 18.0, 49.0, words, 13.0, "start", false, INK_MUTED);
            lx += 34.0 + 7.5 * words.len() as f64;
        }
        let numbered = self.nodes.len() > MAX_NAMED_PARTICIPANTS;
        let link_counts = self.edges.len() <= MAX_LABELLED_LINKS;
        let mut caveats = Vec::new();
        if self.total_participants as usize > self.nodes.len()
            || self.participants_in_data > self.nodes.len()
        {
            caveats.push(format!(
                "INCOMPLETE: {} of {} participants drawn; {} link(s) not drawn",
                self.nodes.len(),
                self.total_participants
                    .max(self.participants_in_data as i64),
                self.links_not_drawn
            ));
        }
        if self.truncated {
            caveats.push("source query truncated".to_string());
        }
        if !caveats.is_empty() {
            f.text(
                W - 20.0,
                24.0,
                &caveats.join("; "),
                13.0,
                "end",
                true,
                INK_ALERT,
            );
        }

        let max_w = self
            .edges
            .iter()
            .map(|e| e.weight)
            .max()
            .unwrap_or(1)
            .max(1) as f64;
        for e in &self.edges {
            let (a, b) = (&self.nodes[e.a], &self.nodes[e.b]);
            let width = 1.0 + 3.0 * (e.weight.max(0) as f64 / max_w);
            f.line(a.x, a.y, b.x, b.y, EDGE, width);
        }
        // Count labels sit on a small surface tab so they stay legible over
        // the line; the number is the text node itself.
        if link_counts {
            for e in &self.edges {
                let (a, b) = (&self.nodes[e.a], &self.nodes[e.b]);
                let (mx, my) = ((a.x + b.x) / 2.0, (a.y + b.y) / 2.0);
                let label = e.weight.to_string();
                let tw = 8.0 * label.len() as f64 + 8.0;
                f.rect(mx - tw / 2.0, my - 9.0, tw, 17.0, SURFACE, Some(GRID));
                f.text(mx, my + 4.0, &label, 12.0, "middle", false, INK);
            }
        }
        for node in &self.nodes {
            f.circle(node.x, node.y, node.r, kind_fill(&node.kind), SURFACE);
        }
        let (cx, cy) = (W / 2.0, H / 2.0 + 20.0);
        for (i, node) in self.nodes.iter().enumerate() {
            let dx = node.x - cx;
            let dy = node.y - cy;
            let label = if numbered {
                (i + 1).to_string()
            } else {
                short_label(&node.label)
            };
            let centre = dx.abs() < 1.0 && dy.abs() < 1.0;
            if centre && numbered {
                // The spokes converge on the centre node, so its number goes
                // inside it rather than under it.
                f.text(node.x, node.y + 5.0, &label, 13.0, "middle", true, SURFACE);
                continue;
            }
            let (anchor, x, y) = if centre {
                ("middle", node.x, node.y + node.r + 16.0)
            } else if numbered {
                // A number fits just outside the node along its own radius.
                let d = (dx * dx + dy * dy).sqrt().max(1.0);
                let off = node.r + 11.0;
                ("middle", node.x + dx / d * off, node.y + dy / d * off + 5.0)
            } else if dx > 20.0 {
                ("start", node.x + node.r + 5.0, node.y + 5.0)
            } else if dx < -20.0 {
                ("end", node.x - node.r - 5.0, node.y + 5.0)
            } else if dy < 0.0 {
                ("middle", node.x, node.y - node.r - 7.0)
            } else {
                ("middle", node.x, node.y + node.r + 16.0)
            };
            f.text(x, y, &label, 13.0, anchor, false, INK);
        }
        let mut notes = Vec::new();
        if numbered {
            notes.push("Participants are numbered by their rank in the Participants table beside this figure.");
        }
        if !link_counts {
            notes.push("Link width scales with the number of exchanges; the counts are in the Links table.");
        }
        if !notes.is_empty() {
            f.text(
                20.0,
                H - 12.0,
                &notes.join(" "),
                12.0,
                "start",
                false,
                INK_MUTED,
            );
        }
        f
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamps_in_every_form_the_report_writes_are_parsed() {
        assert_eq!(parse_timestamp("1970-01-01T00:00:10+00:00"), Some(10));
        assert_eq!(parse_timestamp("1970-01-01T00:00:10Z"), Some(10));
        assert_eq!(parse_timestamp("1970-01-01T01:00:10+01:00"), Some(10));
        assert_eq!(parse_timestamp("1970-01-01 00:00:10"), Some(10));
        assert_eq!(parse_timestamp("1970-01-01 00:00:10 UTC"), Some(10));
        assert_eq!(parse_timestamp("1970-01-02"), Some(86_400));
        assert_eq!(parse_timestamp(""), None);
        assert_eq!(parse_timestamp("yesterday"), None);
    }

    #[test]
    fn negative_timestamps_bucket_without_panicking() {
        let events = vec![
            ReportTimelineEvent {
                timestamp: "1601-01-01T00:00:00Z".into(),
                ..Default::default()
            },
            ReportTimelineEvent {
                timestamp: "2024-01-01T00:00:00Z".into(),
                ..Default::default()
            },
        ];
        let fig = timeline_figure(&events, 2).unwrap();
        assert_eq!(fig.plotted, 2);
        assert_eq!(fig.buckets.iter().map(|b| b.count).sum::<i64>(), 2);
        assert_eq!(fig.bucket_label, "3650 days");
        let _ = fig.to_figure().to_svg();
    }

    #[test]
    fn the_stated_bar_ceiling_is_the_one_the_ladder_produces() {
        // A width w is chosen only when the next coarser width W gives at
        // most MIN_BUCKETS - 1 bars, i.e. the span is at most
        // (MIN_BUCKETS - 1) W - 1 seconds; each end can straddle a w-edge,
        // so that is at most floor(span / w) + 2 bars of w.
        let derived = BUCKET_LADDER
            .windows(2)
            .map(|pair| (((MIN_BUCKETS - 1) * pair[1].0 - 1) / pair[0].0 + 2) as usize)
            .max()
            .unwrap();
        assert_eq!(derived, MAX_BUCKETS);
    }

    #[test]
    fn a_long_label_is_shortened_on_the_figure_only() {
        let long = "a".repeat(40);
        let short = short_label(&long);
        assert_eq!(short.chars().count(), 24);
        assert!(short.ends_with('\u{2026}'));
        assert_eq!(short_label("short"), "short");
    }

    #[test]
    fn numbers_are_written_with_one_decimal_and_no_negative_zero() {
        assert_eq!(n(1.0), "1.0");
        assert_eq!(n(-0.0), "0.0");
        assert_eq!(n(2.25), "2.2");
    }
}
