//! The visualisations baked into generated reports (ROADMAP §2.10): an event
//! histogram over the listed timeline and a communications graph.
//!
//! Both are computed from the same `ReportData` every other renderer reads,
//! laid out without randomness, and captioned with what they were computed
//! from and what they leave out.

use seance_reporting::figures::{
    comms_figure, timeline_figure, Figure, MAX_BUCKETS, MAX_LABELLED_LINKS, MAX_NAMED_PARTICIPANTS,
};
use seance_reporting::{
    render_docx_with, render_html, render_html_with, render_pdf, render_pdf_with, render_rtf_with,
    render_xml_with, ReportCommEdge, ReportCommNode, ReportCommunicationGraph, ReportData,
    ReportExtras, ReportTimelineEvent,
};

fn with_graph() -> ReportExtras {
    ReportExtras {
        communications: Some(graph()),
        ..Default::default()
    }
}

fn event(ts: &str) -> ReportTimelineEvent {
    ReportTimelineEvent {
        timestamp: ts.into(),
        description: "event".into(),
        source_module: "mft".into(),
        ..Default::default()
    }
}

fn graph() -> ReportCommunicationGraph {
    ReportCommunicationGraph {
        nodes: vec![
            ReportCommNode {
                id: "\u{1}self".into(),
                label: "This device".into(),
                kind: "self".into(),
                weight: 12,
            },
            ReportCommNode {
                id: "+447700900001".into(),
                label: "Alice <Mobile>".into(),
                kind: "contact".into(),
                weight: 9,
            },
            ReportCommNode {
                id: "bob@example.com".into(),
                label: "bob@example.com".into(),
                kind: "email".into(),
                weight: 3,
            },
        ],
        edges: vec![
            ReportCommEdge {
                source: "\u{1}self".into(),
                target: "+447700900001".into(),
                weight: 9,
            },
            ReportCommEdge {
                source: "\u{1}self".into(),
                target: "bob@example.com".into(),
                weight: 3,
            },
        ],
        truncated: false,
        total_participants: 3,
        unusable_email_records: 0,
    }
}

#[test]
fn timeline_events_are_bucketed_and_the_bucket_size_and_count_are_stated() {
    let events = vec![
        event("2024-03-01T00:10:00+00:00"),
        event("2024-03-01T13:00:00+00:00"),
        event("2024-03-03T09:00:00+00:00"),
        event("2024-03-05T23:59:59+00:00"),
    ];
    let fig = timeline_figure(&events, 4).expect("four parseable events make a figure");
    // The coarsest bucket on the ladder that still gives at least twelve
    // bars: a five-day span is 20 six-hour buckets (one-day would be 5).
    assert_eq!(fig.bucket_seconds, 6 * 3_600);
    assert_eq!(fig.bucket_label, "6 hours");
    assert_eq!(fig.plotted, 4);
    assert_eq!(fig.unparseable, 0);
    // Contiguous and zero-filled from the first occupied bucket to the last.
    assert_eq!(fig.buckets.len(), 20);
    let counts: Vec<i64> = fig.buckets.iter().map(|b| b.count).collect();
    let mut expected = vec![0i64; 20];
    expected[0] = 1; // 03-01 00:10
    expected[2] = 1; // 03-01 13:00
    expected[9] = 1; // 03-03 09:00
    expected[19] = 1; // 03-05 23:59:59
    assert_eq!(counts, expected);
    assert_eq!(fig.buckets[0].start, "2024-03-01T00:00:00Z");
    assert_eq!(fig.buckets[19].start, "2024-03-05T18:00:00Z");

    let svg = fig.to_figure().to_svg();
    assert!(svg.starts_with("<svg"), "{svg}");
    assert!(
        svg.contains("4 events") && svg.contains("20 buckets of 6 hours"),
        "the figure must state the event count and the bucket size on its face: {svg}"
    );

    // A span that needs day buckets gets them: 40 days is 40 one-day bars,
    // where seven-day buckets would be six or seven.
    let month = vec![
        event("2024-03-01T00:10:00+00:00"),
        event("2024-04-09T13:00:00+00:00"),
    ];
    let fig = timeline_figure(&month, 2).expect("figure");
    assert_eq!(fig.bucket_label, "1 day");
    assert_eq!(fig.buckets.len(), 40);
}

#[test]
fn a_timeline_figure_states_what_it_omits_when_the_listing_was_capped() {
    let events = vec![
        event("2024-03-01T00:10:00+00:00"),
        event("2024-03-02T00:10:00+00:00"),
    ];
    let fig = timeline_figure(&events, 5_400).expect("figure");
    let caption = fig.caption();
    assert!(
        caption.contains("5400") && caption.contains("5398"),
        "the caption must state the case total and how many events are not plotted: {caption}"
    );
    let svg = fig.to_figure().to_svg();
    assert!(
        svg.contains("INCOMPLETE") && svg.contains("5398"),
        "the cap must be stated on the figure itself, not only beneath it: {svg}"
    );

    // An uncapped listing says so too, so silence never means "complete".
    let full = timeline_figure(&events, 2).expect("figure");
    assert!(
        full.caption().contains("all 2"),
        "an uncapped caption must say the listing is the whole case: {}",
        full.caption()
    );
}

#[test]
fn unparseable_timestamps_are_counted_on_the_figure_not_silently_dropped() {
    let events = vec![
        event("2024-03-01T00:10:00+00:00"),
        event("not a date"),
        event(""),
    ];
    let fig = timeline_figure(&events, 3).expect("one parseable event is enough");
    assert_eq!(fig.plotted, 1);
    assert_eq!(fig.unparseable, 2);
    assert!(
        fig.caption().contains("2 not plotted"),
        "unparseable events must be disclosed: {}",
        fig.caption()
    );

    assert!(
        timeline_figure(&[event("garbage")], 1).is_none(),
        "nothing parseable means no figure, never an empty chart presented as a finding"
    );
    assert!(timeline_figure(&[], 0).is_none());
}

#[test]
fn a_wide_span_picks_a_coarser_bucket_so_the_figure_stays_readable() {
    let events = vec![
        event("2021-06-01T00:00:00+00:00"),
        event("2024-01-01T00:00:00+00:00"),
    ];
    let fig = timeline_figure(&events, 2).expect("figure");
    assert!(
        (12..=MAX_BUCKETS).contains(&fig.buckets.len()),
        "between 12 and {MAX_BUCKETS} buckets, got {}",
        fig.buckets.len()
    );
    assert_eq!(fig.bucket_label, "30 days");

    // Seven years is 85 thirty-day bars, not eight year bars.
    let years = vec![
        event("1999-02-08T10:08:08+00:00"),
        event("2006-01-19T16:53:29+00:00"),
    ];
    let fig = timeline_figure(&years, 2).expect("figure");
    assert_eq!(fig.bucket_label, "30 days");
    assert_eq!(fig.buckets.len(), 85);

    // A span shorter than twelve hours takes the finest width there is.
    let short = vec![
        event("2024-03-01T00:10:00+00:00"),
        event("2024-03-01T02:10:00+00:00"),
    ];
    let fig = timeline_figure(&short, 2).expect("figure");
    assert_eq!(fig.bucket_label, "1 hour");
    assert_eq!(fig.buckets.len(), 3);
}

#[test]
fn the_widest_ladder_step_sets_the_bar_ceiling_and_the_figure_states_its_true_count() {
    // The 30-day to 365-day rung is a 12.17x step, not 10x: a span that
    // falls one bucket short of twelve year-bars drops to thirty-day bars and
    // reaches well past 120 of them. The ceiling the crate states must be one
    // the ladder cannot exceed, not a rounder number.
    let events = vec![
        event("2000-01-01T00:00:00+00:00"),
        event("2010-12-01T00:00:00+00:00"),
    ];
    let fig = timeline_figure(&events, 2).expect("figure");
    assert_eq!(fig.bucket_label, "30 days");
    assert_eq!(fig.buckets.len(), 134);
    assert!(fig.buckets.len() <= MAX_BUCKETS);
    let caption = fig.caption();
    assert!(
        caption.contains("134 bucket(s) of 30 days"),
        "the caption states the count the figure carries: {caption}"
    );
    let svg = fig.to_figure().to_svg();
    assert!(svg.contains("134 buckets"), "{svg}");

    // The ceiling itself. A span is under eleven year-buckets when the two
    // ends fall inside eleven consecutive 365-day buckets, which admits a
    // span one second short of 11 x 365 days; laid over 30-day buckets whose
    // edges the ends straddle, that is floor((11 x 365 - 1 s) / 30 d) + 2 =
    // 135 bars. The first stamp is one second before a 30-day edge and the
    // last one second after another, 3990 days later.
    let widest = vec![
        event("1972-01-20T23:59:59+00:00"),
        event("1982-12-24T00:00:01+00:00"),
    ];
    let fig = timeline_figure(&widest, 2).expect("figure");
    assert_eq!(fig.bucket_label, "30 days");
    assert_eq!(fig.buckets.len(), 135);
    assert!(
        fig.buckets.len() <= MAX_BUCKETS,
        "the stated ceiling ({MAX_BUCKETS}) is below a count the ladder produces ({})",
        fig.buckets.len()
    );
    assert_eq!(MAX_BUCKETS, 135);
    assert!(fig.caption().contains("135 bucket(s) of 30 days"));
}

#[test]
fn the_communications_graph_draws_every_participant_and_labels_each_link_with_its_count() {
    let fig = comms_figure(&graph()).expect("three participants make a figure");
    assert_eq!(fig.nodes.len(), 3);
    assert_eq!(fig.edges.len(), 2);
    let svg = fig.to_figure().to_svg();
    // Labels are escaped for XML, not passed raw.
    assert!(svg.contains("Alice &lt;Mobile&gt;"), "{svg}");
    assert!(!svg.contains("Alice <Mobile>"));
    assert!(svg.contains("This device"), "{svg}");
    // Edge counts on the figure.
    assert!(svg.contains(">9<") && svg.contains(">3<"), "{svg}");
    // Node kinds are named in words, not by colour alone.
    assert!(
        svg.contains("device owner") && svg.contains("messaging contact") && svg.contains("email"),
        "{svg}"
    );
    let caption = fig.caption();
    assert!(
        caption.contains("3 of 3 participants"),
        "the caption must say how many participants are drawn: {caption}"
    );
    assert!(
        caption.contains("each of the 2 link(s) is labelled with the number of exchanges"),
        "two links are within the labelling cap, so the caption may say they are labelled: {caption}"
    );
    assert!(
        !caption.contains("Links table"),
        "nothing is deferred to the table when every link carries its count: {caption}"
    );
}

#[test]
fn a_communications_graph_beyond_the_drawing_cap_says_which_participants_are_left_out() {
    let mut g = graph();
    for i in 0..60 {
        let id = format!("peer{i:02}@example.com");
        g.nodes.push(ReportCommNode {
            id: id.clone(),
            label: id.clone(),
            kind: "email".into(),
            weight: 1,
        });
        g.edges.push(ReportCommEdge {
            source: "\u{1}self".into(),
            target: id,
            weight: 1,
        });
    }
    g.total_participants = 63;
    g.truncated = true;
    let fig = comms_figure(&g).expect("figure");
    assert_eq!(fig.nodes.len(), 40, "drawn participants are capped at 40");
    // Forty names around a ring overwrite one another, so a crowded figure
    // numbers its nodes by their rank in the participant table and says so.
    let svg = fig.to_figure().to_svg();
    assert!(
        svg.contains(">40<"),
        "the last drawn node is numbered 40: {svg}"
    );
    assert!(!svg.contains("peer00@example.com"), "{svg}");
    assert!(svg.contains("numbered by their rank"), "{svg}");
    assert!(
        svg.contains("counts are in the Links table"),
        "39 links carry no per-link count on the figure: {svg}"
    );
    let caption = fig.caption();
    assert!(
        caption.contains("40 of 63 participants"),
        "the caption must state the drawing cap it hit: {caption}"
    );
    assert!(
        caption.contains("23 link(s)") && caption.contains("not drawn"),
        "links to undrawn participants must be counted, not silently dropped: {caption}"
    );
    assert!(
        caption.contains("truncated"),
        "the source query's own cap must be carried onto the figure: {caption}"
    );
    // The caption is printed under the figure in every format, so it must say
    // what this figure carries: 39 links exceed the 24 the figure labels, so
    // no link is labelled and the caption may not claim otherwise.
    assert_eq!(fig.edges.len(), 39);
    assert!(fig.edges.len() > MAX_LABELLED_LINKS);
    assert!(
        !caption.contains("is labelled with the number of exchanges"),
        "a figure with unlabelled links must not be captioned as labelled: {caption}"
    );
    assert!(
        caption.contains(&format!(
            "the 39 link(s) are more than the {MAX_LABELLED_LINKS} the figure labels individually"
        )),
        "the labelling cap and its number belong in the caption: {caption}"
    );
    assert!(
        caption.contains("no link carries its count on the figure")
            && caption.contains("Links table"),
        "the caption must send the reader to where the counts are: {caption}"
    );
    // Likewise the numbering: forty nodes carry ranks, not names, and the
    // caption says so rather than leaving the reader to find the footnote.
    assert!(fig.nodes.len() > MAX_NAMED_PARTICIPANTS);
    assert!(
        caption.contains(&format!(
            "the {} drawn participants are more than the {MAX_NAMED_PARTICIPANTS} the figure \
             names, so each is numbered by its rank in the Participants table",
            fig.nodes.len()
        )),
        "{caption}"
    );
}

#[test]
fn a_small_graph_is_captioned_as_named_and_labelled_without_the_cap_notes() {
    let fig = comms_figure(&graph()).expect("figure");
    assert!(fig.nodes.len() <= MAX_NAMED_PARTICIPANTS);
    let caption = fig.caption();
    assert!(
        caption.contains("each of the 3 drawn participants is named"),
        "{caption}"
    );
    assert!(!caption.contains("numbered"), "{caption}");
    assert!(!caption.contains("Participants table"), "{caption}");
}

#[test]
fn a_participant_of_an_unknown_kind_is_named_in_the_legend_not_only_coloured() {
    let mut g = graph();
    g.nodes.push(ReportCommNode {
        id: "sms:+447700900099".into(),
        label: "+447700900099".into(),
        kind: "group".into(),
        weight: 1,
    });
    g.total_participants = 4;
    let svg = comms_figure(&g).expect("figure").to_figure().to_svg();
    assert!(
        svg.contains(">other<"),
        "a kind the legend has no word for is still named, not left as a bare colour: {svg}"
    );
    // And the word appears only when such a participant is drawn.
    let svg = comms_figure(&graph()).expect("figure").to_figure().to_svg();
    assert!(!svg.contains(">other<"), "{svg}");
}

#[test]
fn an_empty_communications_graph_makes_no_figure() {
    let g = ReportCommunicationGraph {
        nodes: vec![],
        edges: vec![],
        truncated: false,
        total_participants: 0,
        unusable_email_records: 4,
    };
    assert!(comms_figure(&g).is_none());
}

#[test]
fn two_renders_of_the_same_case_are_byte_identical() {
    let data = ReportData {
        full_timeline: vec![
            event("2024-03-01T00:10:00+00:00"),
            event("2024-03-03T09:00:00+00:00"),
        ],
        full_timeline_total: 2,
        ..Default::default()
    };
    let extras = with_graph();
    let t = timeline_figure(&data.full_timeline, 2).unwrap();
    assert_eq!(t.to_figure().to_svg(), t.to_figure().to_svg());
    let c = comms_figure(&graph()).unwrap();
    assert_eq!(c.to_figure().to_svg(), c.to_figure().to_svg());
    assert_eq!(
        render_html_with(&data, &extras),
        render_html_with(&data, &extras)
    );
    assert_eq!(
        render_docx_with(&data, &extras).unwrap(),
        render_docx_with(&data, &extras).unwrap()
    );
}

#[test]
fn the_html_report_carries_both_figures_inline_with_captions() {
    let data = ReportData {
        full_timeline: vec![
            event("2024-03-01T00:10:00+00:00"),
            event("2024-03-03T09:00:00+00:00"),
        ],
        full_timeline_total: 900,
        ..Default::default()
    };
    let html = render_html_with(&data, &with_graph());
    assert_eq!(
        html.matches("<svg").count(),
        2,
        "one inline SVG per figure: {html}"
    );
    assert!(html.contains("<figcaption"), "{html}");
    assert!(
        html.contains("Figure 1") && html.contains("Figure 2"),
        "{html}"
    );
    assert!(html.contains("Communications Network"), "{html}");
    assert!(
        html.contains("898"),
        "the cap must reach the caption: {html}"
    );
    // The figure's data travels with it, so the numbers are in the document
    // and not only in a picture of them.
    assert!(html.contains("Alice &lt;Mobile&gt;"), "{html}");
}

#[test]
fn a_report_without_communications_data_says_the_network_was_not_computed() {
    let data = ReportData::default();
    let html = render_html(&data);
    assert!(
        html.contains("Communications Network"),
        "the section is always present so its absence can never read as \"no contacts\": {html}"
    );
    assert!(html.contains("not computed"), "{html}");
    assert!(!html.contains("<svg"), "no data, no figure: {html}");

    let computed_empty = ReportExtras {
        communications: Some(ReportCommunicationGraph {
            nodes: vec![],
            edges: vec![],
            truncated: false,
            total_participants: 0,
            unusable_email_records: 7,
        }),
        ..Default::default()
    };
    let html = render_html_with(&data, &computed_empty);
    assert!(html.contains("no participants"), "{html}");
    assert!(
        html.contains("7 email record(s)"),
        "unusable email records are a separate disclosure: {html}"
    );
    for out in [
        render_rtf_with(&data, &computed_empty),
        render_xml_with(&data, &computed_empty),
    ] {
        assert!(out.to_lowercase().contains("communications"), "{out}");
        assert!(out.contains("7 email record(s)"), "{out}");
    }
}

#[test]
fn the_pdf_report_draws_both_figures() {
    let data = ReportData {
        full_timeline: vec![
            event("2024-03-01T00:10:00+00:00"),
            event("2024-03-03T09:00:00+00:00"),
        ],
        full_timeline_total: 2,
        ..Default::default()
    };
    let with = render_pdf_with(&data, &with_graph()).expect("pdf");
    let without = render_pdf(&ReportData::default()).expect("pdf");
    assert!(with.starts_with(b"%PDF"));
    // Rectangle (`re`) path operators appear only when a figure was drawn;
    // the text-only report has none. Counted by decoding the page content
    // streams with a real PDF parser, not by string-matching the bytes.
    let count_rects = |bytes: &[u8]| {
        let doc = lopdf::Document::load_mem(bytes).expect("a parseable PDF");
        let mut n = 0usize;
        for (_, page_id) in doc.get_pages() {
            let content = doc.get_page_content(page_id).expect("page content");
            let ops = lopdf::content::Content::decode(&content).expect("content stream");
            n += ops
                .operations
                .iter()
                .filter(|op| op.operator == "re")
                .count();
        }
        n
    };
    assert_eq!(
        count_rects(&without),
        0,
        "a text-only report draws no rectangles"
    );
    assert!(
        count_rects(&with) > 0,
        "the PDF with figures must draw the figures' rectangles"
    );
}

#[test]
fn the_figure_model_escapes_text_it_draws() {
    let mut f = Figure::new(100.0, 50.0);
    f.text(1.0, 2.0, "a<b>&\"c\"", 10.0, "start", false, "#000000");
    let svg = f.to_svg();
    assert!(svg.contains("a&lt;b&gt;&amp;&quot;c&quot;"), "{svg}");
    assert!(!svg.contains("a<b>"));
}
