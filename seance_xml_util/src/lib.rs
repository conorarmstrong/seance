#![forbid(unsafe_code)]
//! Bounded XML reading, for documents chosen by the person under investigation.
//!
//! Every XML document Séance parses is evidence: an EVTX record, an Office
//! document's sheet, an Android `packages.xml`. All three arrive from the
//! machine under examination, which means their shape is chosen by whoever had
//! control of that machine. A parser that is merely correct on well-formed
//! input is not enough — it has to stay bounded on input built to make it slow.
//!
//! # The defect this exists to close
//!
//! `quick-xml` checks for duplicate attribute names by comparing each attribute
//! against every attribute already returned for that element. That is O(n²) in
//! the attribute count, and no published version is free of it
//! (RUSTSEC-2026-0194 covers 0.31, 0.36 and 0.38 alike, all three of which are
//! in this tree). Measured on the affected path, one element carrying distinct
//! attributes:
//!
//! | Attributes | Document | Unbounded | Through this crate |
//! |---|---|---|---|
//! | 25,000 | 257 KB | 493 ms | 0.4 ms |
//! | 50,000 | 526 KB | 2.4 s | 0.7 ms |
//! | 100,000 | 1.0 MB | 11.0 s | 7.1 ms |
//! | 200,000 | 2.2 MB | 29.2 s | 2.7 ms |
//!
//! A 2 MB file is not a large exhibit. At that growth rate a 10 MB one costs
//! minutes, and it costs them inside an ingest that an examiner is watching. No
//! version bump fixes this; the mitigation has to sit in front of the parser,
//! which is what this crate is.
//!
//! # Why not simply turn the check off
//!
//! `Attributes::with_checks(false)` removes the quadratic cost outright, and
//! was the obvious fix. It is half of what happens here, but only half, because
//! turning the check off silently discards a forensic signal: a duplicate
//! attribute name is malformed XML, and malformed XML in evidence is worth
//! recording rather than smoothing over.
//!
//! So the check is disabled *and replaced* — [`XmlGuard`] detects duplicates
//! itself with a hash set, which is O(n) rather than O(n²), and counts them.
//! That is strictly more information than the callers had before: of the three
//! call sites, two (`evtx`, `office`) reached the attribute iterator through
//! `.flatten()`, which discards the very `Err` the quadratic check was paying
//! to produce. They were buying the check and throwing away the receipt.
//!
//! # What a wrong answer looks like
//!
//! Two shapes, and the guard has to refuse both. An ingest that takes half an
//! hour on one 10 MB document and reports nothing about why looks to an
//! examiner like a hung tool. An element whose attributes are silently dropped
//! past a cap looks like an element that did not have them — which in a report
//! is a statement about the evidence that is not true. Hence
//! [`XmlGuard::incompleteness_fields`]: a cap that is reached is a cap that
//! gets said out loud.

pub mod abx;

use quick_xml::events::attributes::Attribute;
use quick_xml::events::BytesStart;
use serde_json::Value as JsonValue;
use std::collections::HashSet;

/// The bounds applied to one document.
///
/// One bound, deliberately. There is **no** cap on total element count: that
/// cost is linear in file size, a legitimate spreadsheet really does carry
/// millions of `<c>` elements, and capping it would truncate honest evidence to
/// no purpose. There is no nesting-depth bound either — `quick-xml` is a pull
/// parser and does not recurse, and none of the callers keeps per-depth state,
/// so a depth counter here would have been a guard that never engaged while
/// implying one that did.
#[derive(Debug, Clone, Copy)]
pub struct XmlLimits {
    /// Attributes read from a single element before the rest are refused.
    ///
    /// The quadratic term is bounded by the square of this number, so the
    /// bound is what makes parse time linear in document size. 256 is chosen
    /// for headroom rather than thrift: the widest element in any format this
    /// tree parses carries fewer than 20 attributes, so a document that
    /// reaches this cap is already anomalous, and the anomaly is recorded.
    pub max_attributes_per_element: usize,
}

impl Default for XmlLimits {
    fn default() -> Self {
        Self {
            max_attributes_per_element: 256,
        }
    }
}

/// Reads attributes under a bound, and records what the bound cost.
///
/// One guard per document. Reuse across documents would attribute one
/// exhibit's anomalies to another.
#[derive(Debug)]
pub struct XmlGuard {
    limits: XmlLimits,
    attributes_truncated: bool,
    duplicate_attributes: usize,
    attribute_errors: usize,
    elements_with_truncated_attributes: usize,
    /// Reused across elements so duplicate detection does not allocate per
    /// element. Cleared, not rebuilt.
    seen: HashSet<Vec<u8>>,
}

impl Default for XmlGuard {
    fn default() -> Self {
        Self::new(XmlLimits::default())
    }
}

impl XmlGuard {
    /// A guard applying `limits` to one document.
    pub fn new(limits: XmlLimits) -> Self {
        Self {
            limits,
            attributes_truncated: false,
            duplicate_attributes: 0,
            attribute_errors: 0,
            elements_with_truncated_attributes: 0,
            seen: HashSet::new(),
        }
    }

    /// Every attribute of `element`, up to the cap.
    ///
    /// Returned as a `Vec` rather than an iterator on purpose. The cap makes
    /// the allocation bounded, and an eager read keeps the borrow of `self`
    /// short — a lazy iterator would hold the guard mutably borrowed for the
    /// whole body of the caller's loop, which is exactly where the caller
    /// wants to record what it found.
    ///
    /// Attributes that fail to parse are counted in
    /// [`XmlGuard::attribute_errors`] and omitted, so callers do not have to
    /// decide separately what an unparseable attribute means. Duplicate names
    /// are counted in [`XmlGuard::duplicate_attributes`] and **kept**: the
    /// first wins for lookup purposes, but dropping the later one would hide
    /// the payload an examiner may need to see.
    pub fn attributes<'a>(&mut self, element: &'a BytesStart<'a>) -> Vec<Attribute<'a>> {
        let mut attributes = element.attributes();
        // The O(n²) comparison this crate exists to avoid. Duplicate detection
        // is done below in linear time instead.
        attributes.with_checks(false);

        self.seen.clear();
        let mut out = Vec::new();

        for attribute in attributes {
            if out.len() >= self.limits.max_attributes_per_element {
                // Latched for the document, counted per element, so the marker
                // can say both that it happened and how widespread it was.
                self.attributes_truncated = true;
                self.elements_with_truncated_attributes += 1;
                break;
            }
            match attribute {
                Ok(attribute) => {
                    if !self.seen.insert(attribute.key.as_ref().to_vec()) {
                        self.duplicate_attributes += 1;
                    }
                    out.push(attribute);
                }
                Err(_) => self.attribute_errors += 1,
            }
        }

        out
    }

    /// True once any element's attributes were cut short by the cap.
    pub fn attributes_truncated(&self) -> bool {
        self.attributes_truncated
    }

    /// Attributes whose name repeated one already seen on the same element.
    pub fn duplicate_attributes(&self) -> usize {
        self.duplicate_attributes
    }

    /// Attributes that did not parse.
    pub fn attribute_errors(&self) -> usize {
        self.attribute_errors
    }

    /// Elements that carried more attributes than the cap allowed.
    pub fn elements_with_truncated_attributes(&self) -> usize {
        self.elements_with_truncated_attributes
    }

    /// True when this document tripped any bound, or carried malformed
    /// attributes — i.e. when there is something to disclose at all.
    pub fn has_findings(&self) -> bool {
        self.attributes_truncated || self.duplicate_attributes > 0 || self.attribute_errors > 0
    }

    /// The same findings as prose, one sentence each.
    ///
    /// For callers whose incompleteness channel is a list of human-readable
    /// notes rather than metadata keys — the office parser records skipped and
    /// short parts that way, and an anomaly here belongs beside them rather
    /// than in a second, differently-shaped channel.
    pub fn describe(&self) -> Vec<String> {
        let mut notes = Vec::new();
        if self.attributes_truncated {
            notes.push(format!(
                "{} element(s) carried more than {} attributes; the remainder were \
                 not read",
                self.elements_with_truncated_attributes, self.limits.max_attributes_per_element
            ));
        }
        if self.duplicate_attributes > 0 {
            notes.push(format!(
                "{} attribute name(s) repeated on the same element, which is malformed XML",
                self.duplicate_attributes
            ));
        }
        if self.attribute_errors > 0 {
            notes.push(format!(
                "{} attribute(s) could not be parsed",
                self.attribute_errors
            ));
        }
        notes
    }

    /// Fields to stamp onto the artifact this document produced.
    ///
    /// Empty when nothing was refused and nothing was malformed, so a clean
    /// document carries no noise. Follows the same shape as the SQLite
    /// helpers' incompleteness stamping: the record says what was not read,
    /// never only the log.
    pub fn incompleteness_fields(&self) -> Vec<(&'static str, JsonValue)> {
        let mut fields = Vec::new();

        if self.attributes_truncated {
            fields.push(("xml_attributes_truncated", JsonValue::Bool(true)));
            fields.push((
                "xml_attribute_cap",
                JsonValue::from(self.limits.max_attributes_per_element),
            ));
            fields.push((
                "xml_elements_with_truncated_attributes",
                JsonValue::from(self.elements_with_truncated_attributes),
            ));
        }
        if self.duplicate_attributes > 0 {
            fields.push((
                "xml_duplicate_attributes",
                JsonValue::from(self.duplicate_attributes),
            ));
        }
        if self.attribute_errors > 0 {
            fields.push((
                "xml_attribute_errors",
                JsonValue::from(self.attribute_errors),
            ));
        }

        fields
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quick_xml::events::Event;
    use quick_xml::Reader;

    /// Read every element's attributes through a guard.
    fn drain(xml: &str, guard: &mut XmlGuard) -> usize {
        let mut reader = Reader::from_str(xml);
        let mut buf = Vec::new();
        let mut count = 0;
        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Start(e)) | Ok(Event::Empty(e)) => count += guard.attributes(&e).len(),
                Ok(Event::Eof) | Err(_) => break,
                _ => {}
            }
            buf.clear();
        }
        count
    }

    fn element_with(attributes: usize) -> String {
        let mut s = String::from("<r><Provider");
        for i in 0..attributes {
            s.push_str(&format!(" a{i}=\"v\""));
        }
        s.push_str("/></r>");
        s
    }

    #[test]
    fn an_ordinary_element_passes_through_untouched() {
        let mut guard = XmlGuard::default();
        let read = drain(r#"<r><Provider Name="Svc" Guid="{0}"/></r>"#, &mut guard);
        assert_eq!(read, 2, "both attributes are returned");
        assert!(
            !guard.has_findings(),
            "nothing to disclose about clean input"
        );
        assert!(
            guard.incompleteness_fields().is_empty(),
            "a clean document must not stamp noise onto its artifact"
        );
    }

    #[test]
    fn attributes_past_the_cap_are_refused_and_said_out_loud() {
        let mut guard = XmlGuard::new(XmlLimits {
            max_attributes_per_element: 8,
        });
        let read = drain(&element_with(100), &mut guard);

        assert_eq!(read, 8, "the cap is what bounds the quadratic term");
        assert!(guard.attributes_truncated());
        assert_eq!(guard.elements_with_truncated_attributes(), 1);

        // The point of the cap is not that it triggers, but that it is
        // disclosed. An element reported with 8 attributes when it had 100 is
        // a false statement about the evidence unless the record says so.
        let fields = guard.incompleteness_fields();
        assert!(fields.iter().any(|(k, _)| *k == "xml_attributes_truncated"));
        assert!(fields
            .iter()
            .any(|(k, v)| *k == "xml_attribute_cap" && v.as_u64() == Some(8)));
    }

    #[test]
    fn duplicate_names_are_counted_rather_than_paid_for_quadratically() {
        // The signal quick-xml's O(n²) check produced, kept — and now actually
        // reaching the caller, which `.flatten()` never let it do.
        let mut guard = XmlGuard::default();
        let read = drain(r#"<r><Data Name="a" Name="b" Other="c"/></r>"#, &mut guard);

        assert_eq!(read, 3, "the repeated attribute is kept, not dropped");
        assert_eq!(guard.duplicate_attributes(), 1);
        assert!(guard
            .incompleteness_fields()
            .iter()
            .any(|(k, _)| *k == "xml_duplicate_attributes"));
    }

    #[test]
    fn a_malformed_attribute_is_counted_not_swallowed() {
        let mut guard = XmlGuard::default();
        // An attribute with no value is a parse error in quick-xml.
        drain(r#"<r><Data Name/></r>"#, &mut guard);
        assert_eq!(guard.attribute_errors(), 1);
        assert!(guard.has_findings());
    }

    /// The regression for RUSTSEC-2026-0194.
    ///
    /// Asserted as a time bound rather than a shape, because the defect *is* a
    /// time bound: the unguarded path takes ~29 s on this input and the guarded
    /// one takes single-digit milliseconds. The threshold is set far above the
    /// measured cost and far below the unguarded one, so it distinguishes the
    /// two without being sensitive to how fast the machine is.
    #[test]
    fn a_hostile_attribute_count_stays_bounded() {
        let hostile = element_with(200_000);
        let mut guard = XmlGuard::default();

        let start = std::time::Instant::now();
        let read = drain(&hostile, &mut guard);
        let elapsed = start.elapsed();

        assert_eq!(read, 256, "capped at the default");
        assert!(guard.attributes_truncated());
        assert!(
            elapsed < std::time::Duration::from_secs(2),
            "a 2.2 MB document with 200,000 attributes on one element took \
             {elapsed:?}; unguarded this input costs ~29 s, so anything near \
             that means the guard is not in the path"
        );
    }
}
