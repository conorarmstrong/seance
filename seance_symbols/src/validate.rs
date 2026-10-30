//! The admission gate: the reason this crate exists.
//!
//! # Why validation, and not warnings
//!
//! Every other part of memory forensics either works or visibly fails. Paging
//! is arithmetic; container formats are run lists; pool scanning is byte
//! patterns. The symbol table is different in one specific and dangerous way:
//!
//! > A **wrong** symbol table does not crash and does not look wrong. It
//! > produces a full process list with plausible PIDs, plausible names and
//! > plausible timestamps, all of them garbage, because
//! > `_EPROCESS.UniqueProcessId` was read at the offset a *different* Windows
//! > build uses.
//!
//! Reading the right bytes and interpreting them against the wrong layout
//! cannot be caught downstream: the bytes were genuinely there. So the second
//! job of this crate — the important one — is to **prove, before any plugin
//! reads a single typed field, that this database describes this image**, and
//! to refuse rather than caveat when it cannot.
//!
//! Every check that bears on whether a typed read lands in the right place
//! therefore ends in `Rejected`, not a log line. A warning on a symbol table is
//! a warning nobody reads attached to evidence everybody quotes.
//!
//! # The other failure: refusing evidence that is fine
//!
//! Failing closed has a cost, and paid in the wrong place it is just as
//! damaging. A gate that refuses a legitimate ISF does not produce a wrong
//! answer; it produces no answer, on a case where the evidence was there. Three
//! checks did exactly that: Linux's `struct zone_padding { char x[0]; }` (size
//! 0 with a member), Linux's `migrate_mode` (an enum whose base type dwarf2json
//! left as `void`), and Volatility's netscan overlay packs, 23 of whose 25
//! declare members past a `size` field nobody measured. Between them they meant
//! Linux memory forensics could not run at all and Windows netscan could not
//! run on any modern build.
//!
//! None of those three can move a read. A member is fetched through its own
//! offset and its own type; a type's declared `size` bounds nothing but a
//! whole-type read, which this crate never performs. So they are recorded as
//! [`GateResult::caveat`]s: reservations that reach the [`AdmissionReport`],
//! its JSON, and the case record, without blocking admission. The width that
//! genuinely is unknown -- the unsized enum's -- is refused at the point that
//! would need it, in [`crate::table::SymbolTable::read_member_unsigned`], which
//! rejects any scalar that is not 1 to 8 bytes wide.
//!
//! A caveat is never an alternative to a violation. It is what the gate says
//! when a producer was untidy; a violation is what it says when a layout would
//! yield false evidence. Collapsing the two in either direction is the defect.
//!
//! # The ordered gate
//!
//! | Gate | Question | On failure |
//! |---|---|---|
//! | 1 Structural | is the document internally coherent? | rejected |
//! | 2 Identity | is the ISF's identity byte-equal to the image's? | rejected |
//! | 3 Architecture | does the pointer width agree with the paging mode? | rejected |
//! | 4 Image sanity | do typed reads through this table make sense? | rejected, or inconclusive |
//! | 5 Producer | was this file made by a tool with a known layout defect? | rejected |
//!
//! Gate 4 needs the memory image and is expressed through
//! [`crate::probe::ImageProbe`]; the OS-specific checks live in the crate that
//! owns the address space and are merged into the report with
//! [`AdmissionReport::record`]. Anything not evaluated leaves the table
//! `Unverified`, never `Verified`: an unproved table is not a proved one.
//!
//! # Seven behaviours that are banned outright
//!
//! Nearest-build fallback; try-until-it-works; built-in offset tables for
//! common builds; synthesising a missing member as `0`; zero-padding a short
//! read behind a typed field; running symbol-dependent analysis in a rejected
//! state at the examiner's insistence; and silently reusing a stale compiled
//! cache. There is no "I know better" override, because output produced that
//! way enters the case record indistinguishable from verified output.

use std::collections::HashMap;

use crate::error::SymbolError;
use crate::identify::{IdentifierSource, IsfIdentity};
use crate::isf::{
    Architecture, BaseKind, BaseTypeDef, IsfDocument, TypeDescriptor, POINTER_BASE_TYPE,
};
use crate::table::{size_of_in, TypeEntry, TypeKind};

/// Most violations recorded per gate. Beyond this the count is kept but the
/// text is not: a hostile file with a million broken members must not turn a
/// rejection into a memory-exhaustion event.
pub const MAX_RECORDED_VIOLATIONS: usize = 100;

/// Producers known to emit layouts that are wrong in ways that read as ordinary
/// data. `dwarf2json` before 0.9.0 mis-handles Rust/C type confusion; upstream
/// only warns, which is not sufficient for evidence.
const DWARF2JSON_MIN_SAFE: (u16, u16, u16) = (0, 9, 0);

/// Marker left by the `dwarf2json` defect this gate refuses.
const RUST_HELPER_MARKER: &str = "rust_helper";

/// Which gate a result belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Gate {
    /// Gate 1: schema conformance, version negotiation and the invariants the
    /// JSON Schema cannot express.
    Structural,
    /// Gate 2: the identity from the image, byte-equal to the identity from the
    /// ISF. There is no near-match tier.
    Identity,
    /// Gate 3: pointer width against the selected paging mode and the declared
    /// machine type.
    Architecture,
    /// Gate 4: typed reads through the candidate table against the image.
    ImageSanity,
    /// Gate 5: known-bad producers.
    Producer,
}

impl Gate {
    /// The gate's number in the ordered sequence.
    pub fn number(self) -> u8 {
        match self {
            Gate::Structural => 1,
            Gate::Identity => 2,
            Gate::Architecture => 3,
            Gate::ImageSanity => 4,
            Gate::Producer => 5,
        }
    }

    /// Stable identifier for artifact metadata.
    pub fn as_str(self) -> &'static str {
        match self {
            Gate::Structural => "structural",
            Gate::Identity => "identity",
            Gate::Architecture => "architecture",
            Gate::ImageSanity => "image_sanity",
            Gate::Producer => "producer",
        }
    }
}

/// What a single check concluded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateOutcome {
    /// The check ran and the table satisfied it.
    Pass,
    /// The check ran and the table failed it. Always fatal to admission.
    Fail,
    /// The check ran and could not decide, because the *evidence* is damaged
    /// rather than the layout being wrong. A smeared capture produces this, and
    /// routing it to `Fail` would mean emitting nothing on exactly the images
    /// that most need analysis.
    Inconclusive,
    /// The check did not run and nothing was learned: the caller supplied
    /// nothing to check against, or an earlier gate refused the document before
    /// this one could run. Blocks [`AdmissionState::Verified`], because
    /// something that should have been proved was not.
    NotEvaluated,
    /// The check does not apply to this build, because the structure member it
    /// reads is genuinely absent from the table's layout.
    ///
    /// This does NOT block [`AdmissionState::Verified`], and that is the whole
    /// point of it. A member the build never had is not an unproved claim: it is
    /// a fact about the operating system, and there is nothing left to prove.
    /// Windows XP has no `_KUSER_SHARED_DATA.NtBuildNumber` — the build is read
    /// from `NtBuildLab` instead — so treating its absence as unproved held
    /// every XP capture at `Unverified` forever, which in turn stamped every
    /// analysis stage as short of the evidence when the stages had run in full.
    ///
    /// It is only sound when the absence was established from the layout, via
    /// `has_member`. A read that was ATTEMPTED and failed is
    /// [`GateOutcome::Inconclusive`]: there the member exists and the evidence
    /// would not yield it, which is a real gap and must keep blocking. Using
    /// this variant for a failed read would let a damaged image call itself
    /// verified.
    NotApplicable,
}

impl GateOutcome {
    /// Stable identifier for artifact metadata.
    pub fn as_str(self) -> &'static str {
        match self {
            GateOutcome::Pass => "pass",
            GateOutcome::Fail => "fail",
            GateOutcome::Inconclusive => "inconclusive",
            GateOutcome::NotEvaluated => "not_evaluated",
            GateOutcome::NotApplicable => "not_applicable",
        }
    }
}

/// One recorded check.
#[derive(Debug, Clone)]
pub struct GateResult {
    /// Which gate this belongs to.
    pub gate: Gate,
    /// The check's name. For gates 1, 2, 3 and 5 this is the gate's own name;
    /// gate 4 records several named checks.
    pub check: String,
    /// What it concluded.
    pub outcome: GateOutcome,
    /// One line an examiner can read.
    pub detail: String,
    /// Every specific violation, each naming the offending type and member.
    pub violations: Vec<String>,
    /// Violations beyond [`MAX_RECORDED_VIOLATIONS`], counted but not kept.
    pub suppressed_violations: u64,
    /// Recorded reservations that do NOT block admission.
    ///
    /// A caveat is what the gate says when a document is *untidy in a way its
    /// producer chose* rather than wrong in a way that yields false evidence:
    /// Linux's `struct zone_padding { char x[0]; }`, whose size is 0 and which
    /// still declares a member; Volatility's hand-written netscan overlays,
    /// whose `size` is a stub nothing measured and whose members are therefore
    /// declared past it. Neither can mis-place a read, because a member is read
    /// through its own offset and its own type and a type's declared size bounds
    /// only a whole-type read.
    ///
    /// The distinction that makes this safe is the one the old code could not
    /// draw: a violation says *this layout would produce false evidence*, a
    /// caveat says *this document is not tidy and here is exactly how*. Both
    /// reach [`AdmissionReport::to_json`] and thence the case record, so a
    /// caveat is a table admitted **with reservations on the record**, never a
    /// silent pass.
    pub caveats: Vec<String>,
    /// Caveats beyond [`MAX_RECORDED_VIOLATIONS`], counted but not kept.
    pub suppressed_caveats: u64,
}

impl GateResult {
    /// A check that passed.
    pub fn pass(gate: Gate, check: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            gate,
            check: check.into(),
            outcome: GateOutcome::Pass,
            detail: detail.into(),
            violations: Vec::new(),
            suppressed_violations: 0,
            caveats: Vec::new(),
            suppressed_caveats: 0,
        }
    }

    /// A check that failed.
    pub fn fail(gate: Gate, check: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            outcome: GateOutcome::Fail,
            ..Self::pass(gate, check, detail)
        }
    }

    /// A check that could not decide because the evidence is damaged.
    pub fn inconclusive(gate: Gate, check: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            outcome: GateOutcome::Inconclusive,
            ..Self::pass(gate, check, detail)
        }
    }

    /// A check that did not run.
    pub fn not_evaluated(gate: Gate, check: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            outcome: GateOutcome::NotEvaluated,
            ..Self::pass(gate, check, detail)
        }
    }

    /// A check that does not apply, because the member it reads is absent from
    /// this build's layout.
    ///
    /// Use this ONLY when the absence was established from the table itself
    /// (`has_member` returned false). If a read was attempted and failed, the
    /// member exists and the evidence would not yield it — that is
    /// [`GateResult::inconclusive`], and it must keep blocking admission.
    pub fn not_applicable(gate: Gate, check: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            outcome: GateOutcome::NotApplicable,
            ..Self::pass(gate, check, detail)
        }
    }

    /// Record a specific violation, which also fails the check.
    pub fn violate(&mut self, message: impl Into<String>) {
        self.outcome = GateOutcome::Fail;
        if self.violations.len() < MAX_RECORDED_VIOLATIONS {
            self.violations.push(message.into());
        } else {
            self.suppressed_violations = self.suppressed_violations.saturating_add(1);
        }
    }

    /// Record a reservation that does **not** change the outcome.
    ///
    /// Use this only where the document is untidy in a way that cannot move a
    /// read: a member is fetched through its own offset and its own type, and a
    /// type's declared `size` bounds nothing but a whole-type read. Anything
    /// that could put a typed read at the wrong address, or hand back bytes
    /// that were never the member's, is [`GateResult::violate`].
    ///
    /// `message` must say WHY the untidiness is tolerable, because the examiner
    /// reading the report has to be able to tell "this table has a zero-length
    /// padding struct, which is normal" from "this table disagrees with itself
    /// about where a field lives".
    pub fn caveat(&mut self, message: impl Into<String>) {
        if self.caveats.len() < MAX_RECORDED_VIOLATIONS {
            self.caveats.push(message.into());
        } else {
            self.suppressed_caveats = self.suppressed_caveats.saturating_add(1);
        }
    }

    /// How many violations were found, recorded or not.
    pub fn violation_count(&self) -> u64 {
        self.violations.len() as u64 + self.suppressed_violations
    }

    /// How many caveats were recorded, kept or not.
    pub fn caveat_count(&self) -> u64 {
        self.caveats.len() as u64 + self.suppressed_caveats
    }

    /// Whether this check admitted the document with reservations.
    pub fn has_caveats(&self) -> bool {
        self.caveat_count() > 0
    }

    /// Serializable form for artifact metadata and the findings a rejection
    /// writes into the case record.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "gate": self.gate.number(),
            "gate_name": self.gate.as_str(),
            "check": self.check,
            "outcome": self.outcome.as_str(),
            "detail": self.detail,
            "violations": self.violations,
            "suppressed_violations": self.suppressed_violations,
            "caveats": self.caveats,
            "suppressed_caveats": self.suppressed_caveats,
        })
    }
}

/// What the gate concluded overall, and therefore what plugins may do.
///
/// | State | Plugin behaviour |
/// |---|---|
/// | `Verified` | symbol-dependent analysis runs normally |
/// | `Unverified` | analysis runs; **every artifact carries `symbol_confidence: "unverified"`** plus the unevaluated or inconclusive checks by name |
/// | `Rejected` | **no symbol-dependent analysis runs**; a finding names the failing gate |
/// | `NoMatch` | **no symbol-dependent analysis runs**; a finding plus the acquisition recipe |
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionState {
    /// Every check ran and passed.
    Verified,
    /// Nothing failed, but something was not proved.
    Unverified,
    /// At least one check failed.
    Rejected,
    /// No candidate ISF was found at all. Never produced by
    /// [`AdmissionReport::state`]; set by the caller that did the searching.
    NoMatch,
}

impl AdmissionState {
    /// Stable identifier for artifact metadata.
    pub fn as_str(self) -> &'static str {
        match self {
            AdmissionState::Verified => "verified",
            AdmissionState::Unverified => "unverified",
            AdmissionState::Rejected => "rejected",
            AdmissionState::NoMatch => "no_match",
        }
    }

    /// Whether symbol-dependent analysis may run in this state.
    pub fn permits_analysis(self) -> bool {
        matches!(self, AdmissionState::Verified | AdmissionState::Unverified)
    }

    /// The confidence label every artifact must carry in this state.
    pub fn symbol_confidence(self) -> &'static str {
        match self {
            AdmissionState::Verified => "verified",
            _ => "unverified",
        }
    }
}

/// Every check that ran, and everything that was merely odd.
#[derive(Debug, Clone, Default)]
pub struct AdmissionReport {
    /// Checks in the order they ran.
    pub gates: Vec<GateResult>,
    /// Recorded oddities that are not grounds for refusal, e.g. an enum whose
    /// declared size disagrees with its base type. Kept because a producer that
    /// is sloppy in a harmless way is worth knowing about when a later finding
    /// is disputed.
    pub warnings: Vec<String>,
}

impl AdmissionReport {
    /// Add a check result, e.g. a gate-4 check performed by the crate that owns
    /// the memory image.
    pub fn record(&mut self, result: GateResult) {
        self.gates.push(result);
    }

    /// Note something odd that is not grounds for refusal.
    pub fn warn(&mut self, message: impl Into<String>) {
        self.warnings.push(message.into());
    }

    /// Every check that failed.
    pub fn failures(&self) -> impl Iterator<Item = &GateResult> + '_ {
        self.gates.iter().filter(|g| g.outcome == GateOutcome::Fail)
    }

    /// Whether any check failed.
    pub fn is_rejected(&self) -> bool {
        self.failures().next().is_some()
    }

    /// The overall state.
    ///
    /// Anything not proved leaves the table `Unverified`. That is deliberate:
    /// "we did not check" and "we checked and it was fine" are different facts
    /// and must not render the same in a report.
    pub fn state(&self) -> AdmissionState {
        if self.is_rejected() {
            return AdmissionState::Rejected;
        }
        // A report nothing has been recorded into has proved nothing. Reading an
        // empty gate list as "every check passed" would hand a table built by
        // some future path that forgot to run the gate the word `verified`, and
        // that word is what a report quotes.
        if self.gates.is_empty() {
            return AdmissionState::Unverified;
        }
        // `NotApplicable` is deliberately absent from this list. A check that
        // does not apply to this build has nothing left to prove — the member
        // it reads is not in the layout, which is a fact about the operating
        // system rather than a gap in what was established. Counting it as
        // unproved held every Windows XP capture at `Unverified`, because XP
        // has no `_KUSER_SHARED_DATA.NtBuildNumber`, and that verdict then
        // stamped analysis stages as short of the evidence when they had in
        // fact run in full.
        let unproved = self.gates.iter().any(|g| {
            matches!(
                g.outcome,
                GateOutcome::NotEvaluated | GateOutcome::Inconclusive
            )
        });
        if unproved {
            AdmissionState::Unverified
        } else {
            AdmissionState::Verified
        }
    }

    /// Checks that ran but could not decide, by name. These are what an
    /// `Unverified` artifact must carry.
    ///
    /// Excludes `NotApplicable`: naming a check that does not apply to this
    /// build would tell an examiner something was left unproved when there was
    /// never anything to prove. Those are reported separately by
    /// [`AdmissionReport::inapplicable_checks`], because an examiner comparing
    /// two builds still wants to see which checks each one supported.
    pub fn unproved_checks(&self) -> Vec<&str> {
        self.gates
            .iter()
            .filter(|g| {
                matches!(
                    g.outcome,
                    GateOutcome::NotEvaluated | GateOutcome::Inconclusive
                )
            })
            .map(|g| g.check.as_str())
            .collect()
    }

    /// Every reservation recorded by every check, in the order they were found.
    ///
    /// Each entry names the gate and the check it came from, so a caveat cannot
    /// be read out of context. A non-empty result means the table was admitted
    /// **with reservations**: nothing here blocks analysis, and nothing here may
    /// be dropped from a report either.
    pub fn caveats(&self) -> Vec<String> {
        self.gates
            .iter()
            .flat_map(|gate| {
                let g = gate.gate;
                let check = gate.check.clone();
                gate.caveats
                    .iter()
                    .map(move |message| format!("gate {} ({check}): {message}", g.number()))
            })
            .collect()
    }

    /// How many reservations were recorded, kept or not.
    pub fn caveat_count(&self) -> u64 {
        self.gates.iter().map(GateResult::caveat_count).sum()
    }

    /// Whether the table was admitted with reservations on the record.
    pub fn has_caveats(&self) -> bool {
        self.caveat_count() > 0
    }

    /// Checks that do not apply to this build, by name.
    ///
    /// Not a defect and not a gap: the member each one reads is absent from
    /// this build's layout. Reported so a profile can state which checks its
    /// operating system supported, rather than leaving an examiner to wonder
    /// why a gate they have seen elsewhere is missing here.
    pub fn inapplicable_checks(&self) -> Vec<&str> {
        self.gates
            .iter()
            .filter(|g| g.outcome == GateOutcome::NotApplicable)
            .map(|g| g.check.as_str())
            .collect()
    }

    /// Serializable form for artifact metadata.
    ///
    /// `admitted_with_caveats` and `caveats` sit at the top level beside
    /// `state`, deliberately: a consumer that renders only the summary must not
    /// be able to render a table admitted with reservations as if it had been
    /// admitted clean. The per-gate copies under `gates[].caveats` say which
    /// check found each one.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "state": self.state().as_str(),
            "gates": self.gates.iter().map(GateResult::to_json).collect::<Vec<_>>(),
            "warnings": self.warnings,
            "admitted_with_caveats": self.has_caveats(),
            "caveats": self.caveats(),
            "caveat_count": self.caveat_count(),
        })
    }
}

impl std::fmt::Display for AdmissionReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut first = true;
        for failure in self.failures() {
            if !first {
                f.write_str("; ")?;
            }
            first = false;
            write!(
                f,
                "gate {} ({}) failed: {}",
                failure.gate.number(),
                failure.check,
                failure.detail
            )?;
            for violation in failure.violations.iter().take(5) {
                write!(f, " [{violation}]")?;
            }
            if failure.violation_count() > 5 {
                write!(f, " (+{} more)", failure.violation_count() - 5)?;
            }
        }
        if first {
            f.write_str("no gate failed")?;
        }
        // Rendered even when nothing failed. A caveat that only exists in the
        // JSON is a caveat an examiner reading the one-line summary never sees,
        // and a reservation nobody sees is the silent pass this whole concept
        // exists to avoid.
        let caveats = self.caveats();
        if !caveats.is_empty() {
            write!(f, "; admitted with {} caveat(s)", self.caveat_count())?;
            for caveat in caveats.iter().take(5) {
                write!(f, " [{caveat}]")?;
            }
            if self.caveat_count() > 5 {
                write!(f, " (+{} more)", self.caveat_count() - 5)?;
            }
        }
        Ok(())
    }
}

/// What the caller knows independently of the ISF, and can therefore check it
/// against.
#[derive(Debug, Clone, Default)]
pub struct ValidationOptions {
    /// Pointer width the selected paging mode implies. Supplied by whatever
    /// built the address space; absent means gate 3 can only check the ISF
    /// against itself.
    pub expected_architecture: Option<Architecture>,
    /// The identity recovered from the **image**: the CodeView triple, or the
    /// normalised banner. Absent means gate 2 cannot run.
    pub expected_identifier: Option<String>,
    /// Base types that must be declared. Defaults to `pointer` alone, which is
    /// the only one whose absence is unambiguously fatal — see
    /// [`crate::isf::POINTER_BASE_TYPE`]. A caller that knows more about the
    /// platform may require more.
    pub required_base_types: Vec<String>,
}

impl ValidationOptions {
    /// Options requiring only what every usable ISF must have.
    pub fn new() -> Self {
        Self {
            expected_architecture: None,
            expected_identifier: None,
            required_base_types: vec![POINTER_BASE_TYPE.to_string()],
        }
    }

    /// The identity recovered from the image, for gate 2.
    pub fn expect_identifier(mut self, identifier: impl Into<String>) -> Self {
        self.expected_identifier = Some(identifier.into());
        self
    }

    /// The architecture the paging mode implies, for gate 3.
    pub fn expect_architecture(mut self, architecture: Architecture) -> Self {
        self.expected_architecture = Some(architecture);
        self
    }

    /// The required base types, defaulting to `pointer` when none were set.
    fn required_base_types(&self) -> Vec<&str> {
        if self.required_base_types.is_empty() {
            vec![POINTER_BASE_TYPE]
        } else {
            self.required_base_types
                .iter()
                .map(String::as_str)
                .collect()
        }
    }
}

/// Gate 1, document half: everything checkable from the JSON alone.
///
/// Runs **before** the arena is built, because the build applies
/// version-dependent semantics (anonymous-field flattening at format 6.2.0) and
/// a document whose version this reader does not implement must not be compiled
/// under a guess about which semantics apply.
pub fn structural_document(
    doc: &IsfDocument,
    options: &ValidationOptions,
    warnings: &mut Vec<String>,
) -> GateResult {
    let mut gate = GateResult::pass(
        Gate::Structural,
        "structural",
        "the document is internally coherent",
    );

    // --- version negotiation -------------------------------------------------
    let version = match doc.version() {
        Ok(version) => {
            if !version.is_supported() {
                gate.violate(format!(
                    "the document declares ISF format {version}, outside the supported range {} to {}",
                    crate::isf::MIN_SUPPORTED_FORMAT,
                    crate::isf::MAX_SUPPORTED_FORMAT
                ));
            }
            Some(version)
        }
        Err(err) => {
            gate.violate(err.to_string());
            None
        }
    };

    // --- metadata is a oneOf -------------------------------------------------
    if doc.metadata.os_key_count() > 1 {
        gate.violate(format!(
            "metadata declares {} operating systems; the metadata block is a oneOf \
             and an ISF cannot describe two platforms",
            doc.metadata.os_key_count()
        ));
    }

    // --- repeated keys -------------------------------------------------------
    // A repeated key is not a curiosity: parsed into a map it silently keeps the
    // last value, so one member's offset overwrites another's and the table is
    // wrong with nothing to show for it.
    for name in doc.base_types.duplicates() {
        gate.violate(format!("base type '{name}' is declared more than once"));
    }
    for name in doc.user_types.duplicates() {
        gate.violate(format!("user type '{name}' is declared more than once"));
    }
    for name in doc.enums.duplicates() {
        gate.violate(format!("enum '{name}' is declared more than once"));
    }
    for name in doc.symbols.duplicates() {
        gate.violate(format!("symbol '{name}' is declared more than once"));
    }
    for (type_name, user) in doc.user_types.iter() {
        for member in user.fields.duplicates() {
            gate.violate(format!(
                "type '{type_name}' declares the member '{member}' more than once"
            ));
        }
    }
    for (enum_name, definition) in doc.enums.iter() {
        for constant in definition.constants.duplicates() {
            gate.violate(format!(
                "enum '{enum_name}' declares the constant '{constant}' more than once"
            ));
        }
    }

    // --- one name declared in two blocks -------------------------------------
    // `base_types`, `user_types` and `enums` are separate namespaces and a name
    // may legally appear in more than one, because every type *descriptor* names
    // the block it means. A caller asking the table for "the type called X" does
    // not name a block, so a shadowed name is recorded here and that query
    // refuses to answer rather than silently picking a block on the examiner's
    // behalf — see `SymbolTable::type_id`.
    let base_names: std::collections::HashSet<&str> =
        doc.base_types.iter().map(|(name, _)| name).collect();
    let enum_names: std::collections::HashSet<&str> =
        doc.enums.iter().map(|(name, _)| name).collect();
    for (name, _) in doc.user_types.iter() {
        if base_names.contains(name) {
            warnings.push(format!(
                "'{name}' is declared both as a base type and as a user type; \
                 a lookup by name alone is ambiguous and is refused"
            ));
        }
        if enum_names.contains(name) {
            warnings.push(format!(
                "'{name}' is declared both as an enum and as a user type; \
                 a lookup by name alone is ambiguous and is refused"
            ));
        }
    }
    for name in &enum_names {
        if base_names.contains(name) {
            warnings.push(format!(
                "'{name}' is declared both as a base type and as an enum; \
                 a lookup by name alone is ambiguous and is refused"
            ));
        }
    }

    // --- base types ----------------------------------------------------------
    let base_index: HashMap<&str, &BaseTypeDef> = doc.base_types.iter().collect();

    // A document with no types declares no layouts, so a base type it does not
    // name is not a layout it cannot describe. See the `pointer` arm below.
    let declares_layouts = !doc.user_types.is_empty() || !doc.enums.is_empty();
    if declares_layouts {
        for required in options.required_base_types() {
            if !base_index.contains_key(required) {
                gate.violate(format!(
                    "the document declares no base type named '{required}'"
                ));
            }
        }
    }
    // The schema has no `pointer` *kind*: the pointer base type is recognised by
    // name, so an ISF without that entry is silently pointer-less rather than
    // architecture-mismatched. Absence is therefore a structural failure here,
    // not something for gate 3 to notice later.
    match base_index.get(POINTER_BASE_TYPE) {
        Some(pointer) => {
            if pointer.size != 4 && pointer.size != 8 {
                gate.violate(format!(
                    "the 'pointer' base type declares a size of {} bytes, which is neither 4 nor 8",
                    pointer.size
                ));
            }
        }
        None if doc.user_types.is_empty() && doc.enums.is_empty() => {
            // A document that declares no types is a name-to-address map, not a
            // layout: there is nothing in it to do pointer arithmetic with, so
            // a pointer width is not something it is missing. Volatility ships
            // exactly this for individual drivers -- tcpip.pdb is 9329 symbols,
            // no base types, no user types -- and netstat needs it to find
            // tcpip.sys's own tables. Demanding a pointer width of it refused
            // the file and took netstat out on every modern Windows build.
            warnings.push(
                "the document declares no types, only symbol addresses, so it defines no \
                 pointer width; nothing in it can be read as a structure"
                    .to_string(),
            );
        }
        None => {
            // Already reported above when `pointer` is in the required list;
            // report it explicitly when a caller cleared that list.
            if !options.required_base_types().contains(&POINTER_BASE_TYPE) {
                gate.violate(
                    "the document declares no base type named 'pointer', so it defines no \
                     pointer width and cannot be checked against any paging mode",
                );
            }
        }
    }

    for (name, base) in doc.base_types.iter() {
        if base.size == 0 && base.kind != BaseKind::Void {
            gate.violate(format!(
                "base type '{name}' is of kind {} and declares a size of 0",
                base.kind.as_str()
            ));
        }
        if base.size > 32 {
            gate.violate(format!(
                "base type '{name}' declares an implausible size of {} bytes",
                base.size
            ));
        }
    }

    // --- user types ----------------------------------------------------------
    for (type_name, user) in doc.user_types.iter() {
        if user.size == 0 {
            // A zero-size type is incoherent only if a member actually occupies
            // bytes. C's zero-length-array padding idiom does not: Linux's
            // `struct zone_padding { char x[0]; }` is a genuine 0-byte type
            // whose one member spans the empty range at offset 0, and it is
            // present in every NUMA kernel. Reading "size 0 with members" as
            // proof of a broken producer refused Volatility's own Debian 3.2
            // table -- 4118 types, one of them this idiom -- and with it the
            // whole Linux tier.
            let occupying: Vec<&str> = user
                .fields
                .iter()
                .filter(|(_, field)| occupies_bytes(&field.ty))
                .map(|(member_name, _)| member_name)
                .collect();
            if !occupying.is_empty() {
                gate.violate(format!(
                    "type '{type_name}' declares a size of 0 but has {} member(s) that \
                     occupy bytes ({}); each of them would lie outside it",
                    occupying.len(),
                    occupying.join(", ")
                ));
            } else if !user.fields.is_empty() {
                // Tolerated, but never silently. A shape a check once refused
                // and now admits has to leave a mark an examiner can read,
                // otherwise the fix has only traded a loud wrong answer for a
                // quiet one.
                gate.caveat(format!(
                    "type '{type_name}' declares a size of 0 and has {} member(s), none of \
                     which occupies a byte; this is C's zero-length-array padding idiom \
                     (`char x[0]`), which is normal in kernel headers, and it cannot displace \
                     a read because the member is fetched at its own offset through its own \
                     type",
                    user.fields.len()
                ));
            }
        }
        for (member_name, field) in user.fields.iter() {
            // A member past the declared size says the size is a stub, not that
            // the member is misplaced, and the gate cannot tell the two apart
            // from the document alone -- so it records which one it saw and
            // lets the read decide, because a read never consults the enclosing
            // type's size.
            //
            // Volatility's hand-written netscan overlays are the worked case:
            // 23 of the 25 packs upstream ships declare members past `size`,
            // and `_TCP_ENDPOINT.Owner` tracks the real structure build by
            // build -- 712 at 17763, 656 at 18362, 728 at 19041, 752 at 20348.
            // Those offsets are measured facts about the object; the `size`
            // beside them was never measured. Refusing the pack refused netscan
            // and netstat on every modern Windows build.
            if user.size > 0 && field.offset > user.size {
                gate.caveat(format!(
                    "type '{type_name}' member '{member_name}' lies at offset {}, beyond the \
                     type's own size of {}; the declared size is treated as a producer's stub, \
                     because the member is read at its own offset through its own type and the \
                     declared size bounds only a whole-type read",
                    field.offset, user.size
                ));
            }
            if let TypeDescriptor::Bitfield {
                bit_position,
                bit_length,
                ..
            } = &field.ty
            {
                if *bit_length == 0 {
                    gate.violate(format!(
                        "type '{type_name}' member '{member_name}' is a bitfield of zero bits"
                    ));
                }
                if *bit_length > 64 || *bit_position >= 64 {
                    gate.violate(format!(
                        "type '{type_name}' member '{member_name}' is a bitfield at bit {bit_position} \
                         of length {bit_length}, which no integer base type can hold"
                    ));
                }
            }
        }
    }

    // --- enums ---------------------------------------------------------------
    for (enum_name, definition) in doc.enums.iter() {
        let base = match base_index.get(definition.base.as_str()) {
            Some(base) => base,
            None => {
                // Without the base type the width and sign of every constant is
                // unknown, so nothing about this enum can be checked. The ISF
                // says the base defines the width; a missing base is not
                // something to substitute the advisory `size` for.
                gate.violate(format!(
                    "enum '{enum_name}' declares the base type '{}', which the document \
                     does not define, so its width and sign are unknown",
                    definition.base
                ));
                continue;
            }
        };
        if definition.constants.is_empty() {
            // Nothing to hold, so the base width cannot be incoherent about
            // holding it. dwarf2json emits this shape for an enum that is
            // declared but never defined in the compilation unit -- Debian
            // 3.2's `migrate_mode` is `size 0, base "void", constants {}`.
            // Judging it against a width it never uses refused the table.
            warnings.push(format!(
                "enum '{enum_name}' declares no constants, so nothing in the document \
                 can resolve a name through it"
            ));
        }
        if base.size == 0 || base.size > 8 {
            // The width is unstated, not wrong. dwarf2json emits `base: "void"`
            // for an enum whose underlying type the compilation unit never
            // settled -- Debian 3.2's `migrate_mode` is exactly that -- and the
            // enum itself is real. Refusing the whole document over one enum
            // nothing touches is disproportionate; refusing to hand back a
            // value for it is not, and that is where the refusal now lives:
            // `SymbolTable::read_member_unsigned` rejects any scalar that is
            // not 1 to 8 bytes wide, so a member typed by this enum errors
            // instead of guessing a width. The constants below are left
            // unchecked, because a range test against an unknown width would
            // assert something the document does not say.
            gate.caveat(format!(
                "enum '{enum_name}' has base type '{}' of {} bytes, so its width is unstated \
                 and no constant of it can be range-checked; the enum is admitted because \
                 nothing else in the document depends on that width, and any READ of a \
                 member typed by it fails closed rather than assuming one",
                definition.base, base.size
            ));
            continue;
        }
        // The base type defines the width; `enums[].size` is advisory. A
        // mismatch means the producer disagrees with itself, which is worth
        // recording but is not by itself a wrong layout.
        if definition.size != base.size {
            warnings.push(format!(
                "enum '{enum_name}' declares size {} but its base type '{}' is {} bytes; \
                 the base type governs",
                definition.size, definition.base, base.size
            ));
        }
        for (constant_name, value) in definition.constants.iter() {
            let integer = match number_to_i128(value) {
                Some(integer) => integer,
                None => {
                    gate.violate(format!(
                        "enum '{enum_name}' constant '{constant_name}' has the value {value}, \
                         which is not an exact integer"
                    ));
                    continue;
                }
            };
            if !fits(integer, base.size, base.signed) {
                gate.violate(format!(
                    "enum '{enum_name}' constant '{constant_name}' is {integer}, which does not \
                     fit in its {} {}-byte base type '{}'",
                    if base.signed { "signed" } else { "unsigned" },
                    base.size,
                    definition.base
                ));
            }
        }
    }

    // --- symbols -------------------------------------------------------------
    for (symbol_name, symbol) in doc.symbols.iter() {
        if symbol.address.as_u64().is_none() {
            gate.violate(format!(
                "symbol '{symbol_name}' has the address {}, which is not an exact unsigned \
                 integer; kernel addresses exceed 2^53 and are never rounded",
                symbol.address
            ));
        }
        if let Some(version) = version {
            if symbol.constant_data.is_some() && !version.has_constant_data() {
                warnings.push(format!(
                    "symbol '{symbol_name}' carries constant_data, which format {version} \
                     does not define"
                ));
            }
        }
    }

    describe(&mut gate);
    gate
}

/// Restate a gate's one-line detail once every check has run.
///
/// A caveat that only exists in the `caveats` vector is a caveat an examiner
/// skimming the detail line never sees, so the detail says how many there were
/// even when nothing failed.
fn describe(gate: &mut GateResult) {
    if gate.outcome == GateOutcome::Fail {
        gate.detail = format!(
            "the document is not internally coherent: {} violation(s)",
            gate.violation_count()
        );
        if gate.has_caveats() {
            gate.detail
                .push_str(&format!(", and {} caveat(s)", gate.caveat_count()));
        }
    } else if gate.has_caveats() {
        gate.detail = format!(
            "the document is internally coherent, with {} caveat(s): shapes its producer left \
             untidy that cannot displace a typed read",
            gate.caveat_count()
        );
    }
}

/// Gate 1, layout half: the checks that need resolved sizes.
///
/// Appends to the same gate result, because "member 8 of `_EPROCESS` is beyond
/// the end of `_EPROCESS`" is the same class of failure as a repeated member
/// name and belongs in the same rejection.
pub fn layout(entries: &[TypeEntry], gate: &mut GateResult) {
    for entry in entries {
        let aggregate = match &entry.kind {
            TypeKind::Aggregate(aggregate) => aggregate,
            _ => continue,
        };
        // Lifting an anonymous member can land two members on one name. That
        // used to refuse the whole document and now costs the one name, which
        // is the right trade -- but only if it is said out loud. `has_member`
        // answers false for such a name, and a caller following the "ask, then
        // carry Option" discipline reads that as *this build does not have the
        // field*, which is a different claim from *this table cannot say which
        // bytes are its*. Recorded here so the report carries the difference
        // even when no caller ever asks.
        for name in aggregate.ambiguous_names() {
            gate.caveat(format!(
                "type '{}' has {} members named '{name}' once anonymous members are lifted \
                 into it, so that name addresses none of them and every lookup of it is \
                 refused; the type's other members are unaffected",
                entry.name,
                aggregate.ambiguity(name).unwrap_or_default()
            ));
        }
        if aggregate.size == 0 {
            // The document half has already spoken about a zero-sized type that
            // carries members -- a violation when a member occupies bytes, a
            // caveat when they are all zero-length arrays -- and naming the same
            // type again here would double-count it. A genuinely empty one has
            // nothing to check.
            continue;
        }
        for member in &aggregate.members {
            let origin = match &member.lifted_from {
                Some(anonymous) => {
                    format!(" (lifted from the anonymous member '{anonymous}')")
                }
                None => String::new(),
            };
            // Checked FIRST, and deliberately: this one stays fatal, and the
            // member it would refuse is often exactly the member the offset
            // check below now only caveats. A bit range outside its storage unit
            // is what the extraction shifts and masks by, so it hands back bits
            // that were never the field's -- false evidence, not untidiness --
            // and running it after a `continue` would have made it unreachable
            // for every file the relaxation newly admits.
            if let Some(TypeKind::Bitfield {
                base,
                bit_position,
                bit_length,
            }) = entries.get(member.ty.index()).map(|e| &e.kind)
            {
                if let Ok(unit) = size_of_in(entries, *base, 0) {
                    let bits = unit.saturating_mul(8);
                    if bit_position.saturating_add(*bit_length) > bits {
                        gate.violate(format!(
                            "type '{}' member '{}'{origin} is a bitfield of {bit_length} bit(s) \
                             at bit {bit_position}, past the end of its {unit}-byte storage unit",
                            entry.name, member.name
                        ));
                    }
                }
            }
            // The resolved twin of the document-half check, and it moves for the
            // same reason: the offset is what a read uses and the enclosing
            // type's declared size is not. Leaving this one fatal would have
            // undone the relaxation above, because gate 1 is a single result and
            // one violation anywhere in it rejects the file.
            if member.offset > aggregate.size {
                gate.caveat(format!(
                    "type '{}' member '{}'{origin} lies at offset {}, beyond the type's own \
                     size of {}; the declared size is treated as a producer's stub, because \
                     the member is read at its own offset through its own type",
                    entry.name, member.name, member.offset, aggregate.size
                ));
                continue;
            }
            match size_of_in(entries, member.ty, 0) {
                // A member whose tail runs past the declared size is the same
                // fact seen from the other end, and it is just as undecidable
                // from the document alone: `_IN_ADDR` in every one of
                // Volatility's 25 netscan packs is a union of a 4-byte and a
                // 16-byte address declared with `size: 6`, and the 16-byte
                // member is the one netscan reads correctly. The read takes the
                // member's own offset and the member's own width; the enclosing
                // size never bounds it, in this crate or in the object reader
                // above it. What a caller must NOT do is bound a read by the
                // declared size and slice a member out of it -- that would
                // truncate this member to nothing -- and
                // `SymbolTable::declared_size_is_stub` exists so such a caller
                // can refuse instead.
                Ok(width) => match member.offset.checked_add(width) {
                    Some(end) if end > aggregate.size => gate.caveat(format!(
                        "type '{}' member '{}'{origin} is {width} bytes wide at offset {}, \
                         ending at {end}, past the type's own size of {}; the declared size is \
                         treated as a producer's stub, because the member is read at its own \
                         offset for its own width and no read is bounded by the enclosing \
                         type's size",
                        entry.name, member.name, member.offset, aggregate.size
                    )),
                    Some(_) => {}
                    None => gate.violate(format!(
                        "type '{}' member '{}'{origin} has an offset and width that overflow \
                         a 64-bit address",
                        entry.name, member.name
                    )),
                },
                // A member whose *width cannot be computed at all* is refused
                // here rather than deferred to the first read. An array whose
                // declared count times its element size does not fit in 64 bits
                // has no size, and a table holding one is a table whose sizes
                // wrap somewhere; admitting it and failing later would leave the
                // wrap latent behind whichever plugin happened to touch it
                // first.
                Err(SymbolError::Overflow(detail)) => gate.violate(format!(
                    "type '{}' member '{}'{origin} has no computable size: {detail}",
                    entry.name, member.name
                )),
                Err(SymbolError::Malformed(detail)) => gate.violate(format!(
                    "type '{}' member '{}'{origin} could not be sized: {detail}",
                    entry.name, member.name
                )),
                // An unresolved reference and a function type are both legitimate
                // and both already fail every query that would need their layout,
                // so neither is grounds to refuse the whole document. The
                // unresolved ones are carried in the compile diagnostics.
                Err(_) => {}
            }
        }
    }

    describe(gate);
}

/// Gate 2: the identity from the image against the identity from the ISF.
///
/// Byte equality or nothing. A "close enough" tier here is how a tool ends up
/// analysing a 19045 image with a 19041 table and reporting the results as
/// fact.
pub fn identity(identity: &IsfIdentity, options: &ValidationOptions) -> GateResult {
    match (&options.expected_identifier, &identity.identifier) {
        (Some(expected), Some(actual)) => {
            if expected == actual {
                GateResult::pass(
                    Gate::Identity,
                    "identity",
                    format!("the image and the ISF both identify as '{actual}'"),
                )
            } else {
                let mut result = GateResult::fail(
                    Gate::Identity,
                    "identity",
                    "the ISF describes a different build from the image",
                );
                result.violate(format!(
                    "the image identifies as '{expected}' and the ISF as '{actual}'"
                ));
                result
            }
        }
        (Some(expected), None) => GateResult::not_evaluated(
            Gate::Identity,
            "identity",
            format!(
                "the image identifies as '{expected}' but the ISF declares no identity of its \
                 own ({}), so nothing was proved",
                match identity.identifier_source {
                    IdentifierSource::None => "a version-independent fragment",
                    other => other.as_str(),
                }
            ),
        ),
        (None, _) => GateResult::not_evaluated(
            Gate::Identity,
            "identity",
            "no identity was recovered from the image, so the ISF's identity could not be \
             compared against anything",
        ),
    }
}

/// Gate 3: pointer width against the paging mode and the declared machine type.
pub fn architecture(doc: &IsfDocument, options: &ValidationOptions) -> GateResult {
    let pointer_size = match doc.pointer_size() {
        Some(size) => size,
        None => {
            return GateResult::not_evaluated(
                Gate::Architecture,
                "architecture",
                "the document declares no 'pointer' base type, so there is no width to check \
                 against the paging mode; gate 1 refuses that in any document declaring types, \
                 and records it as a warning in one that declares only symbol addresses",
            )
        }
    };

    let declared = doc.metadata.declared_pointer_size();
    let expected = options.expected_architecture.map(|a| a.pointer_size());

    let mut result = GateResult::pass(
        Gate::Architecture,
        "architecture",
        format!("the ISF declares {pointer_size}-byte pointers"),
    );

    if let Some(expected) = expected {
        if u64::from(expected) != pointer_size {
            result.violate(format!(
                "the selected paging mode implies {expected}-byte pointers but the ISF's \
                 'pointer' base type is {pointer_size} bytes"
            ));
        }
    }
    if let Some(declared) = declared {
        if u64::from(declared) != pointer_size {
            result.violate(format!(
                "the ISF's machine type implies {declared}-byte pointers but its 'pointer' \
                 base type is {pointer_size} bytes"
            ));
        }
    }

    if result.outcome == GateOutcome::Fail {
        result.detail = "the ISF's pointer width contradicts the architecture".to_string();
        return result;
    }
    if expected.is_none() && declared.is_none() {
        return GateResult::not_evaluated(
            Gate::Architecture,
            "architecture",
            format!(
                "the ISF declares {pointer_size}-byte pointers, but neither a paging mode nor a \
                 machine type was available to check that against"
            ),
        );
    }
    result
}

/// Gate 5: producers with a known layout defect.
///
/// Refused rather than warned about. The `dwarf2json` Rust/C type-confusion
/// defect produces member offsets that are wrong and entirely plausible, which
/// is the exact failure mode this whole subsystem exists to prevent.
pub fn producer(doc: &IsfDocument) -> GateResult {
    let producer = match &doc.metadata.producer {
        Some(producer) => producer,
        None => {
            return GateResult::not_evaluated(
                Gate::Producer,
                "producer",
                "the document records no producer, so it cannot be checked against the \
                 known-bad list",
            )
        }
    };
    let name = match producer.name.as_deref() {
        Some(name) if !name.is_empty() => name,
        // A producer block with no name cannot be checked against the list, and
        // "could not check" is not "checked and clean".
        _ => {
            return GateResult::not_evaluated(
                Gate::Producer,
                "producer",
                "the document's producer block names no tool, so it could not be checked \
                 against the known-bad list",
            )
        }
    };
    // Matched case-insensitively and with surrounding whitespace removed. The
    // producer string is written by the file being checked: `"DWARF2JSON"` or
    // `"dwarf2json "` must not walk past the one gate that exists to catch that
    // tool, and a gate that answers "not on the known-bad list" has made a
    // positive claim it would not be entitled to make.
    let normalised = name.trim().to_ascii_lowercase();
    if normalised != "dwarf2json" {
        return GateResult::pass(
            Gate::Producer,
            "producer",
            format!(
                "produced by '{name}' version '{}', which is not on the known-bad list",
                producer.version.as_deref().unwrap_or("unknown")
            ),
        );
    }

    let raw_version = producer.version.as_deref().unwrap_or("");
    let parsed = crate::isf::Version::parse(raw_version).ok();
    let has_marker = doc
        .symbols
        .iter()
        .any(|(symbol, _)| symbol.contains(RUST_HELPER_MARKER))
        || doc
            .user_types
            .iter()
            .any(|(type_name, _)| type_name.contains(RUST_HELPER_MARKER));

    match parsed {
        Some(version) => {
            let triple = (version.major, version.minor, version.patch);
            if triple < DWARF2JSON_MIN_SAFE && has_marker {
                let mut result = GateResult::fail(
                    Gate::Producer,
                    "producer",
                    "produced by a dwarf2json version with a known type-confusion defect",
                );
                result.violate(format!(
                    "dwarf2json {version} is before 0.9.0 and the document contains a \
                     '{RUST_HELPER_MARKER}' entry, the marker of the Rust/C type-confusion \
                     defect that yields plausible but wrong member offsets"
                ));
                result
            } else {
                GateResult::pass(
                    Gate::Producer,
                    "producer",
                    format!("produced by dwarf2json {version}"),
                )
            }
        }
        None => GateResult::not_evaluated(
            Gate::Producer,
            "producer",
            format!(
                "produced by dwarf2json, whose version '{raw_version}' could not be parsed, so \
                 the known-bad check could not run"
            ),
        ),
    }
}

/// A gate-4 placeholder for the case where no image was supplied.
///
/// Recorded rather than omitted, so the report cannot be read as "gate 4
/// passed". Its presence is what keeps such a table `Unverified`.
pub fn image_sanity_not_evaluated() -> GateResult {
    GateResult::not_evaluated(
        Gate::ImageSanity,
        "image_sanity",
        "no memory image was supplied, so nothing was read through this table to falsify it",
    )
}

/// Whether a member described by `ty` spans at least one byte.
///
/// Only a zero-length array spans none. C permits `char x[0]` as a padding or
/// flexible-array member, and a type built solely from those is legitimately
/// zero bytes wide -- so such a member is not evidence that its type's declared
/// size is wrong. Every other descriptor is treated as occupying bytes, which
/// keeps this conservative: the question it answers is "is this proof of a
/// broken producer", and only the zero-length array proves it is not.
fn occupies_bytes(ty: &TypeDescriptor) -> bool {
    !matches!(ty, TypeDescriptor::Array { count: 0, .. })
}

/// Convert a JSON number to an exact integer, or nothing.
fn number_to_i128(number: &serde_json::Number) -> Option<i128> {
    if let Some(unsigned) = number.as_u64() {
        return Some(i128::from(unsigned));
    }
    number.as_i64().map(i128::from)
}

/// Whether `value` fits a `size`-byte integer of the given signedness.
fn fits(value: i128, size: u64, signed: bool) -> bool {
    if !(1..=8).contains(&size) {
        return false;
    }
    let bits = (size * 8) as u32;
    if signed {
        let max = (1i128 << (bits - 1)) - 1;
        let min = -(1i128 << (bits - 1));
        value >= min && value <= max
    } else {
        value >= 0 && value < (1i128 << bits)
    }
}

#[cfg(test)]
mod zero_width_shapes {
    use super::*;

    /// A minimal but genuine ISF document with `extra` merged into it.
    fn doc_with(extra: serde_json::Value) -> IsfDocument {
        let mut value = serde_json::json!({
            "metadata": {"format": "6.1.0", "producer": {"name": "test", "version": "1"}},
            "base_types": {
                "pointer": {"size": 8, "signed": false, "kind": "int", "endian": "little"},
                "char": {"size": 1, "signed": true, "kind": "char", "endian": "little"},
                "void": {"size": 0, "signed": false, "kind": "void", "endian": "little"}
            },
            "user_types": {},
            "enums": {},
            "symbols": {}
        });
        let object = value.as_object_mut().expect("object");
        for (key, entry) in extra.as_object().expect("object") {
            object[key] = entry.clone();
        }
        serde_json::from_value(value).expect("a valid ISF document")
    }

    fn gate_for(extra: serde_json::Value) -> GateResult {
        let mut warnings = Vec::new();
        structural_document(
            &doc_with(extra),
            &ValidationOptions::default(),
            &mut warnings,
        )
    }

    fn violations(extra: serde_json::Value) -> Vec<String> {
        gate_for(extra).violations
    }

    /// The `zone_padding` type exactly as Volatility's Debian 3.2 table
    /// declares it.
    fn zone_padding() -> serde_json::Value {
        serde_json::json!({
            "user_types": {
                "zone_padding": {
                    "size": 0,
                    "kind": "struct",
                    "fields": {
                        "x": {
                            "offset": 0,
                            "type": {"kind": "array", "count": 0,
                                     "subtype": {"kind": "base", "name": "char"}}
                        }
                    }
                }
            }
        })
    }

    #[test]
    fn a_zero_length_array_does_not_make_its_zero_size_type_incoherent() {
        // Verbatim from Volatility's own
        // Debian_3.2.57-3+deb7u2_3.2.0-4-amd64_x64.json.xz: `struct
        // zone_padding { char x[0]; }`, the NUMA cacheline-padding idiom. It
        // is one type out of 4118, and reading it as a broken producer refused
        // the entire table -- so every Linux capture analysed against this
        // kernel emitted nothing at all, silently.
        assert!(violations(zone_padding()).is_empty());
    }

    #[test]
    fn the_padding_idiom_is_admitted_with_a_caveat_rather_than_in_silence() {
        // The half of the fix that is easy to leave out and is the whole risk
        // of it. Admitting the table is not enough: a shape a gate once refused
        // and now admits has to leave a record, or the change has traded a loud
        // wrong answer for a quiet one.
        let gate = gate_for(zone_padding());
        assert_eq!(gate.outcome, GateOutcome::Pass, "{:?}", gate.violations);
        assert!(gate.has_caveats(), "the admission left no trace at all");
        let caveat = gate
            .caveats
            .iter()
            .find(|c| c.contains("zone_padding"))
            .unwrap_or_else(|| panic!("the caveat must name the type: {:?}", gate.caveats));
        assert!(
            caveat.contains("zero-length-array") && caveat.contains("normal"),
            "the caveat must say why it is tolerable, so an examiner can tell it from a \
             table that disagrees with itself: {caveat}"
        );
        assert!(
            gate.detail.contains("caveat"),
            "the one-line detail must say the table was admitted with reservations: {}",
            gate.detail
        );
    }

    #[test]
    fn a_zero_size_type_whose_member_occupies_bytes_is_still_refused() {
        // The defect the predicate was written to catch must survive the fix:
        // a real member at a real offset inside a type declaring no bytes.
        let found = violations(serde_json::json!({
            "user_types": {
                "broken": {
                    "size": 0,
                    "kind": "struct",
                    "fields": {
                        "real": {"offset": 0, "type": {"kind": "base", "name": "pointer"}}
                    }
                }
            }
        }));
        assert!(
            found
                .iter()
                .any(|v| v.contains("'broken'") && v.contains("occupy bytes")),
            "expected a violation naming the occupying member, got {found:?}"
        );
    }

    #[test]
    fn a_document_of_symbol_addresses_alone_is_not_required_to_declare_a_pointer_width() {
        // Volatility ships one of these per driver. `tcpip.pdb` -- the file
        // netstat needs to find tcpip.sys's own connection tables -- is 9329
        // symbols with no base types and no user types. Requiring a pointer
        // width of a document that describes no structure refused it outright,
        // and netstat had never once run against a real image as a result.
        let mut warnings = Vec::new();
        let doc: IsfDocument = serde_json::from_value(serde_json::json!({
            "metadata": {"format": "6.1.0", "producer": {"name": "pdbconv", "version": "1"}},
            "base_types": {},
            "user_types": {},
            "enums": {},
            "symbols": {"TcpPortPool": {"address": 4096}}
        }))
        .expect("a valid ISF document");
        let result = structural_document(&doc, &ValidationOptions::default(), &mut warnings);
        assert_eq!(result.outcome, GateOutcome::Pass, "{:?}", result.violations);
        assert!(
            warnings.iter().any(|w| w.contains("only symbol addresses")),
            "the absent pointer width must still be recorded, got {warnings:?}"
        );
    }

    #[test]
    fn a_document_that_declares_types_still_needs_a_pointer_width() {
        // The other half: once a document describes a layout, the pointer width
        // is load-bearing again and its absence is a refusal.
        let mut warnings = Vec::new();
        let doc: IsfDocument = serde_json::from_value(serde_json::json!({
            "metadata": {"format": "6.1.0", "producer": {"name": "test", "version": "1"}},
            "base_types": {"char": {"size": 1, "signed": true, "kind": "char", "endian": "little"}},
            "user_types": {
                "thing": {"size": 1, "kind": "struct", "fields": {
                    "c": {"offset": 0, "type": {"kind": "base", "name": "char"}}
                }}
            },
            "enums": {},
            "symbols": {}
        }))
        .expect("a valid ISF document");
        let result = structural_document(&doc, &ValidationOptions::default(), &mut warnings);
        assert_eq!(result.outcome, GateOutcome::Fail);
        assert!(
            result.violations.iter().any(|v| v.contains("'pointer'")),
            "{:?}",
            result.violations
        );
    }

    #[test]
    fn an_enum_declaring_no_constants_is_not_judged_against_a_width_it_never_uses() {
        // Also verbatim from that table: `migrate_mode` is `size 0, base
        // "void", constants {}` -- dwarf2json's shape for an enum declared but
        // never defined in the compilation unit. There is no constant to hold,
        // so no width can fail to hold one.
        let mut warnings = Vec::new();
        let doc = doc_with(serde_json::json!({
            "enums": {"migrate_mode": {"size": 0, "base": "void", "constants": {}}}
        }));
        let result = structural_document(&doc, &ValidationOptions::default(), &mut warnings);
        assert_eq!(result.outcome, GateOutcome::Pass, "{}", result.detail);
        assert!(
            warnings
                .iter()
                .any(|w| w.contains("migrate_mode") && w.contains("no constants")),
            "the empty enum should still be recorded, got {warnings:?}"
        );
    }

    #[test]
    fn an_enum_with_constants_and_no_width_is_admitted_with_a_caveat() {
        // An unstated width is not a wrong width. The enum is real; only its
        // underlying type went unrecorded, and nothing else in the document
        // depends on it. Refusing the whole table over one enum no plugin
        // touches is the over-correction; refusing to hand back a VALUE for it
        // is not, and that refusal lives in `read_member_unsigned` -- see
        // `crate::table`'s
        // `reading_a_member_typed_by_an_enum_of_unstated_width_fails_closed`.
        let gate = gate_for(serde_json::json!({
            "enums": {"real": {"size": 0, "base": "void", "constants": {"ONE": 1}}}
        }));
        assert_eq!(gate.outcome, GateOutcome::Pass, "{:?}", gate.violations);
        let caveat = gate
            .caveats
            .iter()
            .find(|c| c.contains("'real'"))
            .unwrap_or_else(|| panic!("the caveat must name the enum: {:?}", gate.caveats));
        assert!(
            caveat.contains("width is unstated") && caveat.contains("fails closed"),
            "the caveat must say both what is unknown and where it is refused: {caveat}"
        );
    }

    #[test]
    fn an_enum_whose_base_type_is_absent_altogether_is_still_refused() {
        // The neighbouring case that must NOT move. A base type the document
        // never declares is not an unstated width, it is a dangling reference:
        // nothing establishes the sign either, so a constant cannot even be
        // told from its two's complement.
        let found = violations(serde_json::json!({
            "enums": {"real": {"size": 4, "base": "nowhere", "constants": {"ONE": 1}}}
        }));
        assert!(
            found
                .iter()
                .any(|v| v.contains("'real'") && v.contains("nowhere")),
            "a missing base type must stay fatal, got {found:?}"
        );
    }

    #[test]
    fn a_member_declared_past_its_type_is_admitted_with_a_caveat_naming_it() {
        // Volatility's netscan overlay packs, reduced to the shape that matters:
        // `_TCP_ENDPOINT.Owner` at 752 inside a type whose declared size is 632.
        // 23 of the 25 packs upstream ships look like this, the offsets track
        // the real structure build by build, and refusing them meant netscan and
        // netstat produced nothing on every modern Windows build.
        let gate = gate_for(serde_json::json!({
            "user_types": {
                "_TCP_ENDPOINT": {
                    "size": 632,
                    "kind": "struct",
                    "fields": {
                        "Owner": {"offset": 752, "type": {"kind": "base", "name": "pointer"}}
                    }
                }
            }
        }));
        assert_eq!(gate.outcome, GateOutcome::Pass, "{:?}", gate.violations);
        let caveat = gate
            .caveats
            .iter()
            .find(|c| c.contains("_TCP_ENDPOINT") && c.contains("Owner"))
            .unwrap_or_else(|| {
                panic!(
                    "the caveat must name the type and member: {:?}",
                    gate.caveats
                )
            });
        assert!(
            caveat.contains("752") && caveat.contains("632"),
            "the caveat must carry both numbers, so the reservation can be checked against \
             the file: {caveat}"
        );
        assert!(
            caveat.contains("stub"),
            "the caveat must say which of the two the gate is disbelieving: {caveat}"
        );
    }

    #[test]
    fn a_caveat_does_not_turn_a_violation_into_an_admission() {
        // The two channels must stay independent: a document that is both
        // untidy and wrong is still refused, and the refusal still carries the
        // violation that caused it.
        let gate = gate_for(serde_json::json!({
            "user_types": {
                "_TCP_ENDPOINT": {
                    "size": 632,
                    "kind": "struct",
                    "fields": {
                        "Owner": {"offset": 752, "type": {"kind": "base", "name": "pointer"}}
                    }
                }
            },
            "enums": {"real": {"size": 4, "base": "nowhere", "constants": {"ONE": 1}}}
        }));
        assert_eq!(gate.outcome, GateOutcome::Fail);
        assert!(gate.has_caveats(), "the caveat must survive the rejection");
        assert!(gate.violations.iter().any(|v| v.contains("nowhere")));
        assert!(
            gate.detail.contains("violation") && gate.detail.contains("caveat"),
            "the detail must report both: {}",
            gate.detail
        );
    }
}

#[cfg(test)]
mod not_applicable_tests {
    use super::*;

    fn report(outcomes: Vec<GateResult>) -> AdmissionReport {
        AdmissionReport {
            gates: outcomes,
            warnings: Vec::new(),
        }
    }

    #[test]
    fn a_check_that_cannot_apply_to_this_build_does_not_hold_the_table_unverified() {
        // Windows XP has no `_KUSER_SHARED_DATA.NtBuildNumber`; the build is
        // read from `NtBuildLab`. Against the unfixed code this member's
        // absence was `NotEvaluated`, every XP capture sat at `Unverified`
        // forever, and every analysis stage was stamped short of the evidence
        // when the stages had run in full.
        let r = report(vec![
            GateResult::pass(Gate::Structural, "structural", "ok"),
            GateResult::pass(Gate::Identity, "identity", "ok"),
            GateResult::pass(Gate::Architecture, "architecture", "ok"),
            GateResult::pass(Gate::ImageSanity, "windows_nt_version", "ok"),
            GateResult::not_applicable(
                Gate::ImageSanity,
                "windows_build_number",
                "this build has no NtBuildNumber member",
            ),
            GateResult::pass(Gate::Producer, "producer", "ok"),
        ]);
        assert_eq!(r.state(), AdmissionState::Verified);
        assert!(r.unproved_checks().is_empty());
        assert_eq!(r.inapplicable_checks(), vec!["windows_build_number"]);
    }

    #[test]
    fn a_check_that_could_not_decide_still_holds_the_table_unverified() {
        // The hole this must not open. `Inconclusive` means the member EXISTS
        // and the evidence would not yield it — a real gap. If a damaged image
        // could reach `Verified` through this door, the whole grade would be
        // worthless.
        let r = report(vec![
            GateResult::pass(Gate::Structural, "structural", "ok"),
            GateResult::inconclusive(Gate::ImageSanity, "windows_nt_version", "unreadable"),
        ]);
        assert_eq!(r.state(), AdmissionState::Unverified);
        assert_eq!(r.unproved_checks(), vec!["windows_nt_version"]);
        assert!(r.inapplicable_checks().is_empty());
    }

    #[test]
    fn a_check_that_never_ran_still_holds_the_table_unverified() {
        // `NotEvaluated` keeps its old meaning: nothing was learned, and
        // something that should have been proved was not.
        let r = report(vec![
            GateResult::pass(Gate::Structural, "structural", "ok"),
            GateResult::not_evaluated(Gate::Producer, "producer", "no producer recorded"),
        ]);
        assert_eq!(r.state(), AdmissionState::Unverified);
        assert_eq!(r.unproved_checks(), vec!["producer"]);
    }

    #[test]
    fn a_failed_check_is_still_fatal_however_many_others_do_not_apply() {
        let r = report(vec![
            GateResult::not_applicable(Gate::ImageSanity, "windows_build_number", "absent"),
            {
                let mut f = GateResult::fail(Gate::ImageSanity, "windows_nt_version", "wrong");
                f.violate("NtMajorVersion reads 99");
                f
            },
        ]);
        assert_eq!(r.state(), AdmissionState::Rejected);
    }

    #[test]
    fn inapplicable_and_unproved_are_reported_apart() {
        // An examiner reading "this check did not apply" and "this check could
        // not decide" must not see the same words: one says the operating
        // system never had the field, the other says the evidence is damaged.
        let r = report(vec![
            GateResult::not_applicable(Gate::ImageSanity, "windows_build_number", "absent"),
            GateResult::inconclusive(Gate::ImageSanity, "windows_nt_version", "unreadable"),
        ]);
        assert_eq!(r.unproved_checks(), vec!["windows_nt_version"]);
        assert_eq!(r.inapplicable_checks(), vec!["windows_build_number"]);
        assert_ne!(
            GateOutcome::NotApplicable.as_str(),
            GateOutcome::NotEvaluated.as_str()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::isf::IsfDocument;

    fn parse(json: &str) -> IsfDocument {
        IsfDocument::parse(json.as_bytes()).unwrap_or_else(|e| panic!("fixture must parse: {e}"))
    }

    fn check(json: &str) -> (GateResult, Vec<String>) {
        let doc = parse(json);
        let mut warnings = Vec::new();
        let gate = structural_document(&doc, &ValidationOptions::new(), &mut warnings);
        (gate, warnings)
    }

    /// A small, entirely valid Linux ISF.
    const VALID: &str = r#"{
      "metadata": {
        "format": "6.2.0",
        "producer": {"name": "dwarf2json", "version": "0.9.0"},
        "linux": {"symbols": [], "types": []}
      },
      "base_types": {
        "pointer": {"size": 8, "signed": false, "kind": "int", "endian": "little"},
        "int": {"size": 4, "signed": true, "kind": "int", "endian": "little"},
        "unsigned int": {"size": 4, "signed": false, "kind": "int", "endian": "little"},
        "char": {"size": 1, "signed": true, "kind": "char", "endian": "little"},
        "void": {"size": 0, "signed": false, "kind": "void", "endian": "little"}
      },
      "user_types": {
        "task_struct": {"size": 32, "kind": "struct", "fields": {
          "parent": {"offset": 0, "type": {"kind": "pointer",
                     "subtype": {"kind": "struct", "name": "task_struct"}}},
          "pid": {"offset": 8, "type": {"kind": "base", "name": "int"}},
          "comm": {"offset": 12, "type": {"kind": "array", "count": 16,
                   "subtype": {"kind": "base", "name": "char"}}}
        }}
      },
      "enums": {
        "pid_type": {"size": 4, "base": "unsigned int",
                     "constants": {"PIDTYPE_PID": 0, "PIDTYPE_TGID": 1}}
      },
      "symbols": {
        "init_task": {"address": 18446744071578845184,
                      "type": {"kind": "struct", "name": "task_struct"}}
      }
    }"#;

    #[test]
    fn a_valid_document_is_admitted() {
        let (gate, warnings) = check(VALID);
        assert_eq!(gate.outcome, GateOutcome::Pass, "{:?}", gate.violations);
        assert!(warnings.is_empty(), "{warnings:?}");
    }

    #[test]
    fn a_document_with_no_pointer_base_type_is_refused() {
        let json = VALID.replace(
            r#""pointer": {"size": 8, "signed": false, "kind": "int", "endian": "little"},"#,
            "",
        );
        let (gate, _) = check(&json);
        assert_eq!(gate.outcome, GateOutcome::Fail);
        assert!(
            gate.violations.iter().any(|v| v.contains("'pointer'")),
            "{:?}",
            gate.violations
        );
    }

    #[test]
    fn a_pointer_that_is_neither_four_nor_eight_bytes_is_refused() {
        let json = VALID.replace(r#""pointer": {"size": 8"#, r#""pointer": {"size": 6"#);
        let (gate, _) = check(&json);
        assert!(gate
            .violations
            .iter()
            .any(|v| v.contains("neither 4 nor 8")));
    }

    #[test]
    fn a_repeated_member_name_is_refused_naming_the_type_and_the_member() {
        let json = VALID.replace(
            r#""pid": {"offset": 8, "type": {"kind": "base", "name": "int"}},"#,
            r#""pid": {"offset": 8, "type": {"kind": "base", "name": "int"}},
               "pid": {"offset": 20, "type": {"kind": "base", "name": "int"}},"#,
        );
        let (gate, _) = check(&json);
        assert_eq!(gate.outcome, GateOutcome::Fail);
        let violation = gate
            .violations
            .iter()
            .find(|v| v.contains("more than once"))
            .expect("the duplicate must be reported");
        assert!(violation.contains("task_struct"), "{violation}");
        assert!(violation.contains("pid"), "{violation}");
    }

    #[test]
    fn a_member_beyond_the_end_of_its_own_struct_is_recorded_but_not_refused() {
        // This was a refusal until the netscan overlays were measured. Of the
        // 25 packs Volatility ships, 23 declare a member past its type's size,
        // and `_TCP_ENDPOINT.Owner` tracks the real structure build by build --
        // 712 at 17763, 656 at 18362, 728 at 19041, 752 at 20348 -- all inside
        // a declared size of 632. The offsets are measured; the size beside
        // them was not. Refusing on it took netscan and netstat out on every
        // modern Windows build, so the gate records the discrepancy and lets
        // the read proceed, since a read never consults the enclosing size.
        let json = VALID.replace(r#""pid": {"offset": 8"#, r#""pid": {"offset": 4096"#);
        let (gate, _) = check(&json);
        assert_eq!(gate.outcome, GateOutcome::Pass, "{:?}", gate.violations);
        let caveats = gate.caveats.join(" | ");
        assert!(
            caveats.contains("beyond the type's own size")
                && caveats.contains("task_struct")
                && caveats.contains("pid")
                && caveats.contains("4096"),
            "the out-of-bounds member must still be reported; caveats were: {caveats}"
        );
    }

    #[test]
    fn a_member_exactly_at_the_end_of_its_struct_is_allowed() {
        // A flexible array member sits at offset == size and is legitimate;
        // "beyond" means past the end, not at it.
        let json = VALID.replace(
            r#""pid": {"offset": 8, "type": {"kind": "base", "name": "int"}},"#,
            r#""tail": {"offset": 32, "type": {"kind": "array", "count": 0,
                       "subtype": {"kind": "base", "name": "char"}}},"#,
        );
        let (gate, _) = check(&json);
        assert_eq!(gate.outcome, GateOutcome::Pass, "{:?}", gate.violations);
    }

    #[test]
    fn a_zero_sized_struct_with_members_is_refused() {
        let json = VALID.replace(
            r#""task_struct": {"size": 32"#,
            r#""task_struct": {"size": 0"#,
        );
        let (gate, _) = check(&json);
        assert_eq!(gate.outcome, GateOutcome::Fail);
        assert!(gate
            .violations
            .iter()
            .any(|v| v.contains("size of 0") && v.contains("task_struct")));
    }

    #[test]
    fn an_empty_struct_with_no_members_is_allowed() {
        // Opaque forward declarations legitimately have size 0 and no members;
        // only a zero-sized type that claims members is impossible.
        let json = r#"{
          "metadata": {"format": "6.2.0"},
          "base_types": {"pointer": {"size": 8, "signed": false, "kind": "int",
                                     "endian": "little"}},
          "user_types": {"opaque_handle": {"size": 0, "kind": "struct", "fields": {}}},
          "enums": {},
          "symbols": {}
        }"#;
        let (gate, _) = check(json);
        assert_eq!(gate.outcome, GateOutcome::Pass, "{:?}", gate.violations);
    }

    #[test]
    fn an_enum_constant_that_does_not_fit_its_base_type_is_refused() {
        let json = VALID.replace(r#""PIDTYPE_TGID": 1"#, r#""PIDTYPE_TGID": 4294967296"#);
        let (gate, _) = check(&json);
        assert_eq!(gate.outcome, GateOutcome::Fail);
        let violation = gate
            .violations
            .iter()
            .find(|v| v.contains("does not fit"))
            .expect("the oversized constant must be reported");
        assert!(violation.contains("pid_type"), "{violation}");
        assert!(violation.contains("PIDTYPE_TGID"), "{violation}");
    }

    #[test]
    fn a_negative_constant_in_an_unsigned_enum_is_refused() {
        let json = VALID.replace(r#""PIDTYPE_PID": 0"#, r#""PIDTYPE_PID": -1"#);
        let (gate, _) = check(&json);
        assert_eq!(gate.outcome, GateOutcome::Fail);
        assert!(gate.violations.iter().any(|v| v.contains("does not fit")));
    }

    #[test]
    fn a_negative_constant_in_a_signed_enum_is_allowed() {
        let json = VALID
            .replace(r#""base": "unsigned int""#, r#""base": "int""#)
            .replace(r#""PIDTYPE_PID": 0"#, r#""PIDTYPE_PID": -1"#);
        let (gate, _) = check(&json);
        assert_eq!(gate.outcome, GateOutcome::Pass, "{:?}", gate.violations);
    }

    #[test]
    fn an_enum_whose_base_type_is_missing_is_refused() {
        let json = VALID.replace(r#""base": "unsigned int""#, r#""base": "u32""#);
        let (gate, _) = check(&json);
        assert_eq!(gate.outcome, GateOutcome::Fail);
        assert!(gate
            .violations
            .iter()
            .any(|v| v.contains("pid_type") && v.contains("u32")));
    }

    #[test]
    fn an_enum_size_disagreeing_with_its_base_is_a_warning_not_a_refusal() {
        let json = VALID.replace(r#""pid_type": {"size": 4"#, r#""pid_type": {"size": 8"#);
        let (gate, warnings) = check(&json);
        assert_eq!(gate.outcome, GateOutcome::Pass, "{:?}", gate.violations);
        assert!(warnings.iter().any(|w| w.contains("the base type governs")));
    }

    #[test]
    fn a_symbol_address_that_is_not_an_exact_integer_is_refused_by_name() {
        let json = VALID.replace(
            r#""address": 18446744071578845184"#,
            r#""address": 1.8446744e19"#,
        );
        let (gate, _) = check(&json);
        assert_eq!(gate.outcome, GateOutcome::Fail);
        let violation = gate
            .violations
            .iter()
            .find(|v| v.contains("init_task"))
            .expect("the offending symbol must be named");
        assert!(violation.contains("never rounded"), "{violation}");
    }

    #[test]
    fn a_format_version_outside_the_supported_range_is_refused() {
        for version in ["3.9.0", "7.0.0", "6.4.0"] {
            let json = VALID.replace(r#""format": "6.2.0""#, &format!(r#""format": "{version}""#));
            let (gate, _) = check(&json);
            assert_eq!(gate.outcome, GateOutcome::Fail, "{version} must be refused");
            assert!(gate
                .violations
                .iter()
                .any(|v| v.contains("outside the supported range")));
        }
    }

    #[test]
    fn the_four_zero_zero_floor_admits_the_pool_header_fragments() {
        let json = r#"{
          "metadata": {"format": "4.0.0"},
          "base_types": {"pointer": {"size": 8, "signed": false, "kind": "int", "endian": "little"},
                         "unsigned long long": {"size": 8, "signed": false, "kind": "int",
                                                "endian": "little"}},
          "user_types": {"_POOL_HEADER": {"size": 16, "kind": "struct", "fields": {
             "PoolTag": {"offset": 4, "type": {"kind": "base", "name": "unsigned long long"}}}}},
          "enums": {},
          "symbols": {}
        }"#;
        let (gate, _) = check(json);
        assert_eq!(gate.outcome, GateOutcome::Pass, "{:?}", gate.violations);
    }

    #[test]
    fn a_metadata_block_with_two_operating_systems_is_refused() {
        let json = VALID.replace(
            r#""linux": {"symbols": [], "types": []}"#,
            r#""linux": {"symbols": [], "types": []}, "windows": {}"#,
        );
        let (gate, _) = check(&json);
        assert_eq!(gate.outcome, GateOutcome::Fail);
        assert!(gate
            .violations
            .iter()
            .any(|v| v.contains("operating systems")));
    }

    #[test]
    fn a_bitfield_wider_than_any_integer_is_refused() {
        let json = VALID.replace(
            r#""pid": {"offset": 8, "type": {"kind": "base", "name": "int"}},"#,
            r#""flag": {"offset": 8, "type": {"kind": "bitfield", "bit_position": 200,
                       "bit_length": 1, "type": {"kind": "base", "name": "int"}}},"#,
        );
        let (gate, _) = check(&json);
        assert_eq!(gate.outcome, GateOutcome::Fail);
        assert!(gate.violations.iter().any(|v| v.contains("bitfield")));
    }

    #[test]
    fn gate_two_refuses_a_table_whose_identity_differs_from_the_image() {
        let identity = crate::identify::identify(
            VALID.as_bytes(),
            &crate::identify::IdentifyOptions::default(),
        )
        .expect("identifies");
        let options = ValidationOptions::new().expect_identifier("Linux version 5.15.0");
        let result = identity_of(&identity, &options);
        assert_eq!(result.outcome, GateOutcome::NotEvaluated);

        // With an identity on both sides, byte equality decides it.
        let mut identity = identity;
        identity.identifier = Some("Linux version 6.1.0".to_string());
        let result = identity_of(&identity, &options);
        assert_eq!(result.outcome, GateOutcome::Fail);
        assert!(result.violations[0].contains("5.15.0"));

        let options = ValidationOptions::new().expect_identifier("Linux version 6.1.0");
        assert_eq!(identity_of(&identity, &options).outcome, GateOutcome::Pass);
    }

    /// Alias so the test above reads as prose without shadowing the module
    /// function name.
    fn identity_of(id: &IsfIdentity, options: &ValidationOptions) -> GateResult {
        super::identity(id, options)
    }

    #[test]
    fn gate_three_refuses_a_pointer_width_that_contradicts_the_paging_mode() {
        let doc = parse(VALID);
        let options = ValidationOptions::new().expect_architecture(Architecture::X86);
        let result = architecture(&doc, &options);
        assert_eq!(result.outcome, GateOutcome::Fail);
        assert!(result.violations[0].contains("4-byte pointers"));

        let options = ValidationOptions::new().expect_architecture(Architecture::X64);
        assert_eq!(architecture(&doc, &options).outcome, GateOutcome::Pass);
    }

    #[test]
    fn gate_three_refuses_a_pointer_width_that_contradicts_the_machine_type() {
        let json = VALID.replace(
            r#""linux": {"symbols": [], "types": []}"#,
            r#""windows": {"pdb": {"GUID": "00", "age": 1, "database": "nt.pdb",
                                   "machine_type": 332}}"#,
        );
        let doc = parse(&json);
        let result = architecture(&doc, &ValidationOptions::new());
        assert_eq!(result.outcome, GateOutcome::Fail);
        assert!(result.violations[0].contains("machine type"));
    }

    #[test]
    fn gate_three_says_so_when_it_has_nothing_to_check_against() {
        let doc = parse(VALID);
        let result = architecture(&doc, &ValidationOptions::new());
        assert_eq!(result.outcome, GateOutcome::NotEvaluated);
    }

    #[test]
    fn gate_five_refuses_a_known_bad_producer_only_with_its_marker() {
        let bad = VALID
            .replace(r#""version": "0.9.0""#, r#""version": "0.8.0""#)
            .replace(
                r#""init_task": {"#,
                r#""rust_helper_BUG": {"address": 1}, "init_task": {"#,
            );
        let doc = parse(&bad);
        let result = producer(&doc);
        assert_eq!(result.outcome, GateOutcome::Fail);
        assert!(result.violations[0].contains("rust_helper"));

        // The old version alone, without the marker, is not grounds to refuse.
        let old_only = VALID.replace(r#""version": "0.9.0""#, r#""version": "0.8.0""#);
        assert_eq!(producer(&parse(&old_only)).outcome, GateOutcome::Pass);

        // And the current version with the marker is fine.
        let marker_only = VALID.replace(
            r#""init_task": {"#,
            r#""rust_helper_BUG": {"address": 1}, "init_task": {"#,
        );
        assert_eq!(producer(&parse(&marker_only)).outcome, GateOutcome::Pass);
    }

    #[test]
    fn a_producer_name_in_another_case_does_not_walk_past_gate_five() {
        // The producer string is written by the file being checked. An exact,
        // case-sensitive comparison means `"DWARF2JSON "` is answered with
        // "not on the known-bad list", which is a positive claim the gate would
        // not be entitled to make.
        let bad = VALID
            .replace(r#""name": "dwarf2json""#, r#""name": "  DWARF2JSON ""#)
            .replace(r#""version": "0.9.0""#, r#""version": "0.8.0""#)
            .replace(
                r#""init_task": {"#,
                r#""rust_helper_BUG": {"address": 1}, "init_task": {"#,
            );
        let result = producer(&parse(&bad));
        assert_eq!(result.outcome, GateOutcome::Fail, "{result:?}");
        assert!(result.violations[0].contains("rust_helper"), "{result:?}");
    }

    #[test]
    fn a_name_declared_in_two_blocks_is_recorded_as_ambiguous() {
        let json = VALID.replace(
            r#""task_struct": {"size": 32,"#,
            r#""int": {"size": 128, "kind": "struct", "fields": {}}, "task_struct": {"size": 32,"#,
        );
        let (gate, warnings) = check(&json);
        assert_eq!(gate.outcome, GateOutcome::Pass, "{:?}", gate.violations);
        assert!(
            warnings
                .iter()
                .any(|w| w.contains("'int'") && w.contains("ambiguous")),
            "{warnings:?}"
        );
    }

    #[test]
    fn a_report_that_recorded_nothing_has_proved_nothing() {
        // An empty gate list is "no check ran", which must never render as
        // "every check passed": `verified` is a word a report quotes.
        let report = AdmissionReport::default();
        assert_eq!(report.state(), AdmissionState::Unverified);
        assert_eq!(report.state().symbol_confidence(), "unverified");
        assert!(!report.is_rejected());
    }

    #[test]
    fn a_report_with_an_unevaluated_check_is_unverified_not_verified() {
        let mut report = AdmissionReport::default();
        report.record(GateResult::pass(Gate::Structural, "structural", "fine"));
        report.record(image_sanity_not_evaluated());
        assert_eq!(report.state(), AdmissionState::Unverified);
        assert!(report.state().permits_analysis());
        assert_eq!(report.state().symbol_confidence(), "unverified");
        assert_eq!(report.unproved_checks(), vec!["image_sanity"]);
    }

    #[test]
    fn a_report_with_an_inconclusive_check_is_unverified_not_rejected() {
        // A smeared capture must remain analysable: damaged evidence is not a
        // wrong symbol table.
        let mut report = AdmissionReport::default();
        report.record(GateResult::pass(Gate::Structural, "structural", "fine"));
        report.record(GateResult::inconclusive(
            Gate::ImageSanity,
            "active_process_links_close",
            "the process list does not close; the capture is smeared",
        ));
        assert_eq!(report.state(), AdmissionState::Unverified);
        assert!(report.state().permits_analysis());
    }

    #[test]
    fn a_report_with_a_failure_is_rejected_and_names_the_gate() {
        let mut report = AdmissionReport::default();
        report.record(GateResult::pass(Gate::Structural, "structural", "fine"));
        let mut failing = GateResult::fail(Gate::Identity, "identity", "wrong build");
        failing.violate("the image identifies as A and the ISF as B");
        report.record(failing);

        assert_eq!(report.state(), AdmissionState::Rejected);
        assert!(!report.state().permits_analysis());
        let rendered = report.to_string();
        assert!(rendered.contains("gate 2"), "{rendered}");
        assert!(rendered.contains("identity"), "{rendered}");
        assert_eq!(report.to_json()["state"], "rejected");
    }

    #[test]
    fn violations_are_capped_but_counted() {
        let mut result = GateResult::pass(Gate::Structural, "structural", "fine");
        for index in 0..MAX_RECORDED_VIOLATIONS + 25 {
            result.violate(format!("violation {index}"));
        }
        assert_eq!(result.violations.len(), MAX_RECORDED_VIOLATIONS);
        assert_eq!(result.suppressed_violations, 25);
        assert_eq!(
            result.violation_count(),
            MAX_RECORDED_VIOLATIONS as u64 + 25
        );
    }

    #[test]
    fn caveats_are_capped_but_counted_and_never_change_the_outcome() {
        // The same bound as violations, for the same reason: a hostile file
        // with a million untidy members must not turn an admission into a
        // memory-exhaustion event. And the count is kept even when the text is
        // not, so a report can never understate how much it tolerated.
        let mut result = GateResult::pass(Gate::Structural, "structural", "fine");
        for index in 0..MAX_RECORDED_VIOLATIONS + 25 {
            result.caveat(format!("caveat {index}"));
        }
        assert_eq!(result.outcome, GateOutcome::Pass, "a caveat must not fail");
        assert_eq!(result.caveats.len(), MAX_RECORDED_VIOLATIONS);
        assert_eq!(result.suppressed_caveats, 25);
        assert_eq!(result.caveat_count(), MAX_RECORDED_VIOLATIONS as u64 + 25);
    }

    #[test]
    fn a_caveat_reaches_the_report_json_and_the_rendered_report() {
        // The whole risk of the relaxation is a caveat that disappears. This is
        // the route it has to survive: gate result -> AdmissionReport ->
        // to_json, which is what
        // `seance_plugin_memory_linux::LinuxProfile::to_json` writes into
        // `symbols_admission` and what `SymbolTable::to_json` puts in artifact
        // metadata.
        let mut report = AdmissionReport::default();
        let mut structural = GateResult::pass(Gate::Structural, "structural", "coherent");
        structural.caveat("type '_TCP_ENDPOINT' member 'Owner' lies at offset 752");
        report.record(structural);
        report.record(GateResult::pass(Gate::Identity, "identity", "matched"));

        // Admitted, and admitted with the reservation on the record.
        assert_eq!(report.state(), AdmissionState::Verified);
        assert!(report.state().permits_analysis());
        assert!(report.has_caveats());
        assert_eq!(report.caveat_count(), 1);

        let json = report.to_json();
        assert_eq!(json["admitted_with_caveats"], true);
        assert_eq!(json["caveat_count"], 1);
        let top = json["caveats"][0]
            .as_str()
            .expect("the caveat must be at the top level, beside the state");
        assert!(top.contains("gate 1"), "{top}");
        assert!(top.contains("structural"), "{top}");
        assert!(top.contains("_TCP_ENDPOINT"), "{top}");
        assert_eq!(
            json["gates"][0]["caveats"][0],
            "type '_TCP_ENDPOINT' member 'Owner' lies at offset 752",
            "the per-gate copy must carry the same text, so the two views cannot drift"
        );

        // And an examiner reading only the one-line summary still sees it.
        let rendered = report.to_string();
        assert!(rendered.contains("admitted with 1 caveat"), "{rendered}");
        assert!(rendered.contains("_TCP_ENDPOINT"), "{rendered}");
    }

    #[test]
    fn a_report_with_no_caveats_says_so_rather_than_saying_nothing() {
        let mut report = AdmissionReport::default();
        report.record(GateResult::pass(Gate::Structural, "structural", "coherent"));
        let json = report.to_json();
        assert_eq!(json["admitted_with_caveats"], false);
        assert_eq!(json["caveat_count"], 0);
        assert!(json["caveats"].as_array().expect("an array").is_empty());
        assert!(!report.to_string().contains("caveat"));
    }

    #[test]
    fn integer_fitting_matches_the_declared_width_and_sign() {
        assert!(fits(255, 1, false));
        assert!(!fits(256, 1, false));
        assert!(fits(127, 1, true));
        assert!(!fits(128, 1, true));
        assert!(fits(-128, 1, true));
        assert!(!fits(-129, 1, true));
        assert!(fits(i128::from(u64::MAX), 8, false));
        assert!(!fits(-1, 8, false));
        assert!(fits(i128::from(i64::MIN), 8, true));
        assert!(!fits(1, 0, false), "a zero-width base holds nothing");
        assert!(!fits(1, 16, false), "no enum base is 16 bytes wide");
    }
}
