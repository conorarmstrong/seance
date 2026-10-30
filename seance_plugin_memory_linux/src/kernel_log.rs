//! The kernel log ring buffer (`dmesg`).
//!
//! At parity with Volatility 3's `linux.dmesg`. The kernel keeps its printed
//! messages in a ring buffer whose shape changed twice:
//!
//! * **Flat ring** (before Linux 3.5): a plain character ring at `log_buf`,
//!   `log_buf_len` bytes long, written up to `log_end`. Each line is
//!   `<priority>[ timestamp] message`. This is the shape of the Debian 3.2
//!   corpus, and the one path validated against real evidence.
//! * **Structured ring** (3.5–5.10): a ring of `printk_log` records, each a
//!   fixed header (`ts_nsec`, `len`, `text_len`, `level`, `facility`) followed by
//!   its message bytes, indexed by `log_first_idx`/`log_next_idx`. Decoded here,
//!   but exercised only by synthetic fixtures — the corpus is pre-3.5 — which the
//!   record states (`validated_on_corpus: false`).
//! * **printk_ringbuffer** (5.10+): a different implementation this build does
//!   not decode; it is refused **by name** rather than reported as an empty log.
//!
//! A ring that has wrapped has overwritten its oldest messages, and this stage
//! cannot recover them — only what is still resident. That limit rides on every
//! record.

use seance_core::io::IncompleteReason;
use seance_memory::binding::{BuildBinding, Field, MemberSet, MemberSpec, TypeSpec};
use seance_memory::meta::Incomplete;
use seance_memory::object::StructReader;
use seance_symbols::SymbolTable;

use crate::error::StageError;
use crate::module::STAGE_LINUX_KERNEL_LOG;
use crate::profile::LinuxProfile;
use crate::read::{decode_nul_terminated, signed_to_json};

/// Most bytes of the ring this stage will read.
pub const MAX_RING_BYTES: u64 = 8 * 1024 * 1024;
/// Most lines/records this stage will emit.
pub const MAX_LINES: usize = 200_000;

/// Syslog level names, indexed 0..7.
const LEVELS: [&str; 8] = [
    "emerg", "alert", "crit", "err", "warn", "notice", "info", "debug",
];
/// Syslog facility names, indexed 0..11.
const FACILITIES: [&str; 12] = [
    "kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news", "uucp", "cron", "authpriv",
    "ftp",
];

fn level_name(value: i64) -> Option<&'static str> {
    LEVELS.get(value as usize).copied()
}
fn facility_name(value: i64) -> Option<&'static str> {
    FACILITIES.get(value as usize).copied()
}

/// Everything the kernel-log stage may read out of the symbol table.
///
/// Nothing is required: this stage discriminates between ring shapes at run time
/// from which symbols and types are present, so binding never refuses it.
pub const LOG_LAYOUT: MemberSet = MemberSet::new(
    STAGE_LINUX_KERNEL_LOG,
    &[
        TypeSpec::new("log_record", &["printk_log", "log"]),
        TypeSpec::new("printk_ringbuffer", &["printk_ringbuffer"]),
    ],
    &[
        MemberSpec::new("ts_nsec", &["printk_log", "log"], &["ts_nsec"]),
        MemberSpec::new("rec_len", &["printk_log", "log"], &["len"]),
        MemberSpec::new("text_len", &["printk_log", "log"], &["text_len"]),
        MemberSpec::new("facility", &["printk_log", "log"], &["facility"]),
        MemberSpec::new("level", &["printk_log", "log"], &["level"]),
    ],
);

/// Caps for one log survey.
#[derive(Debug, Clone)]
pub struct LogConfig {
    pub max_bytes: u64,
    pub max_lines: usize,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            max_bytes: MAX_RING_BYTES,
            max_lines: MAX_LINES,
        }
    }
}

/// Which ring shape the stage found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LogOutcome {
    FlatWalked,
    StructuredWalked,
    RingbufferNotDecoded,
    NoRingSymbols,
}

impl LogOutcome {
    fn is_a_gap(&self) -> bool {
        matches!(
            self,
            LogOutcome::RingbufferNotDecoded | LogOutcome::NoRingSymbols
        )
    }
    fn class(&self) -> &'static str {
        match self {
            LogOutcome::FlatWalked => "flat_ring",
            LogOutcome::StructuredWalked => "structured_ring",
            LogOutcome::RingbufferNotDecoded => "ringbuffer_not_decoded",
            LogOutcome::NoRingSymbols => "no_ring_symbols",
        }
    }
    fn detail(&self) -> String {
        match self {
            LogOutcome::FlatWalked => "the flat log ring was walked".to_string(),
            LogOutcome::StructuredWalked => "the structured log-record ring was walked".to_string(),
            LogOutcome::RingbufferNotDecoded => {
                "this kernel uses the 5.10+ printk_ringbuffer, which this build of Séance does not \
                 decode; the log exists and is NOT empty"
                    .to_string()
            }
            LogOutcome::NoRingSymbols => {
                "this image declares none of the kernel-log ring symbols, so the log could not be \
                 located"
                    .to_string()
            }
        }
    }
    fn to_json(&self) -> serde_json::Value {
        serde_json::json!({ "class": self.class(), "detail": self.detail(), "is_a_gap": self.is_a_gap() })
    }
}

/// One log line.
#[derive(Debug, Clone)]
pub struct LogLine {
    pub source: &'static str,
    pub message: Field<String>,
    pub message_well_formed: bool,
    pub level: Field<i64>,
    pub facility: Field<i64>,
    pub timestamp_seconds: Field<String>,
    pub ts_nsec: Field<u64>,
    pub record_offset: Field<i64>,
}

impl LogLine {
    fn unreadable_fields(&self) -> Vec<&'static str> {
        let mut out = Vec::new();
        if self.message.is_unavailable() {
            out.push("message");
        }
        out
    }

    fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "source": self.source,
            "message": self.message.to_json(),
            "message_well_formed": self.message_well_formed,
            "level": signed_to_json(&self.level),
            "level_name": self.level.known().and_then(|l| level_name(*l)),
            "facility": signed_to_json(&self.facility),
            "facility_name": self.facility.known().and_then(|f| facility_name(*f)),
            "timestamp_seconds": self.timestamp_seconds.to_json(),
            "ts_nsec": self.ts_nsec.to_json(),
            "record_offset": signed_to_json(&self.record_offset),
            "unreadable_fields": self.unreadable_fields(),
        })
    }
}

/// The whole recovered log, and everything that qualifies it.
#[derive(Debug, Clone)]
pub struct LogRingSurvey {
    pub lines: Vec<LogLine>,
    pub outcome: LogOutcome,
    pub ring_base: Field<u64>,
    pub ring_source: Option<&'static str>,
    pub log_buf_len: Field<i64>,
    pub validated_on_corpus: bool,
    pub walk_note: Option<String>,
    pub layout: serde_json::Value,
}

impl LogRingSurvey {
    pub fn line_count(&self) -> usize {
        self.lines.len()
    }

    pub fn is_complete(&self) -> bool {
        !self.outcome.is_a_gap()
            && self.walk_note.is_none()
            && !self.lines.iter().any(|l| !l.unreadable_fields().is_empty())
    }

    pub fn incomplete(&self) -> Vec<Incomplete> {
        let mut out = Vec::new();
        if self.outcome.is_a_gap() {
            out.push(Incomplete::new(
                IncompleteReason::ShortRead,
                self.outcome.detail(),
            ));
        }
        if let Some(note) = &self.walk_note {
            out.push(Incomplete::new(
                IncompleteReason::ShortRead,
                format!("walking the kernel log ring: {note}"),
            ));
        }
        for line in &self.lines {
            if !line.unreadable_fields().is_empty() {
                out.push(Incomplete::new(
                    IncompleteReason::ShortRead,
                    "a log record's message bytes lay in memory the acquisition did not capture"
                        .to_string(),
                ));
            }
        }
        out
    }

    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "ring_shape": self.outcome.class(),
            "ring_base": self.ring_base.to_json_address(),
            "ring_source": self.ring_source,
            "log_buf_len": signed_to_json(&self.log_buf_len),
            "validated_on_corpus": self.validated_on_corpus,
            "line_count": self.lines.len(),
            "complete": self.is_complete(),
            "outcome": self.outcome.to_json(),
            "walk_note": self.walk_note,
            "levels_reference": LEVELS,
            "facilities_reference": FACILITIES,
            "ring_scope_note": "Only messages still resident in the kernel ring are recoverable; a \
                ring that wrapped has overwritten its oldest messages and this stage cannot recover \
                them.",
            "structured_synthetic_note": "The structured 3.5–5.10 record ring is decoded but, on \
                this image, is validated only against synthetic fixtures unless validated_on_corpus \
                is true.",
            "lines": self.lines.iter().map(LogLine::to_json).collect::<Vec<_>>(),
            "layout": self.layout,
            "incomplete": self.incomplete().iter().map(Incomplete::to_json).collect::<Vec<_>>(),
        })
    }
}

/// Bind the kernel-log stage's declared layout.
pub fn bind(profile: &LinuxProfile) -> Result<BuildBinding, StageError> {
    let reader = crate::tasks::reader_for(profile);
    Ok(LOG_LAYOUT.bind(&reader)?)
}

/// Recover the kernel log.
pub fn survey_kernel_log(
    profile: &LinuxProfile,
    layout: &BuildBinding,
    config: &LogConfig,
) -> Result<LogRingSurvey, StageError> {
    let reader = crate::tasks::reader_for(profile);
    survey_with_reader(&reader, &profile.symbols, layout, config)
}

fn empty(outcome: LogOutcome, layout: &BuildBinding) -> LogRingSurvey {
    LogRingSurvey {
        lines: Vec::new(),
        outcome,
        ring_base: Field::NotApplicable,
        ring_source: None,
        log_buf_len: Field::NotApplicable,
        validated_on_corpus: false,
        walk_note: None,
        layout: layout.to_json(),
    }
}

fn has_symbol(symbols: &SymbolTable, name: &str) -> bool {
    symbols.symbol_address(name).is_ok()
}

fn survey_with_reader(
    reader: &StructReader,
    symbols: &SymbolTable,
    layout: &BuildBinding,
    config: &LogConfig,
) -> Result<LogRingSurvey, StageError> {
    // Discriminate ring shape. Order matters: the newest implementation first.
    let ringbuffer = layout
        .type_of("printk_ringbuffer")
        .map(|t| t.is_declared())
        .unwrap_or(false)
        && has_symbol(symbols, "prb");
    if ringbuffer {
        return Ok(empty(LogOutcome::RingbufferNotDecoded, layout));
    }

    // The structured walk reads log_first_idx, log_next_idx and log_buf_len as
    // globals; requiring all three here is what makes those reads safe rather
    // than an `.expect` that panics — or, for log_next_idx, a silent read of
    // address 0 — on a build that declares only some of them.
    let structured = has_symbol(symbols, "log_first_idx")
        && has_symbol(symbols, "log_next_idx")
        && has_symbol(symbols, "log_buf_len")
        && layout
            .type_of("log_record")
            .map(|t| t.is_declared())
            .unwrap_or(false)
        && layout
            .member("ts_nsec")
            .map(|m| m.is_declared())
            .unwrap_or(false);
    let flat = has_symbol(symbols, "log_end") && has_symbol(symbols, "log_buf_len");

    if !structured && !flat {
        return Ok(empty(LogOutcome::NoRingSymbols, layout));
    }

    // Ring base: the log_buf pointer, else the __log_buf static buffer.
    let (ring, ring_source) = match resolve_ring(reader, symbols) {
        Some(pair) => pair,
        None => return Ok(empty(LogOutcome::NoRingSymbols, layout)),
    };

    if structured {
        walk_structured(reader, symbols, layout, config, ring, ring_source)
    } else {
        Ok(walk_flat(
            reader,
            symbols,
            layout,
            config,
            ring,
            ring_source,
        ))
    }
}

/// The ring base, from `log_buf` (a pointer) or `__log_buf` (the buffer itself).
fn resolve_ring(reader: &StructReader, symbols: &SymbolTable) -> Option<(u64, &'static str)> {
    if let Ok(addr) = symbols.symbol_address("log_buf") {
        if let Ok(pointer) = reader.read_pointer_at(addr) {
            if pointer != 0 {
                return Some((pointer, "log_buf"));
            }
        }
    }
    symbols
        .symbol_address("__log_buf")
        .ok()
        .map(|addr| (addr, "__log_buf_fallback"))
}

/// Read a 4-byte little-endian scalar global.
fn read_u32(reader: &StructReader, addr: u64) -> Field<i64> {
    match reader.read_bytes(addr, 4) {
        Ok(bytes) if bytes.len() == 4 => {
            Field::Known(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as i64)
        }
        Ok(_) => Field::Unavailable("a short read of a log global".into()),
        Err(err) => Field::Unavailable(err.to_string()),
    }
}

/// Read up to `len` bytes of the ring, page by page, stopping at the first hole.
fn read_ring(reader: &StructReader, base: u64, len: u64, cap: u64) -> (Vec<u8>, Option<String>) {
    let len = len.min(cap);
    let mut out: Vec<u8> = Vec::new();
    let mut at = base;
    let mut note = None;
    while (out.len() as u64) < len {
        let to_page_end = 0x1000 - (at & 0xFFF);
        let want = to_page_end.min(len - out.len() as u64);
        match reader.read_bytes(at, want) {
            Ok(bytes) => {
                out.extend_from_slice(&bytes);
                at = at.saturating_add(want);
            }
            Err(_) => {
                note = Some(format!(
                    "the ring became unreadable at {at:#x}; {} of {len} bytes recovered",
                    out.len()
                ));
                break;
            }
        }
    }
    (out, note)
}

fn nsec_to_seconds(nsec: u64) -> String {
    format!(
        "{}.{:06}",
        nsec / 1_000_000_000,
        (nsec % 1_000_000_000) / 1000
    )
}

fn walk_flat(
    reader: &StructReader,
    symbols: &SymbolTable,
    layout: &BuildBinding,
    config: &LogConfig,
    ring: u64,
    ring_source: &'static str,
) -> LogRingSurvey {
    let mut survey = empty(LogOutcome::FlatWalked, layout);
    survey.ring_base = Field::Known(ring);
    survey.ring_source = Some(ring_source);
    survey.validated_on_corpus = true;

    let len_field = read_u32(
        reader,
        symbols.symbol_address("log_buf_len").expect("checked"),
    );
    survey.log_buf_len = len_field.clone();
    let Some(&len) = len_field.known() else {
        survey.walk_note = Some("the ring length could not be read".into());
        return survey;
    };
    if len <= 0 {
        survey.walk_note = Some("the ring length is not positive".into());
        return survey;
    }
    let len = len as u64;
    let end = read_u32(reader, symbols.symbol_address("log_end").expect("checked"));

    let (buf, read_note) = read_ring(reader, ring, len, config.max_bytes);
    if read_note.is_some() {
        survey.walk_note = read_note;
    }

    // Determine the live content. log_end is a free-running counter; its live
    // write position is `end % len` (using the modulus, not an `& (len-1)` mask,
    // so a kernel with a non-power-of-two log buffer is still split correctly).
    // Before the first wrap (end < len) the content is simply the first `end`
    // bytes; after, the ring is rotated so the oldest surviving byte comes first.
    let content: Vec<u8> = match end.known() {
        Some(&e) if (e as u64) < len => buf.iter().copied().take(e as usize).collect(),
        Some(&e) => {
            let start = (e as u64 % len) as usize;
            if start <= buf.len() {
                let mut rotated = buf[start..].to_vec();
                rotated.extend_from_slice(&buf[..start]);
                rotated
            } else {
                // The write position lies past the bytes we could read: a hole
                // truncated the ring. Parse what we have, but say it is short.
                survey.walk_note.get_or_insert_with(|| {
                    "the log ring's write position lies past the bytes the acquisition captured"
                        .to_string()
                });
                buf.clone()
            }
        }
        // log_end could not be read, so live content cannot be told from stale
        // post-wrap remnants. Parse the whole buffer, but never as a clean read:
        // the note flips completeness so the mixed-in stale lines are declared.
        None => {
            survey.walk_note.get_or_insert_with(|| {
                "the log ring's write position (log_end) could not be read, so stale post-wrap \
                 lines cannot be separated from live ones"
                    .to_string()
            });
            buf.clone()
        }
    };

    for (index, raw) in content.split(|&b| b == b'\n').enumerate() {
        if survey.lines.len() >= config.max_lines {
            survey.walk_note = Some(format!("the line cap of {} was reached", config.max_lines));
            break;
        }
        if let Some(line) = parse_flat_line(raw, index) {
            survey.lines.push(line);
        }
    }

    survey
}

/// Parse `<priority>[ timestamp] message`, or `<priority>message`.
fn parse_flat_line(raw: &[u8], index: usize) -> Option<LogLine> {
    if raw.first() != Some(&b'<') {
        return None; // a post-wrap remnant, not a line
    }
    let gt = raw.iter().position(|&b| b == b'>')?;
    let priority: i64 = std::str::from_utf8(&raw[1..gt]).ok()?.trim().parse().ok()?;
    let rest = &raw[gt + 1..];

    let (timestamp, message_bytes) = if rest.first() == Some(&b'[') {
        if let Some(close) = rest.iter().position(|&b| b == b']') {
            let inside = std::str::from_utf8(&rest[1..close]).ok().map(str::trim);
            match inside {
                Some(ts)
                    if ts.contains('.') && ts.chars().all(|c| c.is_ascii_digit() || c == '.') =>
                {
                    let msg = &rest[close + 1..];
                    let msg = msg.strip_prefix(b" ".as_slice()).unwrap_or(msg);
                    (Field::Known(ts.to_string()), msg)
                }
                _ => (Field::NotApplicable, rest),
            }
        } else {
            (Field::NotApplicable, rest)
        }
    } else {
        (Field::NotApplicable, rest)
    };

    let (message, well_formed) = decode_nul_terminated(message_bytes);
    Some(LogLine {
        source: "flat_ring",
        message: Field::Known(message),
        message_well_formed: well_formed,
        level: Field::Known(priority & 7),
        facility: Field::Known(priority >> 3),
        timestamp_seconds: timestamp,
        ts_nsec: Field::NotApplicable,
        record_offset: Field::Known(index as i64),
    })
}

fn walk_structured(
    reader: &StructReader,
    symbols: &SymbolTable,
    layout: &BuildBinding,
    config: &LogConfig,
    ring: u64,
    ring_source: &'static str,
) -> Result<LogRingSurvey, StageError> {
    let mut survey = empty(LogOutcome::StructuredWalked, layout);
    survey.ring_base = Field::Known(ring);
    survey.ring_source = Some(ring_source);

    let rec_type = layout
        .type_of("log_record")
        .ok()
        .and_then(|t| t.type_name())
        .expect("checked declared");
    let len_field = read_u32(
        reader,
        symbols.symbol_address("log_buf_len").expect("checked"),
    );
    survey.log_buf_len = len_field.clone();
    let first = read_u32(
        reader,
        symbols.symbol_address("log_first_idx").expect("checked"),
    );
    let next = read_u32(
        reader,
        symbols.symbol_address("log_next_idx").expect("checked"),
    );

    let (Some(&len), Some(&first), Some(&next)) = (len_field.known(), first.known(), next.known())
    else {
        survey.walk_note = Some("the structured ring indices could not be read".into());
        return Ok(survey);
    };
    let (len, first, next) = (len as u64, first as u64, next as u64);

    // The live records occupy `[first, next)` when the ring has not wrapped, else
    // `[first, len)` followed by `[0, next)`. Building the regions up front means
    // a region that fills to its bound exactly — with no zero-length padding
    // record at the end — still hands off to the wrapped region rather than
    // dropping it (which a single `while cur < end` loop did).
    //
    // `first == next` is the EMPTY ring, not a full one: the printk index scheme
    // frees records from the front before the write index can catch the read
    // index, so equality only ever means no live records. Treating it as
    // fully-wrapped would walk the whole buffer and decode stale bytes left from
    // before it was cleared as live lines (CR-004).
    let regions: [(u64, u64); 2] = if first == next {
        [(0, 0), (0, 0)]
    } else if first < next {
        [(first, next), (0, 0)]
    } else {
        [(first, len), (0, next)]
    };

    'regions: for (start, region_end) in regions {
        let mut cur = start;
        while cur < region_end {
            if survey.lines.len() >= config.max_lines {
                break 'regions;
            }
            let Some(rec_addr) = ring.checked_add(cur) else {
                survey.walk_note = Some("a record address overflowed the address space".into());
                break 'regions;
            };
            let obj = match reader.object(rec_addr, rec_type) {
                Ok(obj) => obj,
                Err(err) => {
                    survey.walk_note = Some(format!(
                        "a log record at {rec_addr:#x} would not read: {err}"
                    ));
                    break 'regions;
                }
            };
            let rec_len = layout.read_unsigned(&obj, "rec_len")?;
            let rec_len = match rec_len.known() {
                // A zero-length record is the end-of-region padding marker: this
                // region is done, move on to the wrapped one (if any).
                Some(&0) => break,
                Some(&value) => value,
                None => {
                    survey.walk_note = Some("a record length could not be read".into());
                    break 'regions;
                }
            };

            let text_len = layout
                .read_unsigned(&obj, "text_len")?
                .known()
                .copied()
                .unwrap_or(0);
            let ts = layout.read_unsigned(&obj, "ts_nsec")?;
            let facility = layout.read_unsigned(&obj, "facility")?;
            let level = layout.read_unsigned(&obj, "level")?;
            let struct_size = obj.size()?;

            if text_len > 0 {
                let text_addr = rec_addr.saturating_add(struct_size);
                push_structured_lines(
                    &mut survey,
                    reader,
                    text_addr,
                    text_len,
                    cur as i64,
                    &ts,
                    &facility,
                    &level,
                );
            }

            // Advance, guarding against a stalled stride.
            let Some(new_cur) = cur.checked_add(rec_len) else {
                survey.walk_note = Some("a record length overflowed the ring cursor".into());
                break 'regions;
            };
            if new_cur <= cur {
                survey.walk_note = Some("a record did not advance the ring cursor".into());
                break 'regions;
            }
            cur = new_cur;
        }
    }
    if survey.lines.len() >= config.max_lines {
        survey.walk_note = Some(format!("the line cap of {} was reached", config.max_lines));
    }

    Ok(survey)
}

#[allow(clippy::too_many_arguments)]
fn push_structured_lines(
    survey: &mut LogRingSurvey,
    reader: &StructReader,
    text_addr: u64,
    text_len: u64,
    offset: i64,
    ts: &Field<u64>,
    facility: &Field<u64>,
    level: &Field<u64>,
) {
    let ts_field = match ts {
        Field::Known(nsec) => Field::Known(*nsec),
        _ => Field::NotApplicable,
    };
    let ts_seconds = match ts.known() {
        Some(nsec) => Field::Known(nsec_to_seconds(*nsec)),
        None => Field::NotApplicable,
    };
    let level_i = to_signed(level);
    let facility_i = to_signed(facility);

    let bytes = match reader.read_bytes(text_addr, text_len) {
        Ok(bytes) => bytes,
        Err(err) => {
            survey.lines.push(LogLine {
                source: "structured_ring",
                message: Field::Unavailable(format!(
                    "the message bytes at {text_addr:#x} were not acquired: {err}"
                )),
                message_well_formed: true,
                level: level_i,
                facility: facility_i,
                timestamp_seconds: ts_seconds,
                ts_nsec: ts_field,
                record_offset: Field::Known(offset),
            });
            return;
        }
    };
    let (text, well_formed) = decode_nul_terminated(&bytes);
    for line in text.split('\n') {
        survey.lines.push(LogLine {
            source: "structured_ring",
            message: Field::Known(line.to_string()),
            message_well_formed: well_formed,
            level: level_i.clone(),
            facility: facility_i.clone(),
            timestamp_seconds: ts_seconds.clone(),
            ts_nsec: ts_field.clone(),
            record_offset: Field::Known(offset),
        });
    }
}

fn to_signed(field: &Field<u64>) -> Field<i64> {
    match field {
        Field::Known(v) => Field::Known(*v as i64),
        Field::NotApplicable => Field::NotApplicable,
        Field::NotDeclared { member } => Field::NotDeclared { member },
        Field::Unavailable(d) => Field::Unavailable(d.clone()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_flat_line_decodes_priority_timestamp_and_message() {
        let line = parse_flat_line(b"<6>[    1.234567] Linux version test", 0).expect("a line");
        assert_eq!(line.level.known(), Some(&6));
        assert_eq!(line.facility.known(), Some(&0));
        assert_eq!(
            line.timestamp_seconds.known().map(String::as_str),
            Some("1.234567")
        );
        assert_eq!(
            line.message.known().map(String::as_str),
            Some("Linux version test")
        );
    }

    #[test]
    fn a_flat_line_with_no_timestamp_is_still_captured() {
        let line = parse_flat_line(b"<4>no timestamp warning", 0).expect("a line");
        assert_eq!(line.level.known(), Some(&4)); // warn
        assert_eq!(line.timestamp_seconds, Field::NotApplicable);
        assert_eq!(
            line.message.known().map(String::as_str),
            Some("no timestamp warning")
        );
    }

    #[test]
    fn a_high_priority_splits_into_level_and_facility() {
        // 11 = facility 1 (user), level 3 (err).
        let line = parse_flat_line(b"<11>[    1.5] user notice", 0).expect("a line");
        assert_eq!(line.level.known(), Some(&3));
        assert_eq!(line.facility.known(), Some(&1));
        let json = line.to_json();
        assert_eq!(json["level_name"], "err");
        assert_eq!(json["facility_name"], "user");
    }

    #[test]
    fn a_remnant_without_a_priority_prefix_is_discarded() {
        assert!(parse_flat_line(b"junk without prefix", 0).is_none());
    }

    #[test]
    fn nsec_renders_as_seconds() {
        assert_eq!(nsec_to_seconds(1_000_000_000), "1.000000");
        assert_eq!(nsec_to_seconds(2_500_000_000), "2.500000");
    }

    #[test]
    fn a_level_past_the_table_keeps_the_number_without_inventing_a_name() {
        assert_eq!(level_name(9), None);
        assert_eq!(facility_name(30), None);
    }
}

#[cfg(test)]
mod walk_tests {
    use std::sync::Arc;

    use seance_core::data_source::{ByteSliceDataSource, DataSource};
    use seance_memory::{MemoryLayer, PhysicalLayer};
    use seance_symbols::{CompileOptions, DecompressLimits, SymbolTable};

    use super::*;

    // Symbol addresses and the ring buffer within one flat image.
    const S_LOGBUF: u64 = 0x100;
    const S_LEN: u64 = 0x108;
    const S_END: u64 = 0x10c;
    const BUF: u64 = 0x1000;

    fn flat_isf() -> String {
        format!(
            r#"{{
          "metadata": {{"format":"6.2.0","producer":{{"name":"seance-dmesg-fixture","version":"1.0.0"}},"linux":{{"symbols":[],"types":[]}}}},
          "base_types": {{
            "pointer": {{"size":8,"signed":false,"kind":"int","endian":"little"}},
            "unsigned int": {{"size":4,"signed":false,"kind":"int","endian":"little"}},
            "char": {{"size":1,"signed":true,"kind":"char","endian":"little"}},
            "void": {{"size":0,"signed":false,"kind":"void","endian":"little"}}
          }},
          "user_types": {{}},
          "enums": {{}},
          "symbols": {{
            "log_buf": {{"address": {S_LOGBUF}, "type": {{"kind":"pointer","subtype":{{"kind":"base","name":"char"}}}}}},
            "__log_buf": {{"address": {BUF}, "type": {{"kind":"base","name":"char"}}}},
            "log_buf_len": {{"address": {S_LEN}, "type": {{"kind":"base","name":"unsigned int"}}}},
            "log_end": {{"address": {S_END}, "type": {{"kind":"base","name":"unsigned int"}}}}
          }}
        }}"#
        )
    }

    struct Image {
        bytes: Vec<u8>,
    }
    impl Image {
        fn new() -> Self {
            Self {
                bytes: vec![0u8; 0x4000],
            }
        }
        fn put(&mut self, a: u64, d: &[u8]) {
            let at = a as usize;
            self.bytes[at..at + d.len()].copy_from_slice(d);
        }
        fn u64(&mut self, a: u64, v: u64) {
            self.put(a, &v.to_le_bytes());
        }
        fn u32(&mut self, a: u64, v: u32) {
            self.put(a, &v.to_le_bytes());
        }
    }

    fn reader_from(image: Image, isf: &str) -> (StructReader, Arc<SymbolTable>) {
        let source: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(image.bytes));
        let layer: Arc<dyn MemoryLayer> =
            Arc::new(PhysicalLayer::raw(source).expect("a non-empty image"));
        let symbols = Arc::new(
            SymbolTable::compile_source(
                seance_symbols::load_slice(isf.as_bytes(), &DecompressLimits::default())
                    .expect("loads"),
                &CompileOptions::default(),
            )
            .expect("compiles"),
        );
        (StructReader::new(layer, Arc::clone(&symbols)), symbols)
    }

    #[test]
    fn the_flat_ring_walk_recovers_lines_levels_and_timestamps() {
        let mut image = Image::new();
        image.u64(S_LOGBUF, BUF);
        image.u32(S_LEN, 128);
        let content = b"<6>[    1.234567] Linux version test\n<11>[    1.500000] user notice\n<4>no timestamp warning\njunk without prefix\n";
        image.put(BUF, content);
        image.u32(S_END, content.len() as u32); // < 128: no wrap

        let (reader, symbols) = reader_from(image, &flat_isf());
        let layout = LOG_LAYOUT.bind(&reader).expect("binds");
        let survey = super::survey_with_reader(&reader, &symbols, &layout, &LogConfig::default())
            .expect("runs");

        assert_eq!(survey.outcome, LogOutcome::FlatWalked);
        assert!(survey.validated_on_corpus);
        assert_eq!(survey.line_count(), 3, "the remnant line is discarded");

        assert_eq!(survey.lines[0].level.known(), Some(&6));
        assert_eq!(
            survey.lines[0]
                .timestamp_seconds
                .known()
                .map(String::as_str),
            Some("1.234567")
        );
        assert_eq!(survey.lines[1].level.known(), Some(&3)); // 11 & 7
        assert_eq!(survey.lines[1].facility.known(), Some(&1)); // 11 >> 3
        assert_eq!(survey.lines[2].timestamp_seconds, Field::NotApplicable);
        assert_eq!(
            survey.lines[2].message.known().map(String::as_str),
            Some("no timestamp warning")
        );
        assert!(survey.is_complete());
        assert_eq!(survey.to_json()["ring_shape"], "flat_ring");
    }

    fn structured_isf() -> String {
        const S_FIRST: u64 = 0x110;
        const S_NEXT: u64 = 0x114;
        format!(
            r#"{{
          "metadata": {{"format":"6.2.0","producer":{{"name":"seance-dmesg-fixture","version":"1.0.0"}},"linux":{{"symbols":[],"types":[]}}}},
          "base_types": {{
            "pointer": {{"size":8,"signed":false,"kind":"int","endian":"little"}},
            "unsigned int": {{"size":4,"signed":false,"kind":"int","endian":"little"}},
            "unsigned short": {{"size":2,"signed":false,"kind":"int","endian":"little"}},
            "unsigned long long": {{"size":8,"signed":false,"kind":"int","endian":"little"}},
            "unsigned char": {{"size":1,"signed":false,"kind":"int","endian":"little"}},
            "char": {{"size":1,"signed":true,"kind":"char","endian":"little"}},
            "void": {{"size":0,"signed":false,"kind":"void","endian":"little"}}
          }},
          "user_types": {{
            "printk_log": {{"size":16,"kind":"struct","fields":{{
              "ts_nsec":{{"offset":0,"type":{{"kind":"base","name":"unsigned long long"}}}},
              "len":{{"offset":8,"type":{{"kind":"base","name":"unsigned short"}}}},
              "text_len":{{"offset":10,"type":{{"kind":"base","name":"unsigned short"}}}},
              "dict_len":{{"offset":12,"type":{{"kind":"base","name":"unsigned short"}}}},
              "facility":{{"offset":14,"type":{{"kind":"base","name":"unsigned char"}}}},
              "level":{{"offset":15,"type":{{"kind":"bitfield","bit_position":5,"bit_length":3,"type":{{"kind":"base","name":"unsigned char"}}}}}}
            }}}}
          }},
          "enums": {{}},
          "symbols": {{
            "log_buf": {{"address": {S_LOGBUF}, "type": {{"kind":"pointer","subtype":{{"kind":"base","name":"char"}}}}}},
            "__log_buf": {{"address": {BUF}, "type": {{"kind":"base","name":"char"}}}},
            "log_buf_len": {{"address": {S_LEN}, "type": {{"kind":"base","name":"unsigned int"}}}},
            "log_first_idx": {{"address": {S_FIRST}, "type": {{"kind":"base","name":"unsigned int"}}}},
            "log_next_idx": {{"address": {S_NEXT}, "type": {{"kind":"base","name":"unsigned int"}}}}
          }}
        }}"#
        )
    }

    #[test]
    fn the_structured_ring_walk_decodes_records() {
        const S_FIRST: u64 = 0x110;
        const S_NEXT: u64 = 0x114;
        let mut image = Image::new();
        image.u64(S_LOGBUF, BUF);
        image.u32(S_LEN, 128);
        image.u32(S_FIRST, 0);
        image.u32(S_NEXT, 43);

        // rec0 @ BUF: ts=1e9, len=21, text_len=5, facility=0, level=6 (byte@15 = 6<<5).
        image.u64(BUF, 1_000_000_000);
        image.put(BUF + 8, &21u16.to_le_bytes());
        image.put(BUF + 10, &5u16.to_le_bytes());
        image.put(BUF + 14, &[0]);
        image.put(BUF + 15, &[(6u8) << 5]);
        image.put(BUF + 16, b"hello");
        // rec1 @ BUF+21: ts=2.5e9, len=22, text_len=6, facility=1, level=3.
        image.u64(BUF + 21, 2_500_000_000);
        image.put(BUF + 21 + 8, &22u16.to_le_bytes());
        image.put(BUF + 21 + 10, &6u16.to_le_bytes());
        image.put(BUF + 21 + 14, &[1]);
        image.put(BUF + 21 + 15, &[(3u8) << 5]);
        image.put(BUF + 21 + 16, b"world!");

        let (reader, symbols) = reader_from(image, &structured_isf());
        let layout = LOG_LAYOUT.bind(&reader).expect("binds");
        let survey = super::survey_with_reader(&reader, &symbols, &layout, &LogConfig::default())
            .expect("runs");

        assert_eq!(survey.outcome, LogOutcome::StructuredWalked);
        assert!(
            !survey.validated_on_corpus,
            "the structured path is synthetic-only here"
        );
        assert_eq!(survey.line_count(), 2);

        assert_eq!(
            survey.lines[0].message.known().map(String::as_str),
            Some("hello")
        );
        assert_eq!(survey.lines[0].level.known(), Some(&6));
        assert_eq!(survey.lines[0].ts_nsec.known(), Some(&1_000_000_000));
        assert_eq!(
            survey.lines[0]
                .timestamp_seconds
                .known()
                .map(String::as_str),
            Some("1.000000")
        );
        assert_eq!(
            survey.lines[1].message.known().map(String::as_str),
            Some("world!")
        );
        assert_eq!(survey.lines[1].level.known(), Some(&3));
        assert_eq!(
            survey.lines[1]
                .timestamp_seconds
                .known()
                .map(String::as_str),
            Some("2.500000")
        );
        assert_eq!(survey.to_json()["ring_shape"], "structured_ring");
    }

    #[test]
    fn an_empty_structured_ring_yields_no_lines() {
        // log_first_idx == log_next_idx means the ring is EMPTY. A walk that read
        // that as a fully-wrapped ring would traverse the whole buffer and decode
        // whatever stale bytes remained from before it was cleared as live dmesg
        // lines (CR-004). The buffer here holds a perfectly valid-looking stale
        // record at the ring base, so a regressed walk yields a fabricated line.
        const S_FIRST: u64 = 0x110;
        const S_NEXT: u64 = 0x114;
        let mut image = Image::new();
        image.u64(S_LOGBUF, BUF);
        image.u32(S_LEN, 128);
        image.u32(S_FIRST, 0);
        image.u32(S_NEXT, 0);

        // A stale but structurally valid record sitting at the base.
        image.u64(BUF, 1_000_000_000);
        image.put(BUF + 8, &21u16.to_le_bytes());
        image.put(BUF + 10, &5u16.to_le_bytes());
        image.put(BUF + 14, &[0]);
        image.put(BUF + 15, &[(6u8) << 5]);
        image.put(BUF + 16, b"hello");

        let (reader, symbols) = reader_from(image, &structured_isf());
        let layout = LOG_LAYOUT.bind(&reader).expect("binds");
        let survey = super::survey_with_reader(&reader, &symbols, &layout, &LogConfig::default())
            .expect("runs");

        assert_eq!(survey.outcome, LogOutcome::StructuredWalked);
        assert_eq!(
            survey.line_count(),
            0,
            "an empty ring (first == next) must yield no lines, not the stale buffer"
        );
    }

    /// An ISF that has the structured *type* (printk_log with ts_nsec) and the
    /// log_first_idx symbol, but none of log_buf_len / log_next_idx / log_end.
    fn structured_type_but_missing_globals_isf() -> String {
        format!(
            r#"{{
          "metadata": {{"format":"6.2.0","producer":{{"name":"f","version":"1"}},"linux":{{"symbols":[],"types":[]}}}},
          "base_types": {{
            "pointer": {{"size":8,"signed":false,"kind":"int","endian":"little"}},
            "unsigned int": {{"size":4,"signed":false,"kind":"int","endian":"little"}},
            "unsigned short": {{"size":2,"signed":false,"kind":"int","endian":"little"}},
            "unsigned long long": {{"size":8,"signed":false,"kind":"int","endian":"little"}},
            "unsigned char": {{"size":1,"signed":false,"kind":"int","endian":"little"}},
            "char": {{"size":1,"signed":true,"kind":"char","endian":"little"}},
            "void": {{"size":0,"signed":false,"kind":"void","endian":"little"}}
          }},
          "user_types": {{
            "printk_log": {{"size":16,"kind":"struct","fields":{{
              "ts_nsec":{{"offset":0,"type":{{"kind":"base","name":"unsigned long long"}}}},
              "len":{{"offset":8,"type":{{"kind":"base","name":"unsigned short"}}}},
              "text_len":{{"offset":10,"type":{{"kind":"base","name":"unsigned short"}}}}
            }}}}
          }},
          "enums": {{}},
          "symbols": {{
            "log_buf": {{"address": {S_LOGBUF}, "type": {{"kind":"pointer","subtype":{{"kind":"base","name":"char"}}}}}},
            "__log_buf": {{"address": {BUF}, "type": {{"kind":"base","name":"char"}}}},
            "log_first_idx": {{"address": 288, "type": {{"kind":"base","name":"unsigned int"}}}}
          }}
        }}"#
        )
    }

    #[test]
    fn a_structured_type_without_log_buf_len_declines_instead_of_panicking() {
        // Regression: the structured discriminator once required only
        // log_first_idx, so a build missing log_buf_len entered walk_structured
        // and panicked on `.expect("checked")`. It must now decline cleanly.
        let mut image = Image::new();
        image.u64(S_LOGBUF, BUF);
        let (reader, symbols) = reader_from(image, &structured_type_but_missing_globals_isf());
        let layout = LOG_LAYOUT.bind(&reader).expect("binds");
        let survey = super::survey_with_reader(&reader, &symbols, &layout, &LogConfig::default())
            .expect("declines without panicking");
        assert_eq!(survey.outcome, LogOutcome::NoRingSymbols);
    }

    /// The flat ISF, but with `log_end` at an address the image does not cover,
    /// so reading the ring's write position fails.
    fn flat_isf_unreadable_end() -> String {
        flat_isf().replace(&format!("\"address\": {S_END}"), "\"address\": 1048576")
    }

    #[test]
    fn an_unreadable_log_end_yields_an_incomplete_flat_survey() {
        // Regression: an Unavailable log_end fell through to `buf.clone()` with no
        // walk_note, so a survey mixing stale post-wrap remnants with live lines
        // reported complete. It must now say it is short.
        let mut image = Image::new();
        image.u64(S_LOGBUF, BUF);
        image.u32(S_LEN, 128);
        image.put(BUF, b"<6>[    1.000000] Linux version live\n");
        // log_end (at 0x100000) is never written, and lies outside the image.

        let (reader, symbols) = reader_from(image, &flat_isf_unreadable_end());
        let layout = LOG_LAYOUT.bind(&reader).expect("binds");
        let survey = super::survey_with_reader(&reader, &symbols, &layout, &LogConfig::default())
            .expect("runs");

        assert_eq!(survey.outcome, LogOutcome::FlatWalked);
        assert!(survey.line_count() > 0, "the live line is still parsed");
        assert!(
            !survey.is_complete(),
            "an unreadable log_end must make the survey a floor, not a clean read"
        );
        assert!(survey
            .walk_note
            .as_deref()
            .is_some_and(|note| note.contains("log_end")));
    }
}
