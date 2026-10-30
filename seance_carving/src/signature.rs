/// Trait for file format signature detection and recovery.
///
/// Inspired by PhotoRec's three-callback architecture:
/// 1. `header_check` - Detect file header and initialize recovery
/// 2. `data_check` - Validate data blocks during recovery
/// 3. `file_check` - Final validation when recovery completes
pub trait FileSignature: Send + Sync {
    /// Human-readable name (e.g., "JPEG")
    fn name(&self) -> &str;

    /// File extensions associated with this format (e.g., ["jpg", "jpeg"])
    fn extensions(&self) -> &[&str];

    /// Check if the buffer at the given offset matches this signature's header.
    /// Returns `Some(RecoveryInit)` to begin recovery, `None` if no match.
    fn header_check(&self, buf: &[u8], offset: usize) -> Option<RecoveryInit>;

    /// Validate a data block during active recovery.
    /// Called for each subsequent block after header match.
    fn data_check(&self, buf: &[u8], recovery: &mut FileRecovery) -> DataCheckResult;

    /// Final validation after recovery completes.
    /// Can adjust the recovered file size in `recovery`.
    ///
    /// This callback reports nothing back to the engine: use
    /// [`verify_footer`](Self::verify_footer) for a pass/fail verdict, so the
    /// answer cannot be computed and then dropped on the floor.
    fn file_check(&self, data: &[u8], recovery: &mut FileRecovery);

    /// Independent confirmation that the recovered extent ends with this
    /// format's terminator. `data` is the tail window of the carved bytes, read
    /// in full from the source.
    ///
    /// - `Some(true)`  — the terminator is present where it must be.
    /// - `Some(false)` — the bytes were read in full and the terminator is NOT
    ///   there; the carve is a heuristic recovery, not a validated one.
    /// - `None` (default) — this signature has no footer to check, so it makes
    ///   no claim either way.
    ///
    /// The engine records this verdict on the carved file. A signature that
    /// computes the check but returns nothing lets the engine assert
    /// "footer-validated" for a file whose footer is missing, which is why the
    /// verdict is a return value rather than a local in `file_check`.
    fn verify_footer(&self, _data: &[u8]) -> Option<bool> {
        None
    }

    /// Size a file whose extent the one header block cannot give, by reading
    /// the structure that follows it in the source. `offset` is where the file
    /// starts. Called only when `header_check` matched and returned no
    /// `calculated_file_size`; `Some(n)` is then used as that size (accepted,
    /// clamped and reported exactly as a header-declared size is), `None`
    /// falls back to block-by-block recovery. Default `None`.
    ///
    /// For a format whose extent is a run of fixed-size structures (a whole
    /// EVTX log is its header block plus its consecutive chunks), walking the
    /// run is the extent; a count in the header is a claim about it.
    fn extent_from_source(
        &self,
        _source: &dyn crate::engine::CarvingDataSource,
        _offset: u64,
    ) -> Option<u64> {
        None
    }

    /// Confirm, from the source, a header whose proof lies beyond the header
    /// block. `offset` is where the file starts. Consulted only when a match
    /// would end a carve already running (CARVE-015), never when a recovery
    /// starts, so a truncated genuine file is never refused by it.
    ///
    /// - `Some(true)`  — the structure the header points at was read and is
    ///   plausible.
    /// - `Some(false)` — it was read and is not: the match is treated as a
    ///   stray magic inside the running file's body and does not end it. A
    ///   genuine file whose structure lies in a fragment not contiguous in
    ///   the source also reads as `Some(false)`; it is then carved as part of
    ///   the running carve and does not start its own (a stated limit).
    /// - `None` (default) — nothing to confirm, or it lies beyond the source,
    ///   so the header block's own check stands alone.
    ///
    /// A TIFF-style header usually points at a directory past its first
    /// block (a camera or ImageMagick TIFF writes it after the strips).
    fn header_confirmed_by_source(
        &self,
        _source: &dyn crate::engine::CarvingDataSource,
        _offset: u64,
    ) -> Option<bool> {
        None
    }

    /// True for a signature that recognises its format by a magic alone, with
    /// no layout past it checked, because neither a public layout nor a real
    /// sample is held to write the check from. Such a match may start a carve
    /// when none is running but never ends one that is: a four-byte
    /// coincidence inside another file's body must not split that file
    /// (CARVE-015, owner decision 2026-09-26). The cost: a genuine file of
    /// such a format met while another carve runs does not start its own, and
    /// wherever the running carve stops before that file ends (its footer,
    /// a `data_check` stop, its size cap), the file's tail past that point is
    /// recovered by no carve, because its header block has already been
    /// passed. Default false.
    fn weak_header(&self) -> bool {
        false
    }

    /// How many bytes from the start of the file `header_check` needs, when
    /// that is more than one engine block (512 bytes by default). The engine
    /// then passes `header_check` that many bytes (fewer only where the source
    /// ends) and matches this signature's registered magic against them, so a
    /// format whose proof lies at 0x438 or 0x8000 can be recognised. Default 0:
    /// the signature is shown the block only.
    fn header_window(&self) -> usize {
        0
    }

    /// Maximum file size in bytes. Recovery stops if exceeded.
    fn max_file_size(&self) -> u64;

    /// When true, the engine reads the carved bytes and calls `file_check` even
    /// for header-sized (calculated_file_size) files, so the signature can
    /// refine the extension from content (e.g. OLE2 -> doc/xls/ppt). Default
    /// false to avoid the extra read for signatures that don't need it.
    fn refines_extension(&self) -> bool {
        false
    }
}

/// Initialization data returned when a file header is detected.
#[derive(Debug, Clone)]
pub struct RecoveryInit {
    /// Minimum expected file size in bytes
    pub min_filesize: u64,
    /// File extension to use for the recovered file
    pub extension: String,
    /// If the exact file size can be determined from the header, set it here
    pub calculated_file_size: Option<u64>,
}

/// Result of a data_check callback during block-by-block recovery.
#[derive(Debug, Clone, PartialEq)]
pub enum DataCheckResult {
    /// Continue scanning more blocks
    Continue,
    /// File end found; the u64 is the final file size from the start of recovery
    Stop(u64),
    /// Unrecoverable error in data stream; abort this file
    Error,
}

/// Mutable state tracked during file recovery.
#[derive(Debug, Clone)]
pub struct FileRecovery {
    /// File extension (may be updated during recovery, e.g., ZIP -> DOCX)
    pub extension: String,
    /// Current accumulated file size in bytes
    pub file_size: u64,
    /// Size calculated from header (if known)
    pub calculated_file_size: Option<u64>,
    /// Starting byte offset in the source data
    pub offset_start: u64,
    /// Minimum expected file size
    pub min_filesize: u64,
    /// Extra state for format-specific use
    pub extra: u64,
    /// Extra byte-buffer state for format-specific use. A signature whose
    /// structure walk needs a few bytes carried across a block boundary — e.g. a
    /// header field that straddles two engine blocks — stashes them here and
    /// completes them from the head of the next block. Empty for signatures that
    /// do not need it.
    pub extra_bytes: Vec<u8>,
}

impl FileRecovery {
    pub fn from_init(init: &RecoveryInit, offset_start: u64) -> Self {
        Self {
            extension: init.extension.clone(),
            file_size: 0,
            calculated_file_size: init.calculated_file_size,
            offset_start,
            min_filesize: init.min_filesize,
            extra: 0,
            extra_bytes: Vec::new(),
        }
    }
}
