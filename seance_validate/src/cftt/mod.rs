//! NIST CFTT published test methodologies, run in-house (`ROADMAP` §5.2).
//!
//! **Running a published methodology is not third-party validation.** A ✅
//! against "NIST CFTT" means NIST tested the tool, and nobody has tested
//! Séance. What a run here supports is narrower and still worth having: that
//! the product was measured against somebody else's published assertions, by a
//! procedure anybody can re-run, with the result recorded whether it passed or
//! not. `documentation/VALIDATION.md` carries the determination of which
//! methodologies apply. No document may claim more than that.

pub mod cases_map;
pub mod dfr_grade;
pub mod dfr_layout;
pub mod grade;
pub mod mdt;
pub mod string_search;
