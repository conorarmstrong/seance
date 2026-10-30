//! Why an analysis stage could not run at all.
//!
//! The distinction this type exists to hold: a stage that **could not run** and
//! a stage that **ran and found nothing** are opposite findings, and a report
//! that renders them the same tells an examiner a machine was idle when in truth
//! nobody looked. Everything in here is the first of those. The second is not an
//! error at all — it is a result with a count of zero and a completeness verdict
//! beside it.
//!
//! A build-variant member this kernel does not have is deliberately **not** in
//! here. That is [`seance_memory::binding::Field::NotDeclared`], an answer, and
//! turning it into a stage failure is the defect that cost the Windows tier
//! eight analysis stages on a real Windows XP capture. The only route from an
//! absent member to a variant of this type is
//! [`seance_memory::binding::Necessity::Required`], which forces whoever marks
//! it required to write down what the stage cannot do without it.

use seance_memory::binding::BindError;
use seance_memory::object::ObjError;

/// A stage could not run.
#[derive(Debug, thiserror::Error)]
pub enum StageError {
    /// The stage's declared layout could not be bound to this kernel build.
    ///
    /// Carries the binding's own sentence, which names the stage, the member,
    /// every name that was looked for, and what is lost without it.
    #[error(transparent)]
    Layout(#[from] BindError),

    /// A structure the stage needs before it can start could not be read.
    #[error(transparent)]
    Object(#[from] ObjError),

    /// The symbol table declares none of the symbols the stage starts from.
    ///
    /// Distinct from a member: a symbol is where a walk *begins*, so without one
    /// there is no address to start at and nothing to report a partial result
    /// over.
    #[error(
        "the symbol table for this kernel declares none of {candidates}, so the {stage} stage \
         has no address to start from. Without it, {without_it}"
    )]
    NoStartSymbol {
        /// Stage key.
        stage: &'static str,
        /// The names that were looked for, quoted and comma-separated.
        candidates: String,
        /// What the stage cannot do without one of them.
        without_it: &'static str,
    },
}

impl StageError {
    /// Stable machine-readable class, for artifact metadata and log lines.
    pub fn class(&self) -> &'static str {
        match self {
            StageError::Layout(err) => err.class(),
            StageError::Object(_) => "structure_unreadable",
            StageError::NoStartSymbol { .. } => "no_start_symbol",
        }
    }
}

/// `'a', 'b'` — candidate names for a message an examiner reads.
pub fn name_list(names: &[&str]) -> String {
    names
        .iter()
        .map(|name| format!("'{name}'"))
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_start_symbol_says_what_the_stage_cannot_do() {
        let err = StageError::NoStartSymbol {
            stage: "linux_kernel_modules",
            candidates: name_list(&["modules"]),
            without_it: "no loaded kernel module can be listed",
        };
        let text = err.to_string();
        assert!(text.contains("'modules'"), "{text}");
        assert!(text.contains("no loaded kernel module"), "{text}");
        assert_eq!(err.class(), "no_start_symbol");
    }
}
