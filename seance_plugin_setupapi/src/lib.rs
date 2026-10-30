#![forbid(unsafe_code)]

//! Windows setupapi device-install logs (`ROADMAP` §2.6).
//!
//! The second, independent source for when a device was first connected: the
//! registry's device-property keys are the first. See `parse.rs` for the
//! format and for the seven things about it that a straightforward parser
//! loses without saying so.

pub mod module;
pub mod parse;

#[cfg(test)]
mod tests;

pub use module::SetupApiParser;
