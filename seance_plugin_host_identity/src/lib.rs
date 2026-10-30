//! Whose machine is this?
//!
//! `system_info` compiles Windows registry hives and the device-facts surface
//! compiles Android property files and iOS backup manifests. On a Linux or macOS
//! exhibit all of them returned empty: the host name, the operating system and
//! its version, the machine id and the accounts on the box were in the evidence,
//! and an examiner could reach them only by knowing the paths and opening the
//! files one at a time (found grading the Magnet 2022 Linux and Magnet 2021
//! macOS images, whose first questions are exactly "what is this machine
//! called" and "which build does it run").
//!
//! Each reader emits `HostDeviceInfo` records in the same `facts` /
//! `fact_sources` shape the Android property records use, so the device-facts
//! endpoint folds every platform the same way.
//!
//! **Every fact names the file and the key it came from, and nothing is
//! reconciled here.** `/etc/os-release` is often a symlink to
//! `/usr/lib/os-release` and the two can differ on a system upgraded in place;
//! a `machine-id` can be stale after a machine is cloned. One record per file
//! keeps the disagreement visible, and the device-facts surface shows it rather
//! than picking a winner.

#![forbid(unsafe_code)]

pub mod linux;
pub mod macos;

pub use linux::{
    identity_file, is_login_account, parse_passwd, parse_release, IdentityFile, LinuxHostParser,
    PasswdEntry,
};
pub use macos::MacHostParser;
