//! Naming the operating system in a capture this build cannot analyse.
//!
//! Every analysis tier is free to decline an image that is not its own — that
//! is how a Windows tier and a Linux tier coexist over one record. But when
//! *no* registered tier claims a capture, the case is left with a Windows
//! discovery failure and silence from everything else, and an examiner reading
//! that sees "this is not a Windows image". They do not see "this is a Mac, and
//! this build does not analyse Macs", which is the fact.
//!
//! Those are different findings. The first invites another attempt with
//! different settings; the second says no setting will help. So a capture whose
//! kernel identifies an operating system with no tier behind it is named here,
//! and the naming lands on the image record.
//!
//! This is deliberately not a tier. It reads one string and claims nothing
//! else: no address space, no processes, no symbols. A recognition is a label
//! on the evidence, and labelling is all it does.

use crate::layer::MemoryLayer;
use crate::scan::{scan_layer, ScanConfig, SingleStringScanner};

/// The Darwin kernel's version banner, present in every macOS capture.
///
/// The full string carries the XNU build ("Darwin Kernel Version 19.6.0: Mon
/// Aug 31 22:12:52 PDT 2020; root:xnu-6153.141.2~1/RELEASE_X86_64"), but only
/// the fixed prefix is needed to say which operating system this is.
const DARWIN_BANNER: &[u8] = b"Darwin Kernel Version ";

/// How much of the banner line to keep, in bytes.
const BANNER_MAX: usize = 240;

/// An operating system recognised in a capture that no tier here analyses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsupportedOs {
    /// Stable identifier for the record.
    pub os: &'static str,
    /// The banner text that established it, trimmed to a printable line.
    pub banner: String,
    /// Physical address the banner was found at.
    pub address: u64,
    /// Why this build does not analyse it. Written for an examiner, not a
    /// developer: it has to answer "so can I get this looked at or not".
    pub reason: &'static str,
}

/// Why macOS is recognised but not analysed.
///
/// Stated once, here, so the record and the online help cannot drift apart.
const MACOS_REASON: &str = "this build does not analyse macOS captures. The analysis code exists \
                            but is not built in, because none of its results has been checked \
                            against a capture of a real Mac -- and a process list produced by \
                            unverified code is indistinguishable, in a report, from one that was \
                            verified. The capture is intact and is recorded as evidence; it is \
                            the analysis that is withheld";

/// Look for an operating system this build recognises but cannot analyse.
///
/// `None` means nothing was recognised, which is the ordinary outcome: a
/// Windows or Linux capture is handled by its own tier and never reaches a
/// conclusion here. `None` is emphatically *not* a claim that the image holds
/// no operating system.
///
/// A scan that could not finish also yields `None`. This function exists to
/// turn a positive identification into a sentence; it is not a completeness
/// check and must never be read as one.
pub fn unsupported_os(physical: &dyn MemoryLayer) -> Option<UnsupportedOs> {
    let scanner = SingleStringScanner::new("darwin_banner", DARWIN_BANNER).ok()?;
    let config = ScanConfig {
        // One hit settles it. The banner appears more than once in a live
        // system, and every copy says the same thing.
        max_hits: 1,
        ..ScanConfig::default()
    };
    let outcome = scan_layer(physical, &scanner, &config).ok()?;
    let hit = outcome.hits.first()?;
    Some(UnsupportedOs {
        os: "macos",
        banner: read_line_at(physical, hit.address),
        address: hit.address,
        reason: MACOS_REASON,
    })
}

/// Read the banner line at `address`, stopping at the first byte that is not
/// printable text.
///
/// A banner is ASCII by construction. Stopping at the first non-printable byte
/// keeps whatever followed it in memory out of the record, rather than
/// rendering unrelated bytes as though they were part of the kernel's version
/// string.
fn read_line_at(physical: &dyn MemoryLayer, address: u64) -> String {
    let mut buf = vec![0u8; BANNER_MAX];
    let read = physical.read_at(address, &mut buf).unwrap_or(0);
    let text: Vec<u8> = buf
        .iter()
        .take(read)
        .copied()
        .take_while(|b| (0x20..0x7F).contains(b))
        .collect();
    String::from_utf8_lossy(&text).into_owned()
}

impl UnsupportedOs {
    /// The record fields, for merging into the image record's metadata.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "recognised_os": self.os,
            "recognised_os_banner": self.banner,
            "recognised_os_banner_address": self.address,
            "recognised_os_supported": false,
            "recognised_os_reason": self.reason,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::physical::PhysicalLayer;
    use seance_core::data_source::ByteSliceDataSource;
    use std::sync::Arc;

    fn layer_holding(bytes: Vec<u8>) -> PhysicalLayer {
        PhysicalLayer::raw(Arc::new(ByteSliceDataSource::new(bytes)))
            .expect("a non-empty source projects")
    }

    #[test]
    fn a_darwin_capture_is_named_rather_than_left_to_silence() {
        // Without this, a macOS image produced a Windows discovery failure and
        // nothing else, which reads as "not a Windows image" -- an invitation
        // to try again with different settings, when no setting would help.
        let mut bytes = vec![0u8; 0x4000];
        let banner = b"Darwin Kernel Version 19.6.0: Mon Aug 31 22:12:52 PDT 2020; \
                       root:xnu-6153.141.2~1/RELEASE_X86_64";
        bytes[0x2000..0x2000 + banner.len()].copy_from_slice(banner);

        let found = unsupported_os(&layer_holding(bytes)).expect("the banner is there to find");
        assert_eq!(found.os, "macos");
        assert_eq!(found.address, 0x2000);
        assert!(
            found.banner.starts_with("Darwin Kernel Version 19.6.0"),
            "{}",
            found.banner
        );
        assert!(found.reason.contains("does not analyse macOS"));

        let body = found.to_json();
        assert_eq!(body["recognised_os"], "macos");
        assert_eq!(body["recognised_os_supported"], false);
    }

    #[test]
    fn an_image_with_no_recognised_banner_claims_nothing() {
        // The ordinary case, and the one that must not turn into a claim: a
        // Windows or Linux capture reaches here too, and "not recognised" is
        // not "holds no operating system".
        let bytes = vec![0x41u8; 0x4000];
        assert!(unsupported_os(&layer_holding(bytes)).is_none());
    }

    #[test]
    fn a_banner_is_cut_at_the_first_unprintable_byte() {
        // Whatever sits after the banner in memory is not part of the kernel's
        // version string and must not be rendered as though it were.
        let mut bytes = vec![0u8; 0x4000];
        let banner = b"Darwin Kernel Version 21.1.0: RELEASE_ARM64_T8101";
        bytes[0x1000..0x1000 + banner.len()].copy_from_slice(banner);
        bytes[0x1000 + banner.len()] = 0x00;
        bytes[0x1000 + banner.len() + 1] = 0xFF;

        let found = unsupported_os(&layer_holding(bytes)).expect("the banner is there");
        assert_eq!(
            found.banner,
            "Darwin Kernel Version 21.1.0: RELEASE_ARM64_T8101"
        );
    }
}
