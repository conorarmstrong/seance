use super::*;
use seance_core::data_source::{ByteSliceDataSource, DataSource};
use std::sync::Arc;

fn artifact_with(name: &str, bytes: &[u8]) -> Artifact {
    let data: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(bytes.to_vec()));
    Artifact::new(
        uuid::Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(data),
        json!({"name": name, "path": format!("/system/{name}")}),
    )
}

/// A real Pixel's `build.prop`, trimmed to the lines a device summary reads.
const PIXEL: &[u8] = b"\
# begin build properties
ro.product.manufacturer=Google
ro.product.model=Pixel 7a
ro.product.device=lynx
ro.build.version.release=14
ro.build.version.sdk=34
ro.build.version.security_patch=2024-01-05
ro.build.id=UQ1A.240105.004
ro.build.fingerprint=google/lynx/lynx:14/UQ1A.240105.004/11206848:user/release-keys
ro.build.type=user
ro.build.tags=release-keys
ro.serialno=1B031JEG500741
ro.crypto.state=encrypted
ro.crypto.type=file
not a property line
";

#[test]
fn a_build_prop_answers_whose_phone_this_is() {
    let out = AndroidPropertiesParser::new()
        .process(&artifact_with("build.prop", PIXEL))
        .expect("parsed");
    assert_eq!(out.len(), 1);
    let m = &out[0].metadata;

    assert_eq!(m["type"], "MobileDeviceInfo");
    assert_eq!(m["platform"], "android");
    assert_eq!(m["facts"]["manufacturer"], "Google");
    assert_eq!(m["facts"]["model"], "Pixel 7a");
    assert_eq!(m["facts"]["android_version"], "14");
    assert_eq!(m["facts"]["build_id"], "UQ1A.240105.004");
    assert_eq!(m["facts"]["serial_number"], "1B031JEG500741");
    assert_eq!(m["facts"]["encryption_state"], "encrypted");

    // The key each fact came from travels with it: an examiner asked to stand
    // over "the model is Pixel 7a" needs to say where that came from, and the
    // keys moved between Android versions.
    assert_eq!(m["fact_sources"]["model"], "ro.product.model");
    assert_eq!(m["source_file"], "/system/build.prop");

    // A line this parser did not understand is counted, never dropped in
    // silence: a half-read property file must not look like a small one.
    assert_eq!(m["unparsed_lines"], 1);
}

/// Android 10 moved `ro.product.*` under per-partition prefixes and the
/// framework falls back through them. Reading only the bare key returns nothing
/// at all on a modern device — a device summary with no model on it.
#[test]
fn the_per_partition_product_keys_are_read_too() {
    let modern = b"ro.product.system.manufacturer=Google\nro.product.vendor.model=Pixel 8\n\
                   ro.build.version.release=15\n";
    let out = AndroidPropertiesParser::new()
        .process(&artifact_with("build.prop", modern))
        .expect("parsed");
    let m = &out[0].metadata;
    assert_eq!(m["facts"]["manufacturer"], "Google");
    assert_eq!(m["facts"]["model"], "Pixel 8");
    assert_eq!(m["fact_sources"]["model"], "ro.product.vendor.model");
}

/// The bare key wins when both are present: it is what the device itself
/// reports, and the per-partition keys are the fallback.
#[test]
fn the_most_authoritative_key_wins() {
    let both = b"ro.product.model=Pixel 7a\nro.product.vendor.model=lynx\nro.build.id=X\n";
    let out = AndroidPropertiesParser::new()
        .process(&artifact_with("build.prop", both))
        .expect("parsed");
    assert_eq!(out[0].metadata["facts"]["model"], "Pixel 7a");
    assert_eq!(out[0].metadata["fact_sources"]["model"], "ro.product.model");
}

/// A name-only match must be corroborated. `build.prop` is not a rare name, and
/// a file of unrelated `key=value` text claimed as a device's identity would put
/// invented facts on a device summary.
#[test]
fn key_value_text_that_is_not_android_is_not_claimed() {
    let config = b"# a build configuration\nCFLAGS=-O2\nPREFIX=/usr/local\n";
    let out = AndroidPropertiesParser::new()
        .process(&artifact_with("build.prop", config))
        .expect("parsed");
    assert!(
        out.is_empty(),
        "no ro.* properties: not Android device facts"
    );
}

#[test]
fn a_file_that_is_not_a_property_file_is_not_ours() {
    let out = AndroidPropertiesParser::new()
        .process(&artifact_with("settings.xml", PIXEL))
        .expect("parsed");
    assert!(out.is_empty());
}

#[test]
fn every_property_file_the_framework_reads_is_recognised() {
    for name in [
        "build.prop",
        "default.prop",
        "prop.default",
        "vendor.prop",
        "odm.prop",
        "BUILD.PROP",
    ] {
        assert!(is_property_file(name), "{name}");
    }
    assert!(!is_property_file("build.props"));
    assert!(!is_property_file("propaganda.txt"));
}

/// A short read is a different device summary from a complete one, so the
/// record says so with the standard pair rather than presenting the properties
/// it did reach as all of them.
#[test]
fn a_truncated_property_file_declares_itself_incomplete() {
    use seance_core::test_support::TruncatedSource;

    // The file declares its real length and only part of it was acquired.
    let data: Arc<dyn DataSource> = Arc::new(TruncatedSource::new(
        PIXEL[..40].to_vec(),
        PIXEL.len() as u64,
    ));
    let artifact = Artifact::new(
        uuid::Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(data),
        json!({"name": "build.prop"}),
    );
    let out = AndroidPropertiesParser::new()
        .process(&artifact)
        .expect("parsed");
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].metadata["content_incomplete"], json!(true));
    assert_eq!(out[0].metadata["content_incomplete_reason"], "short_read");
    // Too little was acquired to tell whether it is a property file at all —
    // and saying nothing would leave a device summary silent about the one file
    // that would have filled it in.
    assert_eq!(out[0].metadata["subtype"], "properties_unidentified");
}

/// Enough of the file was acquired to identify it and not all of it. The facts
/// it did carry are reported AND the record says it is short: presenting a
/// partial property file as a whole one would state a device summary nobody can
/// stand over.
#[test]
fn a_partly_read_property_file_reports_what_it_has_and_says_it_is_short() {
    use seance_core::test_support::TruncatedSource;

    let cut = 200;
    let data: Arc<dyn DataSource> = Arc::new(TruncatedSource::new(
        PIXEL[..cut].to_vec(),
        PIXEL.len() as u64,
    ));
    let artifact = Artifact::new(
        uuid::Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(data),
        json!({"name": "build.prop"}),
    );
    let out = AndroidPropertiesParser::new()
        .process(&artifact)
        .expect("parsed");
    assert_eq!(out.len(), 1);
    let m = &out[0].metadata;
    assert_eq!(m["facts"]["manufacturer"], "Google");
    assert_eq!(m["facts"]["model"], "Pixel 7a");
    assert_eq!(m["content_incomplete"], json!(true));
    assert_eq!(m["content_incomplete_reason"], "short_read");
    // The serial is past the cut: it must be absent, not invented.
    assert!(m["facts"].get("serial_number").is_none());
}
