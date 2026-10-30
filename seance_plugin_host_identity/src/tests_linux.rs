use super::*;
use seance_core::data_source::{ByteSliceDataSource, DataSource};
use std::sync::Arc;

fn artifact_at(path: &str, bytes: &[u8]) -> Artifact {
    let data: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(bytes.to_vec()));
    let name = path.rsplit('/').next().unwrap_or(path);
    Artifact::new(
        uuid::Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(data),
        json!({"name": name, "path": path}),
    )
}

/// `/usr/lib/os-release` as the Magnet 2022 Linux image holds it.
const OS_RELEASE: &[u8] = b"PRETTY_NAME=\"Ubuntu 21.10\"\n\
NAME=\"Ubuntu\"\n\
VERSION_ID=\"21.10\"\n\
VERSION=\"21.10 (Impish Indri)\"\n\
VERSION_CODENAME=impish\n\
ID=ubuntu\n\
ID_LIKE=debian\n\
HOME_URL=\"https://www.ubuntu.com/\"\n\
UBUNTU_CODENAME=impish\n";

const PASSWD: &[u8] = b"root:x:0:0:root:/root:/bin/bash\n\
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n\
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n\
rafael:x:1000:1000:Rafael Shell,,,:/home/rafael:/bin/bash\n";

fn facts(a: &Artifact) -> &serde_json::Map<String, serde_json::Value> {
    a.metadata["facts"].as_object().expect("facts object")
}

#[test]
fn an_os_release_states_the_distribution_and_its_version() {
    let out = LinuxHostParser::new()
        .process(&artifact_at("/usr/lib/os-release", OS_RELEASE))
        .expect("parsed");
    assert_eq!(out.len(), 1);
    let m = &out[0].metadata;
    assert_eq!(m["type"], "HostDeviceInfo");
    assert_eq!(m["platform"], "linux");
    assert_eq!(m["source_file"], "/usr/lib/os-release");
    let f = facts(&out[0]);
    assert_eq!(f["os_name"], "Ubuntu");
    assert_eq!(f["version_id"], "21.10");
    assert_eq!(f["os_version"], "21.10 (Impish Indri)");
    assert_eq!(f["codename"], "impish");
    assert_eq!(f["os_id"], "ubuntu");
    assert_eq!(f["pretty_name"], "Ubuntu 21.10");
    // Every fact names the key it was read from.
    assert_eq!(m["fact_sources"]["version_id"], "VERSION_ID");
}

#[test]
fn an_etc_hostname_names_the_host() {
    let out = LinuxHostParser::new()
        .process(&artifact_at("/etc/hostname", b"rshell-lenovo\n"))
        .expect("parsed");
    assert_eq!(out.len(), 1);
    assert_eq!(facts(&out[0])["host_name"], "rshell-lenovo");
}

#[test]
fn a_file_merely_named_hostname_is_not_the_hosts_name() {
    // The Magnet 2022 Linux image carries metasploit modules with `hostname` in
    // their names. A name-only match would put a ruby script's first line on
    // the host summary as the machine's name.
    let out = LinuxHostParser::new()
        .process(&artifact_at(
            "/opt/metasploit-framework/modules/auxiliary/gather/checkpoint_hostname.rb",
            b"require 'msf/core'\n",
        ))
        .expect("parsed");
    assert!(
        out.is_empty(),
        "only the system's own paths state host facts"
    );
}

#[test]
fn a_machine_id_is_thirty_two_hex_characters_or_it_is_not_one() {
    let good = LinuxHostParser::new()
        .process(&artifact_at(
            "/etc/machine-id",
            b"9d2f1bd7f4e34a9db1c0e4c3a1f5b6e7\n",
        ))
        .expect("parsed");
    assert_eq!(
        facts(&good[0])["machine_id"],
        "9d2f1bd7f4e34a9db1c0e4c3a1f5b6e7"
    );

    let bad = LinuxHostParser::new()
        .process(&artifact_at("/etc/machine-id", b"uninitialized\n"))
        .expect("parsed");
    assert!(bad.is_empty(), "a placeholder is not a machine id");
}

#[test]
fn a_timezone_file_states_the_zone() {
    let out = LinuxHostParser::new()
        .process(&artifact_at("/etc/timezone", b"America/New_York\n"))
        .expect("parsed");
    assert_eq!(facts(&out[0])["timezone"], "America/New_York");
}

#[test]
fn passwd_lists_the_people_with_accounts_on_the_box() {
    let out = LinuxHostParser::new()
        .process(&artifact_at("/etc/passwd", PASSWD))
        .expect("parsed");
    assert_eq!(out.len(), 1);
    let accounts = facts(&out[0])["user_account"]
        .as_array()
        .expect("a list of accounts");
    let rendered: Vec<&str> = accounts.iter().map(|v| v.as_str().unwrap()).collect();
    assert_eq!(
        rendered,
        vec![
            "root (uid 0, /root, /bin/bash)",
            "rafael (uid 1000, /home/rafael, /bin/bash)",
        ],
        "service accounts and `nobody` are not people"
    );
    // The count is of every line read, not only the people, so the record does
    // not read as a machine with two accounts on it.
    assert_eq!(out[0].metadata["accounts_read"], 4);
}

#[test]
fn a_passwd_line_that_is_not_seven_fields_is_counted_not_dropped() {
    let out = LinuxHostParser::new()
        .process(&artifact_at(
            "/etc/passwd",
            b"root:x:0:0:root:/root:/bin/bash\ngarbled line\n",
        ))
        .expect("parsed");
    assert_eq!(out[0].metadata["unparsed_lines"], 1);
}

#[test]
fn an_lsb_release_states_the_same_facts_under_its_own_keys() {
    let out = LinuxHostParser::new()
        .process(&artifact_at(
            "/etc/lsb-release",
            b"DISTRIB_ID=Ubuntu\nDISTRIB_RELEASE=21.10\nDISTRIB_CODENAME=impish\n\
DISTRIB_DESCRIPTION=\"Ubuntu 21.10\"\n",
        ))
        .expect("parsed");
    let f = facts(&out[0]);
    // `DISTRIB_ID` is the vendor's name for the distribution — "Ubuntu" — and
    // `os-release`'s `ID` is its lower-case identifier — "ubuntu". Reading the
    // first as the second made every Ubuntu machine look like two files
    // disagreeing about what it runs.
    assert_eq!(f["os_name"], "Ubuntu");
    assert!(!f.contains_key("os_id"));
    assert_eq!(f["version_id"], "21.10");
    assert_eq!(
        out[0].metadata["fact_sources"]["version_id"],
        "DISTRIB_RELEASE"
    );
}

#[test]
fn an_identity_file_read_only_in_part_says_so_rather_than_nothing() {
    // A short read of `/etc/hostname` that carried nothing usable must not put
    // the host in the same place as a machine with no name recorded.
    #[derive(Debug)]
    struct Short(Vec<u8>, u64);
    impl DataSource for Short {
        fn read_at(&self, off: u64, buf: &mut [u8]) -> std::io::Result<usize> {
            let off = off as usize;
            if off >= self.0.len() || buf.is_empty() {
                return Ok(0);
            }
            let n = buf.len().min(self.0.len() - off);
            buf[..n].copy_from_slice(&self.0[off..off + n]);
            Ok(n)
        }
        fn size(&self) -> u64 {
            self.1
        }
    }
    let data: Arc<dyn DataSource> = Arc::new(Short(b"\n".to_vec(), 4096));
    let artifact = Artifact::new(
        uuid::Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(data),
        json!({"name": "hostname", "path": "/etc/hostname"}),
    );
    let out = LinuxHostParser::new().process(&artifact).expect("parsed");
    assert_eq!(out.len(), 1, "the file must not vanish from the case");
    let m = &out[0].metadata;
    assert_eq!(m["subtype"], "identity_unread");
    assert_eq!(m[CONTENT_INCOMPLETE], true);
    assert_eq!(m[CONTENT_INCOMPLETE_REASON], "short_read");
}

#[test]
fn a_directory_named_like_an_identity_file_states_nothing() {
    let data: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(Vec::new()));
    let artifact = Artifact::new(
        uuid::Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(data),
        json!({"name": "timezone", "path": "/etc/timezone", "is_directory": true}),
    );
    assert!(LinuxHostParser::new()
        .process(&artifact)
        .expect("parsed")
        .is_empty());
}
