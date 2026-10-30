/// The OLE2 (Compound File Binary) signature every `.msg` opens with, and
/// which Word, Excel and PowerPoint documents share — hence the extension
/// check beside it.
pub const OLE2_SIGNATURE: [u8; 8] = [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];

/// Detected email format
#[derive(Debug, Clone, PartialEq)]
pub enum EmailFormat {
    Eml,
    /// Apple Mail `.emlx` / `.partial.emlx`: a decimal byte-count line, that
    /// many bytes of RFC 5322 message, then an XML property list.
    Emlx,
    Mbox,
    Msg,
    Pst,
    Unknown,
}

/// Detect email format from content bytes and file name
pub fn detect_email_format(header: &[u8], name: &str) -> EmailFormat {
    let lower_name = name.to_lowercase();

    // PST/OST: "!BDN" magic at offset 0 (bytes 0x21, 0x42, 0x44, 0x4E)
    if header.len() >= 4 && &header[0..4] == b"!BDN" {
        return EmailFormat::Pst;
    }

    // PST/OST by extension (fallback)
    if lower_name.ends_with(".pst") || lower_name.ends_with(".ost") {
        return EmailFormat::Pst;
    }

    // MSG: the OLE2 compound-document signature, which is
    // `D0 CF 11 E0 A1 B1 1A E1`. It was written here as
    // `D0 CF 11 E0 A1 0B 1A 00` — two transposed bytes and a wrong last one —
    // and the two tests guarding it carried the same wrong bytes, so no real
    // `.msg` ever matched and every one of them fell through to
    // `FormatUnrecognised`. A constant and the test that pins it must not come
    // from the same reading of the format.
    if header.len() >= 8 && header[0..8] == OLE2_SIGNATURE {
        // Only treat as MSG if the extension matches (OLE2 is shared with DOC/XLS/PPT)
        if lower_name.ends_with(".msg") {
            return EmailFormat::Msg;
        }
    }

    // MBOX: starts with "From " at offset 0
    if header.len() >= 5 && &header[0..5] == b"From " {
        return EmailFormat::Mbox;
    }

    // Apple Mail `.emlx` (and `.partial.emlx`): by name, or — for a file whose
    // name was lost — by its whole wrapper: a decimal count line and an XML
    // property list starting exactly where the count says the message ends.
    // A digits-only first line alone is not enough; that is common text.
    if lower_name.ends_with(".emlx") || looks_like_emlx_wrapper(header) {
        return EmailFormat::Emlx;
    }

    // EML: check extension first, then content heuristics
    if lower_name.ends_with(".eml") {
        return EmailFormat::Eml;
    }

    // Content heuristics for EML.
    //
    // A header that only SAYS something about the message — `Subject:`,
    // `Date:`, `MIME-Version:` — is not evidence that the file is mail. Android
    // writes its crash dumps under `/data/system/dropbox` with a header block
    // of `Process:`, `Subject:`, `Build:`, and any-one-header matching turned
    // twenty Java stack traces into twenty emails with no sender, no
    // recipient, no date and a `wtf` trace as the body — on a case an examiner
    // is asked questions about emails (HUNT-095).
    //
    // So the match must be an *identity*-bearing header: who it is from, who it
    // is to, or what names it as a message that travelled. RFC 5322 makes
    // `From:` mandatory and real mail carries `Received:` and `Message-ID:` as
    // well, so nothing genuine is refused by asking for one of them.
    if let Ok(text) = std::str::from_utf8(&header[..header.len().min(1024)]) {
        let lines: Vec<&str> = text.lines().take(10).collect();
        let identifies_a_message = lines.iter().any(|line| {
            line.starts_with("From:")
                || line.starts_with("To:")
                || line.starts_with("Cc:")
                || line.starts_with("Received:")
                || line.starts_with("Message-ID:")
                || line.starts_with("Message-Id:")
                || line.starts_with("Return-Path:")
                || line.starts_with("Delivered-To:")
        });
        if identifies_a_message {
            return EmailFormat::Eml;
        }
    }

    // Extension-based fallback for MBOX
    if lower_name.ends_with(".mbox") || lower_name.ends_with(".mbx") {
        return EmailFormat::Mbox;
    }

    EmailFormat::Unknown
}

/// The `.emlx` byte-count line: decimal digits, optionally padded with spaces
/// (Apple Mail writes `701       `), then a newline. Returns the count and the
/// offset of the first message byte.
pub(crate) fn emlx_count_line(data: &[u8]) -> Option<(usize, usize)> {
    let nl = data.iter().take(32).position(|&b| b == b'\n')?;
    let line = std::str::from_utf8(&data[..nl]).ok()?;
    let digits = line.trim_end_matches(['\r', ' ', '\t']);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some((digits.parse().ok()?, nl + 1))
}

/// True when the bytes carry the whole `.emlx` wrapper, not only a count line:
/// the count lands inside the buffer and an XML plist starts right after it.
fn looks_like_emlx_wrapper(data: &[u8]) -> bool {
    let Some((count, start)) = emlx_count_line(data) else {
        return false;
    };
    let Some(end) = start.checked_add(count) else {
        return false;
    };
    data.get(end..)
        .map(|rest| rest.starts_with(b"<?xml"))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_emlx_by_extension_and_count_line() {
        let data = b"701       \nSubject: Email\nX-Apple-Base-Url: x-msg://1/\n".to_vec();
        assert_eq!(detect_email_format(&data, "2.emlx"), EmailFormat::Emlx);
        assert_eq!(
            detect_email_format(&data, "1498.partial.emlx"),
            EmailFormat::Emlx
        );
        // Without the name: a count line, headers after it, and the plist
        // trailer where the count says the message ends.
        let msg = b"Subject: x\nFrom: a@example.com\n\nbody\n";
        let mut bare = format!("{}\n", msg.len()).into_bytes();
        bare.extend_from_slice(msg);
        bare.extend_from_slice(b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<plist/>");
        assert_eq!(detect_email_format(&bare, "carved_0001"), EmailFormat::Emlx);
        // A digits-only first line alone is not enough.
        assert_ne!(
            detect_email_format(b"12\nhello world\n", "numbers.txt"),
            EmailFormat::Emlx
        );
    }

    #[test]
    fn test_detect_msg_by_ole2_magic() {
        let mut header = vec![0u8; 512];
        header[0..8].copy_from_slice(&OLE2_SIGNATURE);
        assert_eq!(
            detect_email_format(&header, "message.msg"),
            EmailFormat::Msg
        );
    }

    #[test]
    fn test_ole2_not_msg_without_extension() {
        let mut header = vec![0u8; 512];
        header[0..8].copy_from_slice(&OLE2_SIGNATURE);
        // OLE2 but .doc extension — should NOT detect as MSG
        assert_eq!(
            detect_email_format(&header, "document.doc"),
            EmailFormat::Unknown
        );
    }

    #[test]
    fn test_detect_mbox_from_magic() {
        let header = b"From sender@example.com Mon Jan  1 00:00:00 2024\n".to_vec();
        assert_eq!(detect_email_format(&header, "mail"), EmailFormat::Mbox);
    }

    #[test]
    fn test_detect_eml_by_extension() {
        let header = b"Some random content".to_vec();
        assert_eq!(
            detect_email_format(&header, "message.eml"),
            EmailFormat::Eml
        );
    }

    #[test]
    fn test_detect_eml_by_rfc822_headers() {
        let header =
            b"From: user@example.com\r\nTo: other@example.com\r\nSubject: Test\r\n".to_vec();
        assert_eq!(
            detect_email_format(&header, "unknown_file"),
            EmailFormat::Eml
        );
    }

    #[test]
    fn test_detect_eml_by_received_header() {
        let header = b"Received: from mail.example.com by mx.example.com\r\n".to_vec();
        assert_eq!(
            detect_email_format(&header, "no_extension"),
            EmailFormat::Eml
        );
    }

    #[test]
    fn test_detect_mbox_by_extension() {
        let header = b"Not a From line at start".to_vec();
        assert_eq!(
            detect_email_format(&header, "inbox.mbox"),
            EmailFormat::Mbox
        );
    }

    #[test]
    fn test_detect_mbx_extension() {
        let header = b"random bytes".to_vec();
        assert_eq!(
            detect_email_format(&header, "archive.mbx"),
            EmailFormat::Mbox
        );
    }

    #[test]
    fn test_detect_unknown_binary() {
        let header = vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
        assert_eq!(
            detect_email_format(&header, "data.bin"),
            EmailFormat::Unknown
        );
    }

    #[test]
    fn test_detect_empty_header() {
        let header = vec![];
        assert_eq!(detect_email_format(&header, "file.eml"), EmailFormat::Eml);
    }

    #[test]
    fn test_detect_small_file() {
        let header = vec![0xFF, 0xFE];
        assert_eq!(
            detect_email_format(&header, "tiny.dat"),
            EmailFormat::Unknown
        );
    }

    #[test]
    fn test_case_insensitive_extension() {
        let header = b"Some content".to_vec();
        assert_eq!(
            detect_email_format(&header, "Message.EML"),
            EmailFormat::Eml
        );
        assert_eq!(
            detect_email_format(&header, "inbox.MBOX"),
            EmailFormat::Mbox
        );
    }

    #[test]
    fn test_detect_pst_by_magic() {
        let mut header = vec![0u8; 512];
        header[0..4].copy_from_slice(b"!BDN");
        assert_eq!(
            detect_email_format(&header, "outlook.pst"),
            EmailFormat::Pst
        );
    }

    #[test]
    fn test_detect_pst_by_magic_no_extension() {
        let mut header = vec![0u8; 512];
        header[0..4].copy_from_slice(b"!BDN");
        assert_eq!(
            detect_email_format(&header, "unknown_file"),
            EmailFormat::Pst
        );
    }

    #[test]
    fn test_detect_pst_by_extension() {
        let header = b"random bytes".to_vec();
        assert_eq!(
            detect_email_format(&header, "archive.pst"),
            EmailFormat::Pst
        );
    }

    #[test]
    fn test_detect_ost_by_extension() {
        let header = b"random bytes".to_vec();
        assert_eq!(detect_email_format(&header, "cache.ost"), EmailFormat::Pst);
    }

    #[test]
    fn test_detect_pst_case_insensitive() {
        let header = b"Some content".to_vec();
        assert_eq!(
            detect_email_format(&header, "Outlook.PST"),
            EmailFormat::Pst
        );
        assert_eq!(detect_email_format(&header, "CACHE.OST"), EmailFormat::Pst);
    }
}

#[cfg(test)]
mod android_dropbox_tests {
    use super::*;

    /// HUNT-095. Android writes its crash dumps under `/data/system/dropbox`
    /// with a header block that happens to include `Subject:`. Matching any one
    /// RFC-822-looking header turned twenty Java stack traces into twenty
    /// emails — no sender, no recipient, no date, a `wtf` trace as the body —
    /// on a case whose examiner is asked questions about the user's email.
    const ANDROID_WTF: &[u8] = b"Process: system_server\n\
        Subject: ActivityManager\n\
        Build: google/blueline/blueline:9/PD1A.180720.030/4972053:user/release-keys\n\
        \n\
        android.util.Log$TerribleFailure: Sending non-protected broadcast\n\
        \tat android.util.Log.wtf(Log.java:299)\n";

    #[test]
    fn a_crash_dump_that_carries_a_subject_is_not_mail() {
        assert_eq!(
            detect_email_format(ANDROID_WTF, "system_server_wtf@1644781878714.txt"),
            EmailFormat::Unknown
        );
    }

    /// Nothing genuine is refused by asking for an identity-bearing header:
    /// RFC 5322 makes `From:` mandatory, and real mail carries `Received:` and
    /// `Message-ID:` as well.
    #[test]
    fn real_mail_is_still_recognised_by_content_alone() {
        for header in [
            &b"From: ada@example.com\nSubject: hello\n\nbody\n"[..],
            &b"Received: from mx.example.com\nSubject: hello\n\nbody\n"[..],
            &b"Message-ID: <1@example.com>\nSubject: hello\n\nbody\n"[..],
            &b"Delivered-To: ada@example.com\nSubject: hello\n\nbody\n"[..],
        ] {
            assert_eq!(
                detect_email_format(header, "nameless"),
                EmailFormat::Eml,
                "{}",
                String::from_utf8_lossy(&header[..20])
            );
        }
    }

    /// And a file the examiner's own evidence names as mail is still read as
    /// mail, whatever its first ten lines look like.
    #[test]
    fn an_eml_by_name_is_still_read() {
        assert_eq!(
            detect_email_format(ANDROID_WTF, "message.eml"),
            EmailFormat::Eml
        );
    }
}
