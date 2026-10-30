//! Rock Ridge (IEEE P1282 RRIP) over the System Use Sharing Protocol (IEEE
//! P1281 SUSP): the POSIX names, attributes, times and link targets a Unix
//! mastering tool (`mkisofs -R`, `genisoimage -R`, `xorriso -as mkisofs -R`)
//! writes into each directory record's System Use area (HUNT-176).
//!
//! Read: `SP` (presence and skip length, on the root's "." record), `CE`
//! (continuation areas, followed within a budget), `ST`, `ER` (the extension
//! identifier), `NM` (the name, continued across entries), `PX` (mode, links,
//! uid, gid, serial number), `TF` (creation, modification, access and
//! attribute-change times, short and long form) and `SL` (symlink target).
//! Recognised and reported as present but not decoded: `PN` (device
//! numbers), `SF` (sparse file) and `ZF` (zisofs compression); an entry
//! carrying one of those is stamped with the signature so what was not read
//! is said. Deep-directory relocation is followed: `CL` (the placeholder
//! where a relocated directory belongs) and `RE` (the relocated record,
//! which is then not listed a second time); `PL` sits on ".." records, which
//! are never emitted.

use crate::parse_recording_datetime;
use seance_core::data_source::DataSource;
use seance_core::io::read_exact_or_fail;

/// Continuation areas followed per record before giving up.
const MAX_CONTINUATIONS: usize = 32;
/// Continuation bytes read per record before giving up.
const MAX_CONTINUATION_BYTES: usize = 64 * 1024;

/// What the System Use area of one directory record said.
#[derive(Debug, Default, Clone)]
pub(crate) struct RockRidge {
    /// The `NM` name, when one was recorded (absent on "." and "..").
    pub name: Option<String>,
    /// `PX`: st_mode, st_nlink, st_uid, st_gid, and st_ino (RRIP 1.12 only).
    pub mode: Option<u32>,
    pub nlink: Option<u32>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub serial: Option<u32>,
    /// `TF` times as RFC 3339.
    pub created: Option<String>,
    pub modified: Option<String>,
    pub accessed: Option<String>,
    pub changed: Option<String>,
    /// `SL`: the symbolic link's target.
    pub symlink_target: Option<String>,
    /// `CL`: the LBA of the relocated directory this placeholder stands for.
    pub child_link: Option<u32>,
    /// `RE`: this record is a relocated directory, reached through its `CL`.
    pub relocated: bool,
    /// Signatures present and recognised but not decoded here.
    pub unread: Vec<&'static str>,
    /// The System Use area could not be read to its end (a continuation area
    /// past the image, or past the budget). What was read before is kept.
    pub incomplete: bool,
}

/// Rock Ridge as the root "." record declares it.
#[derive(Debug, Clone)]
pub(crate) struct RockRidgeVolume {
    /// `SP`'s LEN_SKP: bytes to skip at the start of every System Use area.
    pub skip: usize,
    /// The `ER` extension identifier, e.g. `RRIP_1991A` or `IEEE_P1282`.
    pub extension_id: Option<String>,
}

/// One `(signature, entry bytes)` of a System Use area, continuation areas
/// included.
fn entries(
    ds: &dyn DataSource,
    block_size: u32,
    sua: &[u8],
    incomplete: &mut bool,
) -> Vec<([u8; 2], Vec<u8>)> {
    let mut out = Vec::new();
    let mut area = sua.to_vec();
    let mut hops = 0usize;
    let mut read_bytes = 0usize;
    loop {
        let mut next: Option<(u64, usize)> = None;
        let mut pos = 0usize;
        while pos + 4 <= area.len() {
            let sig = [area[pos], area[pos + 1]];
            let len = area[pos + 2] as usize;
            if len < 4 || pos + len > area.len() {
                break;
            }
            let entry = &area[pos..pos + len];
            match &sig {
                b"ST" => break,
                b"CE" if len >= 28 => {
                    let le = |o: usize| {
                        u32::from_le_bytes([entry[o], entry[o + 1], entry[o + 2], entry[o + 3]])
                    };
                    next = Some((
                        le(4) as u64 * block_size as u64 + le(12) as u64,
                        le(20) as usize,
                    ));
                }
                _ => out.push((sig, entry.to_vec())),
            }
            pos += len;
        }
        let Some((offset, len)) = next else {
            return out;
        };
        hops += 1;
        read_bytes += len;
        if hops > MAX_CONTINUATIONS || read_bytes > MAX_CONTINUATION_BYTES || len == 0 {
            *incomplete = true;
            return out;
        }
        let mut buf = vec![0u8; len];
        if read_exact_or_fail(ds, offset, &mut buf, "Rock Ridge continuation area").is_err() {
            *incomplete = true;
            return out;
        }
        area = buf;
    }
}

/// Whether the root directory's "." record declares SUSP with Rock Ridge on
/// it: an `SP` entry with its 0xBE 0xEF check bytes at the start of the
/// System Use area, and an `ER` entry, or any RRIP entry, after it.
pub(crate) fn detect(
    ds: &dyn DataSource,
    block_size: u32,
    root_dot_sua: &[u8],
) -> Option<RockRidgeVolume> {
    let sp = root_dot_sua.get(..7)?;
    if &sp[..2] != b"SP" || sp[2] != 7 || sp[4] != 0xBE || sp[5] != 0xEF {
        return None;
    }
    let skip = sp[6] as usize;
    let mut incomplete = false;
    let mut extension_id = None;
    let mut rrip = false;
    for (sig, e) in entries(ds, block_size, root_dot_sua, &mut incomplete) {
        match &sig {
            b"ER" if e.len() >= 8 => {
                let len_id = e[4] as usize;
                if let Some(id) = e.get(8..8 + len_id) {
                    extension_id = Some(String::from_utf8_lossy(id).into_owned());
                }
            }
            b"RR" | b"PX" | b"NM" | b"TF" | b"SL" => rrip = true,
            _ => {}
        }
    }
    let is_rrip = extension_id.as_deref().is_some_and(|id| {
        id.starts_with("RRIP") || id.starts_with("IEEE_P1282") || id.starts_with("IEEE_1282")
    });
    (rrip || is_rrip).then_some(RockRidgeVolume { skip, extension_id })
}

/// Decode a `TF` timestamp: the 7-byte directory-record form, or the 17-byte
/// volume-descriptor form (`YYYYMMDDHHMMSScc` digits and a 15-minute offset).
fn tf_time(b: &[u8], long: bool) -> Option<String> {
    if !long {
        return parse_recording_datetime(b);
    }
    let digits = std::str::from_utf8(b.get(..16)?).ok()?;
    let num = |r: std::ops::Range<usize>| digits.get(r)?.parse::<u32>().ok();
    let date = chrono::NaiveDate::from_ymd_opt(num(0..4)? as i32, num(4..6)?, num(6..8)?)?;
    let time = chrono::NaiveTime::from_hms_milli_opt(
        num(8..10)?,
        num(10..12)?,
        num(12..14)?,
        num(14..16)? * 10,
    )?;
    let tz = chrono::FixedOffset::east_opt((*b.get(16)? as i8) as i32 * 15 * 60)?;
    let dt = chrono::TimeZone::from_local_datetime(&tz, &date.and_time(time)).single()?;
    Some(dt.to_rfc3339())
}

/// Read one directory record's System Use area.
pub(crate) fn read(
    ds: &dyn DataSource,
    block_size: u32,
    sua: &[u8],
    vol: &RockRidgeVolume,
) -> RockRidge {
    let mut rr = RockRidge::default();
    let sua = sua.get(vol.skip..).unwrap_or(&[]);
    let mut name: Vec<u8> = Vec::new();
    let mut have_name = false;
    let mut link: Vec<String> = Vec::new();
    let mut link_part = String::new();
    let mut link_part_open = false;
    let mut incomplete = false;
    for (sig, e) in entries(ds, block_size, sua, &mut incomplete) {
        let le = |o: usize| {
            e.get(o..o + 4)
                .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
        };
        match &sig {
            b"NM" if e.len() >= 5 => {
                // CURRENT (0x02) and PARENT (0x04) name "." and ".."; those
                // records are never emitted, so neither is taken as a name.
                if e[4] & 0x06 == 0 {
                    name.extend_from_slice(&e[5..]);
                    have_name = true;
                }
            }
            b"PX" => {
                rr.mode = le(4);
                rr.nlink = le(12);
                rr.uid = le(20);
                rr.gid = le(28);
                if e.len() >= 44 {
                    rr.serial = le(36);
                }
            }
            b"TF" if e.len() >= 5 => {
                let flags = e[4];
                let long = flags & 0x80 != 0;
                let width = if long { 17 } else { 7 };
                let mut pos = 5usize;
                for bit in 0..7u8 {
                    if flags & (1 << bit) == 0 {
                        continue;
                    }
                    let Some(stamp) = e.get(pos..pos + width) else {
                        break;
                    };
                    let t = tf_time(stamp, long);
                    match bit {
                        0 => rr.created = t,
                        1 => rr.modified = t,
                        2 => rr.accessed = t,
                        3 => rr.changed = t,
                        _ => {} // backup, expiration, effective: not file times
                    }
                    pos += width;
                }
            }
            b"SL" if e.len() >= 5 => {
                let mut pos = 5usize;
                while pos + 2 <= e.len() {
                    let cflags = e[pos];
                    let clen = e[pos + 1] as usize;
                    let Some(content) = e.get(pos + 2..pos + 2 + clen) else {
                        break;
                    };
                    if cflags & 0x02 != 0 {
                        link_part.push('.');
                    } else if cflags & 0x04 != 0 {
                        link_part.push_str("..");
                    } else if cflags & 0x08 != 0 {
                        // Root: an absolute target starts with an empty part.
                    } else {
                        link_part.push_str(&String::from_utf8_lossy(content));
                    }
                    // Component CONTINUE (0x01): the next component carries
                    // on this path component rather than starting a new one.
                    if cflags & 0x01 == 0 {
                        link.push(std::mem::take(&mut link_part));
                        link_part_open = false;
                    } else {
                        link_part_open = true;
                    }
                    pos += 2 + clen;
                }
            }
            b"PN" => rr.unread.push("PN"),
            b"CL" => rr.child_link = le(4),
            b"RE" => rr.relocated = true,
            b"SF" => rr.unread.push("SF"),
            b"ZF" => rr.unread.push("ZF"),
            _ => {}
        }
    }
    if link_part_open {
        link.push(link_part);
    }
    if have_name {
        rr.name = Some(String::from_utf8_lossy(&name).into_owned());
    }
    if !link.is_empty() {
        let joined = link.join("/");
        // A root component alone ("/") joins to the empty string.
        rr.symlink_target = Some(if joined.is_empty() {
            "/".to_string()
        } else {
            joined
        });
    }
    rr.incomplete = incomplete;
    rr
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_long_form_tf_time_is_decoded() {
        let mut b = b"2019050607080912".to_vec();
        b.push(4); // +01:00
        assert_eq!(
            tf_time(&b, true).as_deref(),
            Some("2019-05-06T07:08:09.120+01:00")
        );
    }

    #[test]
    fn an_absolute_symlink_keeps_its_leading_slash() {
        // SL: flags 0, components ROOT, "etc", "passwd".
        let mut sl = vec![b'S', b'L', 0, 1, 0];
        sl.extend_from_slice(&[0x08, 0]);
        sl.extend_from_slice(&[0, 3]);
        sl.extend_from_slice(b"etc");
        sl.extend_from_slice(&[0, 6]);
        sl.extend_from_slice(b"passwd");
        sl[2] = sl.len() as u8;
        let ds = seance_core::data_source::ByteSliceDataSource::new(Vec::new());
        let vol = RockRidgeVolume {
            skip: 0,
            extension_id: None,
        };
        let rr = read(&ds, 2048, &sl, &vol);
        assert_eq!(rr.symlink_target.as_deref(), Some("/etc/passwd"));
    }
}
