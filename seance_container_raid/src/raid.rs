//! RAID geometry and a virtual device that reconstructs the logical block space.
//!
//! The reconstruction handles the case that matters most in a lab: one member
//! disk dead. For RAID 5 (and RAID 6 with a single failure) a missing chunk is
//! the XOR of every other member's chunk in the same stripe row, so the array is
//! still fully readable. The layout implemented is the Linux `md` default,
//! **left-symmetric** RAID 5, and the equivalent for RAID 6's P parity.
//!
//! Every member stores exactly one chunk per stripe row, all at the same physical
//! offset (`stripe * chunk_size`), which is what makes single-member
//! reconstruction an XOR across the row — for RAID 5, across every other member;
//! for RAID 6, across every other member *except the Q-syndrome disk*, since Q is
//! a Reed-Solomon code and not part of the XOR-parity relation.
//!
//! # Verification status
//!
//! The tests build an array with the same left-symmetric placement the reader
//! expects, then verify a full read and a read with each member removed. The XOR
//! *reconstruction* is layout-independent and provably correct for any real
//! array (P is the XOR of the data chunks, so any one missing chunk is the XOR of
//! the rest). The *intact-read mapping* follows the documented Linux
//! left-symmetric algorithm; validating it byte-for-byte against a real `mdadm`
//! array is the recommended follow-up before relying on it in a live case, and
//! the geometry can always be supplied explicitly when a superblock is absent.

use seance_core::data_source::DataSource;
use std::io;
use std::sync::Arc;

/// The RAID level / layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RaidLevel {
    /// Striping, no redundancy. Any missing member makes the array unreadable.
    Raid0,
    /// Mirroring. Readable as long as one member survives.
    Raid1,
    /// Striping with distributed single parity (left-symmetric).
    Raid5,
    /// Striping with distributed double parity; single-failure recovery uses P.
    Raid6,
    /// Just a bunch of disks: linear concatenation.
    Jbod,
}

/// A member disk, present or missing.
type Member = Option<Arc<dyn DataSource>>;

/// A reconstructed RAID device.
#[derive(Clone)]
pub struct RaidDevice {
    level: RaidLevel,
    members: Vec<Member>,
    /// Stripe unit ("chunk") size in bytes. Ignored for RAID 1.
    chunk: u64,
    /// Per-member size in bytes for the levels that require equal members
    /// (RAID 0/1/5/6). **JBOD ignores this** and uses each member's actual size,
    /// since a JBOD concatenates disks that may differ in size.
    member_size: u64,
    /// Total logical size, computed once (and checked for 64-bit
    /// representability) by [`RaidDevice::new`].
    logical_size: u64,
}

impl std::fmt::Debug for RaidDevice {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_struct("RaidDevice")
            .field("level", &self.level)
            .field("members", &self.members.len())
            .field(
                "present",
                &self.members.iter().filter(|m| m.is_some()).count(),
            )
            .field("chunk", &self.chunk)
            .field("member_size", &self.member_size)
            .finish()
    }
}

impl RaidDevice {
    /// Build a device. `members` positions are significant: index is the disk's
    /// place in the array, and a `None` marks a missing disk. Fails if the level
    /// cannot be reconstructed from the members present.
    pub fn new(
        level: RaidLevel,
        members: Vec<Member>,
        chunk: u64,
        member_size: u64,
    ) -> Result<Self, String> {
        if members.is_empty() {
            return Err("no members".into());
        }
        // Minimum member counts: the geometry divides by `n-1` (RAID 5) and
        // `n-2` (RAID 6), so too few members would divide by zero. Enforce the
        // smallest count each level's arithmetic needs.
        let n = members.len();
        let min = match level {
            RaidLevel::Raid5 => 2,
            RaidLevel::Raid6 => 3,
            _ => 1,
        };
        if n < min {
            return Err(format!("{level:?} needs at least {min} members, got {n}"));
        }
        // Every read of a size-derived level divides by `member_size` (JBOD) or
        // bounds the logical size by it; zero would divide by zero or present an
        // empty device as if it were the evidence.
        if member_size == 0 {
            return Err("member size must be non-zero".into());
        }
        // Striped levels need a chunk size; RAID 1 and JBOD do not use one.
        let striped = matches!(
            level,
            RaidLevel::Raid0 | RaidLevel::Raid5 | RaidLevel::Raid6
        );
        if striped && chunk == 0 {
            return Err("chunk size must be non-zero".into());
        }
        let missing = members.iter().filter(|m| m.is_none()).count();
        match level {
            RaidLevel::Raid0 | RaidLevel::Jbod if missing > 0 => {
                return Err(format!(
                    "{level:?} cannot tolerate {missing} missing member(s)"
                ));
            }
            RaidLevel::Raid5 if missing > 1 => {
                return Err(format!(
                    "RAID 5 cannot reconstruct {missing} missing members"
                ));
            }
            RaidLevel::Raid6 if missing > 2 => {
                return Err(format!(
                    "RAID 6 cannot reconstruct {missing} missing members"
                ));
            }
            RaidLevel::Raid1 if missing == members.len() => {
                return Err("RAID 1 has no surviving mirror".into());
            }
            _ => {}
        }
        // The logical size must be expressible in 64 bits. `member_size * n` on a
        // mistaken or hostile geometry can exceed u64, and a wrapped product would
        // present a false device length (or abort the read where overflow checks
        // are on). An array whose size cannot be stated is refused here, once,
        // rather than producing a wrong number on every read.
        let Some(logical_size) = Self::checked_logical_size(level, &members, member_size) else {
            return Err(format!(
                "{level:?} geometry is not representable: {n} members of {member_size} bytes \
                 overflow a 64-bit logical size"
            ));
        };
        Ok(Self {
            level,
            members,
            chunk,
            member_size,
            logical_size,
        })
    }

    /// Number of member disks (present + missing).
    fn n(&self) -> u64 {
        self.members.len() as u64
    }

    /// The logical size a geometry implies, or `None` if it overflows a u64.
    /// Callers must have validated the per-level minimum member counts first
    /// (`n - 1` / `n - 2` below rely on them).
    fn checked_logical_size(level: RaidLevel, members: &[Member], member_size: u64) -> Option<u64> {
        let n = members.len() as u64;
        match level {
            RaidLevel::Raid0 => member_size.checked_mul(n),
            // JBOD concatenates members of their own (possibly unequal) sizes, so
            // its logical size is the SUM of the actual member sizes, not a
            // uniform `member_size * n` (which would misalign unequal members).
            RaidLevel::Jbod => members
                .iter()
                .flatten()
                .try_fold(0u64, |acc, m| acc.checked_add(m.size())),
            RaidLevel::Raid1 => Some(member_size),
            RaidLevel::Raid5 => member_size.checked_mul(n - 1),
            RaidLevel::Raid6 => member_size.checked_mul(n - 2),
        }
    }

    /// Total logical size of the reconstructed device, fixed at construction.
    pub fn logical_size(&self) -> u64 {
        self.logical_size
    }

    /// Read the cell `[phys, phys+len)` straight from a PRESENT member,
    /// distinguishing a truncated member from legitimate end-of-member padding.
    ///
    /// Returns the number of leading bytes in `buf` that are backed by REAL data.
    /// Bytes of the cell that fall within the array's declared `member_size` must
    /// come from the member itself; if the member is shorter than that (a partial
    /// or wrong member image), the missing bytes are NOT real and the count stops
    /// there. Bytes that fall *past* `member_size` are legitimate padding (real
    /// arrays pad members to an equal size) and are zero-filled and counted valid.
    fn read_member_cell(
        &self,
        src: &dyn DataSource,
        phys: u64,
        buf: &mut [u8],
    ) -> io::Result<usize> {
        // How many of the requested bytes lie within the member's usable size.
        let within = self.member_size.saturating_sub(phys).min(buf.len() as u64) as usize;
        // An I/O error on the member propagates: a disk that FAILED must not be
        // reported as a member image that simply ended (see `fill_at`).
        let got = fill_at(src, phys, &mut buf[..within])?;
        // Zero the padding tail so parity math sees the zeros a padded member holds.
        for b in buf[within..].iter_mut() {
            *b = 0;
        }
        if got < within {
            Ok(got) // truncated member: only the bytes actually present are real
        } else {
            Ok(buf.len()) // full in-range data plus legitimate padding
        }
    }

    /// Read one chunk-row cell: the bytes on `disk` at `[phys, phys+len)`,
    /// reconstructing them by XOR if `disk` is missing (parity levels only).
    ///
    /// Returns the number of leading bytes that are backed by real data (see
    /// [`Self::read_member_cell`]); a value below `buf.len()` means a member the
    /// read (or reconstruction) depended on is truncated, so the caller must stop
    /// rather than hand back the zero-filled/fabricated tail as complete.
    ///
    /// Single-member recovery uses the XOR parity P: a missing data chunk is the
    /// XOR of the other data chunks and P. For RAID 6 the **Q syndrome disk must
    /// be excluded** from that XOR — Q is a Reed-Solomon code, not part of the XOR
    /// relation, and folding it in would corrupt the result. `disk` is always a
    /// data disk here (parity disks are never mapped for a data read), so the only
    /// disk to skip beyond the missing one is Q, and only on RAID 6.
    fn read_cell(&self, disk: usize, phys: u64, buf: &mut [u8]) -> io::Result<usize> {
        if let Some(src) = &self.members[disk] {
            return self.read_member_cell(src.as_ref(), phys, buf);
        }
        // Two members down on RAID 6: recover with the Q syndrome, not plain XOR.
        if self.level == RaidLevel::Raid6
            && self.members.iter().filter(|m| m.is_none()).count() == 2
        {
            return self.reconstruct_raid6_double(disk, phys, buf);
        }
        // The Q-syndrome disk for this stripe, excluded from XOR on RAID 6.
        let skip_q = if self.level == RaidLevel::Raid6 {
            let stripe = phys / self.chunk;
            Some(((self.parity_disk(stripe) + 1) % self.n()) as usize)
        } else {
            None
        };
        // Missing member: XOR every other member's bytes at the same physical row,
        // skipping the Q disk on RAID 6. The reconstruction at byte j is only real
        // if EVERY contributing member had a real byte j; a truncated survivor
        // would otherwise fold its zero-fill into the XOR and fabricate the result.
        // So the valid length is the minimum real length across the contributors.
        for b in buf.iter_mut() {
            *b = 0;
        }
        let mut tmp = vec![0u8; buf.len()];
        let mut valid = buf.len();
        for (i, m) in self.members.iter().enumerate() {
            if i == disk || Some(i) == skip_q {
                continue;
            }
            let src = m
                .as_ref()
                .ok_or_else(|| io::Error::other("cannot reconstruct: >1 member missing"))?;
            let got = self.read_member_cell(src.as_ref(), phys, &mut tmp)?;
            valid = valid.min(got);
            for (b, t) in buf.iter_mut().zip(&tmp) {
                *b ^= *t;
            }
        }
        Ok(valid)
    }

    /// The data index (0-based position among a stripe's data chunks) of `disk`
    /// on an `n`-disk RAID 6 array whose Q disk is `q_disk`. Inverse of the
    /// `(q_disk + 1 + d) % n` placement used by [`Self::locate`].
    fn raid6_data_index(&self, disk: usize, q_disk: usize) -> usize {
        let n = self.n() as i64;
        ((disk as i64 - q_disk as i64 - 1).rem_euclid(n)) as usize
    }

    /// Reconstruct a missing data cell when **two** members are down on RAID 6,
    /// using the P and Q syndromes. `disk` is the data cell wanted; the other
    /// missing member may be another data disk, the P disk, or the Q disk.
    ///
    /// Formulas follow Anvin's RAID-6 derivation over [`crate::gf`]:
    /// - two data disks x,y lost (P,Q present): `Dx = (Qxy ⊕ gʸ·Pxy)/(gˣ ⊕ gʸ)`;
    /// - data + Q lost: recover from P (plain XOR of the surviving data);
    /// - data + P lost: recover from Q alone: `Dx = (Q ⊕ Σ gⁱ·Dᵢ) / gˣ`.
    fn reconstruct_raid6_double(
        &self,
        disk: usize,
        phys: u64,
        buf: &mut [u8],
    ) -> io::Result<usize> {
        use crate::gf;
        let n = self.n() as usize;
        let len = buf.len();
        let stripe = phys / self.chunk;
        let p_disk = self.parity_disk(stripe) as usize;
        let q_disk = (p_disk + 1) % n;

        // Sum over present data disks: Σ Dᵢ (for P) and Σ gⁱ·Dᵢ (for Q). Every
        // present member feeds the syndromes, so the recovered bytes are only real
        // where ALL of them had real data — a truncated survivor beyond that point
        // would fabricate the result. Track the minimum real length as `valid`.
        let mut sum_p = vec![0u8; len];
        let mut sum_q = vec![0u8; len];
        let mut p_cell: Option<Vec<u8>> = None;
        let mut q_cell: Option<Vec<u8>> = None;
        let mut tmp = vec![0u8; len];
        let mut valid = len;
        for (i, m) in self.members.iter().enumerate() {
            let Some(src) = m else { continue };
            valid = valid.min(self.read_member_cell(src.as_ref(), phys, &mut tmp)?);
            if i == p_disk {
                p_cell = Some(tmp.clone());
            } else if i == q_disk {
                q_cell = Some(tmp.clone());
            } else {
                let g = gf::gpow(self.raid6_data_index(i, q_disk));
                for j in 0..len {
                    sum_p[j] ^= tmp[j];
                    sum_q[j] ^= gf::mul(g, tmp[j]);
                }
            }
        }

        // The other missing member.
        let other = self
            .members
            .iter()
            .enumerate()
            .find(|(i, m)| *i != disk && m.is_none())
            .map(|(i, _)| i)
            .ok_or_else(|| io::Error::other("RAID 6: expected a second missing member"))?;

        let x = self.raid6_data_index(disk, q_disk);
        let gx = gf::gpow(x);

        if other == q_disk {
            // Data + Q lost: P alone recovers the data.
            let p = p_cell.ok_or_else(|| io::Error::other("RAID 6: P also missing"))?;
            for j in 0..len {
                buf[j] = p[j] ^ sum_p[j];
            }
        } else if other == p_disk {
            // Data + P lost: Q alone recovers the data.
            let q = q_cell.ok_or_else(|| io::Error::other("RAID 6: Q also missing"))?;
            for j in 0..len {
                buf[j] = gf::div(q[j] ^ sum_q[j], gx);
            }
        } else {
            // Two data disks lost: both syndromes needed.
            let p = p_cell.ok_or_else(|| io::Error::other("RAID 6: P missing"))?;
            let q = q_cell.ok_or_else(|| io::Error::other("RAID 6: Q missing"))?;
            let y = self.raid6_data_index(other, q_disk);
            let gy = gf::gpow(y);
            let denom = gx ^ gy;
            for j in 0..len {
                let pxy = p[j] ^ sum_p[j];
                let qxy = q[j] ^ sum_q[j];
                buf[j] = gf::div(qxy ^ gf::mul(gy, pxy), denom);
            }
        }
        Ok(valid)
    }

    /// Left-symmetric parity disk for a stripe on an `n`-disk RAID 5/6 array.
    fn parity_disk(&self, stripe: u64) -> u64 {
        (self.n() - 1) - (stripe % self.n())
    }

    /// Map a logical chunk index to `(disk, stripe)` for the current level.
    fn locate(&self, logical_chunk: u64) -> (usize, u64) {
        let n = self.n();
        match self.level {
            RaidLevel::Raid0 => {
                let disk = (logical_chunk % n) as usize;
                let stripe = logical_chunk / n;
                (disk, stripe)
            }
            RaidLevel::Raid5 => {
                let data_per_stripe = n - 1;
                let stripe = logical_chunk / data_per_stripe;
                let d = logical_chunk % data_per_stripe;
                let parity = self.parity_disk(stripe);
                // Left-symmetric: first data chunk sits just after parity.
                let disk = ((parity + 1 + d) % n) as usize;
                (disk, stripe)
            }
            RaidLevel::Raid6 => {
                let data_per_stripe = n - 2;
                let stripe = logical_chunk / data_per_stripe;
                let d = logical_chunk % data_per_stripe;
                // P at parity_disk, Q at parity_disk+1 wrapping; data after Q.
                let p = self.parity_disk(stripe);
                let disk = ((p + 2 + d) % n) as usize;
                (disk, stripe)
            }
            RaidLevel::Raid1 | RaidLevel::Jbod => unreachable!("handled in read_at"),
        }
    }
}

/// Best-effort read at `off`: fill as much of `buf` as the source provides and
/// return the byte count, without zero-filling the rest. A short read is reported
/// (as a smaller count) rather than disguised as zeros, so every caller — the
/// JBOD path and the striped/parity cell reads — can surface a truncated member
/// instead of fabricating clean data past its end.
///
/// An I/O **error** is not end-of-member: a failing disk reported as a short read
/// is indistinguishable from a truncated member image, and the cause of the
/// incompleteness would never reach the examiner. Errors propagate.
fn fill_at(src: &dyn DataSource, off: u64, buf: &mut [u8]) -> io::Result<usize> {
    let mut total = 0;
    while total < buf.len() {
        match src.read_at(off + total as u64, &mut buf[total..]) {
            Ok(0) => break,
            Ok(k) => total += k,
            Err(e) => return Err(e),
        }
    }
    Ok(total)
}

impl DataSource for RaidDevice {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        let size = self.logical_size();
        if offset >= size {
            return Ok(0);
        }
        let want = (buf.len() as u64).min(size - offset) as usize;
        let mut done = 0;

        match self.level {
            RaidLevel::Raid1 => {
                // Mirrors are identical copies, so byte j is the same on each.
                // Read from the mirrors in turn, using a later (longer) mirror to
                // supply any tail a shorter one could not — a short lead mirror
                // must NOT cap the read, or the reconstruction is silently
                // truncated. Any region no mirror covers stays zero (a hole), and
                // we always return `want` since `offset < size`.
                for b in buf[..want].iter_mut() {
                    *b = 0;
                }
                let mut covered = 0usize;
                // A mirror that ERRORS is not a mirror that ended: remember the
                // failure and let a healthy mirror cover the region — that is what
                // the redundancy is for. It only becomes the read's outcome if no
                // mirror could supply the bytes, so a failing disk never passes as
                // a merely truncated one.
                let mut first_err: Option<io::Error> = None;
                for m in self.members.iter().flatten() {
                    if covered >= want {
                        break;
                    }
                    let mut got = 0usize;
                    while got < want {
                        match m.read_at(offset + got as u64, &mut buf[got..want]) {
                            Ok(0) => break,
                            Ok(k) => got += k,
                            Err(e) => {
                                if first_err.is_none() {
                                    first_err = Some(e);
                                }
                                break;
                            }
                        }
                    }
                    covered = covered.max(got);
                }
                if covered < want {
                    if let Some(e) = first_err {
                        return Err(e);
                    }
                }
                // Return only what a mirror actually supplied. A region no mirror
                // could read stays uncovered and is reported as a SHORT read, not
                // as the zeros the buffer holds — so a truncated/unreadable RAID 1
                // surfaces as an incomplete reconstruction rather than clean data.
                return Ok(covered);
            }
            RaidLevel::Jbod => {
                // Linear concatenation across members of their ACTUAL sizes
                // (JBOD members may be unequal). Walk a cumulative offset built
                // from each member's real size rather than a uniform member_size.
                let mut pos = offset;
                'outer: while done < want {
                    let mut base = 0u64;
                    for m in &self.members {
                        let src = m
                            .as_ref()
                            .ok_or_else(|| io::Error::other("missing JBOD member"))?;
                        let msize = src.size();
                        if pos < base + msize {
                            let within = pos - base;
                            let n = ((base + msize - pos) as usize).min(want - done);
                            let got = fill_at(src.as_ref(), within, &mut buf[done..done + n])?;
                            done += got;
                            pos += got as u64;
                            if got < n {
                                // A short member read: stop and report the partial
                                // count rather than zero-filling past real data.
                                break 'outer;
                            }
                            continue 'outer;
                        }
                        base += msize;
                    }
                    // pos is past the concatenation end: nothing more to read.
                    break;
                }
                return Ok(done);
            }
            _ => {}
        }

        // Striped levels: walk chunk by chunk.
        let mut pos = offset;
        while done < want {
            let logical_chunk = pos / self.chunk;
            let intra = pos % self.chunk;
            let n = ((self.chunk - intra) as usize).min(want - done);
            let (disk, stripe) = self.locate(logical_chunk);
            let phys = stripe * self.chunk + intra;
            let got = self.read_cell(disk, phys, &mut buf[done..done + n])?;
            done += got;
            pos += got as u64;
            if got < n {
                // A member this cell depended on is truncated: stop and report the
                // partial count rather than pass off the zero-filled/fabricated
                // tail as a complete reconstruction.
                break;
            }
        }
        Ok(done)
    }

    fn size(&self) -> u64 {
        self.logical_size()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use seance_core::data_source::ByteSliceDataSource;

    fn arc(v: Vec<u8>) -> Arc<dyn DataSource> {
        Arc::new(ByteSliceDataSource::new(v))
    }

    /// A member that reads fine up to `good.len()` and then FAILS — a disk with
    /// media errors, as opposed to a member image that merely ended early. It
    /// still declares the array-sized `size`, so the failure is not visible from
    /// the geometry.
    #[derive(Debug)]
    struct FailingSource {
        good: Vec<u8>,
        size: u64,
    }
    impl DataSource for FailingSource {
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
            let off = offset as usize;
            if off >= self.good.len() {
                return Err(io::Error::other("member read failed"));
            }
            let n = buf.len().min(self.good.len() - off);
            buf[..n].copy_from_slice(&self.good[off..off + n]);
            Ok(n)
        }
        fn size(&self) -> u64 {
            self.size
        }
    }

    fn failing(good: Vec<u8>, size: u64) -> Arc<dyn DataSource> {
        Arc::new(FailingSource { good, size })
    }

    /// A member that DECLARES a huge size without holding the bytes — what a
    /// sparse image (`truncate -s`) looks like to a reader.
    #[derive(Debug)]
    struct HugeSource(u64);
    impl DataSource for HugeSource {
        fn read_at(&self, _offset: u64, _buf: &mut [u8]) -> io::Result<usize> {
            Ok(0)
        }
        fn size(&self) -> u64 {
            self.0
        }
    }

    fn read_all(dev: &RaidDevice) -> Vec<u8> {
        let mut out = vec![0u8; dev.logical_size() as usize];
        let n = dev.read_at(0, &mut out).unwrap();
        out.truncate(n);
        out
    }

    /// Build RAID 0 members from a logical image and the chunk size, then confirm
    /// the device reads back the original.
    #[test]
    fn raid0_round_trips() {
        let chunk = 4u64;
        let n = 3usize;
        let logical: Vec<u8> = (0..60).map(|i| i as u8).collect();
        // Distribute logical chunks across members round-robin.
        let mut members = vec![Vec::new(); n];
        for (ci, c) in logical.chunks(chunk as usize).enumerate() {
            members[ci % n].extend_from_slice(c);
        }
        let member_size = members[0].len() as u64;
        let dev = RaidDevice::new(
            RaidLevel::Raid0,
            members.into_iter().map(|m| Some(arc(m))).collect(),
            chunk,
            member_size,
        )
        .unwrap();
        assert_eq!(read_all(&dev), logical);
    }

    /// Build a left-symmetric RAID 5 the way `md` lays it out, then verify a
    /// full read AND a read with one member removed reconstruct the original.
    #[test]
    fn raid5_reconstructs_with_a_missing_member() {
        let chunk = 4u64;
        let n = 4usize; // 3 data + 1 parity per stripe
        let data_per_stripe = n - 1;
        let stripes = 5u64;
        let logical_len = (stripes as usize) * data_per_stripe * chunk as usize;
        let logical: Vec<u8> = (0..logical_len).map(|i| (i * 7 % 251) as u8).collect();

        // Lay out members exactly as `locate` expects, computing parity as XOR.
        let member_size = stripes * chunk;
        let mut members: Vec<Vec<u8>> = vec![vec![0u8; member_size as usize]; n];
        for stripe in 0..stripes {
            let parity = (n as u64 - 1) - (stripe % n as u64);
            let mut parity_chunk = vec![0u8; chunk as usize];
            for d in 0..data_per_stripe as u64 {
                let logical_chunk = stripe * data_per_stripe as u64 + d;
                let disk = ((parity + 1 + d) % n as u64) as usize;
                let src = &logical[(logical_chunk * chunk) as usize..][..chunk as usize];
                let phys = (stripe * chunk) as usize;
                members[disk][phys..phys + chunk as usize].copy_from_slice(src);
                for (p, s) in parity_chunk.iter_mut().zip(src) {
                    *p ^= *s;
                }
            }
            let phys = (stripe * chunk) as usize;
            members[parity as usize][phys..phys + chunk as usize].copy_from_slice(&parity_chunk);
        }

        // Full array reads back the original.
        let full = RaidDevice::new(
            RaidLevel::Raid5,
            members.iter().cloned().map(|m| Some(arc(m))).collect(),
            chunk,
            member_size,
        )
        .unwrap();
        assert_eq!(read_all(&full), logical, "intact RAID5 must read original");

        // Remove each member in turn; every one must reconstruct.
        for missing in 0..n {
            let mut m: Vec<Member> = members.iter().cloned().map(|v| Some(arc(v))).collect();
            m[missing] = None;
            let degraded = RaidDevice::new(RaidLevel::Raid5, m, chunk, member_size).unwrap();
            assert_eq!(
                read_all(&degraded),
                logical,
                "RAID5 with member {missing} missing must reconstruct"
            );
        }
    }

    /// Build a left-symmetric RAID 5 `(members, member_size)` from a logical
    /// image, laid out exactly as [`RaidDevice::locate`] expects.
    fn build_raid5(logical: &[u8], n: usize, chunk: u64, stripes: u64) -> (Vec<Vec<u8>>, u64) {
        let data_per_stripe = n - 1;
        let member_size = stripes * chunk;
        let mut members: Vec<Vec<u8>> = vec![vec![0u8; member_size as usize]; n];
        for stripe in 0..stripes {
            let parity = (n as u64 - 1) - (stripe % n as u64);
            let phys = (stripe * chunk) as usize;
            let mut parity_chunk = vec![0u8; chunk as usize];
            for d in 0..data_per_stripe as u64 {
                let logical_chunk = stripe * data_per_stripe as u64 + d;
                let disk = ((parity + 1 + d) % n as u64) as usize;
                let src = &logical[(logical_chunk * chunk) as usize..][..chunk as usize];
                members[disk][phys..phys + chunk as usize].copy_from_slice(src);
                for (p, s) in parity_chunk.iter_mut().zip(src) {
                    *p ^= *s;
                }
            }
            members[parity as usize][phys..phys + chunk as usize].copy_from_slice(&parity_chunk);
        }
        (members, member_size)
    }

    /// A striped (RAID 0) member that is TRUNCATED relative to the array geometry
    /// must surface as a SHORT read, never as a full-length buffer whose tail was
    /// silently zero-filled. Regression for the striped zero-fill finding — the
    /// truncation-detection fix previously covered only RAID 1 and JBOD.
    #[test]
    fn raid0_truncated_member_is_a_short_read_not_zeros() {
        let chunk = 4u64;
        let n = 3usize;
        // Non-zero data so a zero-filled tail is distinguishable from real bytes.
        let logical: Vec<u8> = (0..60).map(|i| (i + 1) as u8).collect();
        let mut members = vec![Vec::new(); n];
        for (ci, c) in logical.chunks(chunk as usize).enumerate() {
            members[ci % n].extend_from_slice(c);
        }
        let member_size = members[0].len() as u64; // 20
                                                   // Drop the last two chunks of member 1: it is now shorter than the array
                                                   // geometry (member_size) implies — a truncated/partial member image.
        members[1].truncate(12);
        let dev = RaidDevice::new(
            RaidLevel::Raid0,
            members.into_iter().map(|m| Some(arc(m))).collect(),
            chunk,
            member_size,
        )
        .unwrap();
        let mut out = vec![0u8; dev.logical_size() as usize];
        let got = dev.read_at(0, &mut out).unwrap();
        assert!(
            got < logical.len(),
            "a truncated striped member must yield a short read, not a zero-filled full length"
        );
        assert_eq!(
            &out[..got],
            &logical[..got],
            "the bytes returned before the truncation point must be the real data"
        );
    }

    /// A truncated PRESENT data member on RAID 5 must surface as a short read
    /// rather than reconstruct/return zero-filled bytes as if complete.
    #[test]
    fn raid5_truncated_present_member_is_a_short_read() {
        let chunk = 4u64;
        let n = 4usize;
        let stripes = 5u64;
        let data_per_stripe = n - 1;
        let logical_len = (stripes as usize) * data_per_stripe * chunk as usize;
        let logical: Vec<u8> = (0..logical_len).map(|i| (i * 7 % 251 + 1) as u8).collect();
        let (mut members, member_size) = build_raid5(&logical, n, chunk, stripes);
        members[0].truncate(8); // truncate a present member mid-array
        let dev = RaidDevice::new(
            RaidLevel::Raid5,
            members.into_iter().map(|m| Some(arc(m))).collect(),
            chunk,
            member_size,
        )
        .unwrap();
        let mut out = vec![0u8; dev.logical_size() as usize];
        let got = dev.read_at(0, &mut out).unwrap();
        assert!(
            got < logical_len,
            "a truncated present RAID5 member must surface as a short read"
        );
        assert_eq!(&out[..got], &logical[..got]);
    }

    /// The evidence-fabrication case: a member is MISSING and a surviving member
    /// is TRUNCATED. Bytes that would need the truncated survivor to reconstruct
    /// the missing disk must NOT be fabricated (XOR-with-zeros) and returned as
    /// complete — they must surface as a short read.
    #[test]
    fn raid5_reconstruction_from_a_truncated_survivor_is_not_fabricated() {
        let chunk = 4u64;
        let n = 4usize;
        let stripes = 5u64;
        let data_per_stripe = n - 1;
        let logical_len = (stripes as usize) * data_per_stripe * chunk as usize;
        let logical: Vec<u8> = (0..logical_len).map(|i| (i * 3 + 5) as u8).collect();
        let (mut members, member_size) = build_raid5(&logical, n, chunk, stripes);
        members[2].truncate(8); // a surviving member is truncated
        let mut m: Vec<Member> = members.into_iter().map(|v| Some(arc(v))).collect();
        m[0] = None; // and another is missing, reconstructed from the survivors
        let dev = RaidDevice::new(RaidLevel::Raid5, m, chunk, member_size).unwrap();
        let mut out = vec![0u8; dev.logical_size() as usize];
        let got = dev.read_at(0, &mut out).unwrap();
        assert!(
            got < logical_len,
            "reconstruction relying on a truncated survivor must be a short read, not fabricated"
        );
        assert_eq!(
            &out[..got],
            &logical[..got],
            "the bytes returned must be genuine, not XOR-with-zero-fill"
        );
    }

    /// RAID 6 intact read, plus single-member reconstruction that must exclude
    /// the Q-syndrome disk. Q is filled with a non-trivial pattern here, so a
    /// reconstruction that wrongly folds Q into the XOR would corrupt the result
    /// and fail this test — which is exactly the bug this guards against.
    #[test]
    fn raid6_reads_intact_and_reconstructs_one_missing_data_disk() {
        let chunk = 4u64;
        let n = 5usize; // 3 data + P + Q per stripe
        let data_per_stripe = n - 2;
        let stripes = 6u64;
        let logical_len = (stripes as usize) * data_per_stripe * chunk as usize;
        let logical: Vec<u8> = (0..logical_len).map(|i| (i * 5 + 3) as u8).collect();

        let member_size = stripes * chunk;
        let mut members: Vec<Vec<u8>> = vec![vec![0u8; member_size as usize]; n];
        let mut data_disks_per_stripe: Vec<Vec<usize>> = Vec::new();
        for stripe in 0..stripes {
            let p = (n as u64 - 1) - (stripe % n as u64);
            let q = (p + 1) % n as u64;
            let phys = (stripe * chunk) as usize;
            let mut p_chunk = vec![0u8; chunk as usize];
            let mut these_data = Vec::new();
            for d in 0..data_per_stripe as u64 {
                let logical_chunk = stripe * data_per_stripe as u64 + d;
                let disk = ((p + 2 + d) % n as u64) as usize;
                these_data.push(disk);
                let src = &logical[(logical_chunk * chunk) as usize..][..chunk as usize];
                members[disk][phys..phys + chunk as usize].copy_from_slice(src);
                for (pc, s) in p_chunk.iter_mut().zip(src) {
                    *pc ^= *s;
                }
            }
            members[p as usize][phys..phys + chunk as usize].copy_from_slice(&p_chunk);
            // Q: a deliberately non-XOR, non-zero pattern. Its exact value is
            // irrelevant to single-member data recovery via P — the point is that
            // it is NOT the XOR parity, so including it would break the result.
            let q_chunk: Vec<u8> = (0..chunk)
                .map(|i| 0xA5 ^ (stripe as u8).wrapping_add(i as u8))
                .collect();
            members[q as usize][phys..phys + chunk as usize].copy_from_slice(&q_chunk);
            data_disks_per_stripe.push(these_data);
        }

        let full = RaidDevice::new(
            RaidLevel::Raid6,
            members.iter().cloned().map(|m| Some(arc(m))).collect(),
            chunk,
            member_size,
        )
        .unwrap();
        assert_eq!(read_all(&full), logical, "intact RAID6 must read original");

        // Every disk that ever holds data in some stripe must be reconstructable
        // when it is the single missing member.
        let mut data_disks: Vec<usize> = data_disks_per_stripe.into_iter().flatten().collect();
        data_disks.sort_unstable();
        data_disks.dedup();
        for missing in data_disks {
            let mut m: Vec<Member> = members.iter().cloned().map(|v| Some(arc(v))).collect();
            m[missing] = None;
            let degraded = RaidDevice::new(RaidLevel::Raid6, m, chunk, member_size).unwrap();
            assert_eq!(
                read_all(&degraded),
                logical,
                "RAID6 with data-bearing member {missing} missing must reconstruct via P, excluding Q"
            );
        }
    }

    /// Build a correct RAID 6 array (real Q syndrome over GF(2⁸)) from a logical
    /// image, returning `(members, member_size)`. Layout matches `locate`.
    fn build_raid6(logical: &[u8], n: usize, chunk: u64, stripes: u64) -> (Vec<Vec<u8>>, u64) {
        use crate::gf;
        let data_per_stripe = n - 2;
        let member_size = stripes * chunk;
        let mut members: Vec<Vec<u8>> = vec![vec![0u8; member_size as usize]; n];
        for stripe in 0..stripes {
            let p = (n as u64 - 1) - (stripe % n as u64);
            let q = (p + 1) % n as u64;
            let phys = (stripe * chunk) as usize;
            let mut p_chunk = vec![0u8; chunk as usize];
            let mut q_chunk = vec![0u8; chunk as usize];
            for d in 0..data_per_stripe as u64 {
                let logical_chunk = stripe * data_per_stripe as u64 + d;
                let disk = ((q + 1 + d) % n as u64) as usize;
                let src = &logical[(logical_chunk * chunk) as usize..][..chunk as usize];
                members[disk][phys..phys + chunk as usize].copy_from_slice(src);
                let g = gf::gpow(d as usize);
                for (k, s) in src.iter().enumerate() {
                    p_chunk[k] ^= *s;
                    q_chunk[k] ^= gf::mul(g, *s);
                }
            }
            members[p as usize][phys..phys + chunk as usize].copy_from_slice(&p_chunk);
            members[q as usize][phys..phys + chunk as usize].copy_from_slice(&q_chunk);
        }
        (members, member_size)
    }

    /// RAID 6 recovers from ANY two simultaneous member losses — two data disks,
    /// data + P, or data + Q — using the Q syndrome. This is the double-fault
    /// capability RAID 6 exists for.
    #[test]
    fn raid6_reconstructs_any_two_missing_members() {
        let chunk = 4u64;
        let n = 6usize; // 4 data + P + Q
        let stripes = 7u64;
        let logical_len = (stripes as usize) * (n - 2) * chunk as usize;
        let logical: Vec<u8> = (0..logical_len).map(|i| (i * 11 + 7) as u8).collect();
        let (members, member_size) = build_raid6(&logical, n, chunk, stripes);

        // Intact read first.
        let full = RaidDevice::new(
            RaidLevel::Raid6,
            members.iter().cloned().map(|m| Some(arc(m))).collect(),
            chunk,
            member_size,
        )
        .unwrap();
        assert_eq!(read_all(&full), logical, "intact RAID6 must read original");

        // Every unordered pair of missing members must reconstruct.
        for a in 0..n {
            for b in (a + 1)..n {
                let mut m: Vec<Member> = members.iter().cloned().map(|v| Some(arc(v))).collect();
                m[a] = None;
                m[b] = None;
                let degraded = RaidDevice::new(RaidLevel::Raid6, m, chunk, member_size).unwrap();
                assert_eq!(
                    read_all(&degraded),
                    logical,
                    "RAID6 with members {a} and {b} missing must reconstruct"
                );
            }
        }
    }

    #[test]
    fn raid6_still_refuses_three_missing() {
        let (members, member_size) = build_raid6(&[0u8; 4 * 4 * 2], 6, 4, 2);
        let mut m: Vec<Member> = members.into_iter().map(|v| Some(arc(v))).collect();
        m[0] = None;
        m[1] = None;
        m[2] = None;
        let err = RaidDevice::new(RaidLevel::Raid6, m, 4, member_size).unwrap_err();
        assert!(err.contains("cannot reconstruct"));
    }

    #[test]
    fn raid1_reads_from_a_surviving_mirror() {
        let data: Vec<u8> = (0..100).map(|i| i as u8).collect();
        let dev = RaidDevice::new(
            RaidLevel::Raid1,
            vec![None, Some(arc(data.clone()))],
            0,
            data.len() as u64,
        )
        .unwrap();
        assert_eq!(read_all(&dev), data);
    }

    /// A RAID 1 region no mirror can supply is reported as a SHORT read, not as
    /// the zeros the buffer holds — so a truncated/unreadable array surfaces as
    /// incomplete rather than clean data. Regression for the zero-fill finding.
    #[test]
    fn raid1_unreadable_region_is_a_short_read_not_zeros() {
        // Both mirrors are only 40 bytes but the array claims 100 (member_size).
        let short = vec![7u8; 40];
        let dev = RaidDevice::new(
            RaidLevel::Raid1,
            vec![Some(arc(short.clone())), Some(arc(short))],
            0,
            100,
        )
        .unwrap();
        // Reading the whole 100 returns only the 40 real bytes, not 100 of zeros.
        let mut buf = vec![0u8; 100];
        let got = dev.read_at(0, &mut buf).unwrap();
        assert_eq!(
            got, 40,
            "unreadable tail must be a short read, not zero-filled"
        );
        // Reading into the hole returns 0 (which the CLI treats as truncation).
        let got2 = dev.read_at(40, &mut buf).unwrap();
        assert_eq!(got2, 0);
    }

    /// JBOD concatenates members of UNEQUAL sizes at their true offsets; the
    /// logical image is the sum of the actual sizes, not member_size * n.
    #[test]
    fn jbod_handles_unequal_members() {
        let a = vec![0xAAu8; 30];
        let b = vec![0xBBu8; 70];
        let dev = RaidDevice::new(
            RaidLevel::Jbod,
            vec![Some(arc(a)), Some(arc(b))],
            0,
            30, // passed member_size is ignored for JBOD
        )
        .unwrap();
        assert_eq!(dev.logical_size(), 100, "sum of actual member sizes");
        let all = read_all(&dev);
        assert_eq!(all.len(), 100);
        assert!(all[..30].iter().all(|&b| b == 0xAA), "first member");
        assert!(
            all[30..].iter().all(|&b| b == 0xBB),
            "second member at its true offset"
        );
    }

    /// A short lead mirror must not truncate the read: the full-length mirror
    /// supplies the tail. Regression for the silent-truncation finding.
    #[test]
    fn raid1_short_lead_mirror_does_not_truncate() {
        let full: Vec<u8> = (0..100).map(|i| i as u8).collect();
        let short = full[..40].to_vec(); // a truncated first mirror
        let dev = RaidDevice::new(
            RaidLevel::Raid1,
            vec![Some(arc(short)), Some(arc(full.clone()))],
            0,
            full.len() as u64, // member_size = max present
        )
        .unwrap();
        // The whole 100 bytes must come back, the tail sourced from the full mirror.
        assert_eq!(
            read_all(&dev),
            full,
            "the longer mirror must supply the tail"
        );
    }

    #[test]
    fn constructor_rejects_degenerate_geometry() {
        let m = || Some(arc(vec![0u8; 16]));
        // RAID 5 needs >= 2 members (n-1 divides), RAID 6 >= 3 (n-2 divides).
        assert!(RaidDevice::new(RaidLevel::Raid5, vec![m()], 4, 16).is_err());
        assert!(RaidDevice::new(RaidLevel::Raid6, vec![m(), m()], 4, 16).is_err());
        // Zero member size would divide by zero / present an empty device.
        assert!(RaidDevice::new(RaidLevel::Jbod, vec![m()], 0, 0).is_err());
        assert!(RaidDevice::new(RaidLevel::Raid0, vec![m(), m()], 4, 0).is_err());
    }

    #[test]
    fn jbod_concatenates_members() {
        let a = vec![1u8; 10];
        let b = vec![2u8; 10];
        let dev =
            RaidDevice::new(RaidLevel::Jbod, vec![Some(arc(a)), Some(arc(b))], 0, 10).unwrap();
        let all = read_all(&dev);
        assert_eq!(&all[..10], &[1u8; 10]);
        assert_eq!(&all[10..], &[2u8; 10]);
    }

    #[test]
    fn raid0_refuses_a_missing_member() {
        let err =
            RaidDevice::new(RaidLevel::Raid0, vec![Some(arc(vec![0; 4])), None], 4, 4).unwrap_err();
        assert!(err.contains("cannot tolerate"));
    }

    #[test]
    fn raid5_refuses_two_missing_members() {
        let err = RaidDevice::new(
            RaidLevel::Raid5,
            vec![None, None, Some(arc(vec![0; 4]))],
            4,
            4,
        )
        .unwrap_err();
        assert!(err.contains("cannot reconstruct"));
    }

    /// A member that FAILS to read is not a member that ended: the I/O error must
    /// surface as an error, not as a short read that reads like a truncated
    /// member image. Regression for the `Err(_) => break` swallow.
    #[test]
    fn raid0_member_read_error_is_not_a_short_read() {
        let chunk = 4u64;
        let n = 3usize;
        let logical: Vec<u8> = (0..60).map(|i| (i + 1) as u8).collect();
        let mut members = vec![Vec::new(); n];
        for (ci, c) in logical.chunks(chunk as usize).enumerate() {
            members[ci % n].extend_from_slice(c);
        }
        let member_size = members[0].len() as u64; // 20
        let mut srcs: Vec<Member> = members.iter().cloned().map(|m| Some(arc(m))).collect();
        // Member 1 reads its first 8 bytes and then fails, while still declaring
        // the full member size — a failing disk, not a short image.
        srcs[1] = Some(failing(members[1][..8].to_vec(), member_size));
        let dev = RaidDevice::new(RaidLevel::Raid0, srcs, chunk, member_size).unwrap();
        let mut out = vec![0u8; dev.logical_size() as usize];
        let err = dev
            .read_at(0, &mut out)
            .expect_err("a failing member must surface as an error, not a short read");
        assert!(
            err.to_string().contains("member read failed"),
            "the member's I/O error must reach the caller: {err}"
        );
    }

    /// The same for a parity rebuild: a survivor the reconstruction depends on
    /// that FAILS must report the I/O error, not shorten the reconstruction as if
    /// the survivor were simply truncated.
    #[test]
    fn raid5_failing_survivor_reports_the_io_error_not_a_short_read() {
        let chunk = 4u64;
        let n = 4usize;
        let stripes = 5u64;
        let data_per_stripe = n - 1;
        let logical_len = (stripes as usize) * data_per_stripe * chunk as usize;
        let logical: Vec<u8> = (0..logical_len).map(|i| (i * 3 + 5) as u8).collect();
        let (members, member_size) = build_raid5(&logical, n, chunk, stripes);
        let mut m: Vec<Member> = members.iter().cloned().map(|v| Some(arc(v))).collect();
        m[0] = None; // reconstructed from the survivors
        m[2] = Some(failing(members[2][..8].to_vec(), member_size)); // a survivor fails
        let dev = RaidDevice::new(RaidLevel::Raid5, m, chunk, member_size).unwrap();
        let mut out = vec![0u8; dev.logical_size() as usize];
        let err = dev
            .read_at(0, &mut out)
            .expect_err("a failing survivor must surface as an error");
        assert!(
            err.to_string().contains("member read failed"),
            "the survivor's I/O error must reach the caller: {err}"
        );
    }

    /// A failing mirror is exactly what the other mirror is for: the read still
    /// succeeds when a healthy mirror covers the region. The error is only the
    /// outcome when the bytes are genuinely lost.
    #[test]
    fn raid1_failing_mirror_is_covered_by_a_healthy_one() {
        let full: Vec<u8> = (0..100).map(|i| i as u8).collect();
        let dev = RaidDevice::new(
            RaidLevel::Raid1,
            vec![
                Some(failing(full[..40].to_vec(), 100)),
                Some(arc(full.clone())),
            ],
            0,
            full.len() as u64,
        )
        .unwrap();
        assert_eq!(read_all(&dev), full, "the healthy mirror supplies the tail");
    }

    /// When no mirror can supply the region, the I/O error is the honest outcome —
    /// not a short read that is indistinguishable from a truncated mirror image.
    #[test]
    fn raid1_read_error_no_mirror_covers_is_reported_as_an_error() {
        let data: Vec<u8> = (0..100).map(|i| i as u8).collect();
        let dev = RaidDevice::new(
            RaidLevel::Raid1,
            vec![
                Some(failing(data[..40].to_vec(), 100)),
                Some(failing(data[..40].to_vec(), 100)),
            ],
            0,
            100,
        )
        .unwrap();
        let mut buf = vec![0u8; 100];
        let err = dev
            .read_at(0, &mut buf)
            .expect_err("an unrecoverable mirror failure must be an error");
        assert!(
            err.to_string().contains("member read failed"),
            "the mirror's I/O error must reach the caller: {err}"
        );
    }

    /// JBOD reads go through the same helper; a failing member there must also
    /// surface its error rather than end the concatenation early.
    #[test]
    fn jbod_member_read_error_is_not_a_short_read() {
        let dev = RaidDevice::new(
            RaidLevel::Jbod,
            vec![Some(arc(vec![0xAA; 30])), Some(failing(vec![0xBB; 10], 70))],
            0,
            30,
        )
        .unwrap();
        let mut out = vec![0u8; dev.logical_size() as usize];
        let err = dev
            .read_at(0, &mut out)
            .expect_err("a failing JBOD member must surface as an error");
        assert!(
            err.to_string().contains("member read failed"),
            "the member's I/O error must reach the caller: {err}"
        );
    }

    /// A geometry whose logical size cannot be expressed in 64 bits is refused at
    /// construction. Multiplying it out would wrap to a false device length (or
    /// abort mid-read where overflow checks are on), and a device that states a
    /// size it cannot back is not evidence.
    #[test]
    fn an_unrepresentable_logical_size_is_refused_not_wrapped() {
        // A member source reporting a near-u64::MAX size is what a sparse image
        // looks like; three of them cannot be striped into a u64 address space.
        let half = u64::MAX / 2;
        let huge = || Some(Arc::new(HugeSource(half)) as Arc<dyn DataSource>);
        let err = RaidDevice::new(RaidLevel::Raid0, vec![huge(), huge(), huge()], 4, half)
            .expect_err("an unrepresentable RAID 0 geometry must be refused");
        assert!(
            err.contains("not representable"),
            "the message must explain the refusal: {err}"
        );
        // RAID 5 spreads the data over n-1 members; that product is checked too.
        let five = RaidDevice::new(
            RaidLevel::Raid5,
            vec![huge(), huge(), huge(), huge()],
            4,
            half,
        );
        assert!(
            five.is_err(),
            "RAID 5 must refuse an unrepresentable geometry"
        );
        // A JBOD's logical size is the SUM of the member sizes; that must not wrap.
        let vast = || Some(Arc::new(HugeSource(u64::MAX - 1)) as Arc<dyn DataSource>);
        let jbod = RaidDevice::new(RaidLevel::Jbod, vec![vast(), vast()], 0, 16);
        assert!(
            jbod.is_err(),
            "JBOD must refuse a concatenation that overflows a 64-bit size"
        );
    }

    #[test]
    fn partial_and_offset_reads_work() {
        let chunk = 8u64;
        let n = 3usize;
        let logical: Vec<u8> = (0..48).map(|i| i as u8).collect();
        let mut members = vec![Vec::new(); n];
        for (ci, c) in logical.chunks(chunk as usize).enumerate() {
            members[ci % n].extend_from_slice(c);
        }
        let dev = RaidDevice::new(
            RaidLevel::Raid0,
            members.into_iter().map(|m| Some(arc(m))).collect(),
            chunk,
            16,
        )
        .unwrap();
        // Read a 10-byte window straddling a chunk boundary at offset 5.
        let mut buf = [0u8; 10];
        let got = dev.read_at(5, &mut buf).unwrap();
        assert_eq!(got, 10);
        assert_eq!(&buf, &logical[5..15]);
    }
}
