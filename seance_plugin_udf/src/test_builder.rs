//! An in-memory UDF 1.02 volume builder for the unit tests, written from
//! ECMA-167 3rd edition and OSTA UDF 1.02. It pins the reader's mechanisms;
//! it is not evidence that the reader handles any real disc, which is what
//! the env-gated Windows-bridge corpus test is for.

use crate::tag::{crc_itu, ident};
use crate::timestamp;

pub const BS: usize = 2048;
/// Where the builder puts the partition, in sectors.
pub const PART_START: u32 = 272;

/// How a file's content is laid out.
#[derive(Clone)]
pub enum Layout {
    /// One recorded extent, short allocation descriptors.
    Short,
    /// Two non-adjacent recorded extents, long allocation descriptors; the
    /// first extent holds `split` bytes (a multiple of the block size).
    Long { split: usize },
    /// The bytes live inside the File Entry (ICB flags 3).
    Embedded,
    /// Short ADs: one recorded block, one allocated-but-unrecorded block,
    /// then the rest recorded.
    HoleAfterFirstBlock,
    /// A single short AD pointing past the end of the partition.
    PastEnd,
    /// Extended allocation descriptors (ICB flags 2), which the reader refuses.
    Extended,
    /// Short ADs whose list continues through an Allocation Extent
    /// Descriptor (extent type 3) after the first block.
    Continued,
}

#[derive(Clone)]
pub enum Kind {
    Dir,
    File {
        data: Vec<u8>,
        layout: Layout,
    },
    /// A directory FID that points back at the root ICB (a crafted loop).
    LoopToRoot,
}

#[derive(Clone)]
pub struct Node {
    pub name: String,
    pub utf16: bool,
    pub kind: Kind,
    pub deleted: bool,
    pub hidden: bool,
    pub parent: usize,
    pub children: Vec<usize>,
}

pub struct UdfBuilder {
    pub nodes: Vec<Node>,
    pub efe: bool,
    pub part_len: u32,
    pub type2_map: Option<&'static str>,
    /// ICB strategy for file entries (4 is the only one read).
    pub strategy: u16,
}

impl Default for UdfBuilder {
    fn default() -> Self {
        Self::new()
    }
}

fn put16(b: &mut [u8], o: usize, v: u16) {
    b[o..o + 2].copy_from_slice(&v.to_le_bytes());
}
fn put32(b: &mut [u8], o: usize, v: u32) {
    b[o..o + 4].copy_from_slice(&v.to_le_bytes());
}
fn put64(b: &mut [u8], o: usize, v: u64) {
    b[o..o + 8].copy_from_slice(&v.to_le_bytes());
}

/// Fill in a descriptor tag over `d[..len]`.
pub fn seal(d: &mut [u8], tag_id: u16, location: u32, len: usize) {
    put16(d, 0, tag_id);
    put16(d, 2, 2);
    put32(d, 12, location);
    let crc = crc_itu(&d[16..len]);
    put16(d, 8, crc);
    put16(d, 10, (len - 16) as u16);
    d[4] = 0;
    d[4] = (0..16)
        .filter(|&i| i != 4)
        .fold(0u8, |a, i| a.wrapping_add(d[i]));
}

fn dstring(field: &mut [u8], s: &str) {
    let n = field.len();
    field[0] = 8;
    field[1..1 + s.len()].copy_from_slice(s.as_bytes());
    field[n - 1] = (s.len() + 1) as u8;
}

fn regid(field: &mut [u8], s: &str) {
    field[1..1 + s.len()].copy_from_slice(s.as_bytes());
}

fn cs0_name(name: &str, utf16: bool) -> Vec<u8> {
    if utf16 {
        let mut v = vec![16u8];
        for u in name.encode_utf16() {
            v.extend_from_slice(&u.to_be_bytes());
        }
        v
    } else {
        let mut v = vec![8u8];
        v.extend(name.chars().map(|c| c as u32 as u8));
        v
    }
}

fn long_ad(len: u32, lbn: u32, part: u16) -> [u8; 16] {
    let mut a = [0u8; 16];
    put32(&mut a, 0, len);
    put32(&mut a, 4, lbn);
    put16(&mut a, 8, part);
    a
}

fn short_ad(len_and_type: u32, lbn: u32) -> [u8; 8] {
    let mut a = [0u8; 8];
    put32(&mut a, 0, len_and_type);
    put32(&mut a, 4, lbn);
    a
}

impl UdfBuilder {
    pub fn new() -> Self {
        let root = Node {
            name: String::new(),
            utf16: false,
            kind: Kind::Dir,
            deleted: false,
            hidden: false,
            parent: 0,
            children: Vec::new(),
        };
        Self {
            nodes: vec![root],
            efe: false,
            part_len: 512,
            type2_map: None,
            strategy: 4,
        }
    }

    fn push(&mut self, parent: usize, name: &str, kind: Kind) -> usize {
        let id = self.nodes.len();
        self.nodes.push(Node {
            name: name.to_string(),
            utf16: false,
            kind,
            deleted: false,
            hidden: false,
            parent,
            children: Vec::new(),
        });
        self.nodes[parent].children.push(id);
        id
    }

    pub fn dir(&mut self, parent: usize, name: &str) -> usize {
        self.push(parent, name, Kind::Dir)
    }

    pub fn file(&mut self, parent: usize, name: &str, data: &[u8], layout: Layout) -> usize {
        self.push(
            parent,
            name,
            Kind::File {
                data: data.to_vec(),
                layout,
            },
        )
    }

    pub fn loop_to_root(&mut self, parent: usize, name: &str) -> usize {
        self.push(parent, name, Kind::LoopToRoot)
    }

    /// Lay the volume out and return the image bytes.
    pub fn build(&self) -> Vec<u8> {
        let part_len = self.part_len;
        let total_sectors = PART_START as u64 + part_len as u64 + 300;
        let mut img = vec![0u8; total_sectors as usize * BS];
        // Partition blocks are addressed relative to PART_START.
        let mut part = vec![0u8; part_len as usize * BS];
        let mut next: u32 = 2; // 0 = FSD, 1 = spare

        // ICB for every node (the loop node has none of its own).
        let mut icb = vec![0u32; self.nodes.len()];
        for (i, n) in self.nodes.iter().enumerate() {
            if !matches!(n.kind, Kind::LoopToRoot) {
                icb[i] = next;
                next += 1;
            }
        }

        let blocks_for = |len: usize| len.div_ceil(BS).max(1) as u32;

        for (i, n) in self.nodes.iter().enumerate() {
            match &n.kind {
                Kind::LoopToRoot => {}
                Kind::Dir => {
                    // FID stream: parent first, then children.
                    let mut fids: Vec<u8> = Vec::new();
                    let parent_icb = icb[n.parent];
                    push_fid(&mut fids, 0x0A, parent_icb, &[]);
                    for &c in &n.children {
                        let cn = &self.nodes[c];
                        let mut chars = 0u8;
                        let target = match cn.kind {
                            Kind::Dir => {
                                chars |= 0x02;
                                icb[c]
                            }
                            Kind::LoopToRoot => {
                                chars |= 0x02;
                                icb[0]
                            }
                            Kind::File { .. } => icb[c],
                        };
                        if cn.deleted {
                            chars |= 0x04;
                        }
                        if cn.hidden {
                            chars |= 0x01;
                        }
                        push_fid(&mut fids, chars, target, &cs0_name(&cn.name, cn.utf16));
                    }
                    let lbn = next;
                    next += blocks_for(fids.len());
                    let off = lbn as usize * BS;
                    part[off..off + fids.len()].copy_from_slice(&fids);
                    let ads = short_ad(fids.len() as u32, lbn).to_vec();
                    self.write_fe(&mut part, icb[i], 4, fids.len() as u64, 0, &ads);
                }
                Kind::File { data, layout } => {
                    let len = data.len();
                    let (ad_type, ads): (u16, Vec<u8>) = match layout {
                        Layout::Embedded => (3, data.clone()),
                        Layout::Short | Layout::Extended => {
                            let lbn = next;
                            next += blocks_for(len);
                            let off = lbn as usize * BS;
                            part[off..off + len].copy_from_slice(data);
                            if matches!(layout, Layout::Extended) {
                                (2, vec![0u8; 20])
                            } else {
                                (0, short_ad(len as u32, lbn).to_vec())
                            }
                        }
                        Layout::Long { split } => {
                            let a = next;
                            next += blocks_for(*split);
                            next += 3; // a gap so the extents are not adjacent
                            let b = next;
                            next += blocks_for(len - split);
                            part[a as usize * BS..a as usize * BS + split]
                                .copy_from_slice(&data[..*split]);
                            part[b as usize * BS..b as usize * BS + len - split]
                                .copy_from_slice(&data[*split..]);
                            let mut v = long_ad(*split as u32, a, 0).to_vec();
                            v.extend_from_slice(&long_ad((len - split) as u32, b, 0));
                            (1, v)
                        }
                        Layout::HoleAfterFirstBlock => {
                            // data = block0 ++ zeros(block) ++ rest
                            let a = next;
                            next += 1;
                            let hole = next;
                            next += 1;
                            let rest = &data[2 * BS..];
                            let b = next;
                            next += blocks_for(rest.len());
                            part[a as usize * BS..(a as usize + 1) * BS]
                                .copy_from_slice(&data[..BS]);
                            // The hole block holds junk that must NOT be read.
                            part[hole as usize * BS..(hole as usize + 1) * BS].fill(0xEE);
                            part[b as usize * BS..b as usize * BS + rest.len()]
                                .copy_from_slice(rest);
                            let mut v = short_ad(BS as u32, a).to_vec();
                            v.extend_from_slice(&short_ad((1 << 30) | BS as u32, hole));
                            v.extend_from_slice(&short_ad(rest.len() as u32, b));
                            (0, v)
                        }
                        Layout::PastEnd => (0, short_ad(len as u32, part_len - 1).to_vec()),
                        Layout::Continued => {
                            let a = next;
                            next += 1;
                            let aed = next;
                            next += 1;
                            let rest = &data[BS..];
                            let b = next;
                            next += blocks_for(rest.len());
                            part[a as usize * BS..(a as usize + 1) * BS]
                                .copy_from_slice(&data[..BS]);
                            part[b as usize * BS..b as usize * BS + rest.len()]
                                .copy_from_slice(rest);
                            // AED at `aed`: tag, prev loc, L_AD, ADs.
                            let off = aed as usize * BS;
                            let d = &mut part[off..off + BS];
                            let ad = short_ad(rest.len() as u32, b);
                            put32(d, 20, 8);
                            d[24..32].copy_from_slice(&ad);
                            seal(d, ident::AED, aed, 32);
                            let mut v = short_ad(BS as u32, a).to_vec();
                            v.extend_from_slice(&short_ad((3 << 30) | BS as u32, aed));
                            (0, v)
                        }
                    };
                    self.write_fe(&mut part, icb[i], 5, len as u64, ad_type, &ads);
                }
            }
        }
        assert!(next <= part_len, "builder partition too small");

        // FSD at partition block 0.
        {
            let d = &mut part[0..BS];
            d[16..28].copy_from_slice(&timestamp::encode(2024, 1, 2, 3, 4, 5, 0));
            put16(d, 28, 3);
            put16(d, 30, 3);
            dstring(&mut d[112..240], "TESTVOL");
            dstring(&mut d[304..336], "TESTSET");
            d[400..416].copy_from_slice(&long_ad(BS as u32, icb[0], 0));
            regid(&mut d[416..448], "*OSTA UDF Compliant");
            seal(d, ident::FSD, 0, 512);
        }
        let ps = PART_START as usize * BS;
        img[ps..ps + part.len()].copy_from_slice(&part);

        // Volume Recognition Sequence.
        for (i, id) in [b"BEA01", b"NSR02", b"TEA01"].iter().enumerate() {
            let o = (16 + i) * BS;
            img[o + 1..o + 6].copy_from_slice(*id);
            img[o + 6] = 1;
        }

        // Main VDS at 257.., reserve at 264..
        for base in [257u32, 264u32] {
            self.write_vds(&mut img, base);
        }
        // AVDP at 256 and at the last sector.
        for s in [256u64, total_sectors - 1] {
            let o = s as usize * BS;
            let d = &mut img[o..o + BS];
            put32(d, 16, 4 * BS as u32);
            put32(d, 20, 257);
            put32(d, 24, 4 * BS as u32);
            put32(d, 28, 264);
            seal(d, ident::AVDP, s as u32, 512);
        }
        img
    }

    fn write_vds(&self, img: &mut [u8], base: u32) {
        let sec = |s: u32| s as usize * BS;
        // PVD
        {
            let o = sec(base);
            let d = &mut img[o..o + BS];
            dstring(&mut d[24..56], "TESTVOL");
            put16(d, 56, 1);
            put16(d, 58, 1);
            dstring(&mut d[72..200], "0123456789ABCDEFTESTSET");
            seal(d, ident::PVD, base, 512);
        }
        // PD
        {
            let o = sec(base + 1);
            let d = &mut img[o..o + BS];
            put32(d, 16, 1);
            put16(d, 20, 1);
            put16(d, 22, 0);
            regid(&mut d[24..56], "+NSR02");
            put32(d, 184, 1);
            put32(d, 188, PART_START);
            put32(d, 192, self.part_len);
            seal(d, ident::PD, base + 1, 512);
        }
        // LVD
        {
            let o = sec(base + 2);
            let d = &mut img[o..o + BS];
            put32(d, 16, 2);
            dstring(&mut d[84..212], "TESTLV");
            put32(d, 212, BS as u32);
            regid(&mut d[216..248], "*OSTA UDF Compliant");
            d[240] = 0x02;
            d[241] = 0x01;
            d[248..264].copy_from_slice(&long_ad(BS as u32, 0, 0));
            let mut maps = vec![1u8, 6, 1, 0, 0, 0];
            if let Some(id) = self.type2_map {
                let mut m = vec![0u8; 64];
                m[0] = 2;
                m[1] = 64;
                m[5..5 + id.len()].copy_from_slice(id.as_bytes());
                maps.extend_from_slice(&m);
            }
            put32(d, 264, maps.len() as u32);
            put32(d, 268, if self.type2_map.is_some() { 2 } else { 1 });
            d[440..440 + maps.len()].copy_from_slice(&maps);
            seal(d, ident::LVD, base + 2, 440 + maps.len());
        }
        // TD
        {
            let o = sec(base + 3);
            let d = &mut img[o..o + BS];
            seal(d, ident::TD, base + 3, 512);
        }
    }

    fn write_fe(
        &self,
        part: &mut [u8],
        lbn: u32,
        file_type: u8,
        info_len: u64,
        ad_type: u16,
        ads: &[u8],
    ) {
        let off = lbn as usize * BS;
        let d = &mut part[off..off + BS];
        // ICB tag
        put16(d, 20, self.strategy);
        put16(d, 24, 1);
        d[27] = file_type;
        put16(d, 34, ad_type);
        put32(d, 36, 1000);
        put32(d, 40, 100);
        put32(d, 44, 0x1CE7);
        put16(d, 48, 1);
        put64(d, 56, info_len);
        let (atime, mtime, attr, ad_at, len_at, tag) = if self.efe {
            (80, 92, 116, 216, 208, ident::EFE)
        } else {
            (72, 84, 96, 176, 168, ident::FE)
        };
        d[atime..atime + 12].copy_from_slice(&timestamp::encode(2024, 3, 1, 10, 0, 0, 0));
        d[mtime..mtime + 12].copy_from_slice(&timestamp::encode(2024, 3, 2, 11, 30, 0, 60));
        d[attr..attr + 12].copy_from_slice(&timestamp::encode(2024, 3, 3, 12, 0, 0, 0));
        if self.efe {
            d[104..116].copy_from_slice(&timestamp::encode(2023, 12, 25, 8, 0, 0, 0));
            put64(d, 64, info_len);
        }
        put32(d, len_at, 0);
        put32(d, len_at + 4, ads.len() as u32);
        d[ad_at..ad_at + ads.len()].copy_from_slice(ads);
        seal(d, tag, lbn, ad_at + ads.len());
    }
}

fn push_fid(out: &mut Vec<u8>, chars: u8, icb_lbn: u32, name: &[u8]) {
    let len = (38 + name.len()).div_ceil(4) * 4;
    let mut f = vec![0u8; len];
    put16(&mut f, 16, 1);
    f[18] = chars;
    f[19] = name.len() as u8;
    f[20..36].copy_from_slice(&long_ad(BS as u32, icb_lbn, 0));
    f[38..38 + name.len()].copy_from_slice(name);
    seal(&mut f, ident::FID, 0, len);
    out.extend_from_slice(&f);
}
