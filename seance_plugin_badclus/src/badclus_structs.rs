/// Represents a data run in NTFS
/// Data runs encode cluster ranges using a variable-length encoding scheme
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct DataRun {
    pub length: i64,    // Number of clusters in this run
    pub start_lcn: i64, // Starting Logical Cluster Number
    pub start_vcn: i64, // Starting Virtual Cluster Number
    pub offset: i64,    // Offset in the source data where this run was found
}

/// A bad-cluster region recovered from the `$BadClus:$Bad` non-resident runlist.
///
/// Offsets and lengths are in **bytes**, taken directly from the MFT runlist
/// (`data_runs` metadata), so the physical location is exact without assuming a
/// cluster size. Cluster/LCN figures are derived at artifact-build time only
/// when the volume's cluster size is known.
#[derive(Debug, Clone)]
pub struct BadClusterRange {
    /// Which stream this came from, e.g. "$BadClus:$Bad".
    pub stream: String,
    /// Absolute filesystem byte offset of the bad region.
    pub offset_bytes: u64,
    /// Length of the bad region in bytes.
    pub length_bytes: u64,
    /// Byte position of this region within the `$Bad` stream (logical VCN).
    pub vcn_bytes: u64,
}
