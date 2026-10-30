use anyhow::Result;
use clap::{Parser, Subcommand};

// Process-wide allocator. mimalloc markedly outperforms the system allocator on
// the ingest workload (many small per-record/per-block allocations across all
// worker threads).
//
// Wrapped in an allocation tracer that does nothing unless
// `SEANCE_ALLOC_TRACE_MB` is set (`alloc_trace`, HUNT-125).
#[global_allocator]
static GLOBAL: alloc_trace::TracingAllocator<mimalloc::MiMalloc> =
    alloc_trace::TracingAllocator(mimalloc::MiMalloc);
// The forensic module set lives in `seance_api::modules` and is registered
// there, by one function, for both binaries. It used to be a hand-written list
// in this file and a second, different hand-written list in
// `seance_api/src/main.rs`; see that module's documentation for what the drift
// between them cost (LIVE-005).
use seance_api::modules::{register_all_modules, ModuleSetOptions, UnlockSecrets};
use seance_api::{router_with_auth, AppState, AuthConfig, EvidenceRootPolicy, ProcessingCensus};
use seance_core::{
    artifact::ArtifactType, data_source::FileDataSource, db::DatabaseConnection,
    orchestrator::Orchestrator,
};
use seance_db::SqliteConnection;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::{error, info, warn, Level};
use tracing_subscriber::{filter::LevelFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

mod alloc_trace;
mod workspace_lock;
use workspace_lock::WorkspaceLock;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Logging level (1=WARN, 2=INFO, 3=DEBUG, 4=TRACE)
    #[arg(global = true, short, long, default_value_t = 2)]
    loglevel: u8,

    /// Enable the REPL interface
    #[arg(long)]
    interactive: bool,

    /// Run in headless mode (API only, no GUI)
    #[arg(long)]
    headless: bool,

    /// Set the workspace directory
    #[arg(long, default_value = "workspace")]
    workspace: PathBuf,

    /// Port to listen on
    #[arg(short, long, default_value_t = 8080)]
    port: u16,

    /// Directory containing the built Web UI (frontend/dist)
    #[arg(long, default_value = "frontend/dist")]
    web_root: PathBuf,

    /// Auto-shutdown the server after N seconds (useful for testing)
    #[arg(long)]
    timeout: Option<u64>,

    /// Path to PEM-encoded X.509 certificate for PDF signing
    #[arg(long, requires = "signing_key")]
    signing_cert: Option<PathBuf>,

    /// Path to PEM-encoded private key for PDF signing
    #[arg(long, requires = "signing_cert")]
    signing_key: Option<PathBuf>,

    /// Signer name for PDF digital signatures
    #[arg(long)]
    signing_name: Option<String>,

    /// Reason string for PDF digital signatures
    #[arg(long)]
    signing_reason: Option<String>,

    /// Passphrase to unlock a LUKS-encrypted evidence volume during ingest.
    /// Held in process memory and handed to the LUKS decryptor module; never
    /// written to the case database, an artifact's metadata, or an export.
    /// Prefer the SEANCE_LUKS_PASSPHRASE environment variable: a value given
    /// on the command line is visible to every user of the host in `ps` and
    /// lands in the shell's history.
    #[arg(long, env = "SEANCE_LUKS_PASSPHRASE", hide_env_values = true)]
    luks_passphrase: Option<String>,

    /// Password to unlock a BitLocker-encrypted evidence volume during ingest.
    /// Held in process memory only; never persisted (see --luks-passphrase).
    /// Prefer the SEANCE_BITLOCKER_PASSWORD environment variable, for the
    /// same reason.
    #[arg(long, env = "SEANCE_BITLOCKER_PASSWORD", hide_env_values = true)]
    bitlocker_password: Option<String>,

    /// Password for an encrypted iOS backup, so its files can be decrypted
    /// during ingest. Without it an encrypted backup is recorded as present but
    /// not extracted, which is honest but means none of its files reach the
    /// case. Held in process memory only; never persisted (see
    /// --luks-passphrase).
    #[arg(long, env = "SEANCE_IOS_BACKUP_PASSWORD", hide_env_values = true)]
    ios_backup_password: Option<String>,

    /// 48-digit recovery password to unlock a BitLocker evidence volume.
    /// Held in process memory only; never persisted (see --luks-passphrase).
    #[arg(long, env = "SEANCE_BITLOCKER_RECOVERY_KEY", hide_env_values = true)]
    bitlocker_recovery_key: Option<String>,

    /// Path to a JSON file of user-defined carving signatures (custom-defs).
    /// Each entry declares a header (and optional footer) so the carver can
    /// recover file types the built-in signatures don't cover.
    #[arg(long)]
    carver_defs: Option<PathBuf>,

    #[command(subcommand)]
    command: Option<Commands>,
}

/// Redacting `Debug`, like `UnlockSecrets`: `Args` carries the four
/// evidence-unlock credentials, and a derived `Debug` would print them into
/// whatever log line or panic message ever formatted the parsed arguments.
/// Nothing does today; this is what keeps it that way.
impl std::fmt::Debug for Args {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let redacted = |v: &Option<String>| v.as_ref().map(|_| "<redacted>");
        f.debug_struct("Args")
            .field("loglevel", &self.loglevel)
            .field("workspace", &self.workspace)
            .field("port", &self.port)
            .field("luks_passphrase", &redacted(&self.luks_passphrase))
            .field("bitlocker_password", &redacted(&self.bitlocker_password))
            .field(
                "bitlocker_recovery_key",
                &redacted(&self.bitlocker_recovery_key),
            )
            .field("ios_backup_password", &redacted(&self.ios_backup_password))
            .finish_non_exhaustive()
    }
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Scan a single file or artifact (Legacy/Utility Mode)
    Scan {
        /// Path to the raw evidence file
        #[arg(short, long)]
        path: PathBuf,

        /// Exit when the task queue is idle for 10 seconds.
        ///
        /// Accepts an explicit value so the default can actually be overridden:
        /// `--exit-on-idle=false` keeps the orchestrator alive after the queue
        /// drains. Declared as a bare flag this was unoverridable — clap
        /// rejected `--exit-on-idle=false` with "unexpected value 'false'", so
        /// the option the code read could only ever be true.
        #[arg(
            long,
            action = clap::ArgAction::Set,
            num_args = 0..=1,
            require_equals = true,
            default_value_t = true,
            default_missing_value = "true",
            value_name = "BOOL"
        )]
        exit_on_idle: bool,

        /// Declare that this source is a capture of physical memory.
        ///
        /// A raw dump is headerless, so the memory pipeline refuses to guess:
        /// with no magic to find it treats the source as "not memory" and every
        /// memory stage reports `did_not_run`. Only this declaration (or
        /// `--memory-image-format`) makes a raw capture analysable, and until
        /// it existed the commonest acquisition format could not be examined
        /// from the command line at all (LIVE-002).
        ///
        /// The declaration does not override what the source is: it is
        /// honoured only where the memory module would receive the artifact
        /// (RawEvidence or FileEntry). A headerless capture matches no magic
        /// and no known extension, so it classifies as RawEvidence and the
        /// declaration stands; a source whose own bytes identify it as
        /// something else — a ZIP, an E01 — ends the run instead, because a
        /// declaration recorded on that artifact would never be read.
        #[arg(
            long,
            action = clap::ArgAction::Set,
            num_args = 0..=1,
            require_equals = true,
            default_missing_value = "true",
            value_name = "BOOL"
        )]
        memory_image: Option<bool>,

        /// Read this source as the named memory-image format, overriding
        /// detection.
        ///
        /// Unlike the flag, a name is a claim the evidence itself can
        /// contradict: a header that says otherwise wins and the disagreement
        /// is recorded against the image. Only names the analysis actually
        /// parses are accepted; anything else is refused here rather than
        /// dropped, so a declaration that will not be honoured is never
        /// mistaken for one that was. Do not pass "raw" — say
        /// `--memory-image` instead, which asserts "this is memory" without
        /// claiming a format.
        #[arg(long, value_name = "NAME")]
        memory_image_format: Option<String>,
    },

    /// Obtain the symbol file a memory image needs, and convert it for use.
    ///
    /// Séance can already name the symbols an image requires — the Windows tier
    /// reports the PDB name, GUID and age out of the kernel's CodeView record —
    /// and it can already read an ISF once one is present. This is the step in
    /// between, and it is a separate command rather than something ingest does
    /// because reaching the network during an examination is a decision about
    /// the lab, not a convenience: some are air-gapped by policy, and in others
    /// an outbound request from an analysis workstation is itself an event
    /// someone has to account for.
    ///
    /// Nothing is requested unless `--allow-network` is given. The file that
    /// arrives is hashed and its origin printed, because a symbol table
    /// determines what the analysis says about the image and therefore belongs
    /// in the chain of custody alongside it.
    FetchSymbols {
        /// PDB GUID as Séance reported it: 32 hex characters, symbol-store order.
        #[arg(long, required_unless_present = "isf")]
        guid: Option<String>,

        /// PDB age, as reported alongside the GUID.
        #[arg(long, required_unless_present = "isf")]
        age: Option<u32>,

        /// PDB file name. Defaults to the Windows kernel's.
        #[arg(long, default_value = "ntkrnlmp.pdb")]
        pdb: String,

        /// Directory to write the converted ISF into. Use one the analysis
        /// already searches — `SEANCE_SYMBOL_DIRS`, `<exe dir>/symbols`, or
        /// `./symbols`.
        #[arg(long, default_value = "symbols")]
        into: PathBuf,

        /// Permit exactly one outbound request, to the symbol source below.
        /// Without this the command explains what it would have fetched and
        /// stops.
        #[arg(long)]
        allow_network: bool,

        /// Symbol server to ask. Defaults to Microsoft's public one; point it
        /// at a lab mirror to keep the request inside the network.
        #[arg(long, default_value = seance_symbol_fetch::MICROSOFT_SYMBOL_SERVER)]
        source: String,

        /// Keep the downloaded PDB beside the ISF. Off by default: the PDB is
        /// Microsoft's to distribute, not the lab's, and the ISF is what the
        /// analysis reads.
        #[arg(long)]
        keep_pdb: bool,

        /// Fetch a prebuilt ISF by its path in the symbol store instead of
        /// converting a PDB — the route for Linux and macOS, which have no
        /// upstream symbol server and are served by community-built packs.
        /// Given this, `--guid` and `--age` are not used.
        #[arg(long, value_name = "PATH", conflicts_with = "guid")]
        isf: Option<String>,
    },

    /// Reset (or create) the admin account in the workspace database.
    ///
    /// Recovery path for a locked-out operator: the initial bootstrap only
    /// seeds the default password on an empty database, so a workspace created
    /// by an older build keeps its old, unknown hash. This rewrites the admin
    /// password in place and forces a change on next login.
    ResetAdmin {
        /// Account to reset. Created as an admin if it does not exist.
        #[arg(long, default_value = "admin")]
        username: String,

        /// New password. The account is flagged to change it on first login.
        #[arg(long, default_value = "seance")]
        password: String,
    },

    /// Reconstruct a RAID/JBOD array from member images into one logical image.
    ///
    /// Presents the reconstructed device as a single file the normal `scan`
    /// path then examines. A single missing member is reconstructed from parity
    /// on RAID 5/6; pass `MISSING` in its position.
    AssembleRaid {
        /// RAID level: raid0, raid1, raid5, raid6, or jbod.
        #[arg(long)]
        level: String,

        /// Stripe unit ("chunk") size in bytes (ignored for raid1/jbod).
        #[arg(long, default_value_t = 65536)]
        chunk: u64,

        /// Member images in array order. Use the literal `MISSING` for a dead
        /// disk (RAID 5 tolerates one; RAID 6 one via P).
        #[arg(long = "member", required = true)]
        members: Vec<String>,

        /// Output path for the reconstructed logical image.
        #[arg(long)]
        out: PathBuf,
    },

    /// Reconstruct a RAID/LVM array from its members and scan it IN-INGEST —
    /// virtually, without writing a second copy of the array to disk. Geometry is
    /// auto-detected from an `md` superblock when present; otherwise pass --level.
    ScanRaid {
        /// RAID level override: raid0, raid1, raid5, raid6, or jbod. Optional
        /// when the members carry an md superblock.
        #[arg(long)]
        level: Option<String>,

        /// Stripe unit ("chunk") size in bytes; overrides the superblock.
        #[arg(long)]
        chunk: Option<u64>,

        /// Member images in array order. Use the literal `MISSING` for a dead disk.
        #[arg(long = "member", required = true)]
        members: Vec<String>,

        /// Exit once the pipeline goes idle (batch mode). Both values sayable
        /// (`--exit-on-idle=false`), per the no-valueless-true-bool convention.
        #[arg(
            long,
            action = clap::ArgAction::Set,
            num_args = 0..=1,
            require_equals = true,
            default_value_t = true,
            default_missing_value = "true",
            value_name = "BOOL"
        )]
        exit_on_idle: bool,
    },

    /// Recover a LUKS passphrase by dictionary and/or mask (OFF by default;
    /// this subcommand IS the explicit opt-in). Every candidate is tried
    /// through the real LUKS unlock, so a hit is proven, not guessed.
    CrackLuks {
        /// Path to the LUKS volume image.
        #[arg(long)]
        volume: PathBuf,

        /// Wordlist file, one candidate per line. Combined with `--mask` if both
        /// are given (wordlist first).
        #[arg(long)]
        wordlist: Option<PathBuf>,

        /// Mask, e.g. `?d?d?d?d` for a 4-digit PIN (?d digit, ?l lower, ?u
        /// upper, ?s special, ?a all).
        #[arg(long)]
        mask: Option<String>,

        /// Hard ceiling on candidates tried.
        #[arg(long)]
        max_attempts: Option<u64>,
    },

    /// Recover a BitLocker user password by dictionary and/or mask (OFF by
    /// default; this subcommand IS the opt-in). Each candidate is tried through
    /// the real BitLocker unlock — the AES-CCM MAC proves a correct password.
    /// (A 48-digit recovery *key* is not dictionary-recoverable; this is for
    /// volumes protected with a chosen password.)
    CrackBitlocker {
        /// Path to the BitLocker (FVE) volume image.
        #[arg(long)]
        volume: PathBuf,

        /// Wordlist file, one candidate per line.
        #[arg(long)]
        wordlist: Option<PathBuf>,

        /// Mask (see crack-luks).
        #[arg(long)]
        mask: Option<String>,

        /// Hard ceiling on candidates tried.
        #[arg(long)]
        max_attempts: Option<u64>,
    },

    /// Recover the password of an encrypted ZIP archive (ZipCrypto or WinZip AES)
    /// by dictionary/mask. Off by default; a hit is proven by a correct decrypt.
    CrackZip {
        /// Path to the encrypted .zip archive.
        #[arg(long)]
        archive: PathBuf,

        /// Wordlist file, one candidate per line.
        #[arg(long)]
        wordlist: Option<PathBuf>,

        /// Mask (see crack-luks).
        #[arg(long)]
        mask: Option<String>,

        /// Hard ceiling on candidates tried.
        #[arg(long)]
        max_attempts: Option<u64>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    alloc_trace::configure_from_env();
    let args = Args::parse();

    if !args.interactive {
        // SÉANCE wordmark in the app's amber accent (#e5a13c). Uses 24-bit
        // truecolor ANSI (\x1b[38;2;R;G;Bm). The dim amber (#8a6224) mirrors
        // the app's --accent-dim token used for secondary text.
        const AMBER: &str = "\x1b[38;2;229;161;60m";
        const AMBER_DIM: &str = "\x1b[38;2;138;98;36m";
        const RESET: &str = "\x1b[0m";
        println!(
            "
{AMBER}               ╱
   ███████╗███████╗ █████╗ ███╗   ██╗ ██████╗███████╗
   ██╔════╝██╔════╝██╔══██╗████╗  ██║██╔════╝██╔════╝
   ███████╗█████╗  ███████║██╔██╗ ██║██║     █████╗
   ╚════██║██╔══╝  ██╔══██║██║╚██╗██║██║     ██╔══╝
   ███████║███████╗██║  ██║██║ ╚████║╚██████╗███████╗
   ╚══════╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝╚══════╝{RESET}
{AMBER_DIM}   D I G I T A L   F O R E N S I C S   W O R K B E N C H{RESET}
"
        );
        println!(
            "   {AMBER_DIM}v{} · built {} · {}{RESET}\n",
            env!("CARGO_PKG_VERSION"),
            env!("BUILD_TIMESTAMP"),
            env!("GIT_COMMIT")
        );
    }

    let log_level = match args.loglevel {
        1 => Level::WARN,
        2 => Level::INFO,
        3 => Level::DEBUG,
        4 => Level::TRACE,
        _ => Level::INFO,
    };

    // Create workspace directory early so log file can be written
    if !args.workspace.exists() {
        std::fs::create_dir_all(&args.workspace)?;
    }

    // Set up dual-output logging: stderr (colored) + log file (plain text)
    let file_appender = tracing_appender::rolling::never(&args.workspace, "seance.log");
    let (non_blocking_file, _guard) = tracing_appender::non_blocking(file_appender);

    tracing_subscriber::registry()
        .with(LevelFilter::from_level(log_level))
        .with(fmt::layer().with_writer(std::io::stderr))
        .with(fmt::layer().with_writer(non_blocking_file).with_ansi(false))
        .init();

    info!("Logging to {}/seance.log", args.workspace.display());

    // Handle explicit subcommands (Legacy Scan)
    if let Some(Commands::Scan {
        path,
        exit_on_idle,
        memory_image,
        memory_image_format,
    }) = args.command
    {
        // For scan mode, we use the workspace DB if it exists, or memory?
        // Let's respect the workspace arg for consistency
        let carver_defs = load_carver_defs(&args.carver_defs);
        return run_scan(
            path,
            exit_on_idle,
            MemoryDeclaration {
                memory_image,
                memory_image_format,
            },
            args.workspace,
            args.luks_passphrase,
            args.bitlocker_password,
            args.bitlocker_recovery_key,
            args.ios_backup_password,
            carver_defs,
            None,
        )
        .await;
    }

    if let Some(Commands::ScanRaid {
        level,
        chunk,
        members,
        exit_on_idle,
    }) = &args.command
    {
        let carver_defs = load_carver_defs(&args.carver_defs);
        return run_scan_raid(
            level,
            *chunk,
            members,
            *exit_on_idle,
            args.workspace.clone(),
            args.luks_passphrase.clone(),
            args.bitlocker_password.clone(),
            args.bitlocker_recovery_key.clone(),
            args.ios_backup_password.clone(),
            carver_defs,
        )
        .await;
    }

    if let Some(Commands::FetchSymbols {
        guid,
        age,
        pdb,
        into,
        allow_network,
        source,
        keep_pdb,
        isf,
    }) = &args.command
    {
        return run_fetch_symbols(
            guid.as_deref(),
            *age,
            pdb,
            into,
            *allow_network,
            source,
            *keep_pdb,
            isf.as_deref(),
        );
    }

    if let Some(Commands::ResetAdmin { username, password }) = &args.command {
        return run_reset_admin(&args.workspace, username, password).await;
    }

    if let Some(Commands::AssembleRaid {
        level,
        chunk,
        members,
        out,
    }) = &args.command
    {
        return run_assemble_raid(level, *chunk, members, out);
    }

    if let Some(Commands::CrackLuks {
        volume,
        wordlist,
        mask,
        max_attempts,
    }) = &args.command
    {
        return run_crack_luks(volume, wordlist.as_deref(), mask.as_deref(), *max_attempts);
    }

    if let Some(Commands::CrackBitlocker {
        volume,
        wordlist,
        mask,
        max_attempts,
    }) = &args.command
    {
        return run_crack_bitlocker(volume, wordlist.as_deref(), mask.as_deref(), *max_attempts);
    }

    if let Some(Commands::CrackZip {
        archive,
        wordlist,
        mask,
        max_attempts,
    }) = &args.command
    {
        return run_crack_zip(archive, wordlist.as_deref(), mask.as_deref(), *max_attempts);
    }

    // Default Mode: Server (API + GUI/REPL)
    run_server(args).await
}

/// Reconstruct a RAID/JBOD array from member images into one logical image.
fn run_assemble_raid(level: &str, chunk: u64, members: &[String], out: &Path) -> Result<()> {
    use seance_container_raid::raid::{RaidDevice, RaidLevel};
    use seance_core::data_source::{DataSource, FileDataSource};
    use std::io::Write;
    use std::sync::Arc;

    let level = match level.to_ascii_lowercase().as_str() {
        "raid0" | "0" => RaidLevel::Raid0,
        "raid1" | "1" => RaidLevel::Raid1,
        "raid5" | "5" => RaidLevel::Raid5,
        "raid6" | "6" => RaidLevel::Raid6,
        "jbod" => RaidLevel::Jbod,
        other => anyhow::bail!("unknown RAID level '{other}' (raid0/1/5/6 or jbod)"),
    };

    // Open each member; the literal MISSING marks a dead disk.
    let mut member_srcs: Vec<Option<Arc<dyn DataSource>>> = Vec::new();
    let mut member_size = 0u64;
    for m in members {
        if m == "MISSING" {
            member_srcs.push(None);
        } else {
            let src = Arc::new(FileDataSource::new(PathBuf::from(m))?);
            member_size = member_size.max(src.size());
            member_srcs.push(Some(src as Arc<dyn DataSource>));
        }
    }
    if member_size == 0 {
        anyhow::bail!("no present member image to size the array from");
    }

    let dev = RaidDevice::new(level, member_srcs, chunk, member_size)
        .map_err(|e| anyhow::anyhow!("RAID geometry rejected: {e}"))?;
    let total = dev.logical_size();
    println!(
        "Reconstructing {level:?}: {} members, {} logical bytes -> {}",
        members.len(),
        total,
        out.display()
    );

    // Stream the reconstruction in blocks so memory stays bounded on a large array.
    let mut file = std::fs::File::create(out)?;
    let mut pos = 0u64;
    let mut buf = vec![0u8; 8 * 1024 * 1024];
    while pos < total {
        let want = ((total - pos) as usize).min(buf.len());
        let got = dev.read_at(pos, &mut buf[..want])?;
        if got == 0 {
            break;
        }
        file.write_all(&buf[..got])?;
        pos += got as u64;
    }
    file.flush()?;
    // A short reconstruction is a failure to state plainly, not a success:
    // reporting it as "done" would let an examiner scan an image that is missing
    // evidence past the truncation point without knowing it.
    if pos < total {
        anyhow::bail!(
            "reconstruction is INCOMPLETE: wrote {pos} of {total} logical bytes to {}. \
             A member image is shorter than the array geometry implies (a truncated or \
             wrong member); do not treat the output as the full volume.",
            out.display()
        );
    }
    println!(
        "Wrote {pos} bytes. Now examine it: seance scan --path {}",
        out.display()
    );
    Ok(())
}

/// Reconstruct a RAID/LVM array from its members and scan it VIRTUALLY — the
/// reconstructed device is streamed straight into the ingest pipeline, with no
/// second copy of the array written to disk (unlike `assemble-raid`).
#[allow(clippy::too_many_arguments)]
async fn run_scan_raid(
    level: &Option<String>,
    chunk: Option<u64>,
    members: &[String],
    exit_on_idle: bool,
    workspace: PathBuf,
    luks_passphrase: Option<String>,
    bitlocker_password: Option<String>,
    bitlocker_recovery_key: Option<String>,
    ios_backup_password: Option<String>,
    carver_defs: Option<String>,
) -> Result<()> {
    use seance_container_raid::{assemble, RaidLevel};
    use seance_core::data_source::{DataSource, FileDataSource};

    let level_override = match level.as_deref() {
        None => None,
        Some(s) => Some(match s.to_ascii_lowercase().as_str() {
            "raid0" | "0" => RaidLevel::Raid0,
            "raid1" | "1" => RaidLevel::Raid1,
            "raid5" | "5" => RaidLevel::Raid5,
            "raid6" | "6" => RaidLevel::Raid6,
            "jbod" => RaidLevel::Jbod,
            other => anyhow::bail!("unknown RAID level '{other}' (raid0/1/5/6 or jbod)"),
        }),
    };

    // Open each member; the literal MISSING marks a dead disk. Remember the first
    // real member's path for the scan banner/workspace naming.
    let mut member_srcs: Vec<Option<Arc<dyn DataSource>>> = Vec::new();
    let mut first_path: Option<PathBuf> = None;
    for m in members {
        if m == "MISSING" {
            member_srcs.push(None);
        } else {
            let p = PathBuf::from(m);
            let src = Arc::new(FileDataSource::new(p.clone())?);
            if first_path.is_none() {
                first_path = Some(p);
            }
            member_srcs.push(Some(src as Arc<dyn DataSource>));
        }
    }
    let first_path = first_path.ok_or_else(|| anyhow::anyhow!("no present member image given"))?;

    let (device, report) = assemble(member_srcs, level_override, chunk)
        .map_err(|e| anyhow::anyhow!("RAID assembly rejected: {e}"))?;
    let total = device.logical_size();
    let name = format!(
        "RAID {:?} ({} members, {} logical bytes)",
        report.level,
        members.len(),
        total
    );
    println!(
        "Assembled {:?}{} — {} logical bytes, scanning virtually (no image written).",
        report.level,
        if report.auto_detected {
            " (auto-detected from md superblock)"
        } else {
            " (geometry from --level)"
        },
        total
    );

    let source: Arc<dyn DataSource> = Arc::new(device);
    run_scan(
        first_path,
        exit_on_idle,
        MemoryDeclaration::default(),
        workspace,
        luks_passphrase,
        bitlocker_password,
        bitlocker_recovery_key,
        ios_backup_password,
        carver_defs,
        Some((name, source)),
    )
    .await
}

/// Recover a LUKS passphrase, off by default and proven by real unlock.
/// Shared cracking core: run a verifier over a wordlist (rule-mutated) plus an
/// optional mask, print the outcome. Kept generic so LUKS and BitLocker share
/// one tested path; the verifier is the only thing that differs.
fn run_crack(
    label: &str,
    verifier: &dyn seance_crack::Verifier,
    wordlist: Option<&Path>,
    mask: Option<&str>,
    max_attempts: Option<u64>,
) -> Result<seance_crack::Outcome> {
    use seance_crack::{Dictionary, Engine, Mask, Outcome, Profile};

    if wordlist.is_none() && mask.is_none() {
        anyhow::bail!("give --wordlist and/or --mask; there is nothing to try otherwise");
    }

    let mut profile = Profile::enabled();
    if let Some(m) = max_attempts {
        profile = profile.with_max_attempts(m);
    }
    let engine = Engine::new(profile);

    // Wordlist candidates, each expanded with the rule mutations people actually
    // use (Password → Password1, P@ssword, …).
    let mut candidates: Vec<String> = Vec::new();
    if let Some(wl) = wordlist {
        let text = std::fs::read_to_string(wl)?;
        for line in text.lines() {
            let w = line.trim();
            if !w.is_empty() {
                candidates.extend(seance_crack::rule_mutations(w));
            }
        }
    }
    println!(
        "Cracking {label} ({} dictionary candidates{})…",
        candidates.len(),
        mask.map(|m| format!(" + mask {m}")).unwrap_or_default(),
    );

    let dict = Dictionary::new(candidates);
    let outcome = if let Some(m) = mask {
        let mask_iter = Mask::parse(m).ok_or_else(|| anyhow::anyhow!("invalid mask '{m}'"))?;
        engine.crack(dict.chain(mask_iter), verifier)
    } else {
        engine.crack(dict, verifier)
    };

    match &outcome {
        Outcome::Recovered { password, attempts } => {
            println!("\nRECOVERED after {attempts} attempts: {password}");
            println!("Evidence grade: validated (it unlocked the volume).");
        }
        Outcome::Exhausted { attempts } => {
            println!("\nNot found. {attempts} candidates tried.");
        }
        Outcome::Refused => {
            println!("\nCracker refused (profile disabled).");
        }
    }
    Ok(outcome)
}

fn run_crack_luks(
    volume: &Path,
    wordlist: Option<&Path>,
    mask: Option<&str>,
    max_attempts: Option<u64>,
) -> Result<()> {
    use seance_core::data_source::{DataSource, FileDataSource};
    use seance_crack::Verifier;
    use std::sync::Arc;

    let vol: Arc<dyn DataSource> = Arc::new(FileDataSource::new(volume.to_path_buf())?);
    if !seance_plugin_luks::is_luks(vol.as_ref()) {
        anyhow::bail!("{} is not a LUKS volume", volume.display());
    }

    // The verifier IS the real LUKS unlock: a candidate that unlocks is proven.
    struct LuksVerifier(Arc<dyn DataSource>);
    impl Verifier for LuksVerifier {
        fn target(&self) -> &str {
            "luks"
        }
        fn verify(&self, candidate: &str) -> bool {
            seance_plugin_luks::unlock_luks(self.0.clone(), candidate).is_ok()
        }
    }
    run_crack(
        &format!("LUKS on {}", volume.display()),
        &LuksVerifier(vol),
        wordlist,
        mask,
        max_attempts,
    )?;
    Ok(())
}

fn run_crack_bitlocker(
    volume: &Path,
    wordlist: Option<&Path>,
    mask: Option<&str>,
    max_attempts: Option<u64>,
) -> Result<()> {
    use seance_core::data_source::{DataSource, FileDataSource};
    use seance_crack::Verifier;
    use seance_plugin_bitlocker::{is_bitlocker, unlock_bitlocker, Credential};
    use std::sync::Arc;

    let vol: Arc<dyn DataSource> = Arc::new(FileDataSource::new(volume.to_path_buf())?);
    if !is_bitlocker(vol.as_ref()) {
        anyhow::bail!("{} is not a BitLocker volume", volume.display());
    }

    // The verifier IS the real BitLocker unlock: the AES-CCM MAC over the VMK
    // protector authenticates a correct password, so a hit is proven.
    struct BitlockerVerifier(Arc<dyn DataSource>);
    impl Verifier for BitlockerVerifier {
        fn target(&self) -> &str {
            "bitlocker"
        }
        fn verify(&self, candidate: &str) -> bool {
            unlock_bitlocker(self.0.clone(), &Credential::Password(candidate.to_string())).is_ok()
        }
    }
    run_crack(
        &format!("BitLocker on {}", volume.display()),
        &BitlockerVerifier(vol),
        wordlist,
        mask,
        max_attempts,
    )?;
    Ok(())
}

fn run_crack_zip(
    archive: &Path,
    wordlist: Option<&Path>,
    mask: Option<&str>,
    max_attempts: Option<u64>,
) -> Result<()> {
    use seance_container_zip::{ZipCracker, ZipVerdict};
    use seance_crack::Verifier;

    // The whole archive is read into memory and parsed ONCE (ZipCracker), so a
    // dictionary run does not re-walk the central directory per candidate. A
    // hostile multi-gigabyte archive is refused rather than buffered.
    const MAX_ARCHIVE: u64 = 2 * 1024 * 1024 * 1024;
    let meta = std::fs::metadata(archive)?;
    if meta.len() > MAX_ARCHIVE {
        anyhow::bail!(
            "archive is {} bytes, over the {MAX_ARCHIVE}-byte crack cap",
            meta.len()
        );
    }
    let bytes = std::fs::read(archive)?;
    let cracker = ZipCracker::open(bytes)
        .map_err(|_| anyhow::anyhow!("{} is not a parseable ZIP", archive.display()))?;
    if !cracker.has_encrypted_entry() {
        anyhow::bail!("{} has no encrypted entry to crack", archive.display());
    }

    // The verifier IS a real decrypt: a candidate is only a hit when the chosen
    // encrypted entry decrypts and reads to EOF with its CRC/HMAC intact.
    struct ZipVerifier(ZipCracker);
    impl Verifier for ZipVerifier {
        fn target(&self) -> &str {
            "zip"
        }
        fn verify(&self, candidate: &str) -> bool {
            self.0.verify(candidate) == ZipVerdict::Correct
        }
    }
    run_crack(
        &format!("ZIP on {}", archive.display()),
        &ZipVerifier(cracker),
        wordlist,
        mask,
        max_attempts,
    )?;
    Ok(())
}

async fn ensure_workspace(path: &Path) -> Result<String> {
    if !path.exists() {
        info!("Creating workspace directory: {:?}", path);
        std::fs::create_dir_all(path)?;
    }

    let db_path = path.join("seance.sqlite");
    let db_url = format!("sqlite:{}?mode=rwc", db_path.to_string_lossy());
    Ok(db_url)
}

/// Fetch a prebuilt ISF, for the tiers with no upstream symbol server.
///
/// Nothing is converted: what is published is already the format the analysis
/// reads, so the file is placed in the store and hashed, and
/// `seance_symbols::source` records its provenance when it is loaded.
fn run_fetch_isf(relative: &str, into: &Path, allow_network: bool, source: &str) -> Result<()> {
    use anyhow::Context as _;
    use seance_symbol_fetch::FetchPolicy;

    let base = if source == seance_symbol_fetch::MICROSOFT_SYMBOL_SERVER {
        // The default is the Windows server; an ISF request means the other
        // store unless the examiner named one.
        seance_symbol_fetch::VOLATILITY_ISF_BASE
    } else {
        source
    };
    let url = format!(
        "{}/{}",
        base.trim_end_matches('/'),
        relative.trim_start_matches('/')
    );

    if !allow_network {
        println!("Symbol acquisition is off, so nothing was requested.");
        println!();
        println!("  would fetch : {url}");
        println!("  would write : {}", into.display());
        println!();
        println!("Re-run with --allow-network if this lab permits an outbound");
        println!("request during an examination.");
        return Ok(());
    }

    std::fs::create_dir_all(into)
        .with_context(|| format!("creating the symbol directory {}", into.display()))?;
    let policy = FetchPolicy::allowing([base.to_string()]);
    let record = seance_symbol_fetch::fetch_isf(relative, into, &policy, base)
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    println!("Fetched  {}", record.url);
    if let Some(landed) = &record.landed_url {
        println!("  served {landed}");
    }
    println!("  bytes  {}", record.bytes);
    println!("  sha256 {}", record.sha256);
    println!("  written {}", record.path.display());
    println!();
    println!(
        "The analysis will find this on the next run if {} is one of the",
        into.display()
    );
    println!("directories it searches.");
    Ok(())
}

/// Obtain and convert the symbols an image named.
///
/// Prints the provenance of what arrived — URL, size, SHA-256 — because that is
/// the record an examiner needs in order to say later which symbol file
/// produced a finding, and a defence expert needs in order to obtain the same
/// file and reproduce the layout.
#[allow(clippy::too_many_arguments)]
fn run_fetch_symbols(
    guid: Option<&str>,
    age: Option<u32>,
    pdb: &str,
    into: &Path,
    allow_network: bool,
    source: &str,
    keep_pdb: bool,
    isf: Option<&str>,
) -> Result<()> {
    use anyhow::Context as _;
    use seance_symbol_fetch::{FetchPolicy, PdbIdentity};

    // The Linux and macOS route: no symbol server exists upstream, so what is
    // published is an already-built ISF and there is nothing to convert.
    if let Some(relative) = isf {
        return run_fetch_isf(relative, into, allow_network, source);
    }

    // clap guarantees these are present when `--isf` is not.
    let (Some(guid), Some(age)) = (guid, age) else {
        anyhow::bail!("--guid and --age are required unless --isf names a prebuilt ISF");
    };
    let identity = PdbIdentity {
        file_name: pdb.to_string(),
        guid: guid.trim().to_uppercase(),
        age,
    };
    let url = format!("{}/{}", source.trim_end_matches('/'), identity.store_path());

    if !allow_network {
        println!("Symbol acquisition is off, so nothing was requested.");
        println!();
        println!("  would fetch : {url}");
        println!(
            "  would write : {}",
            into.join(format!("{pdb}.json")).display()
        );
        println!();
        println!("Re-run with --allow-network if this lab permits an outbound");
        println!("request during an examination. Nothing else about the case changes.");
        return Ok(());
    }

    std::fs::create_dir_all(into)
        .with_context(|| format!("creating the symbol directory {}", into.display()))?;

    let policy = FetchPolicy::allowing([source.to_string()]);
    let temp = tempfile::tempdir().context("staging directory for the download")?;
    // Staged, not written straight into the symbol store: a partial or refused
    // download must not leave something behind that a later run would load.
    let record = seance_symbol_fetch::fetch_windows_pdb(&identity, temp.path(), &policy, source)
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    println!("Fetched  {}", record.url);
    println!("  bytes  {}", record.bytes);
    println!("  sha256 {}", record.sha256);

    if let Some(landed) = &record.landed_url {
        println!("  served {landed}");
    }

    let pdb_bytes = std::fs::read(&record.path).context("reading the downloaded PDB")?;

    // The file has to be the symbols that were asked for. Symbols for a
    // neighbouring build parse perfectly and put every offset in the wrong
    // place, so this is checked before anything is written into the store.
    seance_symbol_fetch::verify_pdb_identity(&pdb_bytes, &identity)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    println!("  identity confirmed: {} age {}", identity.guid, age);
    let (doc, summary) = seance_symbol_fetch::pdb_to_isf(
        &pdb_bytes,
        &identity.guid,
        age,
        pdb,
        Some(chrono::Utc::now().to_rfc3339()),
    )
    .context("converting the PDB to ISF")?;

    // Named by the identity, not the PDB file name: a store holds symbols for
    // many builds and every Windows kernel's PDB is called `ntkrnlmp.pdb`, so
    // naming by that allows exactly one. `GUID-age` is the fragment a
    // conventional symbol store uses, and the same one `automagic_isf::name_hint`
    // already builds when it goes looking.
    let isf_path = into.join(format!("{}-{}.json", identity.guid, age));
    if isf_path.exists() {
        anyhow::bail!(
            "{} already exists; refusing to replace a symbol file already in the store",
            isf_path.display()
        );
    }
    let json = serde_json::to_vec(&doc).context("serialising the ISF")?;
    // Staged and renamed, like every other file this command puts in the store.
    // A truncated ISF is the dangerous kind of half-file: it still parses, just
    // to a smaller type database, and the members it lost are then reported as
    // absent from the build rather than as a damaged symbol file.
    seance_symbol_fetch::write_new_atomically(&isf_path, &json)
        .with_context(|| format!("writing {}", isf_path.display()))?;

    println!();
    println!("Converted to {}", isf_path.display());
    println!(
        "  {} types, {} enums, {} symbols{}",
        summary.user_types,
        summary.enums,
        summary.symbols,
        if summary.unsupported_types > 0 {
            format!(
                " ({} member(s) had a type this build cannot express and were omitted)",
                summary.unsupported_types
            )
        } else {
            String::new()
        }
    );
    println!("  sha256 {}", seance_symbols::sha256_hex(&json));

    if keep_pdb {
        // Same invariant as everywhere else in this feature: a symbol file
        // already in the store is the lab's evidence about layout, and this is
        // the one an examiner is most likely to have curated by hand.
        let kept = into.join(format!("{}-{}-{pdb}", identity.guid, age));
        if kept.exists() {
            anyhow::bail!(
                "{} already exists; refusing to replace a symbol file already in the store",
                kept.display()
            );
        }
        std::fs::copy(&record.path, &kept)
            .with_context(|| format!("keeping the PDB at {}", kept.display()))?;
        println!("  PDB kept at {}", kept.display());
    }

    println!();
    println!(
        "The analysis will find this on the next run if {} is one of the",
        into.display()
    );
    println!("directories it searches. Re-run the memory analysis to use it.");
    Ok(())
}

/// Reset (or create) an admin account, forcing a password change on next login.
///
/// The startup bootstrap is intentionally idempotent -- it never touches an
/// existing user -- so an operator whose workspace predates the default-password
/// change has no way back in. This gives them one.
async fn run_reset_admin(workspace: &Path, username: &str, password: &str) -> Result<()> {
    let db_url = ensure_workspace(workspace).await?;
    let db = SqliteConnection::new(&db_url).await?;
    db.initialize().await?;

    let hash = seance_api::hash_password(password)
        .map_err(|e| anyhow::anyhow!("failed to hash password: {e}"))?;

    let (id, existed) = match db.get_user_by_username(username).await? {
        Some(user) => {
            db.update_user_password(user.id, &hash).await?;
            (user.id, true)
        }
        None => {
            let id = db.create_user(username, &hash, "admin").await?;
            (id, false)
        }
    };
    db.set_must_change_password(id, true).await?;

    let verb = if existed { "Reset" } else { "Created" };
    println!(
        "{verb} admin account '{username}'. Log in with the new password; \
         you will be required to change it on first login."
    );
    Ok(())
}

/// Read the optional custom carver-definitions file. A missing path yields
/// `None`; a path that fails to read is warned about and treated as absent, so
/// a bad `--carver-defs` never blocks ingest.
fn load_carver_defs(path: &Option<PathBuf>) -> Option<String> {
    let path = path.as_ref()?;
    match std::fs::read_to_string(path) {
        Ok(s) => Some(s),
        Err(e) => {
            error!("Failed to read carver defs {}: {}", path.display(), e);
            None
        }
    }
}

/// The examiner's command-line assertion that the scanned source is a capture
/// of physical memory.
///
/// It is its own type so the scan path cannot reach the metadata keys without
/// validating them: [`MemoryDeclaration::resolve`] is the only way to obtain
/// them, and it defers to `seance_api`'s validator — the same function the HTTP
/// ingest handler uses, checked against the same table of format names. Two
/// entry points, one definition of what may be declared and what the keys are
/// called; a copy here would drift, and a drifted key is silent (the memory
/// module simply finds nothing).
#[derive(Debug, Default)]
struct MemoryDeclaration {
    memory_image: Option<bool>,
    memory_image_format: Option<String>,
}

impl MemoryDeclaration {
    /// Whether this asserts "the source is memory".
    ///
    /// `--memory-image=false` is the absence of a declaration, not one: it
    /// leaves the source on the ordinary disk path exactly as if the flag had
    /// been omitted.
    fn asserts_memory(&self) -> bool {
        seance_api::declaration_asserts_memory(
            self.memory_image,
            self.memory_image_format.as_deref(),
        )
    }

    /// The keys to place verbatim at the top level of the root artifact's
    /// metadata, or the operator-facing reason the declaration was refused.
    ///
    /// A refused declaration ends the run. Dropping it instead would give a
    /// scan that "succeeded" with the whole memory tier silently absent —
    /// indistinguishable from a capture that held no evidence.
    fn resolve(&self) -> Result<Vec<(&'static str, serde_json::Value)>> {
        seance_api::memory_declaration_metadata(
            self.memory_image,
            self.memory_image_format.as_deref(),
        )
        .map_err(|e| anyhow::anyhow!(e))
    }
}

async fn run_server(args: Args) -> Result<()> {
    let db_url = ensure_workspace(&args.workspace).await?;
    info!("Using database: {}", db_url);

    // Initialize Database
    let db_conn = Arc::new(SqliteConnection::new(&db_url).await?);
    db_conn.initialize().await?;

    // Seed predefined filters
    if let Err(e) = db_conn.seed_predefined_filters().await {
        tracing::warn!("Failed to seed predefined filters: {}", e);
    }

    // Guard the workspace against a second live instance, and reclaim any
    // index lock a crashed run left behind. Held until this function returns.
    let _workspace_lock = WorkspaceLock::acquire(&args.workspace)?;

    // Initialize Search Service
    let search_index_path = args.workspace.join("search_index");
    let search_service = Arc::new(seance_search::SearchService::new(&search_index_path)?);
    info!("Search service initialized at {:?}", search_index_path);

    // Initialize Orchestrator
    let orchestrator_db_clone = db_conn.clone();
    let mut orchestrator = Orchestrator::new(Some(orchestrator_db_clone), 50000) // Large buffer for MFT parsing (can produce 10k+ artifacts)
        .with_exit_on_idle(false);

    register_all_modules(
        &mut orchestrator,
        ModuleSetOptions {
            search_service: search_service.clone(),
            carver_defs: load_carver_defs(&args.carver_defs),
            unlock: UnlockSecrets {
                luks_passphrase: args.luks_passphrase,
                bitlocker_password: args.bitlocker_password,
                bitlocker_recovery_key: args.bitlocker_recovery_key,
                ios_backup_password: args.ios_backup_password,
            },
            yara_rules: ModuleSetOptions::yara_rules_from_env(),
            memory_regex: ModuleSetOptions::memory_regex_from_env(),
            memory_strings: ModuleSetOptions::memory_strings_from_env(),
        },
    )?;

    // Collect module registry before spawning the orchestrator
    let module_registry = orchestrator.module_info_list();

    let orchestrator_sender = orchestrator.task_submitter();
    let ad_hoc_sender = orchestrator.ad_hoc_submitter();
    let event_sender = orchestrator.event_sender();
    let status_sender = orchestrator.status_sender();
    let active_tasks = orchestrator.active_tasks();
    let case_census = orchestrator.case_census();
    let ingestion_service = orchestrator.ingestion_service();
    let cancellation = orchestrator.cancellation_handle();

    // Run Orchestrator in background
    tokio::spawn(async move {
        orchestrator.run().await;
    });

    // Refresh query-planner statistics after each ingest settles. Debounced so a
    // burst of ProcessingComplete events triggers at most one (bounded) ANALYZE
    // per interval; keeps planner stats fresh on a long-running server.
    {
        let db_optimize = db_conn.clone();
        let mut status_rx = status_sender.subscribe();
        tokio::spawn(async move {
            use seance_core::orchestrator::OrchestratorEvent;
            let mut last: Option<tokio::time::Instant> = None;
            while let Ok(event) = status_rx.recv().await {
                if matches!(event, OrchestratorEvent::ProcessingComplete { .. })
                    && last.is_none_or(|t| t.elapsed() >= std::time::Duration::from_secs(30))
                {
                    last = Some(tokio::time::Instant::now());
                    if let Err(e) = db_optimize.optimize().await {
                        warn!("ANALYZE after ingest failed (non-fatal): {}", e);
                    }
                }
            }
        });
    }

    // Build optional PDF signing config (clap `requires` ensures both or neither)
    let signing_config =
        if let (Some(cert_path), Some(key_path)) = (&args.signing_cert, &args.signing_key) {
            let config = seance_reporting::SigningConfig::from_files(
                cert_path,
                key_path,
                args.signing_name.clone(),
                args.signing_reason.clone(),
            )
            .expect("Invalid PDF signing configuration");
            info!("PDF signing enabled: cert={}", cert_path.display());
            Some(config)
        } else {
            None
        };

    let app_state = AppState {
        db: db_conn.clone(),
        orchestrator_sender,
        ad_hoc_sender,
        event_sender,
        status_sender,
        active_tasks,
        search_service: Some(search_service.clone()),
        ingestion_service,
        module_registry,
        signing_config,
        // H6: logs a prominent warning when SEANCE_EVIDENCE_ROOTS is unset
        evidence_roots: EvidenceRootPolicy::from_env(),
        cancellation,
    };

    // Build API Router with authentication
    let auth_config = AuthConfig::from_env();

    // Seed the initial admin on first run so every audited action is
    // attributable to a real user. No-op once any user exists. The CLI always
    // serves on loopback (127.0.0.1), so the default 'seance' password applies
    // and must be changed on first login.
    seance_api::bootstrap_admin(&db_conn, &auth_config, true).await?;

    // A case deletion the previous run did not finish is finished now; the
    // case is already hidden by its mark.
    seance_api::resume_pending_case_deletions(&app_state).await;

    // Without this layer `GET /api/v1/status` answers `cases: null` with a
    // `cases_unavailable` reason instead of the per-case census.
    let mut app = router_with_auth(app_state.clone(), Some(auth_config.clone()))
        .layer(axum::Extension(ProcessingCensus(case_census)));

    // Construct API base URL for GUI and REPL
    let api_base_url = format!("http://127.0.0.1:{}", args.port);

    // Web UI (React SPA) is enabled by default. Disable with --headless.
    let enable_gui = !args.headless;

    if enable_gui {
        let index_path = args.web_root.join("index.html");
        if index_path.exists() {
            info!("Serving Web UI from {:?}", args.web_root);
            let spa = tower_http::services::ServeDir::new(&args.web_root)
                .fallback(tower_http::services::ServeFile::new(index_path));
            // Registered as the fallback so all /api/v1 routes keep priority.
            // Static assets are unauthenticated; the SPA handles login itself.
            // SpaFallback keeps unknown /api paths as JSON 404 instead of index.html.
            app = app.fallback_service(seance_api::SpaFallback::new(spa));
        } else {
            error!(
                "Web UI assets not found at {:?}. Build them with `npm --prefix frontend run build`, \
                 pass --web-root, or run with --headless.",
                args.web_root
            );
        }
    } else {
        info!("Running in headless mode (API only). Remove --headless to enable the Web UI.");
    }

    let listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{}", args.port)).await?;

    let local_addr = listener.local_addr()?;
    info!("Seance Server listening on {}", local_addr);

    // Render a Unicode box to stderr, sized to its longest row so the right
    // border is always a straight line regardless of address/path length.
    // `None` rows are horizontal separators; `Some(text)` rows are content.
    fn print_banner_box(rows: &[Option<String>]) {
        let inner = rows
            .iter()
            .flatten()
            .map(|s| s.chars().count())
            .max()
            .unwrap_or(0)
            + 4; // 2-space left indent + 2-space right margin
        let bar = "═".repeat(inner);
        eprintln!("  ╔{bar}╗");
        for row in rows {
            match row {
                Some(text) => eprintln!("  ║  {:<width$}║", text, width = inner - 2),
                None => eprintln!("  ╠{bar}╣"),
            }
        }
        eprintln!("  ╚{bar}╝");
    }

    // Print startup banner to stderr for user visibility
    eprintln!();
    let mut banner: Vec<Option<String>> = vec![
        Some(format!(
            "Seance v{}  (built {})",
            env!("CARGO_PKG_VERSION"),
            env!("BUILD_TIMESTAMP")
        )),
        Some("Digital Forensics Platform".to_string()),
        None,
    ];
    if !args.headless {
        banner.push(Some(format!("Web GUI:  http://{}", local_addr)));
    }
    banner.push(Some(format!("API: http://{}/api/v1/", local_addr)));
    banner.push(Some(format!(
        "Logs:     {}/seance.log",
        args.workspace.display()
    )));
    banner.push(None);
    banner.push(Some(if !auth_config.enabled {
        "Auth: disabled (SEANCE_AUTH_ENABLED=false)".to_string()
    } else if std::env::var("SEANCE_ADMIN_PASSWORD").is_ok() {
        "Auth: admin / (your SEANCE_ADMIN_PASSWORD)".to_string()
    } else {
        "Auth: admin / seance  (first run; change on first login)".to_string()
    }));
    banner.push(Some(
        "SEANCE_ADMIN_PASSWORD=<pw>  SEANCE_JWT_SECRET".to_string(),
    ));
    banner.push(Some(
        "SEANCE_AUTH_ENABLED=false  (disable auth)".to_string(),
    ));
    print_banner_box(&banner);
    eprintln!();

    // Warn only when authentication is genuinely off: anyone who can reach the
    // port then has full access with no credentials. When auth is on and no
    // SEANCE_ADMIN_PASSWORD is set, the initial admin is seeded with the default
    // 'seance' password (the CLI serves on loopback) and must change it on first
    // login, so there is no lasting insecure default to warn about here.
    if !auth_config.enabled {
        print_banner_box(&[
            Some("!! SECURITY WARNING !!".to_string()),
            Some("Authentication is DISABLED (SEANCE_AUTH_ENABLED=false).".to_string()),
            Some("Anyone who can reach this port has full access.".to_string()),
            Some("Do not expose this server beyond localhost.".to_string()),
        ]);
        eprintln!();
    }
    if auth_config.enabled && std::env::var("SEANCE_JWT_SECRET").is_err() {
        eprintln!("  Note: SEANCE_JWT_SECRET not set — a random secret was generated");
        eprintln!("  for this run. Logins will not survive a server restart.");
        eprintln!();
    }

    // Spawn API server task
    let server_handle = tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, app).await {
            error!("Server error: {}", e);
        }
    });

    if args.interactive {
        info!("Starting REPL...");
        // Give the server a moment to start
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

        if let Err(e) = seance_repl::run_repl(api_base_url.clone()).await {
            error!("REPL error: {}", e);
        }
        // When REPL exits, we can exit the process (killing the server task)
        info!("REPL exited. Shutting down.");
    } else if let Some(seconds) = args.timeout {
        info!("Server will auto-shutdown in {} seconds", seconds);
        tokio::time::sleep(tokio::time::Duration::from_secs(seconds)).await;
        info!("Timeout reached. Shutting down server.");
    } else {
        // Wait for the server task, or for the signal that stops it. Without a
        // handler the process simply died where it stood, and left both of the
        // things finished below undone.
        tokio::select! {
            joined = server_handle => match joined {
                Ok(_) => info!("Server stopped."),
                Err(e) => error!("Server task join error: {}", e),
            },
            _ = shutdown_signal() => info!("Signal received. Shutting down."),
        }
    }

    // What a stopped server leaves behind is the next start's problem, so it is
    // finished here on every exit path. The search index auto-commits every
    // 1000 documents, so without this final commit up to 999 indexed artifacts
    // stay invisible to search — and an unsearchable artifact returns no hits,
    // which reads exactly like an artifact that does not contain the term. The
    // write-ahead log is the other half: recovering a large one runs before any
    // connection opens, and a 45 GB log timed the pool out entirely (HUNT-088).
    if let Err(e) = search_service.commit().await {
        error!("Final search-index commit failed: {}", e);
    }
    db_conn.truncate_wal().await;

    Ok(())
}

/// Resolve when the process is asked to stop: Ctrl-C, or SIGTERM.
async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut sig) => {
                sig.recv().await;
            }
            // Nothing to wait for; leave Ctrl-C as the only stop signal.
            Err(e) => {
                error!("Could not listen for SIGTERM: {}", e);
                std::future::pending::<()>().await;
            }
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}

/// Wait for the scan's orchestrator to finish before the caller reports on it.
///
/// The wait is unconditional. `--exit-on-idle=false` means "do not stop when
/// the queue drains", not "stop waiting": returning early there would print
/// this scan's completion banner while modules were still parsing the evidence,
/// and an examiner cannot tell that banner from a finished run. With idle exit
/// disabled the orchestrator keeps running until the operator interrupts it,
/// which is what was asked for; the per-run summary is still printed by the
/// progress display when the queue drains.
///
/// The cost of that is real and is stated to the operator rather than left to
/// be discovered: this process has no SIGINT handler, so the Ctrl-C that ends
/// an `--exit-on-idle=false` run skips the final `SearchService::commit` and
/// the post-ingest `ANALYZE`. The search index auto-commits every 1000
/// documents, so up to 999 indexed artifacts stay invisible to search — and an
/// unsearchable artifact returns no hits, which reads exactly like an artifact
/// that does not contain the term. A case with fewer than 1000 artifacts loses
/// its whole index that way.
async fn await_orchestrator(handle: tokio::task::JoinHandle<()>, exit_on_idle: bool) -> Result<()> {
    if !exit_on_idle {
        eprintln!(
            "  --exit-on-idle=false: the orchestrator stays up after the queue drains, \
             and this scan will not return on its own."
        );
        eprintln!(
            "  Ending it with Ctrl-C skips the final search-index commit: up to 999 \
             artifacts would be absent from search results with no error shown."
        );
        eprintln!("  Omit the flag unless you need the orchestrator held open.");
    }
    handle.await?;
    Ok(())
}

/// A scan whose run was stopped (cancelled, or ended by the memory governor)
/// must not exit zero: a script reads zero as "the evidence was examined".
fn fail_if_stopped(stopped: &std::sync::atomic::AtomicBool) -> Result<()> {
    if stopped.load(std::sync::atomic::Ordering::SeqCst) {
        anyhow::bail!(
            "the scan was stopped before it finished; the case is INCOMPLETE \
             (see the source's incomplete_detail, and SEANCE_MEMORY_LIMIT / SEANCE_WORKERS \
             if the memory governor stopped it)"
        );
    }
    Ok(())
}

/// Decide what a scanned source is, and refuse the run when the answer means
/// nothing would examine it.
///
/// `Ok(None)` means the path is a directory, which has no single data source
/// and is handed to the directory-aware modules as-is.
///
/// Every check here has to happen before the run does any work, because each
/// failure mode it catches is silent otherwise: an unreadable format, or a
/// memory declaration on a source the memory analysis never receives, both
/// produce a scan that finishes "successfully" having examined nothing. That is
/// indistinguishable from evidence that held nothing.
fn classify_scan_source(
    path: &Path,
    memory: &MemoryDeclaration,
) -> Result<Option<(ArtifactType, Option<&'static str>)>> {
    if path.is_dir() {
        // A directory is not a capture. The declaration would ride an artifact
        // with no data source at all, so the memory module would read the keys
        // and have nothing to read them against.
        if memory.asserts_memory() {
            anyhow::bail!(
                "A memory-image declaration names a single captured file, but {} is a \
                 directory. Point --path at the capture itself.",
                path.display()
            );
        }
        return Ok(None);
    }

    // Classify with the SAME table the HTTP ingest handler uses. This was once
    // a hand-written match here, and it had drifted: it knew nothing of
    // VHD/VHDX/VMDK/QCOW2 and had no extension fallback at all, so a virtual
    // disk scanned from the command line became untyped RawEvidence and the
    // virtual-disk readers -- which subscribe to Container -- never saw it. A
    // fixed-size VHD (whose only signature is a footer) and a descriptor-only
    // VMDK were lost outright. One table, both entry points.
    let (detected_type, detected_subtype) = seance_api::auto_detect_artifact_type(path);

    // Refuse formats this binary recognises but has no registered reader for,
    // in the same words the API uses. Without this the scan "succeeded" and
    // produced an artifact nothing would ever open.
    if let Some(msg) = seance_api::unsupported_format_message(detected_subtype) {
        anyhow::bail!(msg);
    }

    // A memory declaration only reaches the analysis on an artifact type the
    // memory module subscribes to (RawEvidence, FileEntry). Attached to any
    // other type it is persisted, never read, and the scan finishes with the
    // whole memory tier absent. A headerless capture has no magic and no known
    // extension, so it resolves to RawEvidence and is honoured; anything else
    // detected here really is something other than a bare capture, and saying
    // so is the point. Same rule, same reason, as the HTTP handler.
    if memory.asserts_memory()
        && !matches!(
            detected_type,
            ArtifactType::RawEvidence | ArtifactType::FileEntry
        )
    {
        anyhow::bail!(
            "A memory-image declaration cannot be honoured for {}: its contents identify it as \
             {:?}{}, and the memory analysis only receives RawEvidence and FileEntry, so the \
             declaration would be recorded and never read. Remove the declaration if this is \
             not a memory capture.",
            path.display(),
            detected_type,
            detected_subtype
                .map(|s| format!(" ({s})"))
                .unwrap_or_default()
        );
    }

    Ok(Some((detected_type, detected_subtype)))
}

// Nine arguments because nine things the operator declared on the command
// line have to reach the scan: the source, the idle behaviour, the memory
// declaration, the workspace, four unlock secrets and the carver
// definitions. Bundling them into a struct would move the list rather than
// shorten it, and the secrets deliberately do not live together in one
// value that could be logged by accident.
#[allow(clippy::too_many_arguments)]
async fn run_scan(
    path: PathBuf,
    exit_on_idle: bool,
    memory: MemoryDeclaration,
    workspace: PathBuf,
    luks_passphrase: Option<String>,
    bitlocker_password: Option<String>,
    bitlocker_recovery_key: Option<String>,
    ios_backup_password: Option<String>,
    carver_defs: Option<String>,
    // A pre-built source (name, DataSource) to ingest instead of opening `path`.
    // This is how a virtually-assembled RAID/LVM device is scanned WITHOUT first
    // materialising it to a file: the reconstructed device is streamed straight
    // into the pipeline. `path` is still used for the workspace/log banner.
    prebuilt: Option<(String, Arc<dyn seance_core::data_source::DataSource>)>,
) -> Result<()> {
    info!("Seance CLI starting scan...");

    // Validate the declaration and classify the source before any workspace,
    // database, index or case is touched, so a refused run leaves no trace of
    // work it did not do -- not even an empty "CLI Scan" case. This mirrors the
    // HTTP handler, which validates before it activates a profile or queues
    // anything.
    let memory_keys = memory.resolve()?;
    let classified = classify_scan_source(&path, &memory)?;

    eprintln!();
    eprintln!(
        "  Seance v{} — Scanning {:?}",
        env!("CARGO_PKG_VERSION"),
        path.file_name().unwrap_or_default()
    );
    eprintln!("  Workspace: {}", workspace.display());
    eprintln!("  Logs:      {}/seance.log", workspace.display());
    eprintln!();

    info!("Ingesting file: {:?}", path);

    let db_url = ensure_workspace(&workspace).await?;
    let conn = SqliteConnection::new(&db_url).await?;
    conn.initialize().await?;
    let db_conn = Arc::new(conn);

    let _workspace_lock = WorkspaceLock::acquire(&workspace)?;

    // Initialize Search Service
    let search_index_path = workspace.join("search_index");
    let search_service = Arc::new(seance_search::SearchService::new(&search_index_path)?);
    info!("Search service initialized at {:?}", search_index_path);

    // Create the orchestrator
    let mut orchestrator =
        Orchestrator::new(Some(db_conn.clone()), 100).with_exit_on_idle(exit_on_idle);

    register_all_modules(
        &mut orchestrator,
        ModuleSetOptions {
            search_service: search_service.clone(),
            carver_defs,
            unlock: UnlockSecrets {
                luks_passphrase,
                bitlocker_password,
                bitlocker_recovery_key,
                ios_backup_password,
            },
            yara_rules: ModuleSetOptions::yara_rules_from_env(),
            memory_regex: ModuleSetOptions::memory_regex_from_env(),
            memory_strings: ModuleSetOptions::memory_strings_from_env(),
        },
    )?;

    let ingestion_service = orchestrator.ingestion_service();
    let active_tasks = orchestrator.active_tasks();
    let mut status_rx = orchestrator.status_sender().subscribe();
    let orchestrator_handle = tokio::spawn(orchestrator.run());
    // Set when the run ended without completing (an examiner's cancel, or the
    // memory governor's stop), so the scan exits non-zero: a script must not
    // read a partial ingest as a finished one.
    let run_stopped = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let run_stopped_display = run_stopped.clone();

    // Spawn progress display task
    tokio::spawn(async move {
        use seance_core::orchestrator::OrchestratorEvent;
        use std::time::Instant;
        let scan_start = Instant::now();
        let mut modules_succeeded: usize = 0;
        let mut modules_failed: usize = 0;

        while let Ok(event) = status_rx.recv().await {
            match event {
                OrchestratorEvent::PhaseStarted { phase, .. } => {
                    eprintln!("\r[*] {:<60}", phase);
                }
                OrchestratorEvent::PhaseProgress {
                    artifacts_processed,
                    ..
                } => {
                    let elapsed = scan_start.elapsed().as_secs_f64();
                    let rate = if elapsed > 0.5 {
                        format!(" ({:.0}/s)", artifacts_processed as f64 / elapsed)
                    } else {
                        String::new()
                    };
                    eprint!("\r    {} artifacts{:<30}", artifacts_processed, rate);
                }
                OrchestratorEvent::ModuleCompleted { .. } => {
                    modules_succeeded += 1;
                }
                OrchestratorEvent::ProcessingComplete {
                    total_artifacts,
                    total_duration_ms,
                    artifacts_by_type,
                    ..
                } => {
                    let rate = if total_duration_ms > 0 {
                        format!(
                            " ({:.0}/s)",
                            total_artifacts as f64 / (total_duration_ms as f64 / 1000.0)
                        )
                    } else {
                        String::new()
                    };
                    eprintln!(
                        "\r[+] Complete: {} artifacts in {:.1}s{}",
                        total_artifacts,
                        total_duration_ms as f64 / 1000.0,
                        rate
                    );
                    for (type_name, count) in &artifacts_by_type {
                        if *count > 0 {
                            eprintln!("    {:<25} {}", type_name, count);
                        }
                    }
                    eprintln!(
                        "    Modules: {} succeeded, {} failed",
                        modules_succeeded, modules_failed
                    );
                }
                OrchestratorEvent::ProcessingCancelled {
                    artifacts_processed,
                    ..
                } => {
                    run_stopped_display.store(true, std::sync::atomic::Ordering::SeqCst);
                    eprintln!(
                        "\r[!] STOPPED after {} artifacts: the ingest is INCOMPLETE. If the \
                         memory governor stopped it, each source records why (see \
                         SEANCE_MEMORY_LIMIT and SEANCE_WORKERS in DEPLOYMENT.md)",
                        artifacts_processed
                    );
                }
                OrchestratorEvent::ModuleError {
                    module_id, error, ..
                } => {
                    eprintln!("\r[!] Error in {}: {}", module_id, error);
                    modules_failed += 1;
                }
                _ => {}
            }
        }
    });

    // Everything from here to the moment the first artifact reaches the queue
    // is work on the evidence that the orchestrator cannot see: creating the
    // case, opening the source, detecting its type, and — the expensive one —
    // acquisition hashing (MD5 + SHA-1 + SHA-256 over the whole file) inside
    // `ingest_artifact`. On a 512 MB image that is far longer than the idle
    // window, and an `--exit-on-idle` orchestrator used to exit mid-hash; the
    // ingest that followed hit a closed channel ("Failed to send artifact to
    // queue") and the scan examined nothing at all.
    //
    // The guard makes the run observably busy for that whole period, which is
    // the truth. It MUST be dropped before awaiting `orchestrator_handle`, or
    // the run can never go idle — hence the explicit `drop` on both the
    // directory and the single-file path below.
    let ingest_guard = seance_core::orchestrator::ActiveTaskGuard::new(active_tasks);

    // Create a case for this scan
    let case_id = db_conn.create_case("CLI Scan", "CLI User").await?;

    // A pre-built (virtually-assembled) source — a RAID/LVM device reconstructed
    // in memory — is ingested directly as RawEvidence, so the whole array flows
    // through partitioning, filesystems, carving and hashing WITHOUT a materialised
    // second copy on disk. Its byte size is the reconstructed logical size.
    if let Some((name, source)) = prebuilt {
        let size = source.size();
        // No `source_path`: a virtually-assembled device is not a single acquired
        // file, so no path-based acquisition baseline is recorded over the
        // reconstructed stream (that would assert a chain of custody the stream
        // never had). The acquisition baseline lives on the member images, which
        // were acquired and hashed in their own right; this states that plainly
        // rather than fabricating a digest for a derived artifact.
        let mut metadata = serde_json::json!({
            "name": name,
            "size": size,
            "subtype": "raid_virtual",
            "acquisition_note": "Virtually-assembled RAID/LVM device: reconstructed on the fly \
                                 from its member images, not a separately-acquired file. The \
                                 acquisition baseline is the member images, hashed individually.",
        });
        if let Some(obj) = metadata.as_object_mut() {
            seance_api::attach_memory_declaration(obj, &memory_keys);
        }
        ingestion_service
            .ingest_artifact(case_id, ArtifactType::RawEvidence, Some(source), metadata)
            .await?;
        drop(ingest_guard);
        await_orchestrator(orchestrator_handle, exit_on_idle).await?;
        fail_if_stopped(&run_stopped)?;
        if let Err(e) = search_service.commit().await {
            error!("Failed to commit search index: {}", e);
        }
        if let Err(e) = db_conn.optimize().await {
            warn!("ANALYZE after ingest failed (non-fatal): {}", e);
        }
        info!("Seance CLI finished processing a virtually-assembled device.");
        print_method_advisories(&db_conn, case_id).await;
        return Ok(());
    }

    // A directory input (e.g. an iOS backup folder) has no single data source;
    // hand its path to the directory-aware modules (iOS backup) as RawEvidence.
    // Their produced FileEntry children then flow through the rest of the pipeline.
    let Some((detected_type, detected_subtype)) = classified else {
        let dir_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("directory")
            .to_string();
        let metadata = serde_json::json!({
            "name": dir_name,
            "path": path.to_str().unwrap_or_default(),
            "is_directory": true,
        });
        ingestion_service
            .ingest_artifact(case_id, ArtifactType::RawEvidence, None, metadata)
            .await?;
        // Queued: the orchestrator now tracks this work itself.
        drop(ingest_guard);
        await_orchestrator(orchestrator_handle, exit_on_idle).await?;
        fail_if_stopped(&run_stopped)?;
        if let Err(e) = search_service.commit().await {
            error!("Failed to commit search index: {}", e);
        }
        if let Err(e) = db_conn.optimize().await {
            warn!("ANALYZE after ingest failed (non-fatal): {}", e);
        }
        info!("Seance CLI finished processing directory.");
        return Ok(());
    };

    let file_data_source = Arc::new(FileDataSource::new(path.clone())?);

    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown")
        .to_string();
    let file_path_str = path.to_str().unwrap_or_default().to_string();

    info!(
        "Auto-detected {:?} (subtype: {:?})",
        detected_type, detected_subtype
    );
    let artifact_type = detected_type;

    let mut metadata = serde_json::json!({
        "name": file_name,
        // Both keys: modules read one or the other (the E01 reader opens
        // `path`, the $BadClus and utmp parsers read `source_path`), and the
        // scan path used to write only `source_path` for anything it typed as
        // RawEvidence.
        "path": file_path_str,
        "source_path": file_path_str,
    });
    {
        let obj = metadata
            .as_object_mut()
            .expect("metadata was built as a JSON object");
        if let Some(subtype) = detected_subtype {
            obj.insert("subtype".to_string(), serde_json::json!(subtype));
        }
        // The source byte size, as the HTTP ingest records it. The disk-map
        // endpoint reads `$.size` for the total extent of the source and falls
        // back to the end of the furthest region it found -- which silently
        // omits any unallocated tail after the last partition, so a
        // CLI-ingested image drew a map of a disk shorter than the evidence.
        // Absent when the stat fails, never zero: an unknown size and an empty
        // source must not render alike.
        if let Ok(size) = std::fs::metadata(&path).map(|m| m.len()) {
            obj.insert("size".to_string(), serde_json::json!(size));
        }
        // The examiner's memory declaration, verbatim and top-level, under the
        // keys `seance_memory` reads. Renaming or nesting them does not fail --
        // the module simply finds nothing and every memory stage reports
        // `did_not_run` with nothing an examiner can read.
        seance_api::attach_memory_declaration(obj, &memory_keys);

        // An encrypted Apple disk image (`encrcdsa`) has no reader and would
        // otherwise ingest as a silent zero-artifact no-op on this path too. Mark
        // it as a stated gap so it is counted in the incompleteness census,
        // exactly as the HTTP handler does — the CLI `scan` was the second entry
        // point that still ingested it silently (LIVE-003).
        if let Some(fmt) = seance_api::mark_if_apple_encrypted_dmg(&path, obj) {
            warn!(
                "{:?} is an encrypted Apple disk image ('{}'): it is recorded as \
                 encrypted and present but not opened; no key is available to \
                 decrypt it, so it appears as a stated gap rather than an empty result",
                path, fmt
            );
        }
    }

    // Volume-unlock secrets are NOT attached here. They were handed to the LUKS
    // and BitLocker decryptor modules at registration and live only in process
    // memory: this metadata is persisted verbatim to `artifacts.metadata_json`
    // and served by the artifact-detail API, so a passphrase written here would
    // outlive the process next to the evidence it unlocks.

    // Use the ingestion service to properly ingest the artifact
    // This ensures DB persistence, SSE broadcast, and proper task tracking
    ingestion_service
        .ingest_artifact(case_id, artifact_type, Some(file_data_source), metadata)
        .await?;
    // Queued: the orchestrator now tracks this work itself.
    drop(ingest_guard);

    await_orchestrator(orchestrator_handle, exit_on_idle).await?;

    // Final commit to ensure all indexed documents are visible to search readers
    if let Err(e) = search_service.commit().await {
        error!("Failed to commit search index: {}", e);
    }

    // Refresh planner statistics now that the tables are fully populated, so the
    // first queries against this case use real cardinality (bounded ANALYZE).
    if let Err(e) = db_conn.optimize().await {
        warn!("ANALYZE after ingest failed (non-fatal): {}", e);
    }

    fail_if_stopped(&run_stopped)?;

    info!("Seance CLI finished processing.");
    println!("--------------------------------------------------");
    println!("Seance Processing Complete");
    println!("Evidence: {}", path.display());
    println!("Logs:     {}/seance.log", workspace.display());
    println!("--------------------------------------------------");
    print_method_advisories(&db_conn, case_id).await;

    Ok(())
}

/// Tell the examiner, at the end of a run, where a result rested on a weaker
/// footing than the usual one.
///
/// # Why this is printed and not merely recorded
///
/// The provenance of these findings is in the artifact and in the report. An
/// examiner who never opens either — who runs a scan, sees it complete, and
/// carries the process list into a statement — would not know. Saying it on the
/// console is the only surface that reaches somebody who does not go looking.
///
/// Printed to stdout beside the completion summary rather than logged: a
/// warning in `seance.log` is a warning nobody reads until something has
/// already gone wrong.
///
/// # Why it asks the reporting layer rather than querying for itself
///
/// It ends by telling the examiner "this appears in the report's Limitations
/// and Qualifications section", which is a promise that the two say the same
/// thing. It used to query for `symbols_origin` alone, so when a second kind of
/// qualification arrived — the decompression ceiling a run was expanded under —
/// the console fell silent about it while the report stated it, and the closing
/// sentence became untrue. Both surfaces now read the one gatherer
/// `seance_api::gather_method_qualifications`, so a third kind cannot land on
/// one and not the other.
async fn print_method_advisories(db: &SqliteConnection, case_id: uuid::Uuid) {
    let qualifications = seance_api::gather_method_qualifications(db, case_id).await;
    if qualifications.is_empty() {
        return;
    }

    println!();
    println!("ADVISORY — how this examination was conducted");
    println!("--------------------------------------------------");
    for (at, qualification) in qualifications.iter().enumerate() {
        if at > 0 {
            println!();
        }
        println!("{}", qualification.subject);
        for line in wrap_console(&qualification.statement, 78) {
            println!("{line}");
        }
        // `affects` names the findings the qualification bears on. It is what
        // stops a reader taking a caveat about one container's contents as a
        // caveat about the whole case, so it is not dropped for brevity.
        if let Some(affects) = qualification
            .affects
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            for line in wrap_console(&format!("Bears on: {affects}"), 78) {
                println!("{line}");
            }
        }
    }
    println!("--------------------------------------------------");
    println!("This appears in the report's Limitations and Qualifications section.");
}

/// Wrap prose to a console width, breaking on spaces.
fn wrap_console(text: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut current = String::new();
    for word in text.split_whitespace() {
        if !current.is_empty() && current.len() + 1 + word.len() > width {
            lines.push(std::mem::take(&mut current));
        }
        if !current.is_empty() {
            current.push(' ');
        }
        current.push_str(word);
    }
    if !current.is_empty() {
        lines.push(current);
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::{ArgAction, CommandFactory};

    /// Every argument in the command tree, including subcommand arguments,
    /// paired with the path of commands it sits under.
    fn all_args(cmd: &clap::Command, path: &str, out: &mut Vec<(String, String)>) {
        for arg in cmd.get_arguments() {
            let name = arg
                .get_long()
                .map(|l| format!("--{l}"))
                .unwrap_or_else(|| arg.get_id().to_string());
            // An argument that takes no value on the command line but whose
            // default is `true` can never be given any other value.
            let is_flag = matches!(arg.get_action(), ArgAction::SetTrue);
            let defaults_true = arg
                .get_default_values()
                .iter()
                .any(|v| v.to_string_lossy() == "true");
            if is_flag && defaults_true {
                out.push((path.to_string(), name));
            }
        }
        for sub in cmd.get_subcommands() {
            let sub_path = format!("{path} {}", sub.get_name());
            all_args(sub, &sub_path, out);
        }
    }

    /// LIVE-001, generalised. `#[arg(long, default_value_t = true)]` on a `bool`
    /// is compiled by clap's derive into `ArgAction::SetTrue` with a default of
    /// `true`: the flag takes no value, so `--thing=false` is rejected with
    /// "unexpected value 'false'" and the field the code reads can only ever be
    /// true. That is how `--exit-on-idle=false` came to be unexpressible, which
    /// made `seance scan` unable to ingest any image whose acquisition hashing
    /// ran past the ten-second idle window: the orchestrator exited mid-hash and
    /// the ingest that followed hit a closed channel.
    ///
    /// Every such argument must be declared with `action = ArgAction::Set` and
    /// `num_args = 0..=1` (see `exit_on_idle`) so both values can be said. This
    /// walks the whole command tree, so the class cannot come back through a new
    /// flag or a new subcommand.
    #[test]
    fn no_boolean_flag_defaults_to_true_without_a_way_to_say_false() {
        let cmd = Args::command();
        let mut offenders = Vec::new();
        all_args(&cmd, "seance", &mut offenders);
        assert!(
            offenders.is_empty(),
            "these arguments default to true but are exposed as valueless flags, so `=false` is \
             rejected and the option can only ever be true. Declare each with \
             `action = clap::ArgAction::Set, num_args = 0..=1, require_equals = true, \
             default_missing_value = \"true\"`: {offenders:?}"
        );
    }

    /// Parse a `scan` invocation and return its `exit_on_idle`, or the clap
    /// error rendered as a string.
    fn scan_exit_on_idle(extra: &[&str]) -> Result<bool, String> {
        let mut argv = vec!["seance", "scan", "--path", "evidence.dd"];
        argv.extend_from_slice(extra);
        match Args::try_parse_from(argv) {
            Ok(Args {
                command: Some(Commands::Scan { exit_on_idle, .. }),
                ..
            }) => Ok(exit_on_idle),
            Ok(other) => panic!("expected a scan subcommand, got {other:?}"),
            Err(e) => Err(e.to_string()),
        }
    }

    /// LIVE-001, second defect. `exit_on_idle` was declared as a bare bool
    /// flag, which clap exposes as `SetTrue`: `--exit-on-idle=false` was
    /// rejected with "unexpected value 'false'", so the option the code reads
    /// could only ever be true and an operator had no way to keep the
    /// orchestrator alive past the idle window.
    #[test]
    fn exit_on_idle_can_be_turned_off_on_the_command_line() {
        assert_eq!(
            scan_exit_on_idle(&["--exit-on-idle=false"]),
            Ok(false),
            "`--exit-on-idle=false` must be accepted and must disable idle exit"
        );
    }

    #[test]
    fn exit_on_idle_defaults_to_true_and_accepts_an_explicit_true() {
        assert_eq!(scan_exit_on_idle(&[]), Ok(true), "default is idle exit");
        assert_eq!(scan_exit_on_idle(&["--exit-on-idle=true"]), Ok(true));
        // The bare flag keeps its historical meaning rather than erroring.
        assert_eq!(scan_exit_on_idle(&["--exit-on-idle"]), Ok(true));
    }

    /// A value that is neither true nor false is an operator mistake and must
    /// be refused, not silently read as one of them.
    #[test]
    fn exit_on_idle_rejects_a_non_boolean_value() {
        let err = scan_exit_on_idle(&["--exit-on-idle=maybe"])
            .expect_err("`maybe` is not a boolean and must not parse");
        assert!(
            err.contains("maybe"),
            "the error must name the rejected value: {err}"
        );
    }

    /// Parse a `scan` invocation and return the memory declaration it carries.
    fn scan_memory(extra: &[&str]) -> Result<MemoryDeclaration, String> {
        let mut argv = vec!["seance", "scan", "--path", "memory.raw"];
        argv.extend_from_slice(extra);
        match Args::try_parse_from(argv) {
            Ok(Args {
                command:
                    Some(Commands::Scan {
                        memory_image,
                        memory_image_format,
                        ..
                    }),
                ..
            }) => Ok(MemoryDeclaration {
                memory_image,
                memory_image_format,
            }),
            Ok(other) => panic!("expected a scan subcommand, got {other:?}"),
            Err(e) => Err(e.to_string()),
        }
    }

    /// LIVE-002. `seance_memory` analyses a headerless capture only when the
    /// case declares it, and the command line had no way to say so: the flag
    /// existed nowhere in `seance_cli`, so the commonest memory acquisition
    /// format could not be examined through `seance scan` at all. Every unit
    /// test passed throughout, because they hand the module its metadata.
    #[test]
    fn a_raw_memory_capture_can_be_declared_on_the_command_line() {
        let declared = scan_memory(&["--memory-image"]).expect("the flag must parse");
        assert!(declared.asserts_memory());
        assert_eq!(
            declared.resolve().expect("a bare declaration is valid"),
            vec![("memory_image", serde_json::Value::Bool(true))],
            "the key must be the one seance_memory reads, at the top level"
        );
    }

    /// The declaration is an assertion, so denying it must be expressible too,
    /// and must read as the absence of a declaration rather than as one.
    #[test]
    fn memory_image_false_is_the_absence_of_a_declaration() {
        let denied = scan_memory(&["--memory-image=false"]).expect("must parse");
        assert!(!denied.asserts_memory());
        assert_eq!(
            denied.resolve().expect("an explicit false is valid"),
            vec![("memory_image", serde_json::Value::Bool(false))],
            "recorded verbatim; the analysis reads it as no declaration"
        );

        let absent = scan_memory(&[]).expect("must parse");
        assert!(!absent.asserts_memory());
        assert!(absent
            .resolve()
            .expect("no declaration is valid")
            .is_empty());
    }

    /// A named format is a claim, and only names the analysis parses may be
    /// made. Accepting an unparsable one would give a scan that succeeded with
    /// the whole memory tier silently absent.
    #[test]
    fn a_named_memory_format_is_checked_against_what_the_analysis_parses() {
        let good = scan_memory(&["--memory-image-format", "lime"]).expect("must parse");
        assert!(good.asserts_memory());
        assert_eq!(
            good.resolve().expect("lime is a name the analysis parses"),
            vec![(
                "memory_image_format",
                serde_json::Value::String("lime".to_string())
            )]
        );

        let bad = scan_memory(&["--memory-image-format", "not-a-format"]).expect("must parse");
        let err = bad
            .resolve()
            .expect_err("an unparsable name must end the run, not be dropped")
            .to_string();
        assert!(
            err.contains("not-a-format"),
            "the error must name the rejected format: {err}"
        );
    }

    /// The two ways of declaring contradict each other when combined, and the
    /// analysis resolves that by reading the name and ignoring the flag -- so
    /// the operator's "this is not memory" would vanish without a word.
    #[test]
    fn a_contradictory_memory_declaration_ends_the_run() {
        let contradictory = scan_memory(&["--memory-image=false", "--memory-image-format", "lime"])
            .expect("must parse");
        assert!(contradictory.resolve().is_err());
    }

    /// A memory declaration on a source whose own bytes identify it as
    /// something else cannot be honoured: the memory module never receives that
    /// artifact type, so the declaration would be persisted and never read.
    #[test]
    fn a_declaration_is_refused_on_a_source_that_is_not_raw_evidence() {
        let dir = std::env::temp_dir().join(format!("seance-scan-classify-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");

        // A ZIP: its magic is unambiguous, and it resolves to Container.
        let zip = dir.join("evidence.zip");
        std::fs::write(&zip, b"PK\x03\x04").expect("write zip");
        let declared = MemoryDeclaration {
            memory_image: Some(true),
            memory_image_format: None,
        };
        let err = classify_scan_source(&zip, &declared)
            .expect_err("a declared ZIP must be refused, not silently ignored")
            .to_string();
        assert!(
            err.contains("Container"),
            "the refusal must say what the source actually is: {err}"
        );

        // The same file without a declaration is an ordinary container ingest.
        let (art_type, subtype) = classify_scan_source(&zip, &MemoryDeclaration::default())
            .expect("an undeclared ZIP is fine")
            .expect("a file, not a directory");
        assert_eq!(art_type, ArtifactType::Container);
        assert_eq!(subtype, Some("zip"));

        // A headerless capture matches no magic and no known extension, so it
        // resolves to RawEvidence -- the type the memory module receives -- and
        // the declaration is honoured.
        let raw = dir.join("capture.mem");
        std::fs::write(&raw, vec![0u8; 1024]).expect("write capture");
        let (art_type, subtype) = classify_scan_source(&raw, &declared)
            .expect("a declared headerless capture must be accepted")
            .expect("a file, not a directory");
        assert_eq!(
            art_type,
            ArtifactType::RawEvidence,
            "a declared capture must reach the memory module"
        );
        assert_eq!(subtype, None, "no format claim was made");

        // A directory carries no capture, and saying so beats writing a
        // declaration onto an artifact with no bytes behind it.
        assert!(classify_scan_source(&dir, &declared).is_err());
        assert!(
            classify_scan_source(&dir, &MemoryDeclaration::default())
                .expect("an undeclared directory is fine")
                .is_none(),
            "a directory has no single data source"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    /// A format Séance recognises but has no registered reader for must end the
    /// run with a message, not produce an artifact nothing will ever open. The
    /// API refused these already; the scan path did not, so `seance scan` on a
    /// RAR "succeeded" and examined nothing.
    #[test]
    fn a_recognised_but_unreadable_format_ends_the_scan() {
        let dir = std::env::temp_dir().join(format!("seance-scan-rar-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let rar = dir.join("evidence.rar");
        std::fs::write(&rar, b"Rar!\x1a\x07\x00").expect("write rar");

        let err = classify_scan_source(&rar, &MemoryDeclaration::default())
            .expect_err("RAR has no extractor anywhere in the tree")
            .to_string();
        assert!(
            err.to_lowercase().contains("rar"),
            "the refusal must name the format: {err}"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    /// The scan path once carried its own copy of the type table, and the copy
    /// had drifted: it knew nothing of the virtual-disk formats and had no
    /// extension fallback, so a VHD/VHDX/VMDK/QCOW2 became untyped RawEvidence
    /// and the readers -- which subscribe to Container -- never ran on it.
    #[test]
    fn virtual_disks_are_classified_for_the_readers_that_subscribe_to_them() {
        let dir = std::env::temp_dir().join(format!("seance-scan-vdisk-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");

        // By magic (QCOW2) and by name (a fixed-size VHD, whose only signature
        // is a footer the 512-byte header probe never sees).
        let cases: &[(&str, Vec<u8>, &str)] = &[
            ("disk.qcow2", vec![0x51, 0x46, 0x49, 0xFB], "qcow2"),
            ("fixed.vhd", vec![0u8; 1024], "vhd"),
            ("disk.vmdk", b"# Disk DescriptorFile\n".to_vec(), "vmdk"),
        ];
        for (name, bytes, expect) in cases {
            let file = dir.join(name);
            std::fs::write(&file, bytes).expect("write image");
            let (art_type, subtype) = classify_scan_source(&file, &MemoryDeclaration::default())
                .expect("classification must succeed")
                .expect("a file, not a directory");
            assert_eq!(
                art_type,
                ArtifactType::Container,
                "{name} must reach the virtual-disk readers"
            );
            assert_eq!(subtype, Some(*expect), "{name} subtype");
        }

        std::fs::remove_dir_all(&dir).ok();
    }
}
