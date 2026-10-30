//! Isolated E01 read server.
//!
//! Opens the E01 image given as the first argument with libewf and serves random
//! reads over stdio for a parent [`seance_container_e01::IsolatedE01DataSource`].
//! Running libewf here means a crash on a malformed/adversarial image kills only
//! this child, not the caller. See `seance_container_e01::isolated` for the
//! protocol. Logging must go to stderr only; stdout carries the binary protocol.

//!
//! `seance-ewf-helper --logical <l01-path>` instead walks a logical evidence
//! file's entry tree, sends it, and serves reads of individual entries
//! (HUNT-144).

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [flag, path] if flag == "--logical" => seance_container_e01::run_logical_helper(path),
        [path] => seance_container_e01::run_helper(path),
        _ => {
            eprintln!("usage: seance-ewf-helper [--logical] <ewf-path>");
            std::process::exit(2);
        }
    }
}
