//! Regenerate `documentation/METHOD_STATEMENTS.md` from the module set the
//! product actually builds.
//!
//! ```sh
//! cargo run -p seance_api --bin method-statements > documentation/METHOD_STATEMENTS.md
//! ```
//!
//! `ROADMAP` §5.2. The register is generated rather than written because its
//! headline counts how many of the product's modules have a method statement,
//! and a hand-edited count is a claim about the file rather than about the
//! product. A test in `seance_api::modules` fails when the committed file and
//! this output disagree.

use std::sync::Arc;

use seance_api::method_statements::render_register;
use seance_api::modules::{build_module_set, registrable_module_ids, ModuleSetOptions};
use seance_core::module::ForensicsModule;
use seance_core::orchestrator::Orchestrator;

fn main() -> anyhow::Result<()> {
    // A real module set on a real orchestrator, for the same reason the test
    // uses one: a module that is written, compiled and never registered must
    // not appear in this register.
    let index = tempfile::tempdir()?;
    let search_service = Arc::new(seance_search::SearchService::new(index.path())?);
    let orchestrator = Orchestrator::new(None, 8);
    let modules: Vec<Arc<dyn ForensicsModule>> =
        build_module_set(&orchestrator, ModuleSetOptions::new(search_service))?;
    // The built set plus the modules an examiner's configuration adds: the
    // YARA scanner and the memory pattern scan are part of the product and the
    // register has to be able to describe them. See `OPT_IN_MODULE_IDS`.
    let ids = registrable_module_ids(
        &modules
            .iter()
            .map(|m| m.id().to_string())
            .collect::<Vec<String>>(),
    );
    print!("{}", render_register(&ids));
    Ok(())
}
