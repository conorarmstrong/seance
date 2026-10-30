use anyhow::{Context, Result};
use std::sync::Arc;
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

use seance_core::{db::DatabaseConnection, orchestrator::Orchestrator};
use seance_db::SqliteConnection;

use seance_api::modules::{register_all_modules, ModuleSetOptions};
use seance_api::{router_with_auth, AppState, AuthConfig, EvidenceRootPolicy, ProcessingCensus};

#[tokio::main]
async fn main() -> Result<()> {
    // Setup tracing
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber)
        .context("Failed to set tracing subscriber")?;

    info!("Seance API Server starting...");

    // Database connection
    let db_url =
        std::env::var("DATABASE_URL").unwrap_or_else(|_| "sqlite:seance.sqlite".to_string());
    let db_conn = Arc::new(SqliteConnection::new(&db_url).await?);
    db_conn.initialize().await?;

    // Seed predefined filters
    if let Err(e) = db_conn.seed_predefined_filters().await {
        tracing::warn!("Failed to seed predefined filters: {}", e);
    }

    // Initialize Search Service
    let search_index_path = std::path::PathBuf::from("search_index");
    let search_service = Arc::new(seance_search::SearchService::new(&search_index_path)?);
    info!("Search service initialized at {:?}", search_index_path);

    // Orchestrator setup
    let orchestrator_db_clone = db_conn.clone();

    // Create orchestrator instance BEFORE spawning
    let mut orchestrator = Orchestrator::new(Some(orchestrator_db_clone), 100) // Pass buffer size
        .with_exit_on_idle(false);

    // Register modules with orchestrator BEFORE spawning.
    //
    // This is the SAME function `seance_cli` calls, and it is the only place in
    // the workspace that registers the module set. This binary used to carry a
    // second, hand-written list of its own, and that list had lost the whole
    // memory tier, seven filesystem readers, both decryptors and every
    // messaging parser -- silently, because a missing module produces no error,
    // just an ingest that examined less than the examiner believes (LIVE-005).
    let mut options = ModuleSetOptions::new(search_service.clone());
    // No process-level unlock secrets: a long-running server takes none from
    // the environment or a config file. An encrypted volume or backup ingested
    // here takes the honest "present but not extracted" path at ingest, and the
    // examiner then supplies the secret for that one artifact through
    // `POST /cases/{id}/artifacts/{id}/credential` (HUNT-120, SEC-204) — held
    // zeroed in memory for that one run and audited by kind and outcome, never
    // by value. `run_module` no longer takes secrets.
    options.yara_rules = ModuleSetOptions::yara_rules_from_env();
    options.memory_regex = ModuleSetOptions::memory_regex_from_env();
    options.memory_strings = ModuleSetOptions::memory_strings_from_env();
    register_all_modules(&mut orchestrator, options)?;

    // Collect module registry before spawning the orchestrator
    let module_registry = orchestrator.module_info_list();

    // Get the sender from the orchestrator
    let orchestrator_sender = orchestrator.task_submitter();
    let ad_hoc_sender = orchestrator.ad_hoc_submitter();
    let event_sender = orchestrator.event_sender();
    let status_sender = orchestrator.status_sender();
    let active_tasks = orchestrator.active_tasks();
    let case_census = orchestrator.case_census();
    let ingestion_service = orchestrator.ingestion_service();
    let cancellation = orchestrator.cancellation_handle();

    // Clone search_service for shutdown commit
    let search_service_for_shutdown = search_service.clone();

    // Spawn the orchestrator to run in the background
    tokio::spawn(async move {
        orchestrator.run().await;
    });

    // Report signing: load an X.509 cert+key from the environment so the running
    // server can produce tamper-evident reports. When unset, reports are served
    // UNSIGNED and stamped as such by the report layer.
    let signing_config = match (
        std::env::var("SEANCE_SIGNING_CERT"),
        std::env::var("SEANCE_SIGNING_KEY"),
    ) {
        (Ok(cert), Ok(key)) => {
            let cfg = seance_reporting::SigningConfig::from_files(
                std::path::Path::new(&cert),
                std::path::Path::new(&key),
                std::env::var("SEANCE_SIGNING_NAME").ok(),
                Some("Séance forensic case report".to_string()),
            )
            .context("Failed to load report signing cert/key from SEANCE_SIGNING_CERT/KEY")?;
            info!("Report signing enabled (SEANCE_SIGNING_CERT/KEY).");
            Some(cfg)
        }
        _ => {
            tracing::warn!(
                "Report signing not configured (SEANCE_SIGNING_CERT/KEY unset). Reports will be \
                 UNSIGNED and marked as not tamper-evident."
            );
            None
        }
    };

    // Auth + bind. Refuse to run with authentication disabled on a non-loopback
    // bind -- that would expose every endpoint to the network with no login.
    let auth_config = AuthConfig::from_env();

    let bind_addr = std::env::var("SEANCE_BIND").unwrap_or_else(|_| "0.0.0.0:8080".to_string());
    let host = bind_addr
        .rsplit_once(':')
        .map(|(h, _)| h)
        .unwrap_or(&bind_addr);
    let bind_is_loopback =
        host == "127.0.0.1" || host == "localhost" || host == "::1" || host == "[::1]";

    // Seed the initial admin on first run so every audited action is
    // attributable to a real user. No-op once any user exists. The default
    // 'seance' password is only used on a loopback bind and must be rotated on
    // first login.
    seance_api::bootstrap_admin(&db_conn, &auth_config, bind_is_loopback)
        .await
        .context("Failed to bootstrap initial admin user")?;

    if !auth_config.enabled {
        if !bind_is_loopback {
            anyhow::bail!(
                "Refusing to start: authentication is disabled (SEANCE_AUTH_ENABLED=false) but the \
                 server is bound to a non-loopback address ({bind_addr}). Either enable auth or bind \
                 to 127.0.0.1 via SEANCE_BIND."
            );
        }
        tracing::warn!("Authentication is DISABLED; serving on loopback {bind_addr} only.");
    }

    // Audit keying. The audit log is the chain of custody, and unkeyed it is a
    // plain SHA-256 chain that anyone with database write access can rewrite and
    // recompute -- it still verifies. That is not a default a network-exposed
    // deployment should reach by leaving a variable out, so it is refused the
    // same way an auth-off bind is (DEPLOY-001). The key is deliberately not
    // generated and persisted beside the database: a key stored where the
    // attacker already is would report `tamper_evident: true` for a property
    // the chain does not have. Loopback keeps the warning seance_db already
    // logs, and SEANCE_AUDIT_UNKEYED_OK=true is the explicit, logged opt-out.
    if !db_conn.audit_chain_keyed() && !bind_is_loopback {
        let opted_out = std::env::var("SEANCE_AUDIT_UNKEYED_OK")
            .map(|v| v.eq_ignore_ascii_case("true") || v == "1")
            .unwrap_or(false);
        if !opted_out {
            anyhow::bail!(
                "Refusing to start: SEANCE_AUDIT_HMAC_KEY is not set, so the audit chain is \
                 UNKEYED and can be rewritten by anyone with database access, but the server is \
                 bound to a non-loopback address ({bind_addr}). Set SEANCE_AUDIT_HMAC_KEY to a \
                 stable secret (e.g. `openssl rand -hex 32`), bind to 127.0.0.1 via SEANCE_BIND, \
                 or set SEANCE_AUDIT_UNKEYED_OK=true to accept an audit log that is not \
                 tamper-evident."
            );
        }
        tracing::warn!(
            "SEANCE_AUDIT_UNKEYED_OK is set: serving on {bind_addr} with an UNKEYED audit chain. \
             Every audit row written from now on can be rewritten by anyone with database \
             access and will still verify; reports and the verify endpoint will say so."
        );
    }

    let app_state = AppState {
        db: db_conn.clone(),
        orchestrator_sender,
        ad_hoc_sender,
        event_sender,
        status_sender,
        active_tasks,
        search_service: Some(search_service),
        ingestion_service,
        module_registry,
        signing_config,
        evidence_roots: EvidenceRootPolicy::from_env(),
        cancellation,
    };

    // The per-case breakdown `GET /api/v1/status` serves beside the
    // process-wide count.
    let app = router_with_auth(app_state, Some(auth_config))
        .layer(axum::Extension(ProcessingCensus(case_census)));

    let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
    info!("Listening on {}", listener.local_addr()?);
    axum::serve(listener, app).await?;

    // Final commit on shutdown to ensure all indexed documents are visible
    if let Err(e) = search_service_for_shutdown.commit().await {
        tracing::error!("Failed to commit search index on shutdown: {}", e);
    }

    Ok(())
}
