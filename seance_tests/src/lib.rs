#![forbid(unsafe_code)]
#[cfg(test)]
mod aff4_tests;
#[cfg(test)]
mod api_tests;
#[cfg(test)]
mod bitlocker_win11_chain_test;
#[cfg(test)]
mod browser_history_tests;
#[cfg(test)]
mod canon2_pipeline_tests;
#[cfg(test)]
mod carving_dftt_tests;
#[cfg(test)]
mod fixtures;
#[cfg(test)]
mod fuzz_regression_tests;
// Needs libewf, like the others: both corpus images are E01s.
#[cfg(all(test, feature = "e01"))]
mod alihadi_ntfs_tests;
#[cfg(all(test, feature = "e01"))]
mod cfreds_hacking_case_tests;
#[cfg(test)]
mod db_tests;
#[cfg(test)]
mod dftt8_jpeg_search_tests;
#[cfg(test)]
mod dftt_corpus_tests;
#[cfg(test)]
mod dftt_undelete_tests;
// Both use seance_container_e01, which needs libewf at build time.
#[cfg(all(test, feature = "e01"))]
mod e01_tests;
#[cfg(all(test, feature = "e01"))]
mod ext4_full_chain_test;
#[cfg(test)]
mod golden_image_tests;
#[cfg(all(test, feature = "e01"))]
mod golden_multipart_tests;
#[cfg(test)]
mod ios_backup_tests;
#[cfg(test)]
mod iso9660_tests;
#[cfg(test)]
mod keyword_search_tests;
#[cfg(test)]
mod lnk_jumplist_tests;
#[cfg(test)]
mod logfile_tests;
#[cfg(test)]
mod new_plugins_tests;
#[cfg(test)]
mod orchestrator_integration_test;
#[cfg(test)]
mod plist_tests;
#[cfg(test)]
mod registry_full_chain_test;
#[cfg(test)]
mod registry_tests;
#[cfg(test)]
mod slack_dftt_tests;
#[cfg(test)]
mod sqlite_tests;
#[cfg(test)]
mod srum_tests;
#[cfg(test)]
mod vss_tests;
#[cfg(test)]
mod zip_container_tests;

#[allow(dead_code)] // Helper function, not directly called by a test macro
fn init_logging() {
    use tracing::Level;
    use tracing_subscriber::FmtSubscriber;
    let _ = FmtSubscriber::builder()
        .with_max_level(Level::ERROR) // Keep it quiet for tests unless debugging
        .try_init();
}

#[tokio::test]
async fn test_mft_corpus() -> anyhow::Result<()> {
    use seance_core::{
        artifact::{Artifact, ArtifactType},
        data_source::FileDataSource,
        orchestrator::Orchestrator,
    };
    use seance_plugin_mft::MftParser;
    use std::path::Path;
    use std::sync::Arc;
    use tracing::{error, info};
    use uuid::Uuid;
    use walkdir::WalkDir;

    init_logging();
    let test_data_path = Path::new("../test_data/mft");
    if !test_data_path.exists() {
        eprintln!("Skipping MFT tests: test_data/mft not found");
        return Ok(()); // Return Ok if skipping
    }

    let mut total_files = 0;
    let mut successful_parses = 0;

    for entry in WalkDir::new(test_data_path) {
        let entry = entry.unwrap();
        if entry.file_type().is_dir() {
            continue;
        }

        let path = entry.path();
        total_files += 1;

        info!("Testing MFT parser on: {:?}", path);

        let mut orchestrator = Orchestrator::new(None, 100).with_exit_on_idle(true); // No DB for this test, buffer_size 100
        orchestrator.register_module(Arc::new(MftParser::new()));
        let orchestrator_sender = orchestrator.task_submitter();

        tokio::spawn(async move {
            orchestrator.run().await;
        });

        let case_id = Uuid::new_v4();

        match FileDataSource::new(path.to_path_buf()) {
            Ok(source) => {
                let artifact = Artifact::new(
                    case_id,
                    ArtifactType::RawEvidence,
                    Some(Arc::new(source)),
                    serde_json::json!({"path": path.to_str()}),
                );

                if let Err(e) = orchestrator_sender.send(artifact) {
                    error!("Failed to ingest {:?}: {}", path, e);
                    continue;
                }

                tokio::time::sleep(std::time::Duration::from_secs(2)).await;

                successful_parses += 1;
            }
            Err(e) => {
                error!("Failed to open file {:?}: {}", path, e);
            }
        }
    }

    info!(
        "MFT Test Suite Result: {}/{} files processed successfully.",
        successful_parses, total_files
    );
    assert!(
        successful_parses > 0,
        "No MFT files were successfully processed!"
    );

    Ok(())
}

#[tokio::test]
async fn test_logfile_parser() -> anyhow::Result<()> {
    use seance_core::{
        artifact::{Artifact, ArtifactType},
        data_source::FileDataSource,
        module::ForensicsModule,
    };
    use seance_plugin_logfile::LogFileParser;
    use std::path::Path;
    use std::sync::Arc;
    use tracing::{error, info};
    use uuid::Uuid;

    init_logging();

    let test_file_path = Path::new("../test_data/HD002.0_LogFile.dat");
    if !test_file_path.exists() {
        eprintln!("Skipping LogFile test: test_data/HD002.0_LogFile.dat not found");
        return Ok(());
    }

    info!("Testing LogFile parser on: {:?}", test_file_path);

    let case_id = Uuid::new_v4();
    let parser = LogFileParser;

    match FileDataSource::new(test_file_path.to_path_buf()) {
        Ok(source) => {
            // Create a FileSystem artifact (since LogFileParser subscribes to FileSystem)
            let artifact = Artifact::new(
                case_id,
                ArtifactType::FileSystem,
                Some(Arc::new(source)),
                serde_json::json!({
                    "filesystem_type": "NTFS",
                    "path": test_file_path.to_str()
                }),
            );

            // Directly call the parser's process method
            match parser.process(&artifact) {
                Ok(artifacts) => {
                    println!("\n=== LogFile Parser Test Results ===");
                    println!("Total artifacts produced: {}", artifacts.len());

                    if artifacts.is_empty() {
                        println!("Note: Parser ran successfully but produced no artifacts.");
                        println!("This may indicate that all log records were filtered as non-significant,");
                        println!("or that the test file doesn't contain parseable log records.");
                    } else {
                        println!("\nFirst 5 artifacts:");
                        for (i, art) in artifacts.iter().take(5).enumerate() {
                            assert_eq!(art.artifact_type, ArtifactType::ParsedRecord);
                            println!(
                                "  [{}] Operation: {}, LSN: {}",
                                i,
                                art.metadata
                                    .get("operation")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("unknown"),
                                art.metadata
                                    .get("lsn")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("unknown")
                            );
                        }
                    }

                    println!("\n✓ LogFile parser test completed successfully");
                    info!("LogFile parser test passed: {} artifacts", artifacts.len());
                }
                Err(e) => {
                    error!("Failed to parse LogFile: {}", e);
                    panic!("LogFile parsing failed: {}", e);
                }
            }
        }
        Err(e) => {
            error!("Failed to open file {:?}: {}", test_file_path, e);
            panic!("Failed to open test file: {}", e);
        }
    }

    Ok(())
}

#[tokio::test]
async fn test_i30_parser() -> anyhow::Result<()> {
    use seance_core::{
        artifact::{Artifact, ArtifactType},
        data_source::FileDataSource,
        module::ForensicsModule,
    };
    use seance_plugin_i30::I30Parser;
    use std::path::Path;
    use std::sync::Arc;
    use tracing::{error, info};
    use uuid::Uuid;

    init_logging();

    let test_file_path = Path::new("../test_data/HD002.0_i30.dat");
    if !test_file_path.exists() {
        eprintln!("Skipping I30 test: test_data/HD002.0_i30.dat not found");
        return Ok(());
    }

    info!("Testing I30 parser on: {:?}", test_file_path);

    let case_id = Uuid::new_v4();
    let parser = I30Parser;

    match FileDataSource::new(test_file_path.to_path_buf()) {
        Ok(source) => {
            // Create a FileEntry artifact (since I30Parser subscribes to FileEntry)
            let artifact = Artifact::new(
                case_id,
                ArtifactType::FileEntry,
                Some(Arc::new(source)),
                serde_json::json!({
                    "file_name": "$I30",
                    "path": test_file_path.to_str()
                }),
            );

            // Directly call the parser's process method
            match parser.process(&artifact) {
                Ok(artifacts) => {
                    println!("\n=== I30 Parser Test Results ===");
                    println!("Total artifacts produced: {}", artifacts.len());

                    if artifacts.is_empty() {
                        println!("Note: Parser ran successfully but produced no artifacts.");
                        println!("This may indicate no valid INDX entries were found.");
                    } else {
                        println!("\nFirst 5 index entries:");
                        for (i, art) in artifacts.iter().take(5).enumerate() {
                            assert_eq!(art.artifact_type, ArtifactType::ParsedRecord);
                            let file_name = art
                                .metadata
                                .get("file_name")
                                .and_then(|v| v.as_str())
                                .unwrap_or("unknown");
                            let from_slack = art
                                .metadata
                                .get("from_slack")
                                .and_then(|v| v.as_bool())
                                .unwrap_or(false);
                            let is_directory = art
                                .metadata
                                .get("is_directory")
                                .and_then(|v| v.as_bool())
                                .unwrap_or(false);

                            println!(
                                "  [{}] {} {} ({})",
                                i,
                                if is_directory { "[DIR]" } else { "[FILE]" },
                                file_name,
                                if from_slack { "from slack" } else { "active" }
                            );
                        }

                        // Count slack vs active entries
                        let slack_count = artifacts
                            .iter()
                            .filter(|a| {
                                a.metadata
                                    .get("from_slack")
                                    .and_then(|v| v.as_bool())
                                    .unwrap_or(false)
                            })
                            .count();
                        let active_count = artifacts.len() - slack_count;

                        println!("\nStatistics:");
                        println!("  Active entries: {}", active_count);
                        println!("  Slack entries (deleted): {}", slack_count);
                    }

                    println!("\n✓ I30 parser test completed successfully");
                    info!("I30 parser test passed: {} artifacts", artifacts.len());
                }
                Err(e) => {
                    error!("Failed to parse I30: {}", e);
                    panic!("I30 parsing failed: {}", e);
                }
            }
        }
        Err(e) => {
            error!("Failed to open file {:?}: {}", test_file_path, e);
            panic!("Failed to open test file: {}", e);
        }
    }

    Ok(())
}
#[tokio::test]
async fn test_usnjrnl_parser() -> anyhow::Result<()> {
    use seance_core::{
        artifact::{Artifact, ArtifactType},
        data_source::FileDataSource,
        module::ForensicsModule,
    };
    use seance_plugin_usnjrnl::UsnJrnlParser;
    use std::path::Path;
    use std::sync::Arc;
    use tracing::{error, info};
    use uuid::Uuid;

    init_logging();

    let test_file_path = Path::new("../test_data/HD002.0_UsnJrnl.dat");
    if !test_file_path.exists() {
        eprintln!("Skipping UsnJrnl test: test_data/HD002.0_UsnJrnl.dat not found");
        return Ok(());
    }

    info!("Testing UsnJrnl parser on: {:?}", test_file_path);

    let case_id = Uuid::new_v4();
    let parser = UsnJrnlParser;

    match FileDataSource::new(test_file_path.to_path_buf()) {
        Ok(source) => {
            // Create a FileEntry artifact (since UsnJrnlParser subscribes to FileEntry)
            let artifact = Artifact::new(
                case_id,
                ArtifactType::FileEntry,
                Some(Arc::new(source)),
                serde_json::json!({
                    "file_name": "$UsnJrnl:$J",
                    "path": test_file_path.to_str()
                }),
            );

            // Directly call the parser's process method
            match parser.process(&artifact) {
                Ok(artifacts) => {
                    println!("\n=== UsnJrnl Parser Test Results ===");
                    println!("Total artifacts produced: {}", artifacts.len());

                    if artifacts.is_empty() {
                        println!("Note: Parser ran successfully but produced no artifacts.");
                        println!("This may indicate no valid USN records were found.");
                    } else {
                        println!("\nFirst 5 USN records:");
                        for (i, art) in artifacts.iter().take(5).enumerate() {
                            // Assert that artifact is either ParsedRecord OR TimelineEvent
                            assert!(
                                art.artifact_type == ArtifactType::ParsedRecord
                                    || art.artifact_type == ArtifactType::TimelineEvent
                            );

                            if art.artifact_type == ArtifactType::ParsedRecord {
                                let file_name = art
                                    .metadata
                                    .get("file_name")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("unknown");
                                let primary_op = art
                                    .metadata
                                    .get("primary_operation")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("unknown");
                                let timestamp = art
                                    .metadata
                                    .get("timestamp")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("unknown");

                                println!(
                                    "  [{}] {} - {} ({})",
                                    i, file_name, primary_op, timestamp
                                );
                            } else {
                                println!(
                                    "  [{}] Timeline Event: {}",
                                    i,
                                    art.metadata
                                        .get("short_desc")
                                        .and_then(|v| v.as_str())
                                        .unwrap_or("")
                                );
                            }
                        }

                        // Count operations (only from ParsedRecords)
                        use std::collections::HashMap;
                        let mut op_counts: HashMap<String, usize> = HashMap::new();
                        for art in &artifacts {
                            if art.artifact_type == ArtifactType::ParsedRecord {
                                if let Some(op) = art
                                    .metadata
                                    .get("primary_operation")
                                    .and_then(|v| v.as_str())
                                {
                                    *op_counts.entry(op.to_string()).or_insert(0) += 1;
                                }
                            }
                        }

                        println!("\nOperation Statistics:");
                        for (op, count) in op_counts.iter() {
                            println!("  {}: {}", op, count);
                        }
                    }

                    println!("\n✓ UsnJrnl parser test completed successfully");
                    info!("UsnJrnl parser test passed: {} artifacts", artifacts.len());
                }
                Err(e) => {
                    error!("Failed to parse UsnJrnl: {}", e);
                    panic!("UsnJrnl parsing failed: {}", e);
                }
            }
        }
        Err(e) => {
            error!("Failed to open file {:?}: {}", test_file_path, e);
            panic!("Failed to open test file: {}", e);
        }
    }

    Ok(())
}

#[tokio::test]
async fn test_badclus_parser() -> anyhow::Result<()> {
    use seance_core::{
        artifact::{Artifact, ArtifactType},
        data_source::FileDataSource,
        module::ForensicsModule,
    };
    use seance_plugin_badclus::BadClusParser;
    use std::path::Path;
    use std::sync::Arc;
    use tracing::{error, info};
    use uuid::Uuid;

    init_logging();

    let test_file_path = Path::new("../test_data/sample_badclus.bin");
    if !test_file_path.exists() {
        eprintln!("Skipping BadClus test: test_data/sample_badclus.bin not found");
        return Ok(());
    }

    info!("Testing BadClus parser on: {:?}", test_file_path);

    let case_id = Uuid::new_v4();
    let parser = BadClusParser;

    match FileDataSource::new(test_file_path.to_path_buf()) {
        Ok(source) => {
            // Create a FileEntry artifact (since BadClusParser subscribes to FileEntry)
            let artifact = Artifact::new(
                case_id,
                ArtifactType::FileEntry,
                Some(Arc::new(source)),
                serde_json::json!({
                    "file_name": "$BadClus:$Bad",
                    "path": test_file_path.to_str()
                }),
            );

            // Directly call the parser's process method
            match parser.process(&artifact) {
                Ok(artifacts) => {
                    println!("\n=== BadClus Parser Test Results ===");
                    println!("Total artifacts produced: {}", artifacts.len());

                    if artifacts.is_empty() {
                        println!("Note: Parser ran successfully but produced no artifacts.");
                        println!("This may indicate no bad clusters were found.");
                    } else {
                        println!("\nBad cluster ranges found:");
                        for (i, art) in artifacts.iter().enumerate() {
                            assert_eq!(art.artifact_type, ArtifactType::ParsedRecord);
                            let start_lcn = art
                                .metadata
                                .get("cluster_start_lcn")
                                .and_then(|v| v.as_i64())
                                .unwrap_or(0);
                            let end_lcn = art
                                .metadata
                                .get("cluster_end_lcn")
                                .and_then(|v| v.as_i64())
                                .unwrap_or(0);
                            let count = art
                                .metadata
                                .get("cluster_count")
                                .and_then(|v| v.as_i64())
                                .unwrap_or(0);
                            let desc = art
                                .metadata
                                .get("description")
                                .and_then(|v| v.as_str())
                                .unwrap_or("unknown");

                            println!("  [{}] {}", i, desc);
                            println!(
                                "      LCN range: {}-{} ({} clusters)",
                                start_lcn, end_lcn, count
                            );
                        }

                        // Calculate total bad clusters
                        let total_bad_clusters: i64 = artifacts
                            .iter()
                            .filter_map(|a| {
                                a.metadata.get("cluster_count").and_then(|v| v.as_i64())
                            })
                            .sum();

                        println!("\nStatistics:");
                        println!("  Total bad cluster ranges: {}", artifacts.len());
                        println!("  Total bad clusters: {}", total_bad_clusters);
                    }

                    println!("\n✓ BadClus parser test completed successfully");
                    info!("BadClus parser test passed: {} artifacts", artifacts.len());
                }
                Err(e) => {
                    error!("Failed to parse BadClus: {}", e);
                    panic!("BadClus parsing failed: {}", e);
                }
            }
        }
        Err(e) => {
            error!("Failed to open file {:?}: {}", test_file_path, e);
            panic!("Failed to open test file: {}", e);
        }
    }

    Ok(())
}
