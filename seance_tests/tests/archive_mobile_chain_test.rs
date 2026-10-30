//! End-to-end: a mobile chat database inside a ZIP/UFDR is extracted with a
//! working data source and then parsed by the messaging plugin. This proves the
//! container-to-parser chain that mobile-image ingestion depends on.

use seance_container_zip::ZipContainerModule;
use seance_core::{
    artifact::{Artifact, ArtifactType},
    data_source::DataSource,
    module::ForensicsModule,
};
use seance_plugin_viber::ViberParser;
use serde_json::json;
use std::io::{Cursor, Write};
use std::sync::Arc;
use uuid::Uuid;

use seance_core::data_source::ByteSliceDataSource;

/// Real Viber `messages` SQLite database bytes.
fn viber_db_bytes() -> Vec<u8> {
    let path = std::env::temp_dir().join(format!("it_viber_{}.db", Uuid::new_v4()));
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch(
            "CREATE TABLE messages (_id INTEGER PRIMARY KEY, conversation_id INTEGER, body TEXT, date INTEGER, send_type INTEGER);
             INSERT INTO messages VALUES (1, 5, 'archived message', 1672848000000, 0);
             INSERT INTO messages VALUES (2, 5, 'sent from archive', 1672848060000, 1);",
        )
        .unwrap();
    }
    let data = std::fs::read(&path).unwrap();
    let _ = std::fs::remove_file(&path);
    data
}

fn build_zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut buf = Cursor::new(Vec::new());
    {
        let mut zw = zip::ZipWriter::new(&mut buf);
        let opts: zip::write::SimpleFileOptions = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        for (name, body) in entries {
            zw.start_file(*name, opts).unwrap();
            zw.write_all(body).unwrap();
        }
        zw.finish().unwrap();
    }
    buf.into_inner()
}

#[test]
fn viber_db_inside_ufdr_is_extracted_and_parsed() {
    // A Cellebrite-style UFDR (a ZIP) carrying a Viber DB at its Android path.
    let zip = build_zip(&[(
        "data/data/com.viber.voip/databases/viber_messages",
        &viber_db_bytes(),
    )]);
    let src: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(zip));
    let container = Artifact::new(
        Uuid::new_v4(),
        ArtifactType::Container,
        Some(src),
        json!({ "name": "phone.ufdr" }),
    );

    // 1) The container extracts the entry with a working, lazy data source.
    let children = ZipContainerModule.process(&container).unwrap();
    let viber_child = children
        .iter()
        .find(|a| a.metadata.get("name").and_then(|v| v.as_str()) == Some("viber_messages"))
        .expect("viber_messages extracted from the UFDR");
    assert!(
        viber_child.data.is_some(),
        "extracted child must carry a data source"
    );

    // 2) The messaging parser reads the extracted child and recovers messages —
    //    the same path the orchestrator drives when it re-queues the child.
    //    Beside the messages it owes one schema-support disclosure per store
    //    (the parser declares no validated schema range, and says so), so the
    //    output is partitioned by subtype rather than counted whole.
    let records = ViberParser.process(viber_child).unwrap();
    let (msgs, others): (Vec<_>, Vec<_>) = records
        .iter()
        .partition(|a| a.metadata.get("subtype").and_then(|v| v.as_str()) == Some("chat_message"));
    assert_eq!(
        msgs.len(),
        2,
        "both Viber messages recovered from inside the UFDR"
    );
    assert!(msgs
        .iter()
        .any(|m| m.metadata.get("text").and_then(|v| v.as_str()) == Some("archived message")));
    assert!(msgs
        .iter()
        .any(|m| m.metadata.get("direction").and_then(|v| v.as_str()) == Some("sent")));

    // 3) The only non-message record is the schema-support disclosure: this
    //    parser has no validated range, the store records no version, every
    //    column resolved, and it counts the two messages without itself.
    assert_eq!(
        others.len(),
        1,
        "exactly one non-message record, the schema-support disclosure: {others:?}"
    );
    let support = others[0];
    assert_eq!(support.metadata["type"], json!("ViberIncomplete"));
    assert_eq!(support.metadata["subtype"], json!("parser_stale"));
    assert_eq!(
        support.metadata["warning_class"],
        json!("ParserStaleWarning")
    );
    assert_eq!(support.metadata["status"], json!("SchemaNotRanged"));
    assert_eq!(support.metadata["records_recovered"], json!(2));
    assert_eq!(
        support.metadata["schema_version_recorded"],
        json!(false),
        "a store built here never sets PRAGMA user_version"
    );
    // Every logical field resolved, so nothing is claimed incomplete and no
    // range is asserted that was never validated.
    assert!(support.metadata.get("content_incomplete").is_none());
    assert!(support.metadata.get("schema_unresolved_fields").is_none());
    assert!(support.metadata.get("schema_version_supported").is_none());
}
