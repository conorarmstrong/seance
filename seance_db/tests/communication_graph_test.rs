use anyhow::Result;
use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::db::DatabaseConnection;
use seance_db::SqliteConnection;
use uuid::Uuid;

async fn setup() -> Result<(SqliteConnection, Uuid)> {
    let db = SqliteConnection::new("sqlite::memory:").await?;
    db.initialize().await?;
    let case_id = db.create_case("Comm", "Examiner").await?;
    Ok((db, case_id))
}

async fn record(db: &SqliteConnection, case_id: Uuid, metadata: serde_json::Value) -> Result<()> {
    db.record_artifact(&Artifact {
        id: Uuid::new_v4(),
        case_id,
        parent_id: None,
        artifact_type: ArtifactType::ParsedRecord,
        metadata,
        data: None,
    })
    .await
}

#[tokio::test]
async fn builds_messaging_star_and_email_network() -> Result<()> {
    let (db, case_id) = setup().await?;

    // Messaging: 3 with Alice, 2 with Bob (device-centric -> star from "self").
    for _ in 0..3 {
        record(&db, case_id, serde_json::json!({
            "type": "iMessage", "chat_display_name": "Alice", "text": "hi", "service": "iMessage"
        })).await?;
    }
    for _ in 0..2 {
        record(
            &db,
            case_id,
            serde_json::json!({
                "type": "AndroidSms", "contact": "Bob", "text": "yo"
            }),
        )
        .await?;
    }
    // Email network: alice -> bob, cc carol.
    record(
        &db,
        case_id,
        serde_json::json!({
            "type": "EmailMessage",
            "from": "Alice@example.com", "from_name": "Alice A",
            "to": ["bob@example.com"], "cc": ["carol@example.com"],
            "subject": "Lunch"
        }),
    )
    .await?;

    let g = db.communication_graph(case_id).await?;

    // Self node present; Alice/Bob contacts fan out from it.
    let self_node = g
        .nodes
        .iter()
        .find(|n| n.kind == "self")
        .expect("self node");
    let edge_weight = |a: &str, b: &str| {
        g.edges
            .iter()
            .find(|e| (e.source == a && e.target == b) || (e.source == b && e.target == a))
            .map(|e| e.weight)
    };
    let contact_id = |label: &str| {
        g.nodes
            .iter()
            .find(|n| n.label == label)
            .map(|n| n.id.clone())
    };

    let alice_c = contact_id("Alice").expect("Alice contact");
    let bob_c = contact_id("Bob").expect("Bob contact");
    assert_eq!(
        edge_weight(&self_node.id, &alice_c),
        Some(3),
        "3 messages with Alice"
    );
    assert_eq!(
        edge_weight(&self_node.id, &bob_c),
        Some(2),
        "2 messages with Bob"
    );

    // Email addresses collapse to normalized (lower-cased) node ids.
    assert!(g
        .nodes
        .iter()
        .any(|n| n.id == "alice@example.com" && n.kind == "email"));
    assert!(g.nodes.iter().any(|n| n.id == "bob@example.com"));
    assert!(g.nodes.iter().any(|n| n.id == "carol@example.com"));
    assert_eq!(edge_weight("alice@example.com", "bob@example.com"), Some(1));
    assert_eq!(
        edge_weight("alice@example.com", "carol@example.com"),
        Some(1)
    );
    assert!(!g.truncated);

    Ok(())
}

/// BUG-271: WhatsApp records the correspondent as a JID (`contact_jid` on iOS,
/// `remote_jid` on Android) or a group `chat_subject` — never
/// `chat_display_name` / `chat_identifier`. Keying only on those left the peer
/// NULL, so the graph advertised WhatsApp and then omitted every peer.
#[tokio::test]
async fn whatsapp_peers_reach_the_graph() -> Result<()> {
    let (db, case_id) = setup().await?;

    // iOS: session JID, no chat_identifier/chat_display_name.
    for _ in 0..2 {
        record(
            &db,
            case_id,
            serde_json::json!({
                "type": "WhatsApp", "platform": "iOS",
                "contact_jid": "15551234567@s.whatsapp.net",
                "remote_jid": "15551234567@s.whatsapp.net",
                "text": "hi", "is_from_me": false
            }),
        )
        .await?;
    }
    // Android: remote_jid only.
    record(
        &db,
        case_id,
        serde_json::json!({
            "type": "WhatsApp", "platform": "Android",
            "remote_jid": "15559998888@s.whatsapp.net",
            "text": "yo", "is_from_me": true
        }),
    )
    .await?;
    // A sent iOS message whose peer is only on to_jid (BUG-252 shape).
    record(
        &db,
        case_id,
        serde_json::json!({
            "type": "WhatsApp", "platform": "iOS",
            "to_jid": "15557770000@s.whatsapp.net",
            "text": "on my way", "is_from_me": true
        }),
    )
    .await?;

    let g = db.communication_graph(case_id).await?;
    let self_node = g
        .nodes
        .iter()
        .find(|n| n.kind == "self")
        .expect("self node");
    let edge_weight = |peer: &str| {
        g.edges
            .iter()
            .find(|e| {
                (e.source == self_node.id && e.target == peer)
                    || (e.target == self_node.id && e.source == peer)
            })
            .map(|e| e.weight)
    };

    assert_eq!(
        edge_weight("15551234567@s.whatsapp.net"),
        Some(2),
        "iOS WhatsApp peer must appear with both its messages"
    );
    assert_eq!(edge_weight("15559998888@s.whatsapp.net"), Some(1));
    assert_eq!(
        edge_weight("15557770000@s.whatsapp.net"),
        Some(1),
        "a sent message whose peer is only on to_jid must still map"
    );
    Ok(())
}

#[tokio::test]
async fn empty_case_yields_empty_graph() -> Result<()> {
    let (db, case_id) = setup().await?;
    let g = db.communication_graph(case_id).await?;
    assert!(g.nodes.is_empty());
    assert!(g.edges.is_empty());
    assert_eq!(g.total_participants, 0);
    Ok(())
}

/// B2-012: the graph aggregated only iMessage / WhatsApp / SMS / calls, so a
/// case whose traffic is Signal, Instagram, Telegram or Skype drew an EMPTY
/// contact network while the messages sat in the database. An understated
/// contact network is a wrong investigative conclusion, not a cosmetic gap.
#[tokio::test]
async fn every_parsed_messaging_platform_reaches_the_graph() -> Result<()> {
    let (db, case_id) = setup().await?;

    let platforms = [
        ("Signal", "signal-peer"),
        ("Instagram", "insta-peer"),
        ("Snapchat", "snap-peer"),
        ("TwitterDM", "twitter-peer"),
        ("Skype", "skype-peer"),
        ("LINE", "line-peer"),
        ("TelegramMessage", "telegram-peer"),
        ("Viber", "viber-peer"),
        ("Kik", "kik-peer"),
        ("WeChat", "wechat-peer"),
        ("FacebookMessenger", "messenger-peer"),
    ];
    for (record_type, peer) in platforms {
        record(
            &db,
            case_id,
            serde_json::json!({
                "type": record_type,
                "subtype": "chat_message",
                "chat_identifier": peer,
                "text": "hello",
            }),
        )
        .await?;
    }

    let g = db.communication_graph(case_id).await?;
    let self_node = g
        .nodes
        .iter()
        .find(|n| n.kind == "self")
        .expect("self node");

    for (record_type, peer) in platforms {
        assert!(
            g.nodes.iter().any(|n| n.id == peer),
            "{record_type} peer missing from the contact network"
        );
        assert!(
            g.edges.iter().any(|e| {
                (e.source == self_node.id && e.target == peer)
                    || (e.target == self_node.id && e.source == peer)
            }),
            "{record_type} traffic missing from the contact network"
        );
    }
    Ok(())
}

/// A Viber record keys on `conversation_id` rather than `chat_identifier`; the
/// peer expression must still find it.
#[tokio::test]
async fn viber_conversation_ids_are_peers_too() -> Result<()> {
    let (db, case_id) = setup().await?;
    record(
        &db,
        case_id,
        serde_json::json!({
            "type": "Viber",
            "subtype": "chat_message",
            "conversation_id": "viber-thread-9",
            "text": "hi",
        }),
    )
    .await?;

    let g = db.communication_graph(case_id).await?;
    assert!(
        g.nodes.iter().any(|n| n.id == "viber-thread-9"),
        "a Viber conversation must appear as a peer, not vanish"
    );
    Ok(())
}

/// B4-005: email edges load under a row cap, but `truncated` was set only when
/// the participant count exceeded the node ceiling. A case with more emails
/// than the cap therefore drew an under-weighted contact network and reported
/// `truncated: false` alongside it — an over-stated completeness claim in the
/// view an examiner uses to decide who talked to whom.
#[tokio::test]
async fn an_email_row_cap_reports_the_network_as_truncated() -> Result<()> {
    let (db, case_id) = setup().await?;

    // Three email records, read under a cap of two: one message never reaches
    // the aggregation.
    for peer in ["bob@example.com", "carol@example.com", "dave@example.com"] {
        record(
            &db,
            case_id,
            serde_json::json!({
                "type": "EmailMessage",
                "from": "alice@example.com",
                "to": [peer],
            }),
        )
        .await?;
    }

    let capped = db.communication_graph_with_email_cap(case_id, 2).await?;
    assert!(
        capped.truncated,
        "a graph that did not read every email must not present as complete"
    );

    // Well under the cap: the same case is NOT truncated, so the flag keeps
    // meaning something.
    let whole = db.communication_graph_with_email_cap(case_id, 1000).await?;
    assert!(!whole.truncated);
    assert_eq!(
        whole.edges.len(),
        3,
        "all three email edges are present when nothing is capped"
    );

    Ok(())
}

/// A call with no number is recorded under the placeholder `Unknown`. That is
/// not a party: it must not appear as a node, and the calls must be counted and
/// disclosed. A chat correspondent genuinely named "Unknown" stays a node.
#[tokio::test]
async fn unidentified_calls_are_disclosed_not_drawn_as_a_contact() -> Result<()> {
    let (db, case_id) = setup().await?;
    for _ in 0..4 {
        record(
            &db,
            case_id,
            serde_json::json!({"type": "CallLog", "contact": "Unknown"}),
        )
        .await?;
    }
    record(
        &db,
        case_id,
        serde_json::json!({"type": "CallLog", "contact": "+353871234567"}),
    )
    .await?;
    record(
        &db,
        case_id,
        serde_json::json!({"type": "WhatsApp", "contact": "Unknown", "text": "hi"}),
    )
    .await?;

    let g = db.communication_graph(case_id).await?;
    assert_eq!(g.records_without_counterparty, 4);
    let weight_of = |label: &str| g.nodes.iter().find(|n| n.label == label).map(|n| n.weight);
    assert_eq!(weight_of("+353871234567"), Some(1));
    assert_eq!(
        weight_of("Unknown"),
        Some(1),
        "only the WhatsApp correspondent named Unknown is a node"
    );
    Ok(())
}
